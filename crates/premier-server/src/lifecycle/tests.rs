use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use http_body_util::BodyExt;
use premier_core::AuditDecision;
use premier_policy::{AutonomyBudget, BudgetAction, CompiledPolicy, parse_policy_toml};
use premier_proxy::{ApprovalRequest, EphemeralCa};
use premier_secrets::{
    EnvSchema, RotationDispatcher, SecretBackend, SecretCoord, SecretLayer,
    verify_webhook_signature,
};
use serde_json::{Value, json};

use crate::runner::{AgentSessionRecord, SessionManager, effective_budget, is_live, session_dir};
use crate::tests::{MEMBER_POLICY, PW, call, commit_all, member_state, oneshot};
use crate::{ServerState, build_router};

// ---- helpers -------------------------------------------------------------------------------

fn set_policy(state: &ServerState, toml: &str) {
    let file = parse_policy_toml(toml).unwrap();
    *state.policy.write().unwrap() = Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
    state.set_repo_policy_metadata(Some(toml.to_owned()), Some(Arc::new(file)));
}

fn set_schema(state: &ServerState, toml: &str) {
    *state.env_schema.write().unwrap() = Some(Arc::new(EnvSchema::parse_toml(toml).unwrap()));
}

async fn send(
    router: &Router,
    method: Method,
    uri: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let (status, _, body) = call(router, method, uri, &[("cookie", cookie)], Some(body)).await;
    (status, body)
}

async fn get(router: &Router, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let (status, _, body) = call(router, Method::GET, uri, &[("cookie", cookie)], None).await;
    (status, body)
}

async fn open_events(router: &Router, cookie: &str) -> hyper::body::Incoming {
    let req = Request::builder()
        .uri("/v1/events/stream")
        .header("host", "localhost")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    oneshot(router.clone(), req).await.into_body()
}

/// Everything the stream sends within `within` (or until `until` shows up).
async fn read_events(stream: &mut hyper::body::Incoming, until: &str, within: Duration) -> String {
    let mut seen = String::new();
    let _ = tokio::time::timeout(within, async {
        while !seen.contains(until) {
            match stream.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        seen.push_str(&String::from_utf8_lossy(&data));
                    }
                }
                _ => break,
            }
        }
    })
    .await;
    seen
}

/// Wait for session `id` to reach `want`; panics if it ends otherwise.
async fn wait_status(state: &ServerState, id: &str, want: &str) -> AgentSessionRecord {
    for _ in 0..600 {
        let rec = state.session_manager.get(id).unwrap();
        if rec.status == want {
            return rec;
        }
        assert!(
            is_live(&rec.status),
            "{id} ended as {} ({:?}) while waiting for {want}: {:?}",
            rec.status,
            rec.ended_reason,
            rec.output_lines
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {id} never reached {want}");
}

const BUDGET_POLICY: &str = r#"
version = 1
[defaults]
public = []
authenticated = ["traverse", "list", "read"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[agent_profiles]]
name = "budgeted"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read", "write"]
max_files_modified = 1
[[agent_profiles]]
name = "killer"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read", "write"]
max_files_modified = 1
on_budget_exceeded = "terminate"
"#;

/// Writes two files, then waits (up to a minute) for the test to drop `release.txt` in.
const WRITE_TWO_AND_WAIT: &str = if cfg!(windows) {
    "Set-Content -Path a.txt -Value a; Set-Content -Path b.txt -Value b; for ($i = 0; $i -lt 600 -and -not (Test-Path release.txt); $i++) { Start-Sleep -Milliseconds 100 }; 'done'"
} else {
    "printf a > a.txt; printf b > b.txt; i=0; while [ ! -e release.txt ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done; echo done"
};

/// A committed one-file repository under [`BUDGET_POLICY`] whose sessions run unconfined
/// when the host has no sandbox. Returns the owner's and a member's cookie.
fn budget_repo(root: &Path) -> (ServerState, String, String) {
    let (mut state, owner, mia, _) = member_state(root);
    set_policy(&state, BUDGET_POLICY);
    state.session_manager = Arc::new(SessionManager::open(root));
    state.allow_unsandboxed_agents = true;
    commit_all(root);
    (state, owner, mia)
}

async fn spawn(router: &Router, owner: &str, body: Value) -> String {
    let (status, body) = send(router, Method::POST, "/v1/agents/sessions", owner, body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["id"].as_str().unwrap().to_owned()
}

// ---- 1. live budget: pause, alert, raise and resume -----------------------------------------

#[test]
fn request_budgets_only_tighten_the_policy_budget() {
    let policy = CompiledPolicy::compile(None, &parse_policy_toml(BUDGET_POLICY).unwrap()).unwrap();
    let loose = AutonomyBudget {
        max_files_modified: Some(100),
        max_egress_requests: Some(5),
        ..AutonomyBudget::default()
    };
    let b = effective_budget(Some(&policy), Some("budgeted"), Some(&loose));
    assert_eq!(b.max_files_modified, Some(1));
    assert_eq!(b.max_egress_requests, Some(5));
    assert_eq!(b.on_budget_exceeded, BudgetAction::Pause);
    let harsher = AutonomyBudget {
        on_budget_exceeded: BudgetAction::Terminate,
        ..AutonomyBudget::default()
    };
    let b = effective_budget(Some(&policy), Some("budgeted"), Some(&harsher));
    assert_eq!(b.on_budget_exceeded, BudgetAction::Terminate);
    // A terminate profile is never softened to pause.
    let b = effective_budget(
        Some(&policy),
        Some("killer"),
        Some(&AutonomyBudget::default()),
    );
    assert_eq!(b.on_budget_exceeded, BudgetAction::Terminate);
    assert_eq!(
        effective_budget(None, None, None),
        AutonomyBudget::default()
    );
}

#[tokio::test]
async fn budget_breach_pauses_alerts_and_resumes_when_the_owner_raises_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia) = budget_repo(root);
    let router = build_router(state.clone());
    let mut alerts = state.session_manager.subscribe_budget_alerts();
    let mut owner_events = open_events(&router, &owner).await;
    let mut mia_events = open_events(&router, &mia).await;

    let id = spawn(
        &router,
        &owner,
        json!({ "command": WRITE_TWO_AND_WAIT, "agent_profile": "budgeted" }),
    )
    .await;
    let (_, list) = get(&router, "/v1/agents/sessions", &owner).await;
    assert_eq!(
        list[0]["budget"]["limits"]["max_files_modified"], 1,
        "{list}"
    );

    let paused = wait_status(&state, &id, "paused").await;
    let budget = paused.budget.clone().unwrap();
    assert!(budget.paused && !budget.terminated, "{budget:?}");
    assert_eq!(budget.breached_metric.as_deref(), Some("files_modified"));
    assert!(budget.files_modified >= 2, "{budget:?}");
    assert!(
        paused
            .output_lines
            .iter()
            .any(|l| l.starts_with("[cage] PAUSED:")),
        "{:?}",
        paused.output_lines
    );

    let alert = tokio::time::timeout(Duration::from_secs(10), alerts.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (alert.session_id.as_str(), alert.metric.as_str()),
        (id.as_str(), "files_modified")
    );
    assert_eq!(alert.action, BudgetAction::Pause);
    assert_eq!(alert.principal, "@owner");

    let seen = read_events(
        &mut owner_events,
        "event: budget_alert",
        Duration::from_secs(10),
    )
    .await;
    assert!(
        seen.contains("event: budget_alert") && seen.contains("files_modified"),
        "{seen}"
    );
    // Another principal's budget alerts are not a member's to see.
    let theirs = read_events(
        &mut mia_events,
        "event: budget_alert",
        Duration::from_millis(800),
    )
    .await;
    assert!(!theirs.contains("budget_alert"), "{theirs}");

    let audited = state.audit_sink.snapshot();
    assert!(
        audited
            .iter()
            .any(|e| e.decision == AuditDecision::BudgetExceeded
                && e.action == "budget_exceeded"
                && e.target.as_deref() == Some(id.as_str())),
        "{audited:?}"
    );

    // Raising the budget is a human (owner, browser) decision.
    let uri = format!("/v1/agents/sessions/{id}/budget");
    let raise = json!({ "limits": { "max_files_modified": 10 } });
    let (status, _) = send(&router, Method::POST, &uri, &mia, raise.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(&router, Method::POST, &uri, &owner, raise.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "running", "{body}");
    assert_eq!(body["budget"]["paused"], false, "{body}");
    assert_eq!(body["budget"]["limits"]["max_files_modified"], 10, "{body}");
    assert!(
        state
            .audit_sink
            .snapshot()
            .iter()
            .any(|e| e.action == "budget_raised")
    );

    std::fs::write(session_dir(root, &id).join("ws/release.txt"), "go").unwrap();
    let done = wait_status(&state, &id, "completed").await;
    assert!(
        done.output_lines
            .iter()
            .any(|l| l == "[cage] RESUMED: budget raised by owner"),
        "{:?}",
        done.output_lines
    );
    let budget = done.budget.unwrap();
    assert!(!budget.paused && !budget.terminated, "{budget:?}");
    assert_eq!(budget.limits.max_files_modified, Some(10));

    // Ended sessions and unknown ones cannot be raised.
    let (status, _) = send(&router, Method::POST, &uri, &owner, raise.clone()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions/cage-9999/budget",
        &owner,
        raise,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- 2. live budget: terminate --------------------------------------------------------------

#[tokio::test]
async fn budget_breach_terminates_a_terminate_profile_and_a_tightened_request() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _) = budget_repo(root);
    let router = build_router(state.clone());

    let id = spawn(
        &router,
        &owner,
        json!({ "command": WRITE_TWO_AND_WAIT, "agent_profile": "killer" }),
    )
    .await;
    let rec = wait_status(&state, &id, "budget_exceeded").await;
    assert!(
        rec.ended_reason
            .as_deref()
            .unwrap_or_default()
            .contains("files_modified"),
        "{rec:?}"
    );
    assert!(rec.budget.as_ref().unwrap().terminated);
    assert!(
        rec.output_lines
            .iter()
            .any(|l| l.starts_with("[cage] TERMINATED:"))
    );
    assert!(
        rec.changes.iter().any(|c| c.path == "a.txt"),
        "what it left is still reviewable: {:?}",
        rec.changes
    );

    // A pause profile asked for `terminate` (and a looser cap) is tightened, never loosened.
    let id = spawn(
        &router,
        &owner,
        json!({
            "command": WRITE_TWO_AND_WAIT,
            "agent_profile": "budgeted",
            "budget": { "max_files_modified": 50, "on_budget_exceeded": "terminate" }
        }),
    )
    .await;
    let rec = wait_status(&state, &id, "budget_exceeded").await;
    assert_eq!(rec.budget.unwrap().limits.max_files_modified, Some(1));
}

// ---- 3. Envelope KMS + Key Transparency ----------------------------------------------------

const KMS_SCHEMA: &str = r#"
version = 1
repo_id = "acme/app"
[vars.STRIPE_API_KEY]
type = "secret"
[vars.DB_PASSWORD]
type = "secret"
"#;

fn vault_value(root: &Path, var: &str) -> Option<String> {
    let vault = crate::store::open_workspace_vault_backend(root, "acme/app").unwrap();
    vault
        .get(&SecretCoord {
            repo_id: "acme/app".to_owned(),
            layer: SecretLayer::Env,
            scope: "dev".to_owned(),
            var_name: var.to_owned(),
        })
        .unwrap()
        .map(|v| v.as_str().to_owned())
}

#[tokio::test]
async fn kms_status_migrates_from_age_to_envelope_and_rotates_the_dek() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = member_state(root);
    set_schema(&state, KMS_SCHEMA);
    commit_all(root);
    let router = build_router(state.clone());
    for (key, value) in [("STRIPE_API_KEY", "sk_live_1"), ("DB_PASSWORD", "hunter2")] {
        let body = json!({ "key": key, "value": value, "env": "dev" });
        let (status, body) = send(&router, Method::POST, "/v1/secrets/set", &owner, body).await;
        assert_eq!(
            (status, body["backend"].as_str()),
            (StatusCode::OK, Some("age-aead"))
        );
    }

    let (status, st) = get(&router, "/v1/secrets/kms/status", &owner).await;
    assert_eq!(status, StatusCode::OK, "{st}");
    assert_eq!(st["mode"], "sovereign_age", "{st}");
    assert_eq!(st["provider"], "age");
    assert_eq!(
        (st["entry_count"].as_u64(), st["kt_valid"].as_bool()),
        (Some(2), Some(true)),
        "{st}"
    );
    assert!(st["key_id"].as_str().unwrap().starts_with("age-"));
    assert!(
        !st["kt_recent_entries"].as_array().unwrap().is_empty(),
        "{st}"
    );
    let (status, _) = get(&router, "/v1/secrets/kms/status", &mia).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // No DEK to rotate before the migration.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/secrets/kms/rotate-dek",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/secrets/kms/migrate",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (
            body["migrated_entries"].as_u64(),
            body["already_migrated"].as_bool()
        ),
        (Some(2), Some(false))
    );
    assert_eq!(body["status"]["mode"], "envelope", "{body}");
    assert_eq!(body["status"]["kt_valid"], true, "{body}");
    assert_eq!(body["status"]["dek_version"], 1);
    let events: Vec<&str> = body["status"]["kt_recent_entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert!(events.contains(&"migrate_to_envelope"), "{events:?}");
    assert!(events.contains(&"migrate_retire_age"), "{events:?}");
    assert!(!crate::store::age_vault_path(root).exists());
    // Local AgeKeyWrapper still uses age.key (kek_separated == false).
    assert!(crate::store::age_key_path(root).exists());
    let (_, again) = send(
        &router,
        Method::POST,
        "/v1/secrets/kms/migrate",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(
        (
            again["migrated_entries"].as_u64(),
            again["already_migrated"].as_bool()
        ),
        (Some(0), Some(true))
    );
    let (_, meta) = get(&router, "/v1/secrets/status", &owner).await;
    assert_eq!(
        meta["entries"]["dev:STRIPE_API_KEY"]["backend"], "envelope-kms",
        "{meta}"
    );
    assert_eq!(
        vault_value(root, "STRIPE_API_KEY").as_deref(),
        Some("sk_live_1")
    );

    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/secrets/kms/rotate-dek",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["dek_version"], 2);
    assert_eq!(
        (
            body["status"]["dek_version"].as_u64(),
            body["status"]["kt_valid"].as_bool()
        ),
        (Some(2), Some(true))
    );
    assert_eq!(
        vault_value(root, "STRIPE_API_KEY").as_deref(),
        Some("sk_live_1")
    );
    assert_eq!(vault_value(root, "DB_PASSWORD").as_deref(), Some("hunter2"));

    // New writes land in the envelope vault; nothing in a response carries a value.
    let body = json!({ "key": "STRIPE_API_KEY", "value": "sk_live_2", "env": "dev" });
    let (_, body) = send(&router, Method::POST, "/v1/secrets/set", &owner, body).await;
    assert_eq!(body["backend"], "envelope-kms");
    assert_eq!(
        vault_value(root, "STRIPE_API_KEY").as_deref(),
        Some("sk_live_2")
    );
    let (_, st) = get(&router, "/v1/secrets/kms/status", &owner).await;
    assert!(!st.to_string().contains("sk_live") && !st.to_string().contains("hunter2"));
    assert_eq!(st["kt_valid"], true, "{st}");
}

// ---- 4. signed dual-phase rotation over verified loopback TLS -------------------------------

#[derive(Clone, Debug)]
struct Hook {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Hook {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    fn phase(&self) -> String {
        let v: Value = serde_json::from_slice(&self.body).unwrap();
        v["phase"].as_str().unwrap().to_owned()
    }
}

/// HTTPS rotation provider on 127.0.0.1 with a certificate from a throwaway CA: `prepare`
/// answers a new value, `commit` fails while `fail_commit` is set.
struct Provider {
    url: String,
    ca: EphemeralCa,
    hooks: Arc<Mutex<Vec<Hook>>>,
    fail_commit: Arc<AtomicBool>,
}

fn provider() -> Provider {
    let ca = EphemeralCa::generate().unwrap();
    let cfg = ca.server_config_for_host("127.0.0.1").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hooks: Arc<Mutex<Vec<Hook>>> = Arc::default();
    let fail_commit = Arc::new(AtomicBool::new(false));
    let (hooks_bg, fail_bg) = (Arc::clone(&hooks), Arc::clone(&fail_commit));
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (cfg, hooks, fail) = (
                Arc::clone(&cfg),
                Arc::clone(&hooks_bg),
                Arc::clone(&fail_bg),
            );
            std::thread::spawn(move || {
                let conn = tokio_rustls::rustls::ServerConnection::new(cfg).unwrap();
                let mut s = tokio_rustls::rustls::StreamOwned::new(conn, tcp);
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let end = loop {
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break i + 4;
                    }
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                };
                let head = String::from_utf8_lossy(&buf[..end]).to_string();
                let headers: Vec<(String, String)> = head
                    .split("\r\n")
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                    .collect();
                let len: usize = headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, v)| v.parse().unwrap());
                let mut body = buf[end..].to_vec();
                while body.len() < len {
                    match s.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                    }
                }
                let hook = Hook { headers, body };
                let phase = hook.phase();
                hooks.lock().unwrap().push(hook);
                let (code, reply) = match phase.as_str() {
                    "prepare" => (200, r#"{"new_value":"sk_rotated_by_provider"}"#),
                    "commit" if fail.load(Ordering::SeqCst) => (500, r#"{"error":"boom"}"#),
                    _ => (200, "{}"),
                };
                let resp = format!(
                    "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = s.write_all(resp.as_bytes());
                s.conn.send_close_notify();
                let _ = s.flush();
            });
        }
    });
    Provider {
        url: format!("https://127.0.0.1:{port}/rotate"),
        ca,
        hooks,
        fail_commit,
    }
}

fn rotation_schema(url: &str) -> String {
    format!(
        r#"
version = 1
repo_id = "acme/app"
[vars.STRIPE_API_KEY]
type = "secret"
[vars.STRIPE_API_KEY.rotation]
provider = "stripe"
webhook_url = "{url}"
signing_secret_ref = "ROTATION_HMAC"
[vars.PLAIN_TOKEN]
type = "secret"
"#
    )
}

const HMAC: &str = "whsec-test-signing-key";

fn assert_signed(hook: &Hook) {
    let ts: i64 = hook.header("x-premier-timestamp").parse().unwrap();
    let sig = hook.header("x-premier-signature-256");
    assert!(sig.starts_with("sha256="), "{sig}");
    assert!(verify_webhook_signature(
        HMAC.as_bytes(),
        ts,
        &hook.body,
        sig
    ));
    assert!(!verify_webhook_signature(
        b"another key",
        ts,
        &hook.body,
        sig
    ));
}

#[tokio::test]
async fn rotation_is_signed_dual_phase_and_rolls_back_a_failed_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, mia, _) = member_state(root);
    let provider = provider();
    set_schema(&state, &rotation_schema(&provider.url));
    state.rotation_dispatcher = Arc::new(RotationDispatcher {
        allow_insecure_loopback: false,
        allow_private_webhooks: true,
        allowed_hosts: vec![],
        extra_root_certs: vec![provider.ca.ca_cert_der()],
    });
    commit_all(root);
    let router = build_router(state.clone());
    for (key, value) in [("STRIPE_API_KEY", "sk_old"), ("ROTATION_HMAC", HMAC)] {
        let body = json!({ "key": key, "value": value, "env": "dev" });
        let (status, _) = send(&router, Method::POST, "/v1/secrets/set", &owner, body).await;
        assert_eq!(status, StatusCode::OK);
    }
    let rotate = "/v1/secrets/STRIPE_API_KEY/rotate";
    let (status, _) = send(&router, Method::POST, rotate, &mia, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, receipt) = send(
        &router,
        Method::POST,
        rotate,
        &owner,
        json!({ "env": "dev", "reason": "quarterly" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["status"], "committed", "{receipt}");
    assert_eq!(receipt["phase_reached"], "commit");
    assert_eq!(receipt["provider"], "stripe");
    for secret in ["sk_old", "sk_rotated_by_provider", HMAC] {
        assert!(!receipt.to_string().contains(secret), "{receipt}");
    }
    assert_eq!(
        vault_value(root, "STRIPE_API_KEY").as_deref(),
        Some("sk_rotated_by_provider")
    );
    {
        let hooks = provider.hooks.lock().unwrap();
        let phases: Vec<String> = hooks.iter().map(Hook::phase).collect();
        assert_eq!(phases, ["prepare", "commit"]);
        hooks.iter().for_each(assert_signed);
        let body: Value = serde_json::from_slice(&hooks[0].body).unwrap();
        assert_eq!(
            (body["var_name"].as_str(), body["env"].as_str()),
            (Some("STRIPE_API_KEY"), Some("dev"))
        );
    }
    let (_, meta) = get(&router, "/v1/secrets/status", &owner).await;
    assert_eq!(
        meta["entries"]["dev:STRIPE_API_KEY"]["rotated_count"], 2,
        "{meta}"
    );

    // A failed commit puts the previous value back and tells the provider to roll back.
    provider.fail_commit.store(true, Ordering::SeqCst);
    let (status, receipt) = send(
        &router,
        Method::POST,
        rotate,
        &owner,
        json!({ "env": "dev" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["status"], "rolled_back", "{receipt}");
    assert_eq!(receipt["http_status"], 500);
    assert_eq!(receipt["rollback_sent"], true, "{receipt}");
    assert_eq!(
        vault_value(root, "STRIPE_API_KEY").as_deref(),
        Some("sk_rotated_by_provider")
    );
    {
        let hooks = provider.hooks.lock().unwrap();
        let phases: Vec<String> = hooks.iter().map(Hook::phase).collect();
        assert_eq!(
            phases,
            ["prepare", "commit", "prepare", "commit", "rollback"]
        );
        hooks.iter().for_each(assert_signed);
    }

    let (_, list) = get(&router, "/v1/secrets/rotations", &owner).await;
    let statuses: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["rolled_back", "committed"]);

    // Not in the schema: 404. In it without a webhook: 400.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/secrets/NOPE/rotate",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/secrets/PLAIN_TOKEN/rotate",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- 5. keyless OIDC workload identity -----------------------------------------------------

const OIDC_POLICY_PROFILES: &str = r#"
[[agent_profiles]]
name = "stripe-agent"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read"]
allow_secret_use = ["STRIPE_API_KEY"]
[[agent_profiles]]
name = "no-secrets"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read"]
"#;

#[tokio::test]
async fn oidc_tokens_are_scoped_self_only_for_members_and_revocable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, mia_token) = member_state(root);
    set_policy(&state, &format!("{MEMBER_POLICY}{OIDC_POLICY_PROFILES}"));
    set_schema(&state, KMS_SCHEMA);
    let (_, olga_token) = state.auth.seed("olga", PW);
    commit_all(root);
    assert!(
        premier_git_bridge::git_command(root)
            .args(["update-ref", "refs/premier-private/embargo", "HEAD"])
            .status()
            .unwrap()
            .success()
    );
    let router = build_router(state.clone());

    let (status, doc) = get(&router, "/v1/oidc/discovery", &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        doc["id_token_signing_alg_values_supported"],
        json!(["EdDSA"])
    );
    assert!(doc["issuer"].as_str().is_some());

    let (status, minted) = send(&router, Method::POST, "/v1/oidc/token", &mia, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert_eq!(minted["claims"]["sub"], "@mia");
    assert_eq!(minted["claims"]["aud"], json!(["premier"]));
    assert_eq!(minted["claims"]["branch"], "main");
    assert_eq!(minted["alg"], "EdDSA");
    let scope = minted["claims"]["scope"].to_string();
    assert!(scope.contains("secrets:use:STRIPE_API_KEY"), "{scope}");
    let mia_jwt = minted["token"].as_str().unwrap().to_owned();
    // The raw token never reaches the audit log.
    assert!(
        state
            .audit_sink
            .snapshot()
            .iter()
            .all(|e| !e.reason.contains(&mia_jwt))
    );

    // Members (by session or token) and owner tokens only ever mint for themselves.
    let other = json!({ "principal": "@owner" });
    let (status, _) = send(&router, Method::POST, "/v1/oidc/token", &mia, other.clone()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let mia_bearer = format!("Bearer {mia_token}");
    let (status, _, _) = call(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &[("authorization", &mia_bearer)],
        Some(other),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let olga_bearer = format!("Bearer {olga_token}");
    let as_mia = json!({ "principal": "@mia" });
    let (status, _, _) = call(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &[("authorization", &olga_bearer)],
        Some(as_mia.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &[("authorization", &mia_bearer)],
        Some(json!({ "aud": ["ci"] })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for branch in ["refs/premier-private/embargo", "missing"] {
        let (status, _) = send(
            &router,
            Method::POST,
            "/v1/oidc/token",
            &mia,
            json!({ "branch": branch }),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Scope is human ∩ agent profile.
    let (status, agent) = send(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &owner,
        json!({ "principal": "@mia", "agent_profile": "stripe-agent", "task_id": "t-7" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{agent}");
    assert_eq!(
        agent["claims"]["scope"],
        json!(["secrets:use:STRIPE_API_KEY"]),
        "{agent}"
    );
    assert_eq!(agent["claims"]["act"]["profile"], "stripe-agent");
    assert_eq!(agent["claims"]["act"]["task_id"], "t-7");
    let (_, fenced) = send(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &owner,
        json!({ "principal": "@mia", "agent_profile": "no-secrets" }),
    )
    .await;
    assert_eq!(fenced["claims"]["scope"], json!([]), "{fenced}");
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &owner,
        json!({ "agent_profile": "ghost" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let verify = |token: &str, aud: &str| json!({ "token": token, "audience": aud });
    let (status, ok) = send(
        &router,
        Method::POST,
        "/v1/oidc/verify",
        &mia,
        verify(&mia_jwt, "premier"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (ok["valid"].as_bool(), ok["claims"]["sub"].as_str()),
        (Some(true), Some("@mia")),
        "{ok}"
    );
    let (_, wrong) = send(
        &router,
        Method::POST,
        "/v1/oidc/verify",
        &mia,
        verify(&mia_jwt, "elsewhere"),
    )
    .await;
    assert_eq!(wrong["valid"], false);
    let mut forged = mia_jwt.clone();
    forged.push('A');
    let (_, bad) = send(
        &router,
        Method::POST,
        "/v1/oidc/verify",
        &mia,
        verify(&forged, "premier"),
    )
    .await;
    assert_eq!(bad["valid"], false);
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/oidc/verify",
        &mia,
        verify("", "premier"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Revoking the principal rejects every token it was issued, including agent ones.
    state.oidc_issuer.revoke_principal("@mia");
    for token in [&mia_jwt, &agent["token"].as_str().unwrap().to_owned()] {
        let (_, after) = send(
            &router,
            Method::POST,
            "/v1/oidc/verify",
            &owner,
            verify(token, "premier"),
        )
        .await;
        assert_eq!(after["valid"], false, "{after}");
        assert!(
            after["error"].as_str().unwrap().contains("revoked"),
            "{after}"
        );
    }
}

#[test]
fn oidc_signing_key_is_persisted_and_reused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Building a state never creates the account directory.
    let _ = super::load_oidc_issuer(root, false);
    assert!(!root.join(".premier").exists());
    let first = super::load_oidc_issuer(root, true);
    assert!(root.join(".premier/oidc.key").exists());
    let token = first
        .issue(premier_secrets::WorkloadTokenRequest {
            sub: "@a".to_owned(),
            aud: vec!["x".to_owned()],
            ..Default::default()
        })
        .unwrap();
    let again = super::load_oidc_issuer(root, true);
    assert!(again.verify(&token.token, "x").is_ok());
    assert!(super::decode_key(&"ab".repeat(32)).is_some());
    let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    assert!(super::decode_key(&b64).is_some());
    assert!(super::decode_key("short").is_none());
}

// ---- 6. one-click offboarding ---------------------------------------------------------------

fn fake_ed25519_key(seed: u8) -> String {
    let mut blob = Vec::new();
    let tag = b"ssh-ed25519";
    blob.extend_from_slice(&(tag.len() as u32).to_be_bytes());
    blob.extend_from_slice(tag);
    blob.extend_from_slice(&32u32.to_be_bytes());
    blob.extend_from_slice(&[seed; 32]);
    format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    )
}

const LONG_WAIT: &str = if cfg!(windows) {
    "Start-Sleep -Seconds 60"
} else {
    "sleep 60"
};

#[tokio::test]
async fn offboarding_revokes_everything_and_rotates_exposed_secrets() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, mia, mia_token) = member_state(root);
    let provider = provider();
    set_policy(&state, MEMBER_POLICY);
    set_schema(&state, &rotation_schema(&provider.url));
    state.rotation_dispatcher = Arc::new(RotationDispatcher {
        allow_insecure_loopback: false,
        allow_private_webhooks: true,
        allowed_hosts: vec![],
        extra_root_certs: vec![provider.ca.ca_cert_der()],
    });
    state.session_manager = Arc::new(SessionManager::open(root));
    state.allow_unsandboxed_agents = true;
    let (zed, _) = state.auth.seed_as("zed", PW, crate::auth::Role::Member);
    commit_all(root);
    let router = build_router(state.clone());
    for (key, value) in [
        ("STRIPE_API_KEY", "sk_old"),
        ("ROTATION_HMAC", HMAC),
        ("PLAIN_TOKEN", "tok"),
    ] {
        let body = json!({ "key": key, "value": value, "env": "prod" });
        let (status, _) = send(&router, Method::POST, "/v1/secrets/set", &owner, body).await;
        assert_eq!(status, StatusCode::OK);
    }

    // Everything @mia holds: a session and a token (from `member_state`), an SSH key, a pending
    // JIT approval, a live agent session and a workload token.
    state
        .auth
        .add_ssh_key("mia", "laptop", &fake_ed25519_key(3))
        .unwrap();
    let (pending, _waiter) = state.approval_hub.enqueue(ApprovalRequest {
        principal: "@mia".to_owned(),
        agent_profile: None,
        var_name: "STRIPE_API_KEY".to_owned(),
        host: "api.stripe.com".to_owned(),
        method: "POST".to_owned(),
        path: "/v1/".to_owned(),
        ttl_secs: 60,
        ..Default::default()
    });
    let session = spawn(
        &router,
        &owner,
        json!({ "command": LONG_WAIT, "principal": "@mia" }),
    )
    .await;
    wait_status(&state, &session, "running").await;
    let (_, minted) = send(&router, Method::POST, "/v1/oidc/token", &mia, json!({})).await;
    let mia_jwt = minted["token"].as_str().unwrap().to_owned();

    // Refused before anything changes: yourself, and a member.
    let offboard = "/v1/security/offboard";
    let (status, _) = send(
        &router,
        Method::POST,
        offboard,
        &owner,
        json!({ "principal": "@owner" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &router,
        Method::POST,
        offboard,
        &zed,
        json!({ "principal": "@mia" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = get(&router, "/v1/auth/status", &mia).await;
    assert_eq!(status, StatusCode::OK);

    let (status, receipt) = send(
        &router,
        Method::POST,
        offboard,
        &owner,
        json!({ "principal": "mia", "reason": "left the company" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["principal"], "@mia");
    assert_eq!(receipt["actor"], "@owner");
    assert_eq!(
        (
            receipt["account_disabled"].as_bool(),
            receipt["account_deleted"].as_bool()
        ),
        (Some(true), Some(false))
    );
    assert_eq!(
        (
            receipt["sessions_revoked"].as_u64(),
            receipt["tokens_revoked"].as_u64(),
            receipt["ssh_keys_revoked"].as_u64(),
            receipt["approvals_revoked"].as_u64(),
            receipt["agent_sessions_terminated"].as_u64(),
        ),
        (Some(1), Some(1), Some(1), Some(1), Some(1)),
        "{receipt}"
    );
    assert_eq!(receipt["oidc_revoked"], true);
    let rotations = receipt["rotations"].as_array().unwrap();
    let status_of = |var: &str| {
        rotations
            .iter()
            .find(|r| r["var_name"] == var)
            .map(|r| r["status"].as_str().unwrap().to_owned())
    };
    assert_eq!(
        status_of("STRIPE_API_KEY").as_deref(),
        Some("committed"),
        "{receipt}"
    );
    assert_eq!(
        status_of("PLAIN_TOKEN").as_deref(),
        Some("manual_required"),
        "{receipt}"
    );
    assert!(rotations.iter().all(|r| r["triggered_by_offboard"] == true));
    assert!(!receipt.to_string().contains("sk_old") && !receipt.to_string().contains(HMAC));
    let prod = |var: &str| {
        crate::store::open_workspace_vault_backend(root, "acme/app")
            .unwrap()
            .get(&SecretCoord {
                repo_id: "acme/app".to_owned(),
                layer: SecretLayer::Env,
                scope: "prod".to_owned(),
                var_name: var.to_owned(),
            })
            .unwrap()
            .map(|v| v.as_str().to_owned())
    };
    assert_eq!(
        prod("STRIPE_API_KEY").as_deref(),
        Some("sk_rotated_by_provider")
    );
    let hooks = provider.hooks.lock().unwrap().clone();
    assert_eq!(
        hooks.iter().map(Hook::phase).collect::<Vec<_>>(),
        ["prepare", "commit"]
    );
    let payload: Value = serde_json::from_slice(&hooks[0].body).unwrap();
    assert_eq!(payload["triggered_by_offboard"], true);
    hooks.iter().for_each(assert_signed);

    // Her browser session and access token are dead.
    let (status, _) = get(&router, "/v1/agents/sessions", &mia).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let bearer = format!("Bearer {mia_token}");
    let (status, _, _) = call(
        &router,
        Method::GET,
        "/v1/agents/sessions",
        &[("authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Her approval, agent session and workload tokens too.
    let approval = state
        .approval_hub
        .list()
        .into_iter()
        .find(|a| a.id == pending.id)
        .unwrap();
    assert_eq!(approval.status, premier_proxy::ApprovalStatus::Denied);
    let rec = state.session_manager.get(&session).unwrap();
    assert!(!is_live(&rec.status), "{rec:?}");
    assert_eq!(rec.status, "budget_exceeded");
    assert!(rec.ended_reason.unwrap().contains("offboarded"));
    let (_, after) = send(
        &router,
        Method::POST,
        "/v1/oidc/verify",
        &owner,
        json!({ "token": mia_jwt, "audience": "premier" }),
    )
    .await;
    assert_eq!(after["valid"], false, "{after}");
    let (_, users) = get(&router, "/v1/users", &owner).await;
    let mia_row = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "mia")
        .unwrap()
        .clone();
    assert_eq!(mia_row["disabled"], true, "{mia_row}");

    let (_, receipts) = get(&router, "/v1/security/offboard/receipts", &owner).await;
    assert_eq!(receipts.as_array().unwrap().len(), 1);
    assert!(
        state
            .audit_sink
            .snapshot()
            .iter()
            .any(|e| e.action == "principal_offboarded")
    );

    // The alias, deleting the account: it is gone, and so are its directory groups.
    let (status, again) = send(
        &router,
        Method::POST,
        "/v1/auth/offboard",
        &owner,
        json!({ "principal": "@mia", "delete_account": true, "rotate_secrets": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(
        (
            again["account_deleted"].as_bool(),
            again["sessions_revoked"].as_u64()
        ),
        (Some(true), Some(0))
    );
    assert_eq!(again["rotations"], json!([]));
    let (_, users) = get(&router, "/v1/users", &owner).await;
    assert!(
        users
            .as_array()
            .unwrap()
            .iter()
            .all(|u| u["username"] != "mia")
    );
}

#[test]
fn the_last_enabled_owner_cannot_be_revoked() {
    let tmp = tempfile::tempdir().unwrap();
    let store = crate::auth::AuthStore::open(tmp.path());
    store.seed("solo", PW);
    let refused = store.revoke_user_access("solo", "@cli", "test", false);
    assert_eq!(refused.unwrap_err().0, StatusCode::CONFLICT);
    // Nothing changed: the session still exists.
    assert_eq!(store.accounts().unwrap().len(), 1);
    // A policy-only principal is not an error.
    let none = store
        .revoke_user_access("ghost", "@cli", "test", false)
        .unwrap();
    assert!(!none.found);
    store.seed("second", PW);
    let done = store
        .revoke_user_access("solo", "@cli", "test", false)
        .unwrap();
    assert!(done.found && done.account_disabled && done.sessions_revoked == 1);
    assert_eq!(done.tokens_revoked, 1);
}

// ---- 7. owner-only routes: members and owner access tokens get 403 ---------------------------

#[tokio::test]
async fn lifecycle_admin_routes_are_owner_and_browser_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, _owner, mia, mia_token) = member_state(root);
    let (_, olga_token) = state.auth.seed("olga", PW);
    commit_all(root);
    let router = build_router(state);
    let routes = [
        (Method::POST, "/v1/agents/sessions/cage-0001/budget"),
        (Method::GET, "/v1/secrets/kms/status"),
        (Method::POST, "/v1/secrets/kms/rotate-dek"),
        (Method::POST, "/v1/secrets/kms/migrate"),
        (Method::POST, "/v1/secrets/STRIPE_API_KEY/rotate"),
        (Method::GET, "/v1/secrets/rotations"),
        (Method::POST, "/v1/security/offboard"),
        (Method::GET, "/v1/security/offboard/receipts"),
        (Method::POST, "/v1/auth/offboard"),
    ];
    let mia_cookie = [("cookie", mia.as_str())];
    let mia_bearer = format!("Bearer {mia_token}");
    let olga_bearer = format!("Bearer {olga_token}");
    for (method, uri) in routes {
        for who in [
            &mia_cookie[..],
            &[("authorization", mia_bearer.as_str())][..],
            &[("authorization", olga_bearer.as_str())][..],
        ] {
            let body =
                (method == Method::POST).then(|| json!({ "principal": "@mia", "limits": {} }));
            let (status, _, _) = call(&router, method.clone(), uri, who, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
    }
    // OIDC is for every signed-in caller, but never anonymous.
    let (status, _, _) = call(&router, Method::GET, "/v1/oidc/discovery", &[], None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = call(
        &router,
        Method::GET,
        "/v1/oidc/discovery",
        &[("authorization", &mia_bearer)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---- 8. security audit regressions (H3, H5, M1, M5, M7, L1, L3, L7) -------------------------

#[test]
fn external_kms_unmigrated_vault_fails_closed_until_external_migration_retires_age_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let vault = crate::store::open_workspace_vault(root, "acme/app").unwrap();
    vault
        .set(
            &SecretCoord {
                repo_id: "acme/app".to_owned(),
                layer: SecretLayer::Env,
                scope: "dev".to_owned(),
                var_name: "API_KEY".to_owned(),
            },
            "sk_live_before_migrate",
        )
        .unwrap();
    assert!(crate::store::age_vault_path(root).exists());
    assert!(crate::store::age_key_path(root).exists());

    // L3: configuring external KMS while an un-migrated vault.toml exists refuses silent empty access.
    let err = crate::store::open_workspace_vault_backend_with_kms(root, "acme/app", true)
        .err()
        .unwrap();
    assert!(err.contains("migrate first"), "{err}");

    // H5: migrating under an external KEK (separated = true) verifies contents and deletes BOTH
    // vault.toml and age.key.
    let wrapper = Arc::new(premier_secrets::EnvKekWrapper::from_key_bytes(
        "external-kek",
        [9u8; 32],
    ));
    let (migrated, already) =
        super::migrate_to_envelope_with_wrapper(root, "acme/app", "@owner", wrapper.clone(), true)
            .unwrap();
    assert_eq!((migrated, already), (1, false));
    assert!(!crate::store::age_vault_path(root).exists());
    assert!(!crate::store::age_key_path(root).exists());
    let envelope = premier_secrets::EnvelopeVaultBackend::new(
        crate::store::envelope_vault_path(root),
        "acme/app",
        wrapper,
    )
    .with_key_transparency(crate::store::kt_path(root));
    assert_eq!(
        envelope
            .get(&SecretCoord {
                repo_id: "acme/app".to_owned(),
                layer: SecretLayer::Env,
                scope: "dev".to_owned(),
                var_name: "API_KEY".to_owned(),
            })
            .unwrap()
            .unwrap()
            .as_str(),
        "sk_live_before_migrate"
    );
}

#[test]
fn signing_secret_blocks_arbitrary_env_and_rotate_request_debug_redacts() {
    let vault = premier_secrets::MemoryBackend::new();
    let lookup = |k: &str| match k {
        "PREMIER_KMS_KEY" => Some("kms-master-secret".to_owned()),
        "PREMIER_ROTATION_WEBHOOK" => Some("whsec-allowed".to_owned()),
        _ => None,
    };
    assert!(
        super::signing_secret_with(&vault, "acme/app", "prod", "PREMIER_KMS_KEY", lookup).is_none()
    );
    assert_eq!(
        super::signing_secret_with(
            &vault,
            "acme/app",
            "prod",
            "PREMIER_ROTATION_WEBHOOK",
            lookup
        )
        .unwrap()
        .as_str(),
        "whsec-allowed"
    );

    let req = super::RotateSecretRequest {
        env: "prod".to_owned(),
        reason: Some("incident".to_owned()),
        new_value: Some(zeroize::Zeroizing::new("super_secret_pw_99".to_owned())),
    };
    let dbg = format!("{req:?}");
    assert!(!dbg.contains("super_secret_pw_99"), "{dbg}");
    assert!(dbg.contains("[REDACTED]"), "{dbg}");
}

#[tokio::test]
async fn offboarding_handles_case_branches_disabled_spawn_ssrf_and_multi_repo_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, _mia, mia_token) = member_state(root);
    // M7: secret permitted ONLY on non-default branch `release`.
    let release_policy = r#"
version = 1
[defaults]
public = []
authenticated = ["traverse", "list", "read"]
[[rules]]
id = "owners-full"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-release-secret"
effect = "allow"
principals = ["@mia"]
paths = ["secrets/STRIPE_API_KEY"]
refs = ["release"]
capabilities = ["use"]
"#;
    set_policy(&state, release_policy);
    let provider_http = provider();
    set_schema(&state, &rotation_schema(&provider_http.url));
    state.rotation_dispatcher = Arc::new(RotationDispatcher {
        allow_insecure_loopback: false,
        allow_private_webhooks: true,
        allowed_hosts: vec![],
        extra_root_certs: vec![provider_http.ca.ca_cert_der()],
    });
    state.session_manager = Arc::new(SessionManager::open(root));
    state.allow_unsandboxed_agents = true;
    commit_all(root);
    assert!(
        premier_git_bridge::git_command(root)
            .args(["branch", "release"])
            .status()
            .unwrap()
            .success()
    );

    // H3: sibling repo under `.premier/repos/billing` with its own pending approval & exposed secret.
    let billing_dir = crate::store::state_dir(root)
        .join(crate::repos::REPOS_DIR)
        .join("billing");
    std::fs::create_dir_all(&billing_dir).unwrap();
    for args in [
        &["init", "--initial-branch=main"][..],
        &["config", "user.email", "t@t"][..],
        &["config", "user.name", "T"][..],
    ] {
        assert!(
            premier_git_bridge::git_command(&billing_dir)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    std::fs::write(
        billing_dir.join(".access.toml"),
        r#"
version = 1
[defaults]
public = []
authenticated = []
[[rules]]
id = "owners-full"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-billing-key"
effect = "allow"
principals = ["@mia"]
paths = ["secrets/BILLING_KEY"]
refs = ["*"]
capabilities = ["use"]
"#,
    )
    .unwrap();
    std::fs::write(
        billing_dir.join(".env.schema"),
        r#"
version = 1
repo_id = "acme/billing"
[vars.BILLING_KEY]
type = "secret"
"#,
    )
    .unwrap();
    commit_all(&billing_dir);

    let registry = crate::repos::Registry::open(state, None, None);
    let state = registry.default_state();
    let billing = registry.state_for_repo("billing").unwrap();
    let router = build_router(state.clone());

    for (key, value) in [("STRIPE_API_KEY", "sk_old"), ("ROTATION_HMAC", HMAC)] {
        let (status, _) = send(
            &router,
            Method::POST,
            "/v1/secrets/set",
            &owner,
            json!({ "key": key, "value": value, "env": "prod" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    let (billing_approval, _) = billing.approval_hub.enqueue(ApprovalRequest {
        principal: "@mia".to_owned(),
        agent_profile: None,
        var_name: "BILLING_KEY".to_owned(),
        host: "api.stripe.com".to_owned(),
        method: "POST".to_owned(),
        path: "/v1/".to_owned(),
        ttl_secs: 60,
        ..Default::default()
    });

    // M1: Offboard using uppercase `@MIA`.
    let (status, receipt) = send(
        &router,
        Method::POST,
        "/v1/security/offboard",
        &owner,
        json!({ "principal": "@MIA", "env": "prod", "reason": "multi-repo check" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["principal"], "@mia");
    assert_eq!(receipt["account_disabled"], true);
    assert_eq!(receipt["approvals_revoked"], 1);
    let rotations = receipt["rotations"].as_array().unwrap();
    assert!(
        rotations
            .iter()
            .any(|r| r["var_name"] == "STRIPE_API_KEY" && r["status"] == "committed"),
        "expected branch-scoped STRIPE_API_KEY rotation: {receipt}"
    );
    assert!(
        rotations
            .iter()
            .any(|r| r["var_name"] == "BILLING_KEY" && r["status"] == "manual_required"),
        "expected sibling-repo BILLING_KEY rotation/flag: {receipt}"
    );
    // Sibling repo approval was revoked too.
    assert_eq!(
        billing
            .approval_hub
            .list()
            .into_iter()
            .find(|a| a.id == billing_approval.id)
            .unwrap()
            .status,
        premier_proxy::ApprovalStatus::Denied
    );
    // Access token revoked case-insensitively.
    let (status, _, _) = call(
        &router,
        Method::GET,
        "/v1/agents/sessions",
        &[("authorization", &format!("Bearer {mia_token}"))],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // L1: disabled principal cannot spawn new agent sessions via owner API either.
    let (status, err_body) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": LONG_WAIT, "principal": "@mia" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{err_body}");
    assert!(
        err_body["error"]
            .as_str()
            .unwrap_or("")
            .contains("disabled"),
        "{err_body}"
    );

    // M5: default RotationDispatcher blocks loopback SSRF even on HTTPS.
    let ssrf_dispatcher = RotationDispatcher::default();
    let vault = premier_secrets::MemoryBackend::new();
    let ssrf_receipt = ssrf_dispatcher.execute_dual_phase(
        &premier_secrets::RotationSpec {
            provider: Some("stripe".to_owned()),
            webhook_url: provider_http.url,
            signing_secret_ref: "PREMIER_ROTATION_TEST".to_owned(),
            max_age_days: None,
            schedule: None,
            revoke_on_offboard: true,
        },
        HMAC.as_bytes(),
        &vault,
        &SecretCoord {
            repo_id: "acme/app".to_owned(),
            layer: SecretLayer::Env,
            scope: "prod".to_owned(),
            var_name: "STRIPE_API_KEY".to_owned(),
        },
        "@owner",
        "ssrf-test",
        false,
        None,
    );
    assert_eq!(ssrf_receipt.status, premier_secrets::RotationStatus::Failed);
    assert!(
        ssrf_receipt
            .error
            .as_deref()
            .unwrap_or("")
            .contains("refusing"),
        "{:?}",
        ssrf_receipt.error
    );
}
