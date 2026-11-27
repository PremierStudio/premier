#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use hyper_util::rt::TokioIo;
use premier_proxy::{ApprovalHub, AuditSink};
use premier_server::auth::AuthStore;
use premier_server::runner::SessionManager;
use premier_server::store::{bind_state_dir, load_state};
use premier_server::{ServerState, build_router};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};

const OWNER_PASSWORD: &str = "alice-owner-e2e-passphrase";
const MEMBER_PASSWORD: &str = "mia-member-e2e-passphrase";

const INITIAL_README: &str = "\
# Premier E2E Repo
Line two: original summary
Line three: keep unchanged
Line four: footer
";

const INITIAL_LEDGER: &str = "\
pub const LEDGER_SECRET: &str = \"owner-only-ledger-marker\";
pub fn settle_invoice(cents: u64) -> u64 { cents }
";

const ACCESS_POLICY_TOML: &str = r#"
version = 1

[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read", "write"]

[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[rules]]
id = "deny-billing-non-owners"
effect = "deny"
principals = ["anonymous", "@mia"]
paths = ["billing/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[rules]]
id = "mia-stripe-use"
effect = "allow"
principals = ["@mia"]
paths = ["secrets/STRIPE_API_KEY"]
refs = ["*"]
capabilities = ["use"]
"#;

const ENV_SCHEMA_TOML: &str = r#"
version = 1
repo_id = "acme/premier-e2e"

[vars.STRIPE_API_KEY]
type = "secret"
sensitivity = "secret"
required_in = ["dev", "prod"]
description = "Stripe billing API key"

[vars.STRIPE_API_KEY.egress]
hosts = ["api.stripe.com"]
methods = ["GET", "POST"]
path_prefixes = ["/v1/"]

[vars.BILLING_ADMIN_KEY]
type = "secret"
sensitivity = "restricted"
zone = "billing"
required_in = ["prod"]
description = "Owner-only billing settlement key"
"#;

fn run_git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=Alice",
            "-c",
            "user.email=alice@acme.test",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} failed (status={}):\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn extract_session_cookie(headers: &HeaderMap) -> String {
    for val in headers.get_all(header::SET_COOKIE) {
        if let Ok(s) = val.to_str()
            && let Some(kv) = s.split(';').next()
            && kv.starts_with("premier_session=")
        {
            return kv.to_owned();
        }
    }
    panic!("missing premier_session Set-Cookie header in {headers:?}");
}

struct TestServer {
    _tmp: tempfile::TempDir,
    repo_dir: PathBuf,
    addr: SocketAddr,
    state: ServerState,
    server_task: tokio::task::JoinHandle<()>,
    alice_cookie: String,
    mia_cookie: String,
}

impl TestServer {
    async fn start(ssh_bind: Option<SocketAddr>) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repo");
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(repo_dir.join("billing")).unwrap();
        std::fs::write(repo_dir.join("README.md"), INITIAL_README).unwrap();
        std::fs::write(repo_dir.join("billing/ledger.rs"), INITIAL_LEDGER).unwrap();
        std::fs::write(repo_dir.join(".access.toml"), ACCESS_POLICY_TOML).unwrap();
        std::fs::write(repo_dir.join(".env.schema"), ENV_SCHEMA_TOML).unwrap();

        run_git(&repo_dir, &["init", "-q", "-b", "main"]);
        run_git(&repo_dir, &["config", "core.autocrlf", "false"]);
        run_git(
            &repo_dir,
            &[
                "add",
                "README.md",
                "billing/ledger.rs",
                ".access.toml",
                ".env.schema",
            ],
        );
        run_git(&repo_dir, &["commit", "-q", "-m", "initial commit"]);

        bind_state_dir(&repo_dir, &state_dir, "default", true);

        let mut state = ServerState::minimal(None, None, Arc::new(AuditSink::default()));
        state.workspace_root = repo_dir.clone();
        state.persisted = Arc::new(Mutex::new(load_state(&repo_dir).unwrap()));
        state.auth = Arc::new(AuthStore::open(&repo_dir));
        state.approval_hub = Arc::new(ApprovalHub::default());
        state.session_manager = Arc::new(SessionManager::open(&repo_dir));
        state.static_ui_dir = None;
        state.allow_unsandboxed_agents = true;
        state.ssh_bind = ssh_bind;
        state.reload_repo_config().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = build_router(state.clone());
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        let mut harness = Self {
            _tmp: tmp,
            repo_dir,
            addr,
            state,
            server_task,
            alice_cookie: String::new(),
            mia_cookie: String::new(),
        };

        // Sign up owner `alice` via real HTTP `/v1/auth/setup`.
        let (status, headers, setup_body) = harness
            .request_json(
                Method::POST,
                "/v1/auth/setup",
                None,
                Some(json!({
                    "username": "alice",
                    "password": OWNER_PASSWORD,
                    "display_name": "Alice Owner"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "setup alice failed: {setup_body}");
        assert_eq!(setup_body["authenticated"], true);
        assert_eq!(setup_body["user"]["username"], "alice");
        assert_eq!(setup_body["user"]["role"], "owner");
        harness.alice_cookie = extract_session_cookie(&headers);

        // Add member `mia` via real HTTP `/v1/users` as `alice`.
        let (status, _, user_body) = harness
            .request_json(
                Method::POST,
                "/v1/users",
                Some(&harness.alice_cookie),
                Some(json!({
                    "username": "mia",
                    "password": MEMBER_PASSWORD,
                    "display_name": "Mia Member",
                    "role": "member"
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "create mia failed: {user_body}");
        assert_eq!(user_body["username"], "mia");
        assert_eq!(user_body["role"], "member");

        // Log in `mia` via real HTTP `/v1/auth/login`.
        let (status, headers, login_body) = harness
            .request_json(
                Method::POST,
                "/v1/auth/login",
                None,
                Some(json!({
                    "username": "mia",
                    "password": MEMBER_PASSWORD
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "login mia failed: {login_body}");
        assert_eq!(login_body["user"]["username"], "mia");
        harness.mia_cookie = extract_session_cookie(&headers);

        harness
    }

    async fn request_raw(
        &self,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        content_type: Option<&str>,
        body_bytes: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Value) {
        let stream = TcpStream::connect(self.addr).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, self.addr.to_string());
        if let Some(c) = cookie {
            builder = builder.header(header::COOKIE, c);
        }
        if let Some(ct) = content_type {
            builder = builder.header(header::CONTENT_TYPE, ct);
        }
        let req = builder.body(Body::from(body_bytes)).unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json_val = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
        };
        (status, headers, json_val)
    }

    async fn request_json(
        &self,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        match body {
            Some(v) => {
                self.request_raw(
                    method,
                    uri,
                    cookie,
                    Some("application/json"),
                    serde_json::to_vec(&v).unwrap(),
                )
                .await
            }
            None => {
                self.request_raw(method, uri, cookie, None, Vec::new())
                    .await
            }
        }
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> (StatusCode, Value) {
        let (status, _, body) = self.request_json(Method::GET, uri, cookie, None).await;
        (status, body)
    }

    async fn post(&self, uri: &str, cookie: Option<&str>, body: Value) -> (StatusCode, Value) {
        let (status, _, body) = self
            .request_json(Method::POST, uri, cookie, Some(body))
            .await;
        (status, body)
    }

    async fn put(&self, uri: &str, cookie: Option<&str>, body: Value) -> (StatusCode, Value) {
        let (status, _, body) = self
            .request_json(Method::PUT, uri, cookie, Some(body))
            .await;
        (status, body)
    }

    async fn delete_empty(&self, uri: &str, cookie: Option<&str>) -> (StatusCode, Value) {
        let (status, _, body) = self
            .request_raw(Method::DELETE, uri, cookie, None, Vec::new())
            .await;
        (status, body)
    }

    async fn poll_session_finished(&self, session_id: &str, timeout: Duration) -> Value {
        let deadline = Instant::now() + timeout;
        loop {
            let (status, sessions) = self
                .get("/v1/agents/sessions", Some(&self.alice_cookie))
                .await;
            assert_eq!(status, StatusCode::OK, "{sessions}");
            let rec = sessions
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["id"] == session_id)
                .cloned()
                .unwrap_or_else(|| panic!("session {session_id} missing from {sessions}"));
            if rec["status"] != "running" {
                return rec;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for session {session_id} to finish: {rec}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn shutdown(self) {
        self.state.stop().await;
        self.server_task.abort();
    }
}

#[tokio::test]
async fn full_agent_diff_commit_review_comments_verdict_and_publish_e2e() {
    let srv = TestServer::start(None).await;
    let alice = Some(srv.alice_cookie.as_str());
    let mia = Some(srv.mia_cookie.as_str());

    // Store a real secret in the vault so we can verify zero raw secret leakage in agent diff.
    let raw_stripe_buf = ["sk", "live", "AgentLoopVaultKey_0123"].join("_");
    let raw_stripe_secret = raw_stripe_buf.as_str();
    let (status, secret_meta) = srv
        .post(
            "/v1/secrets/set",
            alice,
            json!({
                "key": "STRIPE_API_KEY",
                "value": raw_stripe_secret,
                "env": "dev"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "set secret failed: {secret_meta}");

    // 1. Spawn an agent session that replaces line 2 and adds line 5 in README.md, then exits 0.
    let updated_readme = "\
# Premier E2E Repo
Line two: updated by agent
Line three: keep unchanged
Line four: footer
Line five: added by agent
";
    let agent_cmd = if cfg!(windows) {
        "[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'README.md'), \"# Premier E2E Repo`nLine two: updated by agent`nLine three: keep unchanged`nLine four: footer`nLine five: added by agent`n\", [System.Text.UTF8Encoding]::new($false))"
    } else {
        "printf '# Premier E2E Repo\\nLine two: updated by agent\\nLine three: keep unchanged\\nLine four: footer\\nLine five: added by agent\\n' > README.md"
    };

    let (status, spawned) = srv
        .post(
            "/v1/agents/sessions",
            alice,
            json!({
                "command": agent_cmd,
                "env": "dev",
                "branch": "main"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "spawn agent failed: {spawned}");
    let session_id = spawned["id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("cage-"), "{spawned}");
    // Verify the session only received a placeholder token for STRIPE_API_KEY, never the raw value.
    assert!(
        spawned["placeholders"]["STRIPE_API_KEY"]
            .as_str()
            .is_some_and(|p| p.starts_with("premier_cap_v1_")),
        "expected capability placeholder in {spawned}"
    );
    assert!(
        !spawned.to_string().contains(raw_stripe_secret),
        "raw secret leaked in spawn response"
    );

    // Poll until completed with exit code 0.
    let finished = srv
        .poll_session_finished(&session_id, Duration::from_secs(30))
        .await;
    assert_eq!(finished["status"], "completed", "{finished}");
    assert_eq!(finished["exit_code"], 0, "{finished}");

    // 2. GET /v1/agents/sessions/{id}/diff
    let (status, diff_body) = srv
        .get(&format!("/v1/agents/sessions/{session_id}/diff"), alice)
        .await;
    assert_eq!(status, StatusCode::OK, "session diff failed: {diff_body}");
    assert_eq!(diff_body["session_id"], session_id);
    assert_eq!(diff_body["truncated"], false);
    let diff_files = diff_body["files"].as_array().unwrap();
    let readme_diff = diff_files
        .iter()
        .find(|f| f["path"] == "README.md")
        .unwrap_or_else(|| panic!("README.md missing from diff: {diff_body}"));
    assert_eq!(readme_diff["kind"], "modified");
    assert_eq!(readme_diff["binary"], false);
    assert_eq!(readme_diff["truncated"], false);
    let patch = readme_diff["patch"].as_str().unwrap();
    assert!(
        patch.contains("-Line two: original summary"),
        "missing removed line in patch:\n{patch}"
    );
    assert!(
        patch.contains("+Line two: updated by agent"),
        "missing replacement line in patch:\n{patch}"
    );
    assert!(
        patch.contains("+Line five: added by agent"),
        "missing added line in patch:\n{patch}"
    );
    let diff_serialized = diff_body.to_string();
    assert!(
        !diff_serialized.contains(raw_stripe_secret),
        "raw vault secret leaked in session diff"
    );
    assert!(
        !diff_serialized.contains("owner-only-ledger-marker"),
        "restricted ledger secret leaked in session diff"
    );

    // 3. POST /v1/agents/sessions/{id}/commit to a new restricted branch `agent/e2e-loop`.
    let (status, commit_body) = srv
        .post(
            &format!("/v1/agents/sessions/{session_id}/commit"),
            alice,
            json!({
                "message": "agent: update README",
                "new_branch": "agent/e2e-loop",
                "visibility": { "scope": "restricted", "allow": ["group:owners"] }
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "commit session failed: {commit_body}"
    );
    let source_oid = commit_body["commit"].as_str().unwrap().to_owned();
    assert_eq!(source_oid.len(), 40, "{commit_body}");
    assert_eq!(commit_body["branch"], "agent/e2e-loop");

    // Verify `agent/e2e-loop` exists in GET /v1/branches for owner with `restricted` visibility.
    let (status, owner_branches) = srv.get("/v1/branches", alice).await;
    assert_eq!(status, StatusCode::OK);
    let e2e_branch = owner_branches
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "agent/e2e-loop")
        .unwrap_or_else(|| panic!("agent/e2e-loop missing from {owner_branches}"));
    assert_eq!(
        e2e_branch["visibility"],
        json!({ "scope": "restricted", "allow": ["group:owners"] })
    );

    // Verify member `mia` CANNOT see `agent/e2e-loop` at all.
    let (status, mia_branches) = srv.get("/v1/branches", mia).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !mia_branches
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["name"] == "agent/e2e-loop"),
        "mia saw restricted branch: {mia_branches}"
    );
    assert!(
        !mia_branches.to_string().contains("agent/e2e-loop"),
        "branch name leaked to mia: {mia_branches}"
    );

    // 4. POST /v1/reviews for `agent/e2e-loop` with `session_id` provenance attached.
    let (status, created_review) = srv
        .post(
            "/v1/reviews",
            alice,
            json!({
                "title": "Review agent README update",
                "branch": "agent/e2e-loop",
                "session_id": session_id
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "create review failed: {created_review}"
    );
    let change_id = created_review["change_id"].as_str().unwrap().to_owned();
    assert!(change_id.starts_with('I'), "{created_review}");
    assert_eq!(
        created_review["provenance"]["session_id"], session_id,
        "provenance missing on created review: {created_review}"
    );

    // Verify hydrated GET /v1/reviews has `rounds[0].hunks` populated and provenance attached.
    let (status, reviews) = srv.get("/v1/reviews", alice).await;
    assert_eq!(status, StatusCode::OK);
    let review = reviews
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["change_id"] == change_id)
        .unwrap_or_else(|| panic!("review {change_id} missing from {reviews}"));
    let hunks = review["rounds"][0]["hunks"].as_array().unwrap();
    assert!(!hunks.is_empty(), "expected non-empty hunks: {review}");
    let readme_hunk = hunks
        .iter()
        .find(|h| h["path"] == "README.md")
        .unwrap_or_else(|| panic!("README.md hunk missing: {review}"));
    assert_eq!(readme_hunk["allowed"], true);
    assert_eq!(readme_hunk["provenance"]["session_visible"], true);
    assert_eq!(readme_hunk["provenance"]["model"], session_id);
    let hunk_lines: Vec<&str> = readme_hunk["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        hunk_lines.contains(&"-Line two: original summary"),
        "missing old line in hunk: {hunk_lines:?}"
    );
    assert!(
        hunk_lines.contains(&"+Line two: updated by agent"),
        "missing updated line in hunk: {hunk_lines:?}"
    );
    assert!(
        hunk_lines.contains(&"+Line five: added by agent"),
        "missing added line in hunk: {hunk_lines:?}"
    );

    // Mia must not see the review on the restricted branch.
    let (status, mia_reviews) = srv.get("/v1/reviews", mia).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !mia_reviews.to_string().contains(&change_id),
        "restricted review leaked to mia: {mia_reviews}"
    );

    // 5. POST /v1/reviews/{change_id}/comments — BOTH `side: "new"` and `side: "old"` comments.
    let (status, new_cmt) = srv
        .post(
            &format!("/v1/reviews/{change_id}/comments"),
            alice,
            json!({
                "path": "README.md",
                "line": 5,
                "side": "new",
                "body": "Great new line five"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "new-side comment failed: {new_cmt}");

    let (status, old_cmt) = srv
        .post(
            &format!("/v1/reviews/{change_id}/comments"),
            alice,
            json!({
                "path": "README.md",
                "line": 2,
                "side": "old",
                "body": "Verified deletion of old line two"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "old-side comment failed: {old_cmt}");

    let (status, reviews_after_comments) = srv.get("/v1/reviews", alice).await;
    assert_eq!(status, StatusCode::OK);
    let review = reviews_after_comments
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["change_id"] == change_id)
        .unwrap();
    let comments = review["comments"].as_array().unwrap();
    assert_eq!(comments.len(), 2, "{comments:?}");
    assert!(
        comments.iter().any(|c| c["path"] == "README.md"
            && c["line"] == 5
            && c["side"] == "new"
            && c["body"] == "Great new line five"),
        "new-side comment not persisted accurately: {comments:?}"
    );
    assert!(
        comments.iter().any(|c| c["path"] == "README.md"
            && c["line"] == 2
            && c["side"] == "old"
            && c["body"] == "Verified deletion of old line two"),
        "old-side comment not persisted accurately: {comments:?}"
    );

    // 6. POST /v1/reviews/{change_id}/verdict — invalid returns 400, valid `"approve"` persists.
    let (status, bogus_body) = srv
        .post(
            &format!("/v1/reviews/{change_id}/verdict"),
            alice,
            json!({ "round": 1, "verdict": "bogus" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "invalid verdict must fail with 400: {bogus_body}"
    );

    let (status, verdict_body) = srv
        .post(
            &format!("/v1/reviews/{change_id}/verdict"),
            alice,
            json!({ "round": 1, "verdict": "approve" }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "approve verdict failed: {verdict_body}"
    );
    assert_eq!(verdict_body["ok"], true);
    assert_eq!(verdict_body["verdict"], "approve");

    let (status, reviews_after_verdict) = srv.get("/v1/reviews", alice).await;
    assert_eq!(status, StatusCode::OK);
    let review = reviews_after_verdict
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["change_id"] == change_id)
        .unwrap();
    assert_eq!(review["verdicts"]["r1:@alice"], "approve", "{review}");

    // 7. POST /v1/branches/squash-preview & POST /v1/branches/publish with CAS guards.
    let (status, preview) = srv
        .post(
            "/v1/branches/squash-preview",
            alice,
            json!({
                "branch": "agent/e2e-loop",
                "target_branch": "main",
                "summary_message": "Publish agent README update"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "squash-preview failed: {preview}");
    assert_eq!(preview["declassification_gate_passed"], true, "{preview}");
    assert_eq!(
        preview["published_paths"],
        json!(["README.md"]),
        "{preview}"
    );
    assert_eq!(preview["conflicts"], json!([]));
    assert_eq!(preview["blocked"], json!([]));

    let target_oid = run_git(&srv.repo_dir, &["rev-parse", "refs/heads/main"]);
    let (status, published) = srv
        .post(
            "/v1/branches/publish",
            alice,
            json!({
                "source_branch": "agent/e2e-loop",
                "target_branch": "main",
                "summary_message": "Publish agent README update",
                "expected_source_oid": source_oid,
                "expected_target_oid": target_oid
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "publish failed: {published}");
    assert_eq!(published["target_ref"], "refs/heads/main");
    assert_eq!(published["published_paths"], json!(["README.md"]));
    let new_main_oid = published["new_commit_oid"].as_str().unwrap();
    assert_eq!(new_main_oid.len(), 40);
    assert_ne!(new_main_oid, target_oid);

    // Verify `main` has the agent's edit in README.md and `billing/ledger.rs` is untouched.
    let (status, main_readme) = srv
        .get("/v1/repo/file?path=README.md&ref_name=main", alice)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(main_readme["content"], updated_readme);
    assert_eq!(main_readme["tip_oid"], new_main_oid);

    let main_ledger_git = run_git(&srv.repo_dir, &["show", "main:billing/ledger.rs"]);
    assert_eq!(main_ledger_git, INITIAL_LEDGER.trim_end());

    // Strict Git repository integrity check.
    run_git(&srv.repo_dir, &["fsck", "--strict", "--full"]);

    srv.shutdown().await;
}

#[tokio::test]
async fn agent_stop_terminates_running_session_cleanly_e2e() {
    let srv = TestServer::start(None).await;
    let alice = Some(srv.alice_cookie.as_str());

    let long_cmd = if cfg!(windows) {
        "Start-Sleep -Seconds 30"
    } else {
        "sleep 30"
    };

    let started = Instant::now();
    let (status, spawned) = srv
        .post(
            "/v1/agents/sessions",
            alice,
            json!({
                "command": long_cmd,
                "env": "dev",
                "branch": "main"
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "spawn long session failed: {spawned}"
    );
    let session_id = spawned["id"].as_str().unwrap().to_owned();
    assert_eq!(spawned["status"], "running", "{spawned}");

    // Give the child process a brief moment to launch, then stop it while still running.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (status, stop_resp) = srv
        .post(
            &format!("/v1/agents/sessions/{session_id}/stop"),
            alice,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "stop session failed: {stop_resp}");

    let final_rec = if stop_resp["status"] == "running" {
        srv.poll_session_finished(&session_id, Duration::from_secs(5))
            .await
    } else {
        stop_resp
    };
    let elapsed = started.elapsed();

    assert_eq!(final_rec["status"], "stopped", "{final_rec}");
    assert_eq!(final_rec["ended_reason"], "stopped by owner", "{final_rec}");
    assert!(
        final_rec["finished_at"].is_string(),
        "expected finished_at timestamp: {final_rec}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "stopping a 30s sleep session took too long ({elapsed:?}), possible leaked process"
    );

    // Stopping an already-stopped session returns 409 Conflict.
    let (status, second_stop) = srv
        .post(
            &format!("/v1/agents/sessions/{session_id}/stop"),
            alice,
            json!({}),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "expected 409 stopping non-running session: {second_stop}"
    );

    srv.shutdown().await;
}

#[tokio::test]
async fn file_api_and_vault_dashboard_and_health_contracts_e2e() {
    let ssh_addr: SocketAddr = "127.0.0.1:2222".parse().unwrap();
    let srv = TestServer::start(Some(ssh_addr)).await;
    let alice = Some(srv.alice_cookie.as_str());
    let mia = Some(srv.mia_cookie.as_str());

    // 1. GET /health includes `ssh_enabled` and `ssh_port` for authenticated callers.
    let (status, owner_health) = srv.get("/health", alice).await;
    assert_eq!(status, StatusCode::OK, "{owner_health}");
    assert_eq!(owner_health["status"], "ok");
    assert_eq!(owner_health["ssh_enabled"], true);
    assert_eq!(owner_health["ssh_port"], 2222);

    let (status, mia_health) = srv.get("/health", mia).await;
    assert_eq!(status, StatusCode::OK, "{mia_health}");
    assert_eq!(mia_health["ssh_enabled"], true);
    assert_eq!(mia_health["ssh_port"], 2222);

    let (status, anon_health) = srv.get("/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(anon_health["ssh_enabled"].is_null());

    // 2. GET /v1/repo/file?path=README.md&max_bytes=524288
    let (status, readme_resp) = srv
        .get("/v1/repo/file?path=README.md&max_bytes=524288", alice)
        .await;
    assert_eq!(status, StatusCode::OK, "{readme_resp}");
    assert_eq!(readme_resp["allowed"], true);
    assert_eq!(readme_resp["binary"], false);
    assert_eq!(readme_resp["truncated"], false);
    assert_eq!(readme_resp["content"], INITIAL_README);
    let initial_tip = readme_resp["tip_oid"].as_str().unwrap().to_owned();
    assert_eq!(initial_tip.len(), 40, "{readme_resp}");

    // 3. Commit a binary file containing NUL bytes and verify `binary == true`.
    std::fs::create_dir_all(srv.repo_dir.join("assets")).unwrap();
    std::fs::write(
        srv.repo_dir.join("assets/logo.bin"),
        [0x89u8, b'P', b'N', b'G', 0x00, 0x01, 0x02, 0x03],
    )
    .unwrap();
    run_git(&srv.repo_dir, &["add", "assets/logo.bin"]);
    run_git(&srv.repo_dir, &["commit", "-q", "-m", "add binary asset"]);

    let (status, bin_resp) = srv.get("/v1/repo/file?path=assets/logo.bin", alice).await;
    assert_eq!(status, StatusCode::OK, "{bin_resp}");
    assert_eq!(bin_resp["allowed"], true);
    assert_eq!(bin_resp["binary"], true);
    assert!(
        bin_resp["content"].is_null(),
        "binary file should not return decoded UTF-8 content: {bin_resp}"
    );
    let current_tip = bin_resp["tip_oid"].as_str().unwrap().to_owned();
    assert_ne!(current_tip, initial_tip);

    // 4. PUT /v1/repo/file with stale `expected_tip` -> 409 Conflict; matching `expected_tip` -> 200 OK.
    let (status, stale_put) = srv
        .put(
            "/v1/repo/file",
            alice,
            json!({
                "path": "docs/notes.md",
                "content": "stale attempt\n",
                "expected_tip": initial_tip
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "stale expected_tip must return 409: {stale_put}"
    );

    let (status, ok_put) = srv
        .put(
            "/v1/repo/file",
            alice,
            json!({
                "path": "docs/notes.md",
                "content": "fresh content\n",
                "message": "Create docs/notes.md",
                "expected_tip": current_tip
            }),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "matching expected_tip failed: {ok_put}"
    );
    assert_eq!(ok_put["path"], "docs/notes.md");
    let after_put_tip = ok_put["commit"].as_str().unwrap().to_owned();
    assert_eq!(after_put_tip.len(), 40);

    // 5. DELETE /v1/repo/file?path=...&message=... with EMPTY body (query params only) succeeds.
    let (status, del_resp) = srv
        .delete_empty(
            "/v1/repo/file?path=docs/notes.md&message=Delete%20notes%20via%20query",
            alice,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "empty-body DELETE /v1/repo/file failed: {del_resp}"
    );
    assert_eq!(del_resp["path"], "docs/notes.md");
    assert_eq!(
        run_git(&srv.repo_dir, &["log", "-1", "--format=%s"]),
        "Delete notes via query"
    );

    let (status, deleted_check) = srv.get("/v1/repo/file?path=docs/notes.md", alice).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "deleted file still readable: {deleted_check}"
    );

    // 6. Vault secret storage (`${env}:${var}` meta scoping) & `/v1/env/dashboard` (`can_use`).
    let raw_dev_secret = "sk_dev_contract_secret_do_not_leak_111";
    let raw_prod_secret = "sk_prod_contract_secret_do_not_leak_222";
    let (status, dev_meta) = srv
        .post(
            "/v1/secrets/set",
            alice,
            json!({
                "key": "STRIPE_API_KEY",
                "value": raw_dev_secret,
                "env": "dev"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{dev_meta}");
    assert_eq!(dev_meta["env"], "dev");
    assert_eq!(dev_meta["rotated_count"], 1);

    let (status, prod_meta) = srv
        .post(
            "/v1/secrets/set",
            alice,
            json!({
                "key": "STRIPE_API_KEY",
                "value": raw_prod_secret,
                "env": "prod"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{prod_meta}");
    assert_eq!(prod_meta["env"], "prod");
    assert_eq!(prod_meta["rotated_count"], 1);

    // Check `/v1/secrets/status` uses `${env}:${var}` scoping and never leaks raw values.
    let (status, sec_status) = srv.get("/v1/secrets/status", alice).await;
    assert_eq!(status, StatusCode::OK, "{sec_status}");
    assert_eq!(sec_status["entries"]["dev:STRIPE_API_KEY"]["env"], "dev");
    assert_eq!(
        sec_status["entries"]["dev:STRIPE_API_KEY"]["backend"],
        "age-aead"
    );
    assert_eq!(sec_status["entries"]["prod:STRIPE_API_KEY"]["env"], "prod");
    assert!(
        sec_status["entries"]["STRIPE_API_KEY"].is_null(),
        "meta should be scoped under env:var, not bare key: {sec_status}"
    );
    let sec_status_str = sec_status.to_string();
    assert!(!sec_status_str.contains(raw_dev_secret));
    assert!(!sec_status_str.contains(raw_prod_secret));

    // Owner dashboard: truthful `can_use` for both secrets, validation reflects stored dev/prod values, zero raw secrets.
    let (status, owner_dash) = srv.get("/v1/env/dashboard", alice).await;
    assert_eq!(status, StatusCode::OK, "{owner_dash}");
    assert_eq!(
        owner_dash["can_use"]["STRIPE_API_KEY"], true,
        "{owner_dash}"
    );
    assert_eq!(
        owner_dash["can_use"]["BILLING_ADMIN_KEY"], true,
        "{owner_dash}"
    );
    assert_eq!(
        owner_dash["reports"]["dev"]["issues"],
        json!([]),
        "dev STRIPE_API_KEY was set so dev report should be clean: {owner_dash}"
    );
    let prod_issues = owner_dash["reports"]["prod"]["issues"].as_array().unwrap();
    assert!(
        prod_issues
            .iter()
            .any(|i| i["var_name"] == "BILLING_ADMIN_KEY"),
        "expected missing BILLING_ADMIN_KEY in prod report: {owner_dash}"
    );
    assert!(
        !prod_issues
            .iter()
            .any(|i| i["var_name"] == "STRIPE_API_KEY"),
        "prod STRIPE_API_KEY was set so should not be flagged missing: {owner_dash}"
    );
    let owner_dash_str = owner_dash.to_string();
    assert!(!owner_dash_str.contains(raw_dev_secret));
    assert!(!owner_dash_str.contains(raw_prod_secret));

    // Owner view-as lens for `@mia`: truthful `can_use` shows true for STRIPE_API_KEY and false for BILLING_ADMIN_KEY.
    let (status, lens_dash) = srv.get("/v1/env/dashboard?principal=@mia", alice).await;
    assert_eq!(status, StatusCode::OK, "{lens_dash}");
    assert_eq!(lens_dash["can_use"]["STRIPE_API_KEY"], true, "{lens_dash}");
    assert_eq!(
        lens_dash["can_use"]["BILLING_ADMIN_KEY"], false,
        "{lens_dash}"
    );

    // Member `mia` dashboard: only sees usable STRIPE_API_KEY with `can_use == true`, never sees BILLING_ADMIN_KEY or raw secrets.
    let (status, mia_dash) = srv.get("/v1/env/dashboard", mia).await;
    assert_eq!(status, StatusCode::OK, "{mia_dash}");
    assert_eq!(mia_dash["can_use"]["STRIPE_API_KEY"], true, "{mia_dash}");
    assert!(
        mia_dash["can_use"]["BILLING_ADMIN_KEY"].is_null(),
        "mia should not learn about restricted var: {mia_dash}"
    );
    let mia_dash_str = mia_dash.to_string();
    assert!(!mia_dash_str.contains("BILLING_ADMIN_KEY"));
    assert!(!mia_dash_str.contains(raw_dev_secret));
    assert!(!mia_dash_str.contains(raw_prod_secret));

    // Member cannot read `/v1/secrets/status` (owner-only).
    let (status, _) = srv.get("/v1/secrets/status", mia).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    srv.shutdown().await;
}
