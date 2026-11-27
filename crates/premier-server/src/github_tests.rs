//! GitHub companion, end to end and offline: a local bare repository stands in for GitHub's git
//! endpoint, an in-process HTTP server for its REST API.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::post;
use premier_core::{AuditDecision, Readiness, Visibility};
use premier_policy::{CompiledPolicy, parse_policy_toml};
use premier_proxy::AuditSink;
use serde_json::{Value, json};

use crate::github::{
    GitRemote, GithubCompanionConfigStored, GithubTestOverride, Staging, SyncDirection,
    fetch_ref_into_staging, push_ref_from_staging, resolve_and_vet_host, validate_github_hosts,
    validate_owner_repo,
};
use crate::tests::{PW, call, member_state};
use crate::{ServerState, build_router};

const TOKEN: &str = "ghp_TESTtoken0123456789abcdefSECRET";

const POLICY: &str = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[zones.public]
paths = ["apps/**", "README.md"]

[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;

const APP_TS: &str = "export const a = 1;\nexport const b = 2;\nexport const c = 3;\nexport const d = 4;\nexport const e = 5;\nexport const f = 6;\nexport const g = 7;\n";

/// [`APP_TS`] with its first and last constants replaced.
fn app(a: u32, g: u32) -> String {
    APP_TS
        .replace("a = 1;", &format!("a = {a};"))
        .replace("g = 7;", &format!("g = {g};"))
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .args(["-c", "user.name=Alice", "-c", "user.email=alice@acme.test"])
        .args(["-c", "core.autocrlf=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?} in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn write(dir: &Path, files: &[(&str, &str)]) {
    for (path, content) in files {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }
}

fn commit(dir: &Path, files: &[(&str, &str)], message: &str) -> String {
    write(dir, files);
    let paths: Vec<&str> = files.iter().map(|(p, _)| *p).collect();
    let mut args = vec!["add", "--"];
    args.extend(paths);
    git(dir, &args);
    git(dir, &["commit", "-q", "-m", message]);
    git(dir, &["rev-parse", "HEAD"])
}

fn set_policy(state: &ServerState, toml: &str) {
    let file = parse_policy_toml(toml).unwrap();
    *state.policy.write().unwrap() = Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
    state.set_repo_policy_metadata(Some(toml.to_owned()), Some(Arc::new(file)));
}

/// The mock REST API: every `POST /repos/{owner}/{repo}/pulls` it got (Authorization, path,
/// JSON body); answers PR #42.
#[derive(Clone, Default)]
struct Mock {
    calls: Arc<Mutex<Vec<(String, String, Value)>>>,
}

impl Mock {
    async fn start() -> (Self, String) {
        let mock = Self::default();
        let calls = mock.calls.clone();
        let app = Router::new().route(
            "/repos/{owner}/{repo}/pulls",
            post(
                move |axum::extract::Path((owner, repo)): axum::extract::Path<(String, String)>,
                      headers: HeaderMap,
                      axum::Json(body): axum::Json<Value>| {
                    let calls = calls.clone();
                    async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        calls
                            .lock()
                            .unwrap()
                            .push((auth, format!("{owner}/{repo}"), body));
                        (
                            StatusCode::CREATED,
                            axum::Json(json!({
                                "number": 42,
                                "html_url": "https://github.com/acme/sdk/pull/42"
                            })),
                        )
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (mock, format!("http://{addr}"))
    }

    fn calls(&self) -> Vec<(String, String, Value)> {
        self.calls.lock().unwrap().clone()
    }
}

struct Fx {
    tmp: tempfile::TempDir,
    root: PathBuf,
    remote: PathBuf,
    state: ServerState,
    router: Router,
    owner: String,
    mia: String,
    owner_token: String,
    mock: Mock,
}

impl Fx {
    /// Canonical `main`: README.md, apps/web/app.ts, billing/ledger/tx.rs, tools/build.sh,
    /// .access.toml, .env.schema. GitHub: an empty bare repository.
    async fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("ws");
        std::fs::create_dir_all(&root).unwrap();
        let (mut state, owner, mia, _) = member_state(&root);
        set_policy(&state, POLICY);
        state.audit_sink = Arc::new(AuditSink::new(Some(tmp.path().join("audit.jsonl"))));
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["config", "core.autocrlf", "false"]);
        commit(
            &root,
            &[
                ("README.md", "# SDK\n"),
                ("apps/web/app.ts", APP_TS),
                ("billing/ledger/tx.rs", "SECRET LEDGER ENTRY\n"),
                ("tools/build.sh", "echo build\n"),
                (".access.toml", POLICY),
                (".env.schema", "# schema\n"),
            ],
            "initial",
        );
        let remote = tmp.path().join("remote.git");
        std::fs::create_dir_all(&remote).unwrap();
        git(&remote, &["init", "-q", "--bare", "-b", "main"]);
        git(&remote, &["config", "core.autocrlf", "false"]);
        let (mock, url) = Mock::start().await;
        state.github_test_override = Some(Arc::new(GithubTestOverride {
            bare_remote_path: remote.clone(),
            mock_api_base_url: url,
        }));
        let (_, owner_token) = state.auth.seed("olga", PW);
        let router = build_router(state.clone());
        Self {
            tmp,
            root,
            remote,
            state,
            router,
            owner,
            mia,
            owner_token,
            mock,
        }
    }

    async fn send(&self, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, Value) {
        let (status, _, body) = call(
            &self.router,
            method,
            uri,
            &[("cookie", self.owner.as_str())],
            body,
        )
        .await;
        (status, body)
    }

    async fn post(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        self.send(Method::POST, uri, Some(body)).await
    }

    async fn connect(&self, zone: Option<&str>) {
        let body = json!({ "repo": "acme/sdk", "token": TOKEN, "zone": zone });
        let (status, body) = self
            .send(Method::PUT, "/v1/github/config", Some(body))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    fn tip(&self, rev: &str) -> String {
        git(&self.root, &["rev-parse", rev])
    }

    fn remote_refs(&self) -> String {
        git(
            &self.remote,
            &["for-each-ref", "--format=%(refname) %(objectname)"],
        )
    }

    /// A working clone of the GitHub repository, as a GitHub user would push from.
    fn clone_remote(&self) -> PathBuf {
        let dir = self.tmp.path().join("gh-clone");
        if !dir.exists() {
            git(
                self.tmp.path(),
                &["clone", "-q", self.remote.to_str().unwrap(), "gh-clone"],
            );
            git(&dir, &["config", "core.autocrlf", "false"]);
        }
        dir
    }

    fn audit(&self) -> Vec<premier_core::AuditEvent> {
        self.state
            .audit_sink
            .snapshot()
            .into_iter()
            .filter(|e| e.component == "premier-github")
            .collect()
    }

    fn denied(&self, action: &str) -> usize {
        self.audit()
            .iter()
            .filter(|e| e.action == action && e.decision == AuditDecision::Denied)
            .count()
    }
}

/// Every path of every commit reachable in `repo`.
fn all_paths(repo: &Path) -> String {
    git(repo, &["log", "--all", "--name-only", "--format=%H%n%B"])
}

#[tokio::test]
async fn rbac_rejects_unauth_members_and_access_tokens_on_all_github_routes() {
    let fx = Fx::new().await;
    git(&fx.root, &["checkout", "-q", "-b", "feature"]);
    commit(
        &fx.root,
        &[("apps/web/app.ts", "export const a = 9;\n")],
        "tweak",
    );
    git(&fx.root, &["checkout", "-q", "main"]);

    let routes: [(Method, &str, Value); 7] = [
        (
            Method::PUT,
            "/v1/github/config",
            json!({ "repo": "acme/sdk", "token": TOKEN }),
        ),
        (Method::GET, "/v1/github/status", Value::Null),
        (Method::POST, "/v1/github/sync/out", json!({})),
        (
            Method::POST,
            "/v1/github/pr/preview",
            json!({ "source_branch": "feature" }),
        ),
        (
            Method::POST,
            "/v1/github/pr/publish",
            json!({ "source_branch": "feature" }),
        ),
        (Method::POST, "/v1/github/sync/in", json!({})),
        (Method::DELETE, "/v1/github/config", Value::Null),
    ];
    let bearer = format!("Bearer {}", fx.owner_token);
    for (method, uri, body) in &routes {
        let body = (!body.is_null()).then(|| body.clone());
        let (status, _, _) = call(&fx.router, method.clone(), uri, &[], body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "anonymous {method} {uri}");
        let member = [("cookie", fx.mia.as_str())];
        let (status, _, _) = call(&fx.router, method.clone(), uri, &member, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "member {method} {uri}");
        let token = [("authorization", bearer.as_str())];
        let (status, _, resp) = call(&fx.router, method.clone(), uri, &token, body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "owner token {method} {uri}");
        assert_eq!(resp["error"], "this action requires a browser session");
    }
    assert!(fx.mock.calls().is_empty());
    assert!(fx.remote_refs().is_empty(), "nothing reached GitHub");
    assert!(fx.audit().is_empty(), "refused before any handler ran");

    // The owner's browser session gets through every one of them.
    for (method, uri, body) in routes {
        let body = (!body.is_null()).then_some(body);
        let (status, resp) = fx.send(method.clone(), uri, body).await;
        assert_eq!(status, StatusCode::OK, "owner {method} {uri}: {resp}");
    }
    assert_eq!(fx.mock.calls().len(), 1);
}

#[tokio::test]
async fn ssrf_and_host_pinning_reject_unsafe_targets() {
    let mut fx = Fx::new().await;
    let refused = [
        json!({ "repo": "https://github.com/acme/sdk" }),
        json!({ "repo": "acme/sdk.git" }),
        json!({ "repo": "acme/sdk/extra" }),
        json!({ "repo": "user@acme/sdk" }),
        json!({ "repo": "acme /sdk" }),
        json!({ "repo": "../sdk" }),
        json!({ "repo": "acme/sdk", "host": "http://github.com" }),
        json!({ "repo": "acme/sdk", "host": "localhost" }),
        json!({ "repo": "acme/sdk", "host": "api.localhost" }),
        json!({ "repo": "acme/sdk", "host": "printer.local" }),
        json!({ "repo": "acme/sdk", "host": "127.0.0.1" }),
        json!({ "repo": "acme/sdk", "host": "2130706433" }),
        json!({ "repo": "acme/sdk", "host": "169.254.169.254" }),
        json!({ "repo": "acme/sdk", "host": "10.0.0.1" }),
        json!({ "repo": "acme/sdk", "host": "[::1]" }),
        json!({ "repo": "acme/sdk", "host": "user@github.com" }),
        json!({ "repo": "acme/sdk", "host": "github.com:8443" }),
        json!({ "repo": "acme/sdk", "host": "evil.example.com" }),
        json!({ "repo": "acme/sdk", "api_host": "evil.example.com" }),
        json!({ "repo": "acme/sdk", "host": "ghe.acme.test" }),
        json!({ "repo": "acme/sdk", "token": "ghp_has space" }),
        json!({ "repo": "acme/sdk", "token": "ghp_x\r\nX-Injected: 1" }),
    ];
    for body in &refused {
        let (status, resp) = fx
            .send(Method::PUT, "/v1/github/config", Some(body.clone()))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {resp}");
    }
    assert_eq!(fx.denied("github-configure"), refused.len());
    let (_, status) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(status["connected"], false);

    // An enterprise host only once the server allows it, with only its own API hosts.
    fx.state.github_enterprise_hosts = Arc::new(vec!["GHE.acme.test".to_owned()]);
    fx.router = build_router(fx.state.clone());
    let body =
        json!({ "repo": "acme/sdk", "host": "ghe.acme.test", "api_host": "evil.example.com" });
    let (status, _) = fx.send(Method::PUT, "/v1/github/config", Some(body)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body =
        json!({ "repo": "acme/sdk", "host": "ghe.acme.test", "api_host": "api.ghe.acme.test" });
    let (status, resp) = fx.send(Method::PUT, "/v1/github/config", Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["config"]["host"], "ghe.acme.test");
    assert_eq!(resp["config"]["api_host"], "api.ghe.acme.test");
    assert_eq!(resp["enterprise_hosts_allowed"], json!(["GHE.acme.test"]));

    // The validators on their own.
    assert_eq!(
        validate_github_hosts(None, None, &[]).unwrap(),
        ("github.com".to_owned(), "api.github.com".to_owned())
    );
    assert!(validate_github_hosts(Some("ghe.acme.test"), None, &[]).is_err());
    assert_eq!(
        validate_github_hosts(Some("ghe.acme.test"), None, &["ghe.acme.test".to_owned()]).unwrap(),
        ("ghe.acme.test".to_owned(), "ghe.acme.test".to_owned())
    );
    assert_eq!(
        validate_owner_repo("acme/sdk.js").unwrap(),
        ("acme".to_owned(), "sdk.js".to_owned())
    );
    for bad in [".", "acme/..", "acme/.hidden", "", "acme/", "a/b\n"] {
        assert!(validate_owner_repo(bad).is_err(), "{bad:?}");
    }
    // Resolution: loopback is never a GitHub.
    let err = resolve_and_vet_host("localhost").await.unwrap_err();
    assert!(err.contains("public"), "{err}");
}

#[tokio::test]
async fn vault_stores_token_encrypted_and_never_leaks_plaintext() {
    let mut fx = Fx::new().await;
    fx.connect(None).await;
    let state_dir = crate::store::state_dir(&fx.root);
    let companion = std::fs::read_to_string(state_dir.join("github-companion.json")).unwrap();
    assert!(companion.contains("acme/sdk"));
    assert!(!companion.contains(TOKEN));
    let vault = std::fs::read_to_string(state_dir.join("github.vault.toml")).unwrap();
    assert!(
        vault.contains("GITHUB_COMPANION_TOKEN"),
        "stored under its own key"
    );
    assert!(!vault.contains(TOKEN));
    assert!(!vault.contains("TESTtoken"));
    let (_, status) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(status["config"]["token_configured"], true);
    assert!(!status.to_string().contains(TOKEN));
    assert_eq!(
        crate::store::load_github_token(&fx.root, "__premier_github__")
            .unwrap()
            .unwrap()
            .as_str(),
        TOKEN
    );
    // Under any other vault repo id (what an `.env.schema` names) there is nothing: the sovereign
    // vault is bound to its repo id, so opening it under another one is refused outright.
    for repo_id in ["__premier_github_companion__", "local/repo"] {
        assert!(
            crate::store::load_github_token(&fx.root, repo_id).is_ok_and(|t| t.is_none())
                || crate::store::load_github_token(&fx.root, repo_id)
                    .is_err_and(|e| e.contains("repo_id mismatch")),
            "{repo_id}"
        );
    }

    // Reconnecting on the same host without a token keeps it; moving to another host drops it.
    let (status, resp) = fx
        .send(
            Method::PUT,
            "/v1/github/config",
            Some(json!({ "repo": "acme/other" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["config"]["token_configured"], true);
    fx.state.github_enterprise_hosts = Arc::new(vec!["ghe.acme.test".to_owned()]);
    fx.router = build_router(fx.state.clone());
    let body = json!({ "repo": "acme/sdk", "host": "ghe.acme.test" });
    let (status, resp) = fx.send(Method::PUT, "/v1/github/config", Some(body)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["config"]["token_configured"], false);
    assert!(
        crate::store::load_github_token(&fx.root, "__premier_github__")
            .unwrap()
            .is_none()
    );

    fx.connect(None).await;
    let (status, resp) = fx.send(Method::DELETE, "/v1/github/config", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp["ok"], true);
    assert!(
        crate::store::load_github_token(&fx.root, "__premier_github__")
            .unwrap()
            .is_none()
    );
    let vault = std::fs::read_to_string(state_dir.join("github.vault.toml")).unwrap();
    assert!(!vault.contains("GITHUB_COMPANION_TOKEN"));
    let (_, status) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(status["connected"], false);
    let audit = std::fs::read_to_string(fx.tmp.path().join("audit.jsonl")).unwrap();
    assert!(audit.contains("github-configure"));
    assert!(!audit.contains(TOKEN));
}

#[tokio::test]
async fn pr_preview_and_publish_declassify_cleanly_and_link_review() {
    let fx = Fx::new().await;
    fx.connect(None).await;
    let (status, out) = fx.post("/v1/github/sync/out", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{out}");
    let github_main = git(&fx.remote, &["rev-parse", "refs/heads/main"]);

    git(&fx.root, &["checkout", "-q", "-b", "secret-ledger-rework"]);
    let tweaked = app(20, 7);
    let c1 = commit(
        &fx.root,
        &[
            ("apps/web/app.ts", tweaked.as_str()),
            ("billing/ledger/tx.rs", "SECRET LEDGER ENTRY v2\n"),
        ],
        "SECRET-MSG rework ledger and app",
    );
    let tightened = format!("{POLICY}\n# tightened\n");
    let c2 = commit(
        &fx.root,
        &[(".access.toml", tightened.as_str())],
        "SECRET-MSG tighten policy",
    );
    git(&fx.root, &["checkout", "-q", "main"]);
    fx.state
        .persisted
        .lock()
        .unwrap()
        .reviews
        .push(crate::store::StoredReview {
            change_id: "Iledger01".to_owned(),
            title: "ledger rework".to_owned(),
            branch: "secret-ledger-rework".to_owned(),
            base_ref: "main".to_owned(),
            author: "@owner".to_owned(),
            delegated_agent: None,
            visibility: Visibility::Org,
            readiness: Readiness::Ready,
            round_oids: vec![c2.clone()],
            comments: vec![],
            verdicts: Default::default(),
            provenance: None,
            created_at: String::new(),
            lane_id: None,
            rounds_meta: Vec::new(),
            github_pr_url: None,
            github_pr_number: None,
        });

    let request = json!({
        "source_branch": "secret-ledger-rework",
        "title": "Tune app constants",
        "body": "Public summary of the change.",
    });
    let (status, preview) = fx.post("/v1/github/pr/preview", request.clone()).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["repo"], "acme/sdk");
    assert_eq!(preview["gate_passed"], true);
    assert_eq!(preview["published_paths"], json!(["apps/web/app.ts"]));
    let scrubbed = preview["scrubbed_paths"].to_string();
    assert!(scrubbed.contains("billing/ledger/tx.rs") && scrubbed.contains(".access.toml"));
    assert_eq!(preview["diffs"][0]["path"], "apps/web/app.ts");
    assert!(
        preview["diffs"][0]["patch"]
            .as_str()
            .unwrap()
            .contains("+export const a = 20;")
    );
    assert!(!preview["diffs"].to_string().contains("SECRET LEDGER"));
    assert_eq!(
        preview["scrubbed_metadata"]["source_branch_name_redacted"],
        true
    );
    assert_eq!(preview["scrubbed_metadata"]["commits_squashed"], 2);
    assert!(
        preview["pr_branch"]
            .as_str()
            .unwrap()
            .starts_with("premier/declassify-")
    );
    assert!(preview["attestation_trailer"].as_str().unwrap().len() > 10);
    assert!(fx.mock.calls().is_empty(), "a preview never calls GitHub");
    assert_eq!(
        git(&fx.remote, &["rev-parse", "refs/heads/main"]),
        github_main
    );

    let mut publish = request.clone();
    publish["change_id"] = json!("Iledger01");
    let (status, result) = fx.post("/v1/github/pr/publish", publish).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let receipt = &result["receipt"];
    assert_eq!(receipt["pr_number"], 42);
    assert_eq!(receipt["pr_url"], "https://github.com/acme/sdk/pull/42");
    assert_eq!(receipt["change_id"], "Iledger01");
    assert_eq!(receipt["published_paths"], json!(["apps/web/app.ts"]));
    let pr_branch = receipt["pr_branch"].as_str().unwrap().to_owned();
    let public_oid = receipt["public_commit_oid"].as_str().unwrap().to_owned();

    // What GitHub has: the PR branch, one clean commit on its main, nothing private.
    assert_eq!(
        git(
            &fx.remote,
            &["rev-parse", &format!("refs/heads/{pr_branch}")]
        ),
        public_oid
    );
    assert_eq!(
        git(&fx.remote, &["rev-parse", &format!("{public_oid}^")]),
        github_main
    );
    git(&fx.remote, &["fsck", "--strict", "--full"]);
    let everything = all_paths(&fx.remote);
    for forbidden in [
        "billing/",
        ".access.toml",
        ".env.schema",
        "secret-ledger",
        "SECRET",
        &c1,
        &c2,
    ] {
        assert!(!everything.contains(forbidden), "GitHub got {forbidden}");
    }
    assert!(!fx.remote_refs().contains("secret-ledger"));
    let objects = git(&fx.remote, &["rev-list", "--all", "--objects"]);
    for oid in [&c1, &c2] {
        assert!(!objects.contains(oid.as_str()));
    }
    assert!(!objects.contains(&git(
        &fx.root,
        &["rev-parse", "secret-ledger-rework:billing/ledger/tx.rs"]
    )));

    // What GitHub's API got.
    let calls = fx.mock.calls();
    assert_eq!(calls.len(), 1);
    let (auth, repo, body) = &calls[0];
    assert_eq!(auth, &format!("Bearer {TOKEN}"));
    assert_eq!(repo, "acme/sdk");
    assert_eq!(body["head"], pr_branch.as_str());
    assert_eq!(body["base"], "main");
    assert_eq!(body["title"], "Tune app constants");
    assert!(
        body["body"]
            .as_str()
            .unwrap()
            .contains("Public summary of the change.")
    );
    assert!(!body.to_string().contains("secret-ledger") && !body.to_string().contains("SECRET"));

    // Receipt, review link, audit.
    let (_, status) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(status["receipts"][0]["pr_number"], 42);
    assert_eq!(
        status["receipts"][0]["source_branch"],
        "secret-ledger-rework"
    );
    let review = fx.state.persisted.lock().unwrap().reviews[0].clone();
    assert_eq!(review.github_pr_number, Some(42));
    assert_eq!(
        review.github_pr_url.as_deref(),
        Some("https://github.com/acme/sdk/pull/42")
    );
    let saved = crate::store::load_state(&fx.root).unwrap();
    assert_eq!(saved.reviews[0].github_pr_number, Some(42));
    assert!(
        fx.audit()
            .iter()
            .any(|e| e.action == "github-pr-publish" && e.decision == AuditDecision::Allowed)
    );
    let audit = std::fs::read_to_string(fx.tmp.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains(TOKEN));
}

#[tokio::test]
async fn pr_publish_blocks_private_blob_copyfrom_leak_before_touching_github() {
    let fx = Fx::new().await;
    fx.connect(None).await;
    let (status, _) = fx.post("/v1/github/sync/out", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let before = fx.remote_refs();

    git(&fx.root, &["checkout", "-q", "-b", "leaky"]);
    commit(
        &fx.root,
        &[("apps/web/leak.ts", "SECRET LEDGER ENTRY\n")],
        "copy",
    );
    git(&fx.root, &["checkout", "-q", "main"]);
    let (status, body) = fx
        .post("/v1/github/pr/publish", json!({ "source_branch": "leaky" }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["blocked"], json!(["apps/web/leak.ts"]));
    assert_eq!(fx.remote_refs(), before, "nothing pushed");
    assert!(!all_paths(&fx.remote).contains("leak.ts"));
    assert!(fx.mock.calls().is_empty(), "GitHub's API never called");
    assert_eq!(fx.denied("github-pr-publish"), 1);
}

#[tokio::test]
async fn bidirectional_zone_sync_round_trip_and_fail_closed_boundaries() {
    let fx = Fx::new().await;
    fx.connect(Some("public")).await;
    let hidden = |fx: &Fx| {
        [
            "billing/ledger/tx.rs",
            ".access.toml",
            ".env.schema",
            "tools/build.sh",
        ]
        .map(|p| git(&fx.root, &["rev-parse", &format!("main:{p}")]))
    };

    // Sync-out projects the zone only.
    let (status, out) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["commits_projected"], 1);
    let files = git(&fx.remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert_eq!(files, "README.md\napps/web/app.ts");
    let github_tip = git(&fx.remote, &["rev-parse", "main"]);

    // A private-only commit collapses; a repeat is up to date.
    commit(
        &fx.root,
        &[("billing/ledger/tx.rs", "SECRET LEDGER ENTRY 2\n")],
        "SECRET-MSG ledger",
    );
    let (status, out) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(out["commits_projected"], 0);
    assert_eq!(out["commits_collapsed"], 1);
    assert_eq!(git(&fx.remote, &["rev-parse", "main"]), github_tip);
    let (status, out) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(out["up_to_date"], true);
    assert!(!all_paths(&fx.remote).contains("SECRET"));
    let (_, status) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(
        status["sync_state"]["last_upstream_oid"],
        github_tip.as_str()
    );

    // GitHub moves on its own: sync-out refuses until sync-in.
    let clone = fx.clone_remote();
    let upstream = commit(
        &clone,
        &[("apps/web/new.ts", "export const n = 1;\n")],
        "upstream feature",
    );
    git(&clone, &["push", "-q", "origin", "HEAD:main"]);
    commit(&fx.root, &[("README.md", "# SDK v2\n")], "readme");
    let (status, body) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(git(&fx.remote, &["rev-parse", "main"]), upstream);

    // Sync-in from the default branch, 3-way onto canonical's own new README commit.
    let (status, body) = fx
        .post("/v1/github/sync/in", json!({ "dry_run": true }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["new_canonical_tip"].is_null());
    assert!(git(&fx.root, &["ls-tree", "main", "apps/web/new.ts"]).is_empty());
    let hidden_before = hidden(&fx);
    let (status, body) = fx.post("/v1/github/sync/in", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["commits_imported"], 1);
    assert_eq!(body["imported_paths"], json!(["apps/web/new.ts"]));
    assert_eq!(
        git(&fx.root, &["show", "main:apps/web/new.ts"]),
        "export const n = 1;"
    );
    assert_eq!(git(&fx.root, &["show", "main:README.md"]), "# SDK v2");
    assert_eq!(
        git(&fx.root, &["log", "-1", "--format=%s", "main"]),
        "upstream feature"
    );
    assert_eq!(hidden(&fx), hidden_before);

    // Sync-in from a pull request head.
    git(&clone, &["checkout", "-q", "-b", "pr7"]);
    commit(
        &clone,
        &[("apps/web/pr.ts", "export const pr = 7;\n")],
        "pr seven",
    );
    git(&clone, &["push", "-q", "origin", "HEAD:refs/pull/7/head"]);
    let (status, body) = fx
        .post("/v1/github/sync/in", json!({ "pr_number": 7 }))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["upstream_ref"], "refs/pull/7/head");
    assert_eq!(body["commits_imported"], 1);
    assert_eq!(
        git(&fx.root, &["show", "main:apps/web/pr.ts"]),
        "export const pr = 7;"
    );
    assert_eq!(hidden(&fx), hidden_before);
    git(&clone, &["checkout", "-q", "main"]);

    // Overlapping edits: 409, canonical untouched.
    commit(
        &fx.root,
        &[("apps/web/app.ts", app(100, 7).as_str())],
        "canonical a",
    );
    let base = git(&clone, &["rev-parse", "HEAD"]);
    commit(
        &clone,
        &[("apps/web/app.ts", app(200, 7).as_str())],
        "upstream a",
    );
    git(&clone, &["push", "-q", "origin", "HEAD:main"]);
    let canonical = fx.tip("main");
    let (status, body) = fx.post("/v1/github/sync/in", json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["conflicts"], json!(["apps/web/app.ts"]));
    assert_eq!(fx.tip("main"), canonical);
    git(&clone, &["reset", "-q", "--hard", &base]);
    git(&clone, &["push", "-q", "--force", "origin", "HEAD:main"]);

    // Non-overlapping edits of the same file merge.
    commit(
        &clone,
        &[("apps/web/app.ts", app(1, 700).as_str())],
        "upstream g",
    );
    git(&clone, &["push", "-q", "origin", "HEAD:main"]);
    let (status, body) = fx.post("/v1/github/sync/in", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        git(&fx.root, &["show", "main:apps/web/app.ts"]),
        app(100, 700).trim_end()
    );
    let base = git(&clone, &["rev-parse", "HEAD"]);

    // Anything GitHub may not write: 403, nothing imported, audited.
    let denied_before = fx.denied("github-sync-in");
    let forbidden = [
        ".access.toml",
        ".env.schema",
        "billing/ledger/tx.rs",
        "tools/new.sh",
        "apps/web/AGENTS.local.md",
        "apps/.premier/evil",
    ];
    for path in forbidden {
        commit(&clone, &[(path, "from github\n")], "sneaky");
        git(&clone, &["push", "-q", "origin", "HEAD:main"]);
        let canonical = fx.tip("main");
        let (status, body) = fx.post("/v1/github/sync/in", json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        let violations = body["policy_violations"].as_array().unwrap();
        assert!(
            violations.iter().any(|v| v["path"] == path),
            "{path}: {body}"
        );
        assert_eq!(fx.tip("main"), canonical, "{path}");
        git(&clone, &["reset", "-q", "--hard", &base]);
        git(&clone, &["push", "-q", "--force", "origin", "HEAD:main"]);
    }
    assert_eq!(fx.denied("github-sync-in") - denied_before, forbidden.len());
    assert_eq!(hidden(&fx), hidden_before);
}

#[tokio::test]
async fn pushes_lease_on_the_remote_tip_and_errors_never_show_the_token() {
    let tmp = tempfile::tempdir().unwrap();
    let remote = tmp.path().join("remote.git");
    std::fs::create_dir_all(&remote).unwrap();
    git(&remote, &["init", "-q", "--bare", "-b", "main"]);
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    git(&work, &["init", "-q", "-b", "main"]);
    let one = commit(&work, &[("a.txt", "1\n")], "one");
    let two = commit(&work, &[("a.txt", "2\n")], "two");
    let other = {
        git(&work, &["checkout", "-q", "--orphan", "other"]);
        commit(&work, &[("b.txt", "x\n")], "other")
    };

    let cfg = GithubCompanionConfigStored {
        owner: "acme".to_owned(),
        repo: "sdk".to_owned(),
        full_name: "acme/sdk".to_owned(),
        host: "github.com".to_owned(),
        api_host: "api.github.com".to_owned(),
        default_branch: "main".to_owned(),
        zone: None,
        sync_direction: SyncDirection::Bidirectional,
        token_configured: true,
        token_updated_at: None,
        connected_at: String::new(),
        connected_by: String::new(),
    };
    let ov = GithubTestOverride {
        bare_remote_path: remote.clone(),
        mock_api_base_url: String::new(),
    };
    let gh = GitRemote::new(&cfg, TOKEN, Some(&ov)).await.unwrap();
    let staging = Staging::new().await.unwrap();
    let st = staging.path();
    assert_eq!(
        fetch_ref_into_staging(st, &gh, "refs/heads/main", "refs/heads/main")
            .await
            .unwrap(),
        None
    );
    git(
        st,
        &[
            "fetch",
            "-q",
            work.to_str().unwrap(),
            "main:refs/heads/main",
            "other:refs/heads/other",
        ],
    );

    // A new branch: only while it does not exist.
    git(st, &["update-ref", "refs/heads/main", &one]);
    push_ref_from_staging(st, &gh, "refs/heads/main", "main", None)
        .await
        .unwrap();
    assert_eq!(git(&remote, &["rev-parse", "main"]), one);
    git(st, &["update-ref", "refs/heads/main", &two]);
    let err = push_ref_from_staging(st, &gh, "refs/heads/main", "main", None)
        .await
        .unwrap_err();
    assert!(!err.contains(TOKEN));
    assert_eq!(git(&remote, &["rev-parse", "main"]), one);
    // With the right lease: fast-forward, and even a rewrite.
    push_ref_from_staging(st, &gh, "refs/heads/main", "main", Some(&one))
        .await
        .unwrap();
    assert_eq!(git(&remote, &["rev-parse", "main"]), two);
    push_ref_from_staging(st, &gh, "refs/heads/other", "main", Some(&two))
        .await
        .unwrap();
    assert_eq!(git(&remote, &["rev-parse", "main"]), other);
    // A stale lease is refused.
    assert!(
        push_ref_from_staging(st, &gh, "refs/heads/main", "main", Some(&one))
            .await
            .is_err()
    );
    assert_eq!(git(&remote, &["rev-parse", "main"]), other);
    assert_eq!(
        fetch_ref_into_staging(st, &gh, "refs/heads/main", "refs/remotes/github/main")
            .await
            .unwrap(),
        Some(other)
    );
    // A transport failure is an error, never "no such ref", and never shows the token.
    let gone = GithubTestOverride {
        bare_remote_path: tmp.path().join("missing.git"),
        mock_api_base_url: String::new(),
    };
    let gh = GitRemote::new(&cfg, TOKEN, Some(&gone)).await.unwrap();
    let err = fetch_ref_into_staging(st, &gh, "refs/heads/main", "refs/heads/x")
        .await
        .unwrap_err();
    assert!(!err.contains(TOKEN));
    let staging_dir = st.to_path_buf();
    drop(staging);
    assert!(!staging_dir.exists(), "staging is removed");
}

#[tokio::test]
async fn default_sync_out_squashes_commits_and_blocks_non_public_branches() {
    let fx = Fx::new().await;
    fx.connect(Some("public")).await;
    commit(
        &fx.root,
        &[("apps/web/app.ts", &app(10, 7))],
        "Follow-up 0123456789abcdef0123456789abcdef01234567",
    );

    // Omitting `squash` defaults to true: single squashed commit without raw canonical log/OIDs.
    let (status, out) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{out}");
    assert_eq!(
        git(&fx.remote, &["rev-list", "--count", "refs/heads/main"]),
        "1"
    );
    let msg = git(&fx.remote, &["log", "-1", "--format=%B", "refs/heads/main"]);
    assert!(!msg.contains("0123456789abcdef"), "{msg}");
    assert!(msg.contains("Premier-Projection-Attestation:"), "{msg}");

    // Sync-out enforces branch confidentiality: non-public canonical branches return 403.
    git(&fx.root, &["checkout", "-q", "-b", "org-feature"]);
    commit(&fx.root, &[("README.md", "# Org only\n")], "org tweak");
    git(&fx.root, &["checkout", "-q", "main"]);
    fx.state.persisted.lock().unwrap().branch_metadata.insert(
        "refs/heads/org-feature".to_owned(),
        (Visibility::Org, Readiness::Ready),
    );
    let (status, resp) = fx
        .post(
            "/v1/github/sync/out",
            json!({ "source_branch": "org-feature", "target_branch": "org-feature" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{resp}");
    assert!(fx.denied("github-sync-out") >= 1);
}

#[tokio::test]
async fn non_default_pair_sync_out_does_not_overwrite_default_cursor() {
    let fx = Fx::new().await;
    fx.connect(Some("public")).await;

    let (status, _) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, initial_status) = fx.send(Method::GET, "/v1/github/status", None).await;
    let default_up = initial_status["sync_state"]["last_upstream_oid"]
        .as_str()
        .unwrap()
        .to_owned();

    // Syncing another branch/target pair writes to `pair_mappings`, leaving default cursor intact.
    git(&fx.root, &["checkout", "-q", "-b", "release"]);
    commit(&fx.root, &[("README.md", "# Release 1.0\n")], "release");
    git(&fx.root, &["checkout", "-q", "main"]);

    let (status, rel_out) = fx
        .post(
            "/v1/github/sync/out",
            json!({ "source_branch": "release", "target_branch": "release" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{rel_out}");
    let (_, after_rel_status) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(
        after_rel_status["sync_state"]["last_upstream_oid"].as_str(),
        Some(default_up.as_str())
    );

    // Subsequent default-pair sync-out still uses main's intact cursor cleanly.
    commit(&fx.root, &[("README.md", "# SDK v2\n")], "sdk v2");
    let (status, main_out) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{main_out}");
    assert_eq!(git(&fx.remote, &["show", "main:README.md"]), "# SDK v2");
}

#[tokio::test]
async fn disconnect_and_reconnect_recovers_via_sync_in_then_sync_out() {
    let fx = Fx::new().await;
    fx.connect(Some("public")).await;
    let (status, out1) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{out1}");
    let u1 = out1["upstream_tip"].as_str().unwrap().to_owned();

    // Canonical advances while disconnected (empty mapping after reconnect).
    commit(
        &fx.root,
        &[("README.md", "# SDK v2 (reconnected)\n")],
        "move ahead",
    );
    let (status, _) = fx.send(Method::DELETE, "/v1/github/config", None).await;
    assert_eq!(status, StatusCode::OK);
    fx.connect(Some("public")).await;

    let (status, _) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, in_res) = fx.post("/v1/github/sync/in", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{in_res}");
    assert_eq!(in_res["up_to_date"], true);
    assert!(in_res["new_canonical_tip"].is_null());

    let (_, st) = fx.send(Method::GET, "/v1/github/status", None).await;
    assert_eq!(st["sync_state"]["last_upstream_oid"], u1.as_str());

    let (status, out2) = fx
        .post("/v1/github/sync/out", json!({ "zone": "public" }))
        .await;
    assert_eq!(status, StatusCode::OK, "{out2}");
    assert_eq!(
        git(&fx.remote, &["show", "main:README.md"]),
        "# SDK v2 (reconnected)"
    );
}

#[tokio::test]
async fn publish_pr_protects_unrelated_remote_branches_and_rejects_rev_exprs() {
    let fx = Fx::new().await;
    fx.connect(None).await;
    let (status, _) = fx.post("/v1/github/sync/out", json!({})).await;
    assert_eq!(status, StatusCode::OK);

    // Git rev expressions are rejected instead of resolved via rev-parse.
    let (status, _) = fx
        .post(
            "/v1/github/pr/preview",
            json!({ "source_branch": "HEAD~0" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // An existing remote branch not owned by Premier cannot be clobbered by publish-pr.
    git(&fx.root, &["checkout", "-q", "-b", "feature"]);
    commit(&fx.root, &[("apps/web/app.ts", &app(55, 7))], "feat");
    git(&fx.root, &["checkout", "-q", "main"]);

    let clone = fx.clone_remote();
    git(&clone, &["checkout", "-q", "-b", "release-1.0"]);
    let orig_rel = commit(
        &clone,
        &[("apps/web/rel.ts", "// rel\n")],
        "upstream release",
    );
    git(
        &clone,
        &["push", "-q", "origin", "HEAD:refs/heads/release-1.0"],
    );

    let (status, body) = fx
        .post(
            "/v1/github/pr/publish",
            json!({ "source_branch": "feature", "pr_branch": "release-1.0" }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        git(&fx.remote, &["rev-parse", "refs/heads/release-1.0"]),
        orig_rel
    );
}

#[test]
fn blocked_ip_covers_all_special_use_ipv4_and_ipv6_ranges() {
    use std::net::IpAddr;
    for denied in [
        "0.1.2.3",
        "10.0.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "172.16.0.1",
        "192.0.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "240.0.0.1",
        "::1",
        "::192.0.2.1",
        "64:ff9b::1",
        "100::1",
        "2001:db8::1",
        "2002:c000:204::1",
        "fc00::1",
        "fe80::1",
        "fec0::1",
    ] {
        let ip: IpAddr = denied.parse().unwrap();
        assert!(
            crate::github::blocked_ip(ip),
            "expected blocked IP {denied}"
        );
    }
    for allowed in ["140.82.112.4", "8.8.8.8", "2606:4700:4700::1111"] {
        let ip: IpAddr = allowed.parse().unwrap();
        assert!(
            !crate::github::blocked_ip(ip),
            "expected public IP {allowed}"
        );
    }
}
