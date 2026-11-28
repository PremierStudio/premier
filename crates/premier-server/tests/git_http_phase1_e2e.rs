#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real `git` CLI end-to-end integration tests for Phase 1 Smart HTTP features:
//! 1. `--force-with-lease` push semantics (allowed on personal feature branch, refused on default
//!    branch `main` for non-owners, refused on stale lease)
//! 2. `git push --delete` (removes feature branch + `branch_metadata`, refuses deleting `main`)
//! 3. Lightweight & annotated tags (owner push, non-owner refusal, anti-CFOR secret-only hiding)
//! 4. 3-way line-level Squash-Declassify publish + CAS (`expected_source_oid`/`expected_target_oid`)
//! 5. `OverlayGuard` enforcement over real HTTP `git push`

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use premier_policy::{CompiledPolicy, parse_policy_toml};
use premier_proxy::AuditSink;
use premier_server::auth::AuthStore;
use premier_server::store::{PersistedState, bind_state_dir};
use premier_server::{ServerState, build_router, runner};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tower_service::Service;

const PW: &str = "correct horse battery staple";

const HTTP_E2E_POLICY: &str = r#"version = 1

[defaults]
public = []
authenticated = []

[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[rules]]
id = "public-readme"
effect = "allow"
principals = ["*"]
paths = ["README.md", "docs/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read"]

[[rules]]
id = "authenticated-public-write"
effect = "allow"
principals = ["authenticated"]
paths = ["README.md", "docs/**", "local-overrides/**", "AGENTS.local.md"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write"]

[[rules]]
id = "mia-deny-billing"
effect = "deny"
principals = ["@mia"]
paths = ["billing/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;

async fn api_call(
    router: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Option<String>, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost");
    if let Some(c) = cookie {
        builder = builder.header("cookie", c);
    }
    let req = if let Some(b) = body {
        builder
            .header("content-type", "application/json")
            .body(Body::from(b.to_string()))
            .unwrap()
    } else {
        builder.body(Body::empty()).unwrap()
    };
    let resp = router.clone().call(req).await.unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::to_owned);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, set_cookie, json)
}

fn run_git_sync(dir: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=Premier Test",
            "-c",
            "user.email=test@premier.test",
            "-c",
            "core.autocrlf=false",
            "-c",
            "credential.helper=",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {:?} in {} failed:\nstdout: {}\nstderr: {}",
        args,
        dir.display(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

async fn try_git_http(cwd: &Path, args: &[&str]) -> (bool, String, String) {
    let fut = tokio::process::Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args([
            "-c",
            "user.name=HTTP Tester",
            "-c",
            "user.email=http@premier.test",
            "-c",
            "core.autocrlf=false",
            "-c",
            "credential.helper=",
            "-c",
            "protocol.version=2",
        ])
        .args(args)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .unwrap_or_else(|_| panic!("git {:?} timed out over HTTP", args))
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    )
}

async fn must_git_http(cwd: &Path, args: &[&str]) -> String {
    let (ok, stdout, stderr) = try_git_http(cwd, args).await;
    assert!(
        ok,
        "git {:?} failed:\nstdout: {stdout}\nstderr: {stderr}",
        args
    );
    stdout
}

struct HttpFixture {
    _tmp: tempfile::TempDir,
    main_repo: std::path::PathBuf,
    work_dir: std::path::PathBuf,
    state: ServerState,
    router: Router,
    addr: SocketAddr,
    alice_cookie: String,
    alice_token: String,
    mia_token: String,
    _http_task: tokio::task::JoinHandle<()>,
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self._http_task.abort();
    }
}

impl HttpFixture {
    fn alice_url(&self) -> String {
        format!(
            "http://alice:{}@{}/git/auth/repo.git",
            self.alice_token, self.addr
        )
    }

    fn mia_url(&self) -> String {
        format!(
            "http://mia:{}@{}/git/auth/repo.git",
            self.mia_token, self.addr
        )
    }
}

async fn setup_http_fixture(initial_readme: &str) -> HttpFixture {
    let tmp = tempfile::tempdir().unwrap();
    let main_repo = tmp.path().join("repo");
    let state_dir = tmp.path().join("state");
    let work_dir = tmp.path().join("work");

    std::fs::create_dir_all(main_repo.join("billing")).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();

    run_git_sync(&main_repo, &["init", "-q", "-b", "main"]);
    std::fs::write(main_repo.join(".access.toml"), HTTP_E2E_POLICY).unwrap();
    std::fs::write(main_repo.join("README.md"), initial_readme).unwrap();
    std::fs::write(
        main_repo.join("billing/ledger.rs"),
        "pub const LEDGER: &str = \"secret-v1\";\n",
    )
    .unwrap();
    run_git_sync(&main_repo, &["add", ".access.toml", "README.md", "billing"]);
    run_git_sync(&main_repo, &["commit", "-q", "-m", "initial commit"]);

    bind_state_dir(&main_repo, &state_dir, "repo", true);

    let policy_file = parse_policy_toml(HTTP_E2E_POLICY).unwrap();
    let compiled = CompiledPolicy::compile(None, &policy_file).unwrap();
    let mut state = ServerState::minimal(
        Some(Arc::new(compiled)),
        None,
        Arc::new(AuditSink::default()),
    );
    state.workspace_root = main_repo.clone();
    state.repo_policy_path = Some(main_repo.join(".access.toml"));
    state.set_repo_policy_metadata(
        Some(HTTP_E2E_POLICY.to_owned()),
        Some(Arc::new(policy_file)),
    );
    state.persisted = Arc::new(Mutex::new(PersistedState::default()));
    state.auth = Arc::new(AuthStore::open(&main_repo));
    state.session_manager = Arc::new(runner::SessionManager::open(&main_repo));

    let router = build_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_router = router.clone();
    let http_task = tokio::spawn(async move {
        let _ = axum::serve(listener, serve_router).await;
    });

    // Create owner `alice` and member `mia` + access tokens via real HTTP routes.
    let (status, alice_cookie, body) = api_call(
        &router,
        Method::POST,
        "/v1/auth/setup",
        None,
        Some(json!({ "username": "alice", "password": PW })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alice_cookie = alice_cookie.unwrap();

    let (status, _, body) = api_call(
        &router,
        Method::POST,
        "/v1/users",
        Some(&alice_cookie),
        Some(json!({ "username": "mia", "password": PW })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, mia_cookie, body) = api_call(
        &router,
        Method::POST,
        "/v1/auth/login",
        None,
        Some(json!({ "username": "mia", "password": PW })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mia_cookie = mia_cookie.unwrap();

    let (status, _, alice_tok) = api_call(
        &router,
        Method::POST,
        "/v1/auth/tokens",
        Some(&alice_cookie),
        Some(json!({ "name": "alice-git" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{alice_tok}");
    let alice_token = alice_tok["token"].as_str().unwrap().to_owned();

    let (status, _, mia_tok) = api_call(
        &router,
        Method::POST,
        "/v1/auth/tokens",
        Some(&mia_cookie),
        Some(json!({ "name": "mia-git" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{mia_tok}");
    let mia_token = mia_tok["token"].as_str().unwrap().to_owned();

    HttpFixture {
        _tmp: tmp,
        main_repo,
        work_dir,
        state,
        router,
        addr,
        alice_cookie,
        alice_token,
        mia_token,
        _http_task: http_task,
    }
}

#[tokio::test]
async fn http_force_with_lease_and_branch_delete_over_real_git() {
    let fx = setup_http_fixture("# Initial README\n").await;
    let mia_url = fx.mia_url();
    let alice_url = fx.alice_url();

    let mia_clone1 = fx.work_dir.join("mia-1");
    let mia_clone2 = fx.work_dir.join("mia-2");
    let alice_clone = fx.work_dir.join("alice");

    must_git_http(
        &fx.work_dir,
        &["clone", &mia_url, mia_clone1.to_str().unwrap()],
    )
    .await;
    assert!(!mia_clone1.join("billing").exists());

    // 1. `--force-with-lease` ALLOWED on Mia's personal feature branch `mia/http-feat`.
    run_git_sync(&mia_clone1, &["checkout", "-q", "-b", "mia/http-feat"]);
    std::fs::write(mia_clone1.join("README.md"), "# Feature v1\n").unwrap();
    run_git_sync(&mia_clone1, &["commit", "-q", "-am", "feat: v1"]);
    must_git_http(&mia_clone1, &["push", "-u", "origin", "mia/http-feat"]).await;

    assert!(
        fx.state
            .branch_metadata()
            .contains_key("refs/premier-private/mia/http-feat")
    );

    // Clone a second copy while `mia/http-feat` is at v1 so we can later test a stale lease.
    must_git_http(
        &fx.work_dir,
        &["clone", &mia_url, mia_clone2.to_str().unwrap()],
    )
    .await;
    run_git_sync(
        &mia_clone2,
        &[
            "checkout",
            "-q",
            "-b",
            "mia/http-feat",
            "origin/mia/http-feat",
        ],
    );

    // Amend on clone 1 and push with `--force-with-lease` -> succeeds!
    std::fs::write(mia_clone1.join("README.md"), "# Feature v2 amended\n").unwrap();
    run_git_sync(
        &mia_clone1,
        &["commit", "-q", "--amend", "-am", "feat: v2 amended"],
    );
    must_git_http(
        &mia_clone1,
        &["push", "--force-with-lease", "origin", "mia/http-feat"],
    )
    .await;

    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
    assert_eq!(
        run_git_sync(
            &fx.main_repo,
            &["show", "refs/premier-private/mia/http-feat:README.md"]
        ),
        "# Feature v2 amended"
    );
    assert_eq!(
        run_git_sync(
            &fx.main_repo,
            &[
                "show",
                "refs/premier-private/mia/http-feat:billing/ledger.rs"
            ]
        ),
        "pub const LEDGER: &str = \"secret-v1\";"
    );

    // 2. `--force-with-lease` REFUSED on stale lease (clone 2 still thinks remote is at v1).
    let feat_tip_before = run_git_sync(
        &fx.main_repo,
        &["rev-parse", "refs/premier-private/mia/http-feat"],
    );
    std::fs::write(mia_clone2.join("README.md"), "# Stale overwrite attempt\n").unwrap();
    run_git_sync(
        &mia_clone2,
        &["commit", "-q", "--amend", "-am", "feat: stale attempt"],
    );
    let (ok_stale, _, err_stale) = try_git_http(
        &mia_clone2,
        &["push", "--force-with-lease", "origin", "mia/http-feat"],
    )
    .await;
    assert!(
        !ok_stale,
        "stale --force-with-lease must be refused, stderr={err_stale}"
    );
    assert_eq!(
        run_git_sync(
            &fx.main_repo,
            &["rev-parse", "refs/premier-private/mia/http-feat"]
        ),
        feat_tip_before,
        "stale lease push must not move the remote branch"
    );

    // 3. `--force-with-lease` REFUSED on protected default branch `main` (non-owner Mia).
    run_git_sync(&mia_clone1, &["checkout", "-q", "main"]);
    // First make a fast-forward push so `main` has 2 commits.
    std::fs::write(mia_clone1.join("README.md"), "# Main v2\n").unwrap();
    run_git_sync(&mia_clone1, &["commit", "-q", "-am", "docs: main v2"]);
    must_git_http(&mia_clone1, &["push", "origin", "main"]).await;

    let main_tip_before = run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]);
    std::fs::write(mia_clone1.join("README.md"), "# Main force rewrite\n").unwrap();
    run_git_sync(
        &mia_clone1,
        &["commit", "-q", "--amend", "-am", "docs: try force on main"],
    );
    let (ok_main_force, _, err_main_force) = try_git_http(
        &mia_clone1,
        &["push", "--force-with-lease", "origin", "main"],
    )
    .await;
    assert!(
        !ok_main_force,
        "force-with-lease on protected default branch `main` must be refused for non-owner, stderr={err_main_force}"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]),
        main_tip_before
    );

    // 4. `git push --delete` on feature branch succeeds & removes `branch_metadata`.
    must_git_http(
        &mia_clone1,
        &["push", "--delete", "origin", "mia/http-feat"],
    )
    .await;
    let meta_after = fx.state.branch_metadata();
    assert!(
        !meta_after.contains_key("refs/premier-private/mia/http-feat")
            && !meta_after.contains_key("refs/heads/mia/http-feat"),
        "branch_metadata not cleaned up: {meta_after:?}"
    );
    assert!(
        run_git_sync(
            &fx.main_repo,
            &["for-each-ref", "refs/premier-private/mia/http-feat"]
        )
        .is_empty()
    );

    // 5. `git push --delete origin main` is REFUSED for BOTH member Mia and owner Alice!
    let (ok_mia_del_main, _, err_mia_del_main) =
        try_git_http(&mia_clone1, &["push", "--delete", "origin", "main"]).await;
    assert!(
        !ok_mia_del_main,
        "deleting default branch `main` as Mia must fail: {err_mia_del_main}"
    );

    must_git_http(
        &fx.work_dir,
        &["clone", &alice_url, alice_clone.to_str().unwrap()],
    )
    .await;
    let (ok_alice_del_main, _, err_alice_del_main) =
        try_git_http(&alice_clone, &["push", "--delete", "origin", "main"]).await;
    assert!(
        !ok_alice_del_main,
        "deleting default branch `main` as owner must fail: {err_alice_del_main}"
    );
    assert!(
        err_alice_del_main.contains("cannot delete the default branch"),
        "unexpected error deleting main: {err_alice_del_main}"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]),
        main_tip_before
    );
}

#[tokio::test]
async fn http_tags_lightweight_annotated_owner_only_and_secret_commit_hiding() {
    let fx = setup_http_fixture("# Tag Test v1\n").await;
    let alice_url = fx.alice_url();
    let mia_url = fx.mia_url();

    let alice_clone = fx.work_dir.join("alice-tags");
    let mia_clone = fx.work_dir.join("mia-tags");

    must_git_http(
        &fx.work_dir,
        &["clone", &alice_url, alice_clone.to_str().unwrap()],
    )
    .await;
    must_git_http(
        &fx.work_dir,
        &["clone", &mia_url, mia_clone.to_str().unwrap()],
    )
    .await;

    // 1. Owner creates & pushes lightweight and annotated tags on a public commit.
    run_git_sync(&alice_clone, &["tag", "v2.0-light"]);
    run_git_sync(
        &alice_clone,
        &["tag", "-a", "v2.0-annot", "-m", "Annotated release v2.0"],
    );
    must_git_http(
        &alice_clone,
        &["push", "origin", "v2.0-light", "v2.0-annot"],
    )
    .await;

    // 2. Owner commits a secret-only change to `billing/ledger.rs` and tags that commit.
    std::fs::write(
        alice_clone.join("billing/ledger.rs"),
        "pub const LEDGER: &str = \"secret-v2-only\";\n",
    )
    .unwrap();
    run_git_sync(
        &alice_clone,
        &["commit", "-q", "-am", "billing: secret only"],
    );
    run_git_sync(&alice_clone, &["tag", "v2.0-secret-light"]);
    run_git_sync(
        &alice_clone,
        &[
            "tag",
            "-a",
            "v2.0-secret-annot",
            "-m",
            "Secret only release",
        ],
    );
    must_git_http(
        &alice_clone,
        &[
            "push",
            "origin",
            "main",
            "v2.0-secret-light",
            "v2.0-secret-annot",
        ],
    )
    .await;

    // 3. Non-owner Mia CANNOT create global `refs/tags/*`.
    run_git_sync(&mia_clone, &["tag", "mia-global-tag"]);
    let (ok_mia_tag, _, err_mia_tag) =
        try_git_http(&mia_clone, &["push", "origin", "refs/tags/mia-global-tag"]).await;
    assert!(
        !ok_mia_tag,
        "non-owner must not be allowed to create global refs/tags/*, stderr={err_mia_tag}"
    );
    assert!(
        err_mia_tag.contains("only repository owners may create tags"),
        "unexpected non-owner tag rejection: {err_mia_tag}"
    );
    assert!(run_git_sync(&fx.main_repo, &["for-each-ref", "refs/tags/mia-global-tag"]).is_empty());

    // 4. `git ls-remote --tags` + `git fetch --tags`:
    //    Owner sees all 4 tags; Mia sees ONLY the 2 public-commit tags (secret-only tags hidden!).
    let alice_ls = must_git_http(&alice_clone, &["ls-remote", "--tags", "origin"]).await;
    for tag in [
        "refs/tags/v2.0-light",
        "refs/tags/v2.0-annot",
        "refs/tags/v2.0-secret-light",
        "refs/tags/v2.0-secret-annot",
    ] {
        assert!(alice_ls.contains(tag), "owner missing {tag}: {alice_ls}");
    }

    let mia_ls = must_git_http(&mia_clone, &["ls-remote", "--tags", "origin"]).await;
    assert!(mia_ls.contains("refs/tags/v2.0-light"), "{mia_ls}");
    assert!(mia_ls.contains("refs/tags/v2.0-annot"), "{mia_ls}");
    assert!(
        !mia_ls.contains("v2.0-secret-light") && !mia_ls.contains("v2.0-secret-annot"),
        "tags targeting secret-only commits must be hidden from Mia: {mia_ls}"
    );

    must_git_http(&mia_clone, &["fetch", "origin", "--tags"]).await;
    let mia_local_tags = run_git_sync(&mia_clone, &["tag", "-l"]);
    assert!(mia_local_tags.lines().any(|t| t == "v2.0-light"));
    assert!(mia_local_tags.lines().any(|t| t == "v2.0-annot"));
    assert!(!mia_local_tags.contains("v2.0-secret"));
    assert_eq!(
        run_git_sync(&mia_clone, &["cat-file", "-t", "v2.0-annot"]),
        "tag"
    );
    run_git_sync(&mia_clone, &["fsck", "--strict", "--full"]);
    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
}

#[tokio::test]
async fn http_three_way_squash_declassify_publish_and_cas_guards() {
    let base_readme = [
        "# Header Line",
        "line 02",
        "line 03",
        "line 04",
        "line 05",
        "line 06",
        "line 07",
        "line 08",
        "line 09",
        "line 10",
        "line 11",
        "line 12",
        "# Footer Line",
        "",
    ]
    .join("\n");
    let fx = setup_http_fixture(&base_readme).await;
    let alice_url = fx.alice_url();

    // Create private branch `priv-feature` via HTTP API.
    let (status, _, created) = api_call(
        &fx.router,
        Method::POST,
        "/v1/branches/create",
        Some(&fx.alice_cookie),
        Some(json!({
            "name": "priv-feature",
            "from_ref": "main",
            "visibility": { "scope": "restricted", "allow": ["group:owners"] }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");

    // Clone as owner over real HTTP and advance BOTH `priv-feature` (top lines of README.md +
    // private billing/ledger.rs) and `main` (non-overlapping bottom lines of README.md).
    let alice_clone = fx.work_dir.join("alice-merge");
    must_git_http(
        &fx.work_dir,
        &["clone", &alice_url, alice_clone.to_str().unwrap()],
    )
    .await;

    run_git_sync(
        &alice_clone,
        &[
            "checkout",
            "-q",
            "-b",
            "priv-feature",
            "origin/priv-feature",
        ],
    );
    let feature_readme = base_readme.replace("# Header Line", "# Header Line (from priv-feature)");
    std::fs::write(alice_clone.join("README.md"), &feature_readme).unwrap();
    std::fs::write(
        alice_clone.join("billing/ledger.rs"),
        "pub const LEDGER: &str = \"private-branch-only-secret\";\n",
    )
    .unwrap();
    run_git_sync(
        &alice_clone,
        &[
            "commit",
            "-q",
            "-am",
            "priv: edit top of README and billing",
        ],
    );
    must_git_http(&alice_clone, &["push", "origin", "priv-feature"]).await;

    run_git_sync(&alice_clone, &["checkout", "-q", "main"]);
    let main_readme = base_readme.replace("# Footer Line", "# Footer Line (from main)");
    std::fs::write(alice_clone.join("README.md"), &main_readme).unwrap();
    run_git_sync(
        &alice_clone,
        &["commit", "-q", "-am", "main: edit bottom of README"],
    );
    must_git_http(&alice_clone, &["push", "origin", "main"]).await;

    // 1. `POST /v1/branches/squash-preview`: must report `README.md` in `merged_paths` and ZERO conflicts!
    let (status, _, preview) = api_call(
        &fx.router,
        Method::POST,
        "/v1/branches/squash-preview",
        Some(&fx.alice_cookie),
        Some(json!({ "branch": "priv-feature", "target_branch": "main" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["merged_paths"], json!(["README.md"]), "{preview}");
    assert_eq!(preview["conflicts"], json!([]), "{preview}");
    assert_eq!(
        preview["scrubbed_paths"],
        json!(["billing/ledger.rs"]),
        "{preview}"
    );
    assert_eq!(preview["declassification_gate_passed"], true, "{preview}");

    let source_oid = run_git_sync(
        &fx.main_repo,
        &["rev-parse", "refs/premier-private/priv-feature"],
    );
    let target_oid = run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]);
    let wrong_oid = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    // 2. CAS guard: wrong `expected_source_oid` -> 409 Conflict!
    let (status, _, body) = api_call(
        &fx.router,
        Method::POST,
        "/v1/branches/publish",
        Some(&fx.alice_cookie),
        Some(json!({
            "source_branch": "priv-feature",
            "target_branch": "main",
            "expected_source_oid": wrong_oid,
            "expected_target_oid": target_oid,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // 3. CAS guard: wrong `expected_target_oid` -> 409 Conflict!
    let (status, _, body) = api_call(
        &fx.router,
        Method::POST,
        "/v1/branches/publish",
        Some(&fx.alice_cookie),
        Some(json!({
            "source_branch": "priv-feature",
            "target_branch": "main",
            "expected_source_oid": source_oid,
            "expected_target_oid": wrong_oid,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]),
        target_oid,
        "failed CAS must not move main"
    );

    // 4. Publish with matching `expected_source_oid` + `expected_target_oid` -> 200 OK!
    let (status, _, published) = api_call(
        &fx.router,
        Method::POST,
        "/v1/branches/publish",
        Some(&fx.alice_cookie),
        Some(json!({
            "source_branch": "priv-feature",
            "target_branch": "main",
            "expected_source_oid": source_oid,
            "expected_target_oid": target_oid,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{published}");
    assert_eq!(
        published["merged_paths"],
        json!(["README.md"]),
        "{published}"
    );
    assert_eq!(
        published["published_paths"],
        json!(["README.md"]),
        "{published}"
    );
    assert_eq!(
        published["scrubbed_paths"],
        json!(["billing/ledger.rs"]),
        "{published}"
    );

    // Verify canonical `main:README.md` contains BOTH non-overlapping edits, `billing/ledger.rs`
    // remained untouched, and `git fsck --strict --full` passes!
    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
    let merged_readme = run_git_sync(&fx.main_repo, &["show", "main:README.md"]);
    assert!(
        merged_readme.contains("# Header Line (from priv-feature)"),
        "missing priv-feature edit: {merged_readme}"
    );
    assert!(
        merged_readme.contains("# Footer Line (from main)"),
        "missing main edit: {merged_readme}"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["show", "main:billing/ledger.rs"]),
        "pub const LEDGER: &str = \"secret-v1\";",
        "scrubbed private billing change must never land on main"
    );
}

#[tokio::test]
async fn http_overlay_guard_rejects_mounted_and_default_overlays_over_real_git_push() {
    let fx = setup_http_fixture("# Overlay Guard Test\n").await;
    let mia_url = fx.mia_url();

    // 1. Mount a custom overlay glob via `POST /v1/overlays/mount`.
    let (status, _, manifest) = api_call(
        &fx.router,
        Method::POST,
        "/v1/overlays/mount",
        Some(&fx.alice_cookie),
        Some(json!({
            "path": "local-overrides/**",
            "scope": "personal",
            "create_file": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{manifest}");

    let mia_clone = fx.work_dir.join("mia-overlay");
    must_git_http(
        &fx.work_dir,
        &["clone", &mia_url, mia_clone.to_str().unwrap()],
    )
    .await;
    let main_tip_before = run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]);

    // 2. Commit a file matching the mounted custom overlay glob and push -> cleanly rejected!
    std::fs::create_dir_all(mia_clone.join("local-overrides")).unwrap();
    std::fs::write(
        mia_clone.join("local-overrides/dev.toml"),
        "endpoint = \"http://localhost:9999\"\n",
    )
    .unwrap();
    run_git_sync(&mia_clone, &["add", "local-overrides/dev.toml"]);
    run_git_sync(
        &mia_clone,
        &["commit", "-q", "-m", "oops: commit mounted overlay"],
    );

    let (ok_custom, _, err_custom) = try_git_http(&mia_clone, &["push", "origin", "main"]).await;
    assert!(
        !ok_custom,
        "push containing mounted overlay file must be rejected"
    );
    assert!(
        err_custom.contains("overlay guard blocked push"),
        "expected overlay guard rejection message, got: {err_custom}"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]),
        main_tip_before
    );

    // 3. Reset and commit a built-in guarded overlay (`AGENTS.local.md`) -> cleanly rejected!
    run_git_sync(&mia_clone, &["reset", "--hard", "origin/main"]);
    std::fs::write(
        mia_clone.join("AGENTS.local.md"),
        "# local private agent notes\n",
    )
    .unwrap();
    run_git_sync(&mia_clone, &["add", "AGENTS.local.md"]);
    run_git_sync(
        &mia_clone,
        &["commit", "-q", "-m", "oops: commit AGENTS.local.md"],
    );

    let (ok_builtin, _, err_builtin) = try_git_http(&mia_clone, &["push", "origin", "main"]).await;
    assert!(
        !ok_builtin,
        "push containing AGENTS.local.md must be rejected"
    );
    assert!(
        err_builtin.contains("overlay guard blocked push"),
        "expected overlay guard rejection message, got: {err_builtin}"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["rev-parse", "refs/heads/main"]),
        main_tip_before
    );
    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
}
