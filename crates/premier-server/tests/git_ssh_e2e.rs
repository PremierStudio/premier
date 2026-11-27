#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Real `git` CLI end-to-end integration tests for Premier Git-over-SSH (`premier-ssh` +
//! `ServerSshBackend` + `premier-server` HTTP `/v1/auth/ssh-keys` lifecycle).

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
use premier_server::repos::Registry;
use premier_server::ssh::ServerSshBackend;
use premier_server::store::{PersistedState, bind_state_dir};
use premier_server::{ServerState, runner};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tower_service::Service;

const PW: &str = "correct horse battery staple";

const E2E_POLICY: &str = r#"version = 1

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
paths = ["README.md", "docs/**"]
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

fn generate_ed25519_keypair(dir: &Path, name: &str, comment: &str) -> (std::path::PathBuf, String) {
    let priv_path = dir.join(name);
    let out = std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(&priv_path)
        .output()
        .expect("ssh-keygen must be available on PATH");
    assert!(
        out.status.success(),
        "ssh-keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let pub_path = dir.join(format!("{name}.pub"));
    let pub_key = std::fs::read_to_string(&pub_path)
        .unwrap()
        .trim()
        .to_owned();
    (priv_path, pub_key)
}

fn git_ssh_command(private_key: &Path) -> String {
    let key_fwd = private_key.to_string_lossy().replace('\\', "/");
    let null_dev = if cfg!(windows) { "NUL" } else { "/dev/null" };
    format!(
        "ssh -i \"{key_fwd}\" -o StrictHostKeyChecking=no -o UserKnownHostsFile={null_dev} -o IdentitiesOnly=yes -o BatchMode=yes -o PreferredAuthentications=publickey"
    )
}

async fn try_git_ssh(
    cwd: &Path,
    private_key: &Path,
    protocol_version: &str,
    args: &[&str],
) -> (bool, String, String) {
    let ssh_cmd = git_ssh_command(private_key);
    let proto_arg = format!("protocol.version={protocol_version}");
    let fut = tokio::process::Command::new("git")
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_SSH_COMMAND", ssh_cmd)
        .args([
            "-c",
            "user.name=SSH Tester",
            "-c",
            "user.email=tester@premier.test",
            "-c",
            "core.autocrlf=false",
            "-c",
            &proto_arg,
        ])
        .args(args)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "git {:?} (protocol.version={protocol_version}) timed out — possible SSH negotiation deadlock",
                args
            )
        })
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).trim().to_owned(),
        String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    )
}

async fn must_git_ssh(
    cwd: &Path,
    private_key: &Path,
    protocol_version: &str,
    args: &[&str],
) -> String {
    let (ok, stdout, stderr) = try_git_ssh(cwd, private_key, protocol_version, args).await;
    assert!(
        ok,
        "git {:?} (protocol.version={protocol_version}) failed:\nstdout: {stdout}\nstderr: {stderr}",
        args
    );
    stdout
}

struct SshTestFixture {
    _tmp: tempfile::TempDir,
    main_repo: std::path::PathBuf,
    keys_dir: std::path::PathBuf,
    work_dir: std::path::PathBuf,
    state: ServerState,
    router: Router,
    ssh_addr: SocketAddr,
    alice_cookie: String,
    mia_cookie: String,
    alice_priv: std::path::PathBuf,
    mia_priv: std::path::PathBuf,
    mia_key_id: String,
    _http_task: tokio::task::JoinHandle<()>,
    _ssh_task: tokio::task::JoinHandle<()>,
}

impl Drop for SshTestFixture {
    fn drop(&mut self) {
        self._http_task.abort();
        self._ssh_task.abort();
    }
}

async fn setup_ssh_fixture(test_key_aliases: bool) -> SshTestFixture {
    let tmp = tempfile::tempdir().unwrap();
    let main_repo = tmp.path().join("main-repo");
    let repos_dir = tmp.path().join("extra-repos");
    let hidden_repo = repos_dir.join("hidden-vault");
    let state_dir = tmp.path().join("state");
    let keys_dir = tmp.path().join("keys");
    let work_dir = tmp.path().join("work");

    std::fs::create_dir_all(main_repo.join("billing")).unwrap();
    std::fs::create_dir_all(&hidden_repo).unwrap();
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::create_dir_all(&keys_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();

    // Initialize canonical main repo with .access.toml, README.md, and restricted billing/ledger.rs.
    run_git_sync(&main_repo, &["init", "-q", "-b", "main"]);
    std::fs::write(main_repo.join(".access.toml"), E2E_POLICY).unwrap();
    std::fs::write(main_repo.join("README.md"), "# Premier SSH v1\n").unwrap();
    std::fs::write(
        main_repo.join("billing/ledger.rs"),
        "pub const LEDGER_SECRET: &str = \"top-secret-ledger-v1\";\n",
    )
    .unwrap();
    run_git_sync(&main_repo, &["add", ".access.toml", "README.md", "billing"]);
    run_git_sync(&main_repo, &["commit", "-q", "-m", "initial commit"]);

    // Initialize hidden repo with NO .access.toml -> defaults to owners-only (hidden from Mia).
    run_git_sync(&hidden_repo, &["init", "-q", "-b", "main"]);
    std::fs::write(hidden_repo.join("VAULT.txt"), "owners only\n").unwrap();
    run_git_sync(&hidden_repo, &["add", "VAULT.txt"]);
    run_git_sync(&hidden_repo, &["commit", "-q", "-m", "vault init"]);

    bind_state_dir(&main_repo, &state_dir, "main-repo", true);

    let policy_file = parse_policy_toml(E2E_POLICY).unwrap();
    let compiled = CompiledPolicy::compile(None, &policy_file).unwrap();
    let mut state = ServerState::minimal(
        Some(Arc::new(compiled)),
        None,
        Arc::new(AuditSink::default()),
    );
    state.workspace_root = main_repo.clone();
    state.repo_policy_path = Some(main_repo.join(".access.toml"));
    state.set_repo_policy_metadata(Some(E2E_POLICY.to_owned()), Some(Arc::new(policy_file)));
    state.persisted = Arc::new(Mutex::new(PersistedState::default()));
    state.auth = Arc::new(AuthStore::open(&main_repo));
    state.session_manager = Arc::new(runner::SessionManager::open(&main_repo));

    // Reserve an ephemeral loopback port for SSH before starting `premier_ssh::serve_ssh`.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let ssh_addr = probe.local_addr().unwrap();
    drop(probe);
    state.ssh_bind = Some(ssh_addr);

    let registry = Registry::open(state.clone(), Some("main-repo".to_owned()), Some(repos_dir));
    let router = registry.router();

    // Serve HTTP on an ephemeral loopback port.
    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let serve_router = router.clone();
    let http_task = tokio::spawn(async move {
        let _ = axum::serve(http_listener, serve_router).await;
    });

    // Serve SSH on the ephemeral loopback port.
    let host_key_path = state_dir.join("ssh_host_ed25519.key");
    let backend = Arc::new(ServerSshBackend::new(registry));
    let ssh_task = tokio::spawn(async move {
        let _ = premier_ssh::serve_ssh(ssh_addr, host_key_path, backend).await;
    });

    // Wait until the SSH listener is accepting TCP connections.
    let mut ready = false;
    for _ in 0..100 {
        if TcpStream::connect(ssh_addr).await.is_ok() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(ready, "premier-ssh did not start listening on {ssh_addr}");

    // Bootstrap owner `alice` and member `mia` via real HTTP auth routes.
    let (status, alice_cookie, body) = api_call(
        &router,
        Method::POST,
        "/v1/auth/setup",
        None,
        Some(json!({ "username": "alice", "password": PW })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let alice_cookie = alice_cookie.expect("setup returns session cookie");

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
    let mia_cookie = mia_cookie.expect("login returns session cookie");

    // Generate real Ed25519 SSH keypairs with `ssh-keygen`.
    let (alice_priv, alice_pub) = generate_ed25519_keypair(&keys_dir, "id_alice", "alice@e2e");
    let (mia_priv, mia_pub) = generate_ed25519_keypair(&keys_dir, "id_mia", "mia@e2e");

    // Register Alice's key using `"key"` field.
    let (status, _, created_alice) = api_call(
        &router,
        Method::POST,
        "/v1/auth/ssh-keys",
        Some(&alice_cookie),
        Some(json!({ "name": "alice-ed25519", "key": alice_pub })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created_alice}");
    assert_eq!(created_alice["key_type"], "ssh-ed25519");
    assert!(
        created_alice["fingerprint"]
            .as_str()
            .unwrap()
            .starts_with("SHA256:")
    );

    // Register Mia's key using `"public_key"` alias.
    let (status, _, created_mia) = api_call(
        &router,
        Method::POST,
        "/v1/auth/ssh-keys",
        Some(&mia_cookie),
        Some(json!({ "name": "mia-ed25519", "public_key": mia_pub })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created_mia}");
    let mia_key_id = created_mia["id"].as_str().unwrap().to_owned();

    if test_key_aliases {
        // Duplicate key (same key under `"key"` field or another user) MUST return 409 Conflict.
        let (status, _, dup_same) = api_call(
            &router,
            Method::POST,
            "/v1/auth/ssh-keys",
            Some(&mia_cookie),
            Some(json!({ "name": "mia-dup", "key": mia_pub })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{dup_same}");

        let (status, _, dup_cross) = api_call(
            &router,
            Method::POST,
            "/v1/auth/ssh-keys",
            Some(&alice_cookie),
            Some(json!({ "name": "cross-dup", "public_key": mia_pub })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{dup_cross}");
    }

    SshTestFixture {
        _tmp: tmp,
        main_repo,
        keys_dir,
        work_dir,
        state,
        router,
        ssh_addr,
        alice_cookie,
        mia_cookie,
        alice_priv,
        mia_priv,
        mia_key_id,
        _http_task: http_task,
        _ssh_task: ssh_task,
    }
}

#[tokio::test]
async fn git_ssh_protocol_v2_e2e_clone_push_lease_delete_tags_anti_oracle_and_revocation() {
    let fx = setup_ssh_fixture(true).await;
    let _ = (&fx.keys_dir, &fx.alice_cookie);
    let repo_url = format!("ssh://git@{}/repo.git", fx.ssh_addr);
    let hidden_url = format!("ssh://git@{}/hidden-vault.git", fx.ssh_addr);
    let missing_url = format!("ssh://git@{}/no-such-repo.git", fx.ssh_addr);

    // 1. Mia clones via real `git -c protocol.version=2` over SSH.
    let mia_clone = fx.work_dir.join("mia-clone");
    must_git_ssh(
        &fx.work_dir,
        &fx.mia_priv,
        "2",
        &["clone", &repo_url, mia_clone.to_str().unwrap()],
    )
    .await;

    assert_eq!(
        std::fs::read_to_string(mia_clone.join("README.md")).unwrap(),
        "# Premier SSH v1\n"
    );
    assert!(
        !mia_clone.join("billing").exists(),
        "billing/ must never be projected into Mia's SSH clone"
    );
    assert!(
        !mia_clone.join("billing/ledger.rs").exists(),
        "billing/ledger.rs must never exist in Mia's SSH clone"
    );
    run_git_sync(&mia_clone, &["fsck", "--strict", "--full"]);

    // 2. Mia edits README.md and pushes to `main`: canonical repo updates README.md AND
    //    preserves restricted `billing/ledger.rs` intact.
    std::fs::write(mia_clone.join("README.md"), "# Premier SSH v2 by Mia\n").unwrap();
    run_git_sync(&mia_clone, &["add", "README.md"]);
    run_git_sync(
        &mia_clone,
        &["commit", "-q", "-m", "docs: update via ssh v2"],
    );
    must_git_ssh(&mia_clone, &fx.mia_priv, "2", &["push", "origin", "main"]).await;

    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
    assert_eq!(
        run_git_sync(&fx.main_repo, &["show", "main:README.md"]),
        "# Premier SSH v2 by Mia"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["show", "main:billing/ledger.rs"]),
        "pub const LEDGER_SECRET: &str = \"top-secret-ledger-v1\";"
    );

    // 3. Mia creates feature branch `mia/ssh-feat`, pushes, amends, force-with-lease pushes,
    //    then deletes the branch and verifies `branch_metadata` cleanup.
    run_git_sync(&mia_clone, &["checkout", "-q", "-b", "mia/ssh-feat"]);
    std::fs::write(mia_clone.join("README.md"), "# Feature draft 1\n").unwrap();
    run_git_sync(&mia_clone, &["commit", "-q", "-am", "feat: draft 1"]);
    must_git_ssh(
        &mia_clone,
        &fx.mia_priv,
        "2",
        &["push", "-u", "origin", "mia/ssh-feat"],
    )
    .await;

    assert!(
        fx.state
            .branch_metadata()
            .contains_key("refs/premier-private/mia/ssh-feat"),
        "pushed personal branch should be recorded in branch_metadata"
    );

    std::fs::write(mia_clone.join("README.md"), "# Feature draft 2 (amended)\n").unwrap();
    run_git_sync(
        &mia_clone,
        &["commit", "-q", "--amend", "-am", "feat: draft 2"],
    );
    must_git_ssh(
        &mia_clone,
        &fx.mia_priv,
        "2",
        &["push", "--force-with-lease", "origin", "mia/ssh-feat"],
    )
    .await;

    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
    assert_eq!(
        run_git_sync(
            &fx.main_repo,
            &["show", "refs/premier-private/mia/ssh-feat:README.md"]
        ),
        "# Feature draft 2 (amended)"
    );
    assert_eq!(
        run_git_sync(
            &fx.main_repo,
            &[
                "show",
                "refs/premier-private/mia/ssh-feat:billing/ledger.rs"
            ]
        ),
        "pub const LEDGER_SECRET: &str = \"top-secret-ledger-v1\";"
    );

    must_git_ssh(
        &mia_clone,
        &fx.mia_priv,
        "2",
        &["push", "--delete", "origin", "mia/ssh-feat"],
    )
    .await;

    let remaining_meta = fx.state.branch_metadata();
    assert!(
        !remaining_meta.contains_key("refs/premier-private/mia/ssh-feat")
            && !remaining_meta.contains_key("refs/heads/mia/ssh-feat"),
        "branch_metadata should be cleaned up after SSH branch deletion: {remaining_meta:?}"
    );
    assert!(
        run_git_sync(
            &fx.main_repo,
            &["for-each-ref", "refs/premier-private/mia/ssh-feat"]
        )
        .is_empty()
    );
    run_git_sync(&mia_clone, &["checkout", "-q", "main"]);

    // 4. Owner pushes lightweight + annotated tags over SSH on a public commit AND on a
    //    secret-only commit; Mia fetches tags and sees ONLY the public-commit tags (anti-CFOR).
    let alice_clone = fx.work_dir.join("alice-clone");
    must_git_ssh(
        &fx.work_dir,
        &fx.alice_priv,
        "2",
        &["clone", &repo_url, alice_clone.to_str().unwrap()],
    )
    .await;
    assert!(
        alice_clone.join("billing/ledger.rs").exists(),
        "owner must see billing/ledger.rs"
    );

    run_git_sync(&alice_clone, &["tag", "v1.0-light"]);
    run_git_sync(
        &alice_clone,
        &["tag", "-a", "v1.0-annot", "-m", "Public release v1.0"],
    );

    // Secret-only commit touching ONLY billing/ledger.rs.
    std::fs::write(
        alice_clone.join("billing/ledger.rs"),
        "pub const LEDGER_SECRET: &str = \"top-secret-ledger-v2\";\n",
    )
    .unwrap();
    run_git_sync(
        &alice_clone,
        &["commit", "-q", "-am", "billing: rotate ledger"],
    );
    run_git_sync(&alice_clone, &["tag", "v1.0-secret-light"]);
    run_git_sync(
        &alice_clone,
        &["tag", "-a", "v1.0-secret-annot", "-m", "Secret billing tag"],
    );

    must_git_ssh(
        &alice_clone,
        &fx.alice_priv,
        "2",
        &["push", "origin", "main", "--tags"],
    )
    .await;

    let mia_ls_tags = must_git_ssh(
        &mia_clone,
        &fx.mia_priv,
        "2",
        &["ls-remote", "--tags", "origin"],
    )
    .await;
    assert!(
        mia_ls_tags.contains("refs/tags/v1.0-light"),
        "Mia must see lightweight tag on public commit: {mia_ls_tags}"
    );
    assert!(
        mia_ls_tags.contains("refs/tags/v1.0-annot"),
        "Mia must see annotated tag on public commit: {mia_ls_tags}"
    );
    assert!(
        !mia_ls_tags.contains("v1.0-secret-light") && !mia_ls_tags.contains("v1.0-secret-annot"),
        "tags on secret-only commits must be hidden from Mia (anti-CFOR): {mia_ls_tags}"
    );

    must_git_ssh(
        &mia_clone,
        &fx.mia_priv,
        "2",
        &["fetch", "origin", "--tags"],
    )
    .await;
    let mia_tags = run_git_sync(&mia_clone, &["tag", "-l"]);
    assert!(mia_tags.lines().any(|t| t == "v1.0-light"), "{mia_tags}");
    assert!(mia_tags.lines().any(|t| t == "v1.0-annot"), "{mia_tags}");
    assert!(!mia_tags.contains("v1.0-secret"), "{mia_tags}");
    assert_eq!(
        run_git_sync(&mia_clone, &["cat-file", "-t", "v1.0-annot"]),
        "tag"
    );
    run_git_sync(&mia_clone, &["fsck", "--strict", "--full"]);
    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);

    // 5. Hidden repo anti-oracle: owner can access `hidden-vault`, Mia fails identically to a
    //    nonexistent repository without leaking existence.
    let alice_hidden = must_git_ssh(
        &fx.work_dir,
        &fx.alice_priv,
        "2",
        &["ls-remote", &hidden_url],
    )
    .await;
    assert!(
        alice_hidden.contains("refs/heads/main"),
        "owner should see hidden repo: {alice_hidden}"
    );

    let (ok_hidden, _, err_hidden) =
        try_git_ssh(&fx.work_dir, &fx.mia_priv, "2", &["ls-remote", &hidden_url]).await;
    let (ok_missing, _, err_missing) = try_git_ssh(
        &fx.work_dir,
        &fx.mia_priv,
        "2",
        &["ls-remote", &missing_url],
    )
    .await;
    assert!(!ok_hidden, "Mia must not access hidden repo");
    assert!(!ok_missing, "nonexistent repo must fail");
    assert!(
        err_hidden.contains("repository not found") && err_missing.contains("repository not found"),
        "hidden vs missing errors should both report 'repository not found': hidden={err_hidden:?}, missing={err_missing:?}"
    );

    // 6. Revoke Mia's SSH key via `DELETE /v1/auth/ssh-keys/{id}` -> immediate SSH auth failure!
    let (status, _, body) = api_call(
        &fx.router,
        Method::DELETE,
        &format!("/v1/auth/ssh-keys/{}", fx.mia_key_id),
        Some(&fx.mia_cookie),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (ok_after_revoke, _, err_after_revoke) =
        try_git_ssh(&fx.work_dir, &fx.mia_priv, "2", &["ls-remote", &repo_url]).await;
    assert!(
        !ok_after_revoke,
        "revoked SSH key must be rejected immediately, stderr={err_after_revoke}"
    );
}

#[tokio::test]
async fn git_ssh_protocol_v0_clone_fetch_and_push_without_deadlock() {
    let fx = setup_ssh_fixture(false).await;
    let _ = (
        &fx.keys_dir,
        &fx.alice_cookie,
        &fx.mia_cookie,
        &fx.mia_key_id,
    );
    let repo_url = format!("ssh://git@{}/repo.git", fx.ssh_addr);

    // 1. Real `git -c protocol.version=0 clone` over SSH as Mia.
    let mia_clone = fx.work_dir.join("mia-v0");
    must_git_ssh(
        &fx.work_dir,
        &fx.mia_priv,
        "0",
        &["clone", &repo_url, mia_clone.to_str().unwrap()],
    )
    .await;
    assert_eq!(
        std::fs::read_to_string(mia_clone.join("README.md")).unwrap(),
        "# Premier SSH v1\n"
    );
    assert!(!mia_clone.join("billing").exists());
    run_git_sync(&mia_clone, &["fsck", "--strict", "--full"]);

    // 2. Owner clones & pushes a new commit over protocol v0 so Mia's `fetch` exercises real
    //    v0/v1 `want`/`have`/`NAK`/`done` negotiation.
    let alice_clone = fx.work_dir.join("alice-v0");
    must_git_ssh(
        &fx.work_dir,
        &fx.alice_priv,
        "0",
        &["clone", &repo_url, alice_clone.to_str().unwrap()],
    )
    .await;
    std::fs::write(
        alice_clone.join("README.md"),
        "# Premier SSH v0 from Alice\n",
    )
    .unwrap();
    run_git_sync(
        &alice_clone,
        &["commit", "-q", "-am", "docs: alice v0 update"],
    );
    must_git_ssh(
        &alice_clone,
        &fx.alice_priv,
        "0",
        &["push", "origin", "main"],
    )
    .await;

    // 3. Mia fetches via `-c protocol.version=0` (zero deadlock) and fast-forwards.
    must_git_ssh(&mia_clone, &fx.mia_priv, "0", &["fetch", "origin"]).await;
    run_git_sync(&mia_clone, &["merge", "--ff-only", "origin/main"]);
    assert_eq!(
        std::fs::read_to_string(mia_clone.join("README.md")).unwrap(),
        "# Premier SSH v0 from Alice\n"
    );

    // 4. Mia commits & pushes via `-c protocol.version=0`; canonical repo keeps `billing/ledger.rs`.
    std::fs::write(mia_clone.join("README.md"), "# Premier SSH v0 from Mia\n").unwrap();
    run_git_sync(&mia_clone, &["commit", "-q", "-am", "docs: mia v0 push"]);
    must_git_ssh(&mia_clone, &fx.mia_priv, "0", &["push", "origin", "main"]).await;

    run_git_sync(&fx.main_repo, &["fsck", "--strict", "--full"]);
    assert_eq!(
        run_git_sync(&fx.main_repo, &["show", "main:README.md"]),
        "# Premier SSH v0 from Mia"
    );
    assert_eq!(
        run_git_sync(&fx.main_repo, &["show", "main:billing/ledger.rs"]),
        "pub const LEDGER_SECRET: &str = \"top-secret-ledger-v1\";"
    );
}
