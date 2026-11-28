//! Regression tests for the access-control review: one test per reported way a member (an
//! authenticated non-owner) or an anonymous caller reached something policy or branch
//! visibility withholds.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use premier_core::{Capability, DelegatedIdentity, Principal, Readiness, RepoPath, Visibility};
use premier_policy::{CompiledPolicy, parse_policy_toml};
use serde_json::{Value, json};
use tokio_stream::StreamExt;
use tower_service::Service;

use crate::tests::{MEMBER_POLICY, call, member_state, oneshot, use_member_policy};
use crate::{ServerState, build_router, runner};

fn git(root: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn set_policy(state: &ServerState, toml: &str) {
    let file = parse_policy_toml(toml).unwrap();
    *state.policy.write().unwrap() = Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
    state.set_repo_policy_metadata(Some(toml.to_owned()), Some(Arc::new(file)));
}

/// `main` (checked out): README.md, docs/guide.md, billing/ledger.rs (`// v1`), the last commit
/// touching only billing. `feature` (public): one commit over README.md and billing.
/// `sandbox/x`: the first commit, where billing/ledger.rs is `// sandbox`.
/// `refs/premier-private/hush`: one commit of its own, no declared visibility.
/// Under [`MEMBER_POLICY`] `@mia` reads everything but `billing/**`.
fn repo(root: &Path) -> (ServerState, String, String, String) {
    let (mut state, owner, mia, mia_token) = member_state(root);
    use_member_policy(&state);
    // Its own sessions, kept in this workspace (the default is the process's directory).
    state.session_manager = Arc::new(runner::SessionManager::open(root));
    std::fs::create_dir_all(root.join("billing")).unwrap();
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::write(root.join("docs/guide.md"), "guide\n").unwrap();
    std::fs::write(root.join("billing/ledger.rs"), "// sandbox\n").unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "core.autocrlf", "false"]);
    git(root, &["add", "README.md", "docs", "billing"]);
    git(root, &["commit", "-q", "-m", "initial"]);
    git(root, &["branch", "sandbox/x"]);
    std::fs::write(root.join("billing/ledger.rs"), "// v1\n").unwrap();
    git(root, &["commit", "-q", "-am", "billing only"]);
    git(root, &["checkout", "-q", "-b", "feature"]);
    std::fs::write(root.join("README.md"), "# Demo 2\n").unwrap();
    std::fs::write(root.join("billing/ledger.rs"), "// v2\n").unwrap();
    git(root, &["commit", "-q", "-am", "feature work"]);
    git(root, &["checkout", "-q", "--detach", "main"]);
    std::fs::write(root.join("README.md"), "# Hush\n").unwrap();
    git(root, &["commit", "-q", "-am", "hush work"]);
    git(root, &["update-ref", "refs/premier-private/hush", "HEAD"]);
    git(root, &["checkout", "-q", "main"]);
    (state, owner, mia, mia_token)
}

async fn get(router: &Router, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let (status, _, body) = call(router, Method::GET, uri, &[("cookie", cookie)], None).await;
    (status, body)
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

// ---- 1 -------------------------------------------------------------------------------------

#[tokio::test]
async fn xray_and_rule_traces_are_owner_only() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, mia, _) = repo(tmp.path());
    let router = build_router(state);

    let (status, body) = get(&router, "/v1/repo/tree?xray=true", &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["xray"], false);
    let entries = body["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["path"] == "README.md"));
    for entry in entries {
        assert!(
            !entry["path"].as_str().unwrap().starts_with("billing/"),
            "{entry}"
        );
        assert_eq!(entry["matched_rules"], json!([]), "{entry}");
    }
    assert!(!body.to_string().contains("mia-no-billing"), "{body}");

    // The owner's lens still shows what `@mia` is denied, and why.
    let (_, body) = get(&router, "/v1/repo/tree?xray=true&principal=@mia", &owner).await;
    assert_eq!(body["xray"], true);
    let entries = body["entries"].as_array().unwrap();
    let ledger = entries
        .iter()
        .find(|e| e["path"] == "billing/ledger.rs")
        .unwrap();
    assert_eq!(ledger["visibility_state"], "omitted");
    assert!(body.to_string().contains("mia-no-billing"), "{body}");
}

// ---- 2 -------------------------------------------------------------------------------------

#[tokio::test]
async fn branch_list_hides_undeclared_private_refs_and_unlistable_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, mia, _) = repo(tmp.path());
    let router = build_router(state);
    let branch = |body: &Value, name: &str| {
        let rows = body.as_array().unwrap();
        rows.iter().find(|b| b["name"] == name).cloned()
    };

    let (_, body) = get(&router, "/v1/branches", &mia).await;
    assert!(branch(&body, "hush").is_none(), "{body}");
    assert!(!body.to_string().contains("hush"), "{body}");
    let feature = branch(&body, "feature").unwrap();
    assert_eq!(feature["private_paths_touched"], json!(["README.md"]));

    let (_, body) = get(&router, "/v1/branches", &owner).await;
    let hush = branch(&body, "hush").unwrap();
    assert_eq!(
        hush["visibility"],
        json!({ "scope": "restricted", "allow": ["group:owners"] })
    );
    assert_eq!(
        branch(&body, "feature").unwrap()["private_paths_touched"],
        json!(["README.md", "billing/ledger.rs"])
    );
}

// ---- 3 -------------------------------------------------------------------------------------

#[tokio::test]
async fn members_cannot_rewrite_or_widen_branch_visibility() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);
    git(root, &["update-ref", "refs/premier-private/team", "main"]);
    let team = Visibility::Restricted(vec!["@mia".to_owned(), "@owner".to_owned()]);
    state.persisted.lock().unwrap().branch_metadata.extend([
        (
            "refs/premier-private/hush".to_owned(),
            (
                Visibility::Restricted(vec!["@owner".to_owned()]),
                Readiness::Wip,
            ),
        ),
        (
            "refs/premier-private/team".to_owned(),
            (team.clone(), Readiness::Wip),
        ),
    ]);
    let before = state.branch_visibility_map();
    let router = build_router(state.clone());
    let create = |body: Value| send(&router, Method::POST, "/v1/branches/create", &mia, body);
    let public = || json!({ "scope": "public" });

    // A branch named like a ref would own that ref's visibility entry.
    for name in [
        "refs/premier-private/hush",
        "refs/heads/main",
        "HEAD",
        "-x",
        "a..b",
        "a b",
    ] {
        for visibility in [public(), json!({ "scope": "restricted", "allow": [] })] {
            let (status, body) = create(json!({ "name": name, "visibility": visibility })).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        }
        let body = json!({ "name": name, "visibility": public() });
        let (status, _) = send(&router, Method::POST, "/v1/branches/create", &owner, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
    }
    assert_eq!(state.branch_visibility_map(), before);

    // Branching from a restricted branch into a public one is publishing: not a member's call.
    let (status, body) =
        create(json!({ "name": "leak", "from_ref": "team", "visibility": public() })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        git(
            root,
            &[
                "for-each-ref",
                "refs/heads/leak",
                "refs/premier-private/leak"
            ]
        )
        .is_empty()
    );
    // Nor is any other explicit choice.
    let personal =
        json!({ "name": "mine", "visibility": { "scope": "personal", "allow": "@mia" } });
    assert_eq!(create(personal).await.0, StatusCode::FORBIDDEN);

    // Not even exactly the source's visibility; without a choice the branch is hers alone, as
    // a branch she pushed would be (`new_branch_visibility`), whatever the source.
    let same = json!({ "name": "same", "from_ref": "team", "visibility": team });
    assert_eq!(create(same).await.0, StatusCode::FORBIDDEN);
    let mine = premier_git_bridge::new_branch_visibility(
        false,
        &premier_core::Principal::User("mia".to_owned()),
        std::slice::from_ref(&team),
    );
    assert_eq!(mine, Visibility::Personal("@mia".to_owned()));
    for (name, from) in [("copy", "team"), ("solo", "main")] {
        let (status, body) = create(json!({ "name": name, "from_ref": from })).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["full_ref"], format!("refs/premier-private/{name}"));
        assert_eq!(
            state.branch_visibility_map()[&format!("refs/premier-private/{name}")],
            mine
        );
    }
    // An owner's inherits its source, also like a push.
    let body = json!({ "name": "owned", "from_ref": "team" });
    let (status, body) = send(&router, Method::POST, "/v1/branches/create", &owner, body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        state.branch_visibility_map()["refs/premier-private/owned"],
        team
    );
    let (status, body) = create(json!({ "name": "open", "visibility": public() })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Everything else is as it was.
    let after = state.branch_visibility_map();
    for (full_ref, visibility) in &before {
        assert_eq!(after.get(full_ref), Some(visibility), "{full_ref}");
    }
    assert!(!after.contains_key("refs/heads/main"));
}

#[test]
fn short_branch_metadata_keys_resolve_fail_closed() {
    let restricted = (
        Visibility::Restricted(vec!["@owner".to_owned()]),
        Readiness::Wip,
    );
    let public = (Visibility::Public, Readiness::Ready);
    let org = (Visibility::Org, Readiness::Ready);
    let raw = [
        ("hush".to_owned(), restricted.clone()),
        ("open".to_owned(), public.clone()),
        ("both".to_owned(), restricted.clone()),
        ("refs/heads/both".to_owned(), org.clone()),
    ]
    .into();
    let full = crate::store::full_ref_metadata(&raw);
    assert_eq!(full["refs/premier-private/hush"], restricted);
    assert_eq!(full["refs/heads/hush"], restricted);
    assert_eq!(full["refs/heads/open"], public);
    // A public short entry never opens the private namespace, and a full key wins.
    assert!(!full.contains_key("refs/premier-private/open"));
    assert_eq!(full["refs/heads/both"], org);
    assert_eq!(full["refs/premier-private/both"], restricted);
    assert!(full.keys().all(|k| k.starts_with("refs/")));
}

// ---- 4 -------------------------------------------------------------------------------------

#[tokio::test]
async fn agent_sessions_are_refused_without_a_sandbox_and_never_inherit_the_server_env() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, owner, _, _) = repo(tmp.path());
    let spawn = |command: &str| json!({ "command": command });
    let sessions = "/v1/agents/sessions";

    let router = build_router(state.clone());
    let (_, health) = get(&router, "/health", &owner).await;
    let mode = runner::sandbox_mode(false);
    assert_eq!(health["agent_sandbox"], mode.as_str());
    if mode == runner::SandboxMode::None {
        let (status, body) = send(&router, Method::POST, sessions, &owner, spawn("echo hi")).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("--allow-unsandboxed-agents")
        );
        assert_eq!(get(&router, sessions, &owner).await.1, json!([]));
    }

    state.allow_unsandboxed_agents = true;
    let router = build_router(state.clone());
    let (_, health) = get(&router, "/health", &owner).await;
    assert_eq!(health["agent_sandbox"], runner::sandbox_mode(true).as_str());
    assert_ne!(health["agent_sandbox"], "none");
    let print_env = if cfg!(windows) {
        "Get-ChildItem Env: | ForEach-Object { $_.Name + '=' + $_.Value }"
    } else {
        "env"
    };
    let (status, body) = send(&router, Method::POST, sessions, &owner, spawn(print_env)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut output: Vec<String> = Vec::new();
    for _ in 0..300 {
        let (_, list) = get(&router, sessions, &owner).await;
        if list[0]["status"] != "running" {
            output = serde_json::from_value(list[0]["output_lines"].clone()).unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Windows folds variable names, so compare them upper-cased.
    let has = |prefix: &str| {
        output
            .iter()
            .any(|l| l.to_ascii_uppercase().starts_with(prefix))
    };
    assert!(has("PREMIER_SESSION_ID=CAGE-"), "{output:?}");
    assert!(has("HTTP_PROXY=HTTP://"), "{output:?}");
    // cargo sets these for the test binary, i.e. for "the server": none may reach the agent.
    for inherited in ["CARGO_MANIFEST_DIR", "CARGO_PKG_NAME"] {
        assert!(std::env::var_os(inherited).is_some());
        assert!(!has(inherited), "{inherited} leaked: {output:?}");
    }
    let real_home = std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap();
    for home in ["HOME", "USERPROFILE"] {
        assert!(has(&format!("{home}=")), "{output:?}");
        let real = format!("{home}={real_home}");
        assert!(
            !output.iter().any(|l| l.eq_ignore_ascii_case(&real)),
            "{output:?}"
        );
    }
}

// ---- 5 -------------------------------------------------------------------------------------

const WRITER_POLICY: &str = r#"
version = 1
[defaults]
public = []
authenticated = ["traverse", "list", "read", "write"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-no-billing"
effect = "deny"
principals = ["@mia"]
paths = ["billing/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;

#[tokio::test]
async fn filesystem_aliases_host_paths_and_symlinks_do_not_bypass_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let root = tmp.path();
    crate::tests::state_outside(root);
    let (state, owner, mia, _) = repo(root);
    set_policy(&state, WRITER_POLICY);
    let router = build_router(state);
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "host secret\n").unwrap();
    let outside_abs = secret.to_string_lossy().replace('\\', "/");

    // Spellings that are not repository paths at all.
    for path in [
        "billing./ledger.rs",
        "billing%20/ledger.rs",
        "billing/ledger.rs.",
        "billing/ledger.rs::$DATA",
        "billing%5Cledger.rs",
        "C:/Windows/win.ini",
        "/etc/passwd",
        outside_abs.as_str(),
    ] {
        for api in ["file", "blame"] {
            let (status, body) = get(&router, &format!("/v1/repo/{api}?path={path}"), &mia).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{api} {path}: {body}");
        }
        let write =
            json!({ "path": path.replace("%20", " ").replace("%5C", "\\"), "content": "pwned" });
        let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "write {path}");
    }
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "host secret\n");

    // Another casing: where the filesystem folds it onto billing/, the deny rule decides.
    let (_, body) = get(&router, "/v1/repo/file?path=BILLING/ledger.rs", &mia).await;
    assert_ne!(body["allowed"], true, "{body}");
    assert!(!body.to_string().contains("// v1"), "{body}");
    let write = json!({ "path": "BILLING/new.rs", "content": "pwned" });
    send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert!(!root.join("billing/new.rs").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("billing/ledger.rs")).unwrap(),
        "// v1\n"
    );
    // The real path still works for those allowed.
    let (_, body) = get(&router, "/v1/repo/file?path=billing/ledger.rs", &owner).await;
    assert_eq!(body["content"], "// v1\n");
    let write = json!({ "path": "docs/new.md", "content": "ok" });
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        std::fs::read_to_string(root.join("docs/new.md")).unwrap(),
        "ok"
    );

    // An overlay is a path inside the workspace too.
    let planted = outside
        .path()
        .join("planted")
        .to_string_lossy()
        .into_owned();
    for path in [planted.as_str(), "/etc/planted", "C:/planted", "../planted"] {
        let mount = json!({ "path": path, "scope": "personal", "create_file": true });
        let (status, _) = send(&router, Method::POST, "/v1/overlays/mount", &owner, mount).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(!outside.path().join("planted").exists());

    // A symlink planted in the tree (an imported or pushed repository can carry one).
    #[cfg(unix)]
    let linked = std::os::unix::fs::symlink(&secret, root.join("docs/link")).is_ok()
        && std::os::unix::fs::symlink(outside.path(), root.join("docs/dir")).is_ok();
    #[cfg(windows)]
    let linked = std::os::windows::fs::symlink_file(&secret, root.join("docs/link")).is_ok()
        && std::os::windows::fs::symlink_dir(outside.path(), root.join("docs/dir")).is_ok();
    if !linked {
        eprintln!("symlinks not permitted on this host: symlink half of the test skipped");
        return;
    }
    for path in ["docs/link", "docs/dir/secret.txt"] {
        let (status, body) = get(&router, &format!("/v1/repo/file?path={path}"), &owner).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        let write = json!({ "path": path, "content": "pwned" });
        let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &owner, write).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        let mount = json!({ "path": path, "scope": "personal", "create_file": true });
        let (status, _) = send(&router, Method::POST, "/v1/overlays/mount", &owner, mount).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    let mount = json!({ "path": "docs/dir/new.txt", "scope": "personal", "create_file": true });
    send(&router, Method::POST, "/v1/overlays/mount", &owner, mount).await;
    assert!(!outside.path().join("new.txt").exists());
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "host secret\n");
    let (_, body) = get(&router, "/v1/repo/search?q=host%20secret", &owner).await;
    assert_eq!(body["total_hits"], 0, "{body}");
    let (_, body) = get(&router, "/v1/repo/tree", &owner).await;
    assert!(
        !body.to_string().contains("docs/link") && !body.to_string().contains("docs/dir"),
        "{body}"
    );
}

// ---- 6, 8 ----------------------------------------------------------------------------------

#[tokio::test]
async fn commits_need_a_visible_branch_and_a_listable_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);
    let router = build_router(state.clone());
    let hush = git(root, &["rev-parse", "refs/premier-private/hush"]);
    let main = git(root, &["rev-parse", "main"]);

    // 6: a commit only a hidden branch has answers exactly like one that does not exist.
    for oid in [hush.as_str(), &hush[..7]] {
        let hidden = get(&router, &format!("/v1/commits/{oid}"), &mia).await;
        assert_eq!(hidden.0, StatusCode::NOT_FOUND);
        assert_eq!(
            hidden,
            get(&router, "/v1/commits/deadbeefdeadbeef", &mia).await
        );
    }
    let (status, body) = get(&router, &format!("/v1/commits/{hush}"), &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["subject"], "hush work");
    // So does one on a visible branch of which she can list no changed file; one she can
    // partly list keeps the count of the rest.
    let unlistable = get(&router, &format!("/v1/commits/{main}"), &mia).await;
    assert_eq!(
        unlistable,
        get(&router, "/v1/commits/deadbeefdeadbeef", &mia).await
    );
    let feature = crate::tests::hers(&state, "feature");
    let (status, body) = get(&router, &format!("/v1/commits/{feature}"), &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["hidden_files"], 1);
    assert!(!body.to_string().contains("ledger"), "{body}");

    // 8: a commit that only touches files she may not list is not in her history.
    let subjects = |body: &Value| -> Vec<String> {
        let rows = body.as_array().unwrap().iter();
        rows.map(|c| c["subject"].as_str().unwrap().to_owned())
            .collect()
    };
    let (_, body) = get(&router, "/v1/commits", &mia).await;
    assert_eq!(subjects(&body), ["initial"]);
    assert!(!body.to_string().contains(&main[..7]), "{body}");
    let (_, body) = get(&router, "/v1/commits", &owner).await;
    assert_eq!(subjects(&body), ["billing only", "initial"]);
    // An exact committer time next to the relative one.
    let first = &body[0];
    assert!(
        first["relative_time"]
            .as_str()
            .is_some_and(|t| !t.is_empty()),
        "{first}"
    );
    let at = first["committed_at"].as_str().unwrap();
    let at = chrono::DateTime::parse_from_rfc3339(at).unwrap();
    assert_eq!(
        at.timestamp().to_string(),
        git(root, &["log", "-1", "--format=%ct", &main])
    );
}

// ---- 7 -------------------------------------------------------------------------------------

/// Signed-in accounts read everything, but only on `sandbox/*` branches.
const SANDBOX_POLICY: &str = r#"
version = 1
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
id = "sandbox-open"
effect = "allow"
principals = ["authenticated"]
paths = ["**"]
refs = ["sandbox/*"]
capabilities = ["traverse", "list", "read", "write"]
"#;

#[tokio::test]
async fn content_comes_from_the_ref_the_decision_was_made_on() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, _, mia, _) = repo(root);
    set_policy(&state, SANDBOX_POLICY);
    let router = build_router(state);
    let file = |ref_name: &str| format!("/v1/repo/file?path=billing/ledger.rs&ref_name={ref_name}");

    // On main she reads nothing.
    let (_, body) = get(&router, &file("main"), &mia).await;
    assert_eq!(body["allowed"], false);
    // A ref she made up (or cannot see) is no ref: the rule for it unlocks nothing.
    for ref_name in [
        "sandbox/nope",
        "hush",
        "refs/premier-private/hush",
        "main..sandbox/x",
    ] {
        for uri in [
            file(ref_name),
            format!("/v1/repo/tree?ref_name={ref_name}"),
            format!("/v1/repo/blame?path=README.md&ref_name={ref_name}"),
            format!("/v1/repo/search?q=Demo&ref_name={ref_name}"),
        ] {
            let (status, body) = get(&router, &uri, &mia).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
        }
    }
    // A real one serves its own tree, not main's working tree.
    let (status, body) = get(&router, &file("sandbox/x"), &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["content"], "// sandbox\n", "{body}");
    let (_, body) = get(&router, "/v1/repo/tree?ref_name=sandbox/x", &mia).await;
    let paths: Vec<&str> = body["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "README.md",
            "billing",
            "billing/ledger.rs",
            "docs",
            "docs/guide.md"
        ]
    );
    let blame = "/v1/repo/blame?path=billing/ledger.rs&ref_name=sandbox/x";
    let (_, body) = get(&router, blame, &mia).await;
    assert_eq!(body["allowed"], true);
    assert_eq!(body["lines"][0]["summary"], "initial", "{body}");

    // Search too: the requested branch's tree, judged on that branch.
    let (status, body) = get(
        &router,
        "/v1/repo/search?q=sandbox&ref_name=sandbox/x",
        &mia,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (&body["total_hits"], &body["files_scanned"]),
        (&json!(1), &json!(3)),
        "{body}"
    );
    assert_eq!(
        body["hits"][0],
        json!({ "path": "billing/ledger.rs", "line": 1, "text": "// sandbox" })
    );
    let (_, body) = get(&router, "/v1/repo/search?q=sandbox", &mia).await;
    assert_eq!(
        (&body["total_hits"], &body["files_scanned"]),
        (&json!(0), &json!(0)),
        "{body}"
    );

    // A write is a commit on the named branch, judged there: no WRITE, no commit; and a branch
    // the caller cannot see answers like a missing one.
    let before = git(
        root,
        &["rev-parse", "refs/heads/main", "refs/premier-private/hush"],
    );
    let write = |ref_name: &str| json!({ "path": "docs/guide.md", "content": "mine", "ref_name": ref_name });
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write("main")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write("hush")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        git(
            root,
            &["rev-parse", "refs/heads/main", "refs/premier-private/hush"]
        ),
        before
    );
    // Where she may write, the commit lands on that branch and nowhere near the working tree.
    let (status, body) = send(
        &router,
        Method::PUT,
        "/v1/repo/file",
        &mia,
        write("sandbox/x"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/sandbox/x"]),
        body["commit"].as_str().unwrap()
    );
    assert_eq!(git(root, &["show", "sandbox/x:docs/guide.md"]), "mine");
    assert_eq!(
        std::fs::read_to_string(root.join("docs/guide.md")).unwrap(),
        "guide\n"
    );
}

#[tokio::test]
async fn a_branch_name_never_unlocks_files_hidden_on_its_base() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, _, mia, mia_token) = repo(&root);
    // [`SANDBOX_POLICY`], plus docs readable on every branch: on main she reads docs only.
    let policy = format!(
        "{SANDBOX_POLICY}\n[[rules]]\nid = \"docs-everywhere\"\neffect = \"allow\"\n\
         principals = [\"authenticated\"]\npaths = [\"docs/**\"]\nrefs = [\"*\"]\n\
         capabilities = [\"traverse\", \"list\", \"read\"]\n"
    );
    set_policy(&state, &policy);
    let router = build_router(state);
    let create = |name: &str, from: &str| {
        let body = json!({ "name": name, "from_ref": from });
        send(&router, Method::POST, "/v1/branches/create", &mia, body)
    };
    let ledger = "/v1/repo/file?path=billing/ledger.rs&ref_name=sandbox/leak";

    // From main, a `sandbox/*` name would serve main's billing to her: refused like any other
    // failure to create, naming nothing.
    let (status, body) = create("sandbox/leak", "main").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "branch could not be created");
    assert!(
        git(
            &root,
            &[
                "for-each-ref",
                "refs/heads/sandbox/leak",
                "refs/premier-private/sandbox/leak"
            ]
        )
        .is_empty()
    );
    assert_eq!(get(&router, ledger, &mia).await.0, StatusCode::NOT_FOUND);
    // A name under which she sees nothing new is fine, from main or from a sandbox.
    for (name, from) in [("mine", "main"), ("sandbox/y", "sandbox/x")] {
        let (status, body) = create(name, from).await;
        assert_eq!(status, StatusCode::OK, "{name}: {body}");
    }

    // Over Git, the same branch pointed at the same visible commit.
    let addr = serve(&router).await;
    let url = format!("http://mia:{mia_token}@{addr}/git/auth/repo.git");
    let work = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let (ok, _, err) = try_git(&work, &["clone", "-q", &url, "mia"]);
        assert!(ok, "{err}");
        let push = |refspec: &str| try_git(&work.join("mia"), &["push", "origin", refspec]);
        let (ok, _, err) = push("main:refs/heads/sandbox/leak");
        assert!(!ok, "{err}");
        assert!(!err.contains("billing"), "{err}");
        let (ok, _, err) = push("main:refs/heads/also-mine");
        assert!(ok, "{err}");
    })
    .await
    .unwrap();
    assert!(
        git(
            &root,
            &[
                "for-each-ref",
                "refs/heads/sandbox/leak",
                "refs/premier-private/sandbox/leak"
            ]
        )
        .is_empty()
    );
    assert_eq!(get(&router, ledger, &mia).await.0, StatusCode::NOT_FOUND);
}

// ---- 9 -------------------------------------------------------------------------------------

#[tokio::test]
async fn git_bodies_are_capped_and_a_push_is_refused_before_its_body_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _, _, mia_token) = repo(tmp.path());
    let router = build_router(state);

    let polled = Arc::new(AtomicBool::new(false));
    let chunks = || {
        let flag = Arc::clone(&polled);
        tokio_stream::iter(0..1024).map(move |_| {
            flag.store(true, Ordering::SeqCst);
            Ok::<_, std::convert::Infallible>(vec![0u8; 1024 * 1024])
        })
    };
    for creds in [None, Some("Bearer prm_not-a-token")] {
        let mut push = Request::builder()
            .method(Method::POST)
            .uri("/git/repo.git/git-receive-pack")
            .header("host", "localhost");
        if let Some(creds) = creds {
            push = push.header("authorization", creds);
        }
        let push = push.body(Body::from_stream(chunks())).unwrap();
        let resp = router.clone().call(push).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !polled.load(Ordering::SeqCst),
            "the body was read before the credentials"
        );
    }

    // An authenticated push waits for a slot before its body is read: queued pushes hold none.
    let slots = premier_git_bridge::MAX_CONCURRENT_PUSHES as u32;
    let held = crate::handlers_v1::PUSH_SLOTS
        .acquire_many(slots)
        .await
        .unwrap();
    let push = Request::builder()
        .method(Method::POST)
        .uri("/git/repo.git/git-receive-pack")
        .header("host", "localhost")
        .header("authorization", format!("Bearer {mia_token}"))
        .body(Body::from_stream(chunks().take(2)))
        .unwrap();
    let queued = tokio::spawn(router.clone().call(push));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!queued.is_finished());
    assert!(
        !polled.load(Ordering::SeqCst),
        "a queued push had its body read"
    );
    drop(held);
    let status = queued.await.unwrap().unwrap().status();
    assert!(
        polled.load(Ordering::SeqCst),
        "the admitted push never read its body"
    );
    assert!(
        ![StatusCode::SERVICE_UNAVAILABLE, StatusCode::UNAUTHORIZED].contains(&status),
        "{status}"
    );

    // A fetch request is a short list of wants: nobody gets to park hundreds of megabytes.
    for uri in [
        "/git/repo.git/git-upload-pack",
        "/git/auth/repo.git/git-upload-pack",
    ] {
        let fetch = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header("host", "localhost")
            .body(Body::from(vec![
                b'0';
                crate::ops::GIT_FETCH_BODY_LIMIT + 1024
            ]))
            .unwrap();
        let status = router.clone().call(fetch).await.unwrap().status();
        let expected = if uri.contains("/auth/") {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::PAYLOAD_TOO_LARGE
        };
        assert_eq!(status, expected, "{uri}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parallel_login_burst_cannot_outrun_the_lockout() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, ..) = repo(tmp.path());
    let router = build_router(state);
    let login = |user: &'static str, password: String| {
        let router = router.clone();
        async move {
            let body = json!({ "username": user, "password": password });
            call(&router, Method::POST, "/v1/auth/login", &[], Some(body))
                .await
                .0
        }
    };

    // Over-long passwords are refused without a hash, and without using up attempts.
    for _ in 0..8 {
        assert_eq!(
            login("mia", "x".repeat(1025)).await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login("mia", crate::tests::PW.to_owned()).await,
        StatusCode::OK
    );

    let burst: Vec<_> = (0..24)
        .map(|i| tokio::spawn(login("owner", format!("wrong password {i}"))))
        .collect();
    let mut hashed = 0;
    for attempt in burst {
        match attempt.await.unwrap() {
            StatusCode::UNAUTHORIZED => hashed += 1,
            StatusCode::TOO_MANY_REQUESTS => {}
            other => panic!("unexpected {other}"),
        }
    }
    assert_eq!(hashed, 5, "only the allowed attempts may reach argon2");
}

#[test]
fn lockout_table_is_bounded() {
    let (keys, max_keys, max_per_key) = crate::auth::test_lockout_flood(6_000);
    assert_eq!(keys, max_keys);
    assert!(max_per_key <= 20, "{max_per_key}");
}

// ---- 10 ------------------------------------------------------------------------------------

#[tokio::test]
async fn event_stream_ends_with_the_session_or_the_role() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, mia, _) = repo(tmp.path());
    let (second_owner, _) = state.auth.seed("olga", crate::tests::PW);
    let (third_owner, _) = state.auth.seed("oscar", crate::tests::PW);
    let router = build_router(state);
    let open = |cookie: &str| {
        let req = Request::builder()
            .uri("/v1/events/stream")
            .header("host", "localhost")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        let router = router.clone();
        async move { oneshot(router, req).await.into_body() }
    };
    let ended = |mut stream: hyper::body::Incoming, within: Duration| async move {
        tokio::time::timeout(within, async {
            while let Some(Ok(_)) = stream.frame().await {}
        })
        .await
        .is_ok()
    };

    // Still entitled: the stream stays open across re-checks.
    let mut steady = open(&owner).await;
    let mut signed_out = open(&mia).await;
    let mut demoted = open(&second_owner).await;
    let mut disabled = open(&third_owner).await;
    for stream in [&mut steady, &mut signed_out, &mut demoted, &mut disabled] {
        let first = stream.frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(String::from_utf8_lossy(&first).contains("ready"));
    }
    tokio::time::sleep(crate::SSE_RECHECK * 5).await;

    let origin = [("cookie", mia.as_str()), ("origin", "http://localhost")];
    let (status, _, _) = call(&router, Method::POST, "/v1/auth/logout", &origin, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        ended(signed_out, Duration::from_secs(5)).await,
        "stream survived logout"
    );

    let demote = json!({ "role": "member" });
    let (status, _) = send(&router, Method::PATCH, "/v1/users/olga", &owner, demote).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ended(demoted, Duration::from_secs(5)).await,
        "stream survived demotion"
    );

    let disable = json!({ "disabled": true });
    let (status, _) = send(&router, Method::PATCH, "/v1/users/oscar", &owner, disable).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ended(disabled, Duration::from_secs(5)).await,
        "stream survived disabling"
    );

    assert!(
        !ended(steady, crate::SSE_RECHECK * 5).await,
        "an entitled stream was closed"
    );
}

#[tokio::test]
async fn owner_access_tokens_cannot_administer_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, ..) = repo(tmp.path());
    state.allow_unsandboxed_agents = true;
    let (_, token) = state.auth.seed("olga", crate::tests::PW);
    let bearer = format!("Bearer {token}");
    let router = build_router(state.clone());
    let policy = state.current_repo_policy_toml();

    for (method, uri, body) in [
        (
            Method::POST,
            "/v1/agents/sessions",
            json!({ "command": "echo hi" }),
        ),
        (
            Method::PUT,
            "/v1/policy/repo",
            json!({ "toml": "version = 1\n" }),
        ),
        (
            Method::POST,
            "/v1/secrets/set",
            json!({ "key": "K", "value": "v" }),
        ),
        (Method::DELETE, "/v1/secrets/K", json!({})),
    ] {
        let headers = [("authorization", bearer.as_str())];
        let (status, _, body) = call(&router, method, uri, &headers, Some(body)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(
            body["error"], "this action requires a browser session",
            "{uri}"
        );
    }
    assert_eq!(state.current_repo_policy_toml(), policy);
    assert!(state.session_manager.list().is_empty());
    // The token still reads.
    let headers = [("authorization", bearer.as_str())];
    let (status, _, _) = call(&router, Method::GET, "/v1/branches", &headers, None).await;
    assert_eq!(status, StatusCode::OK);
}

// ---- hidden counts and commit ids ----------------------------------------------------------

/// [`MEMBER_POLICY`] plus `@zed`, who may see nothing, and `@pia`, who may see nothing on `main`.
const COUNTS_POLICY: &str = r#"
[[rules]]
id = "zed-nothing"
effect = "deny"
principals = ["@zed"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "pia-not-main"
effect = "deny"
principals = ["@pia"]
paths = ["**"]
refs = ["main"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;

/// A member learns counts only of what she can list (`hidden_files` of a commit she sees part of
/// is the one exception) and commit ids only of her own clone, live events included.
#[tokio::test]
async fn members_learn_no_hidden_counts_and_only_their_own_commit_ids() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, mia, mia_token) = repo(root);
    set_policy(&state, &format!("{MEMBER_POLICY}{COUNTS_POLICY}"));
    let (zed, _) = state
        .auth
        .seed_as("zed", crate::tests::PW, crate::auth::Role::Member);
    let (pia, _) = state
        .auth
        .seed_as("pia", crate::tests::PW, crate::auth::Role::Member);
    let (main, feature) = (
        git(root, &["rev-parse", "main"]),
        git(root, &["rev-parse", "feature"]),
    );
    // A finished session of mia's on `main`, and a review of `feature` whose first round is the
    // billing-only commit.
    let session = runner::AgentSessionRecord {
        id: "cage-0001".to_owned(),
        principal: "@mia".to_owned(),
        status: "completed".to_owned(),
        branch: "main".to_owned(),
        base_commit: Some(main.clone()),
        commit: Some(main.clone()),
        ..Default::default()
    };
    crate::store::save_json(root, "sessions.json", &[session]).unwrap();
    state.session_manager = Arc::new(runner::SessionManager::open(root));
    state
        .persisted
        .lock()
        .unwrap()
        .reviews
        .push(crate::store::StoredReview {
            change_id: "I1".to_owned(),
            title: "feature".to_owned(),
            branch: "feature".to_owned(),
            base_ref: "main".to_owned(),
            author: "@owner".to_owned(),
            delegated_agent: None,
            visibility: Visibility::Public,
            readiness: Readiness::Ready,
            round_oids: vec![main.clone(), feature.clone()],
            comments: vec![],
            verdicts: Default::default(),
            provenance: None,
            created_at: String::new(),
            lane_id: None,
            rounds_meta: Vec::new(),
            github_pr_url: None,
            github_pr_number: None,
        });
    let router =
        crate::repos::Registry::open(state.clone(), Some("home".to_owned()), None).router();

    // Mia's clone, as Git serves it.
    let addr = serve(&build_router(state.clone())).await;
    let url = format!("http://mia:{mia_token}@{addr}/git/auth/repo.git");
    let work = root.to_path_buf();
    let refs = tokio::task::spawn_blocking(move || try_git(&work, &["ls-remote", &url]))
        .await
        .unwrap();
    assert!(refs.0, "{}", refs.2);
    let tip = |branch: &str| {
        let suffix = format!("\trefs/heads/{branch}");
        refs.1.lines().find(|l| l.ends_with(&suffix)).unwrap()[..40].to_owned()
    };
    let (her_main, her_feature) = (tip("main"), tip("feature"));
    assert_ne!(her_main, main);

    // Nothing at all for zed: no branch, entry, commit, review, preview, repository or session.
    let (_, body) = get(&router, "/v1/branches", &zed).await;
    assert_eq!(body, json!([]));
    let (status, body) = get(&router, "/v1/repo/tree", &zed).await;
    assert!(
        status == StatusCode::NOT_FOUND || body["entries"] == json!([]),
        "{body}"
    );
    assert_eq!(body["omitted_count"].as_u64().unwrap_or(0), 0, "{body}");
    let (_, body) = get(&router, "/v1/commits", &zed).await;
    assert_eq!(body, json!([]));
    let (status, _) = get(&router, &format!("/v1/commits/{main}"), &zed).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for uri in ["/v1/reviews", "/v1/repos", "/v1/agents/sessions"] {
        let (_, body) = get(&router, uri, &zed).await;
        assert_eq!(body, json!([]), "{uri}");
    }
    let preview = json!({ "branch": "feature" });
    let squash = "/v1/branches/squash-preview";
    let (status, _) = send(&router, Method::POST, squash, &zed, preview.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Mia sees all but billing: counts of what she lists, ids of her clone.
    let (_, body) = get(&router, "/v1/branches", &mia).await;
    let branch = |name: &str| {
        body.as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == name)
            .unwrap()
            .clone()
    };
    assert_eq!(branch("main")["head_oid"], her_main[..7]);
    assert_eq!(branch("feature")["head_oid"], her_feature[..7]);
    assert_eq!(branch("feature")["ahead_commits"], 1);
    assert_eq!(
        branch("feature")["private_paths_touched"],
        json!(["README.md"])
    );
    let (_, body) = get(&router, "/v1/repo/tree", &mia).await;
    assert_eq!(body["omitted_count"], 0);
    let (_, body) = get(&router, "/v1/commits", &mia).await;
    assert_eq!(
        (&body[0]["oid"], &body[0]["files_changed"]),
        (&json!(her_main), &json!(2)),
        "{body}"
    );
    let (_, body) = get(&router, &format!("/v1/commits/{her_main}"), &mia).await;
    assert_eq!(body["hidden_files"], 1, "{body}");
    let (_, body) = get(&router, "/v1/reviews", &mia).await;
    let rounds = &body[0]["rounds"];
    assert_eq!(rounds.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(
        (&rounds[0]["round"], &rounds[0]["commit_oid"]),
        (&json!(1), &json!(her_feature[..7]))
    );
    assert_eq!(rounds[0]["hunks"][0]["id"], "r1-h0");
    assert_eq!(body[0]["quarantine_flagged"], false);
    let (_, body) = send(&router, Method::POST, squash, &mia, preview).await;
    assert_eq!(
        (&body["hidden_conflicts"], &body["hidden_blocked"]),
        (&json!(0), &json!(0)),
        "{body}"
    );
    assert_eq!(body["declassification_gate_passed"], false);
    let (_, body) = get(&router, "/v1/repos", &mia).await;
    assert_eq!(body[0]["head_oid"], her_main, "{body}");
    let (_, body) = get(&router, "/v1/repos", &owner).await;
    assert_eq!(body[0]["head_oid"], main);
    let (_, body) = get(&router, "/v1/agents/sessions", &mia).await;
    assert_eq!(
        (&body[0]["base_commit"], &body[0]["commit"]),
        (&json!(her_main), &json!(her_main))
    );

    // Live: her session's event carries no canonical id.
    let req = Request::builder()
        .uri("/v1/events/stream")
        .header("host", "localhost")
        .header("cookie", &mia)
        .body(Body::empty())
        .unwrap();
    let mut stream = oneshot(router.clone(), req).await.into_body();
    let discard = "/v1/agents/sessions/cage-0001";
    let (status, _) = send(&router, Method::DELETE, discard, &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let mut seen = String::new();
    while !seen.contains("event: session") {
        let frame = tokio::time::timeout(Duration::from_secs(10), stream.frame()).await;
        seen.push_str(&String::from_utf8_lossy(
            &frame.unwrap().unwrap().unwrap().into_data().unwrap(),
        ));
    }
    assert!(
        !seen.contains(&main) && seen.contains("\"base_commit\":null"),
        "{seen}"
    );

    // Pia cannot see `main`: nothing is measured against it, and its name is not hers either.
    let (_, body) = get(&router, "/v1/branches", &pia).await;
    let names: Vec<&str> = body
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap())
        .collect();
    assert!(
        !names.contains(&"main") && names.contains(&"feature"),
        "{body}"
    );
    let feature = body
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "feature")
        .unwrap();
    assert_eq!(
        (&feature["ahead_commits"], &feature["private_paths_touched"]),
        (&json!(0), &json!([]))
    );
    let (_, body) = get(&router, "/v1/repos", &pia).await;
    assert_eq!(
        (&body[0]["head_oid"], &body[0]["default_branch"]),
        (&Value::Null, &Value::Null),
        "{body}"
    );
}

/// The label says public only while an anonymous clone is served a file of the branch: `list`
/// without `read` gives a clone nothing.
#[tokio::test]
async fn a_branch_is_public_only_if_an_anonymous_clone_gets_a_file_of_it() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, ..) = repo(tmp.path());
    let router = build_router(state.clone());
    let cases = [
        (r#"["traverse", "list"]"#, "restricted"),
        (r#"["traverse", "list", "read"]"#, "public"),
    ];
    for (public, scope) in cases {
        set_policy(
            &state,
            &format!("version = 1\n[defaults]\npublic = {public}\nauthenticated = []\n"),
        );
        let (_, body) = get(&router, "/v1/branches", &owner).await;
        let main = body
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == "main")
            .unwrap();
        assert_eq!(main["visibility"]["scope"], scope, "{public}: {body}");
    }
}

// ---- 11 ------------------------------------------------------------------------------------

#[tokio::test]
async fn policy_summary_says_when_an_imported_policy_is_not_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, mia, _) = repo(tmp.path());
    let router = build_router(state);
    let pending = |cookie: String| {
        let router = router.clone();
        async move {
            get(&router, "/v1/policy/summary", &cookie).await.1["imported_policy_pending"].clone()
        }
    };
    assert_eq!(pending(owner.clone()).await, false);
    std::fs::write(
        tmp.path()
            .join(".premier")
            .join(crate::repos::PENDING_POLICY),
        "",
    )
    .unwrap();
    assert_eq!(pending(owner.clone()).await, true);
    assert_eq!(pending(mia).await, false);

    // Saving the policy is the owner accepting it.
    let save = json!({ "toml": MEMBER_POLICY });
    let headers = [("cookie", owner.as_str()), ("origin", "http://localhost")];
    let (status, _, _) = call(
        &router,
        Method::PUT,
        "/v1/policy/repo",
        &headers,
        Some(save),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pending(owner).await, false);
}

// ---- seams between the fixes above ---------------------------------------------------------

/// Serve `router` on a loopback port for a real `git` client.
async fn serve(router: &Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = router.clone();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}

/// `git` that may fail: `(succeeded, stdout, stderr)`.
fn try_git(dir: &Path, args: &[&str]) -> (bool, String, String) {
    let out = std::process::Command::new("git")
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).trim().to_owned();
    (out.status.success(), text(&out.stdout), text(&out.stderr))
}

#[tokio::test]
async fn an_undeclared_private_ref_is_the_owners_in_the_api_and_over_git() {
    assert_eq!(
        premier_git_bridge::OWNERS_SELECTOR,
        format!("group:{}", crate::directory::OWNERS_GROUP)
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, owner, mia, mia_token) = repo(&root);
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    let router = build_router(state);
    let addr = serve(&router).await;
    let names = |body: &Value| -> Vec<String> {
        let rows = body.as_array().unwrap().iter();
        rows.map(|b| b["name"].as_str().unwrap().to_owned())
            .collect()
    };

    // The API: listed for an owner; for a member it is no branch at all.
    let (_, body) = get(&router, "/v1/branches", &owner).await;
    assert!(names(&body).contains(&"hush".to_owned()), "{body}");
    let (_, body) = get(&router, "/v1/branches", &mia).await;
    assert!(!body.to_string().contains("hush"), "{body}");
    let hidden = get(&router, "/v1/commits?ref=hush", &mia).await;
    assert_eq!(hidden.0, StatusCode::NOT_FOUND);
    assert_eq!(hidden, get(&router, "/v1/commits?ref=nope", &mia).await);

    // Git: the owner fetches it; the member's answers are those for a branch that does not exist.
    let owner_url = format!("http://root:{root_token}@{addr}/git/auth/repo.git");
    let mia_url = format!("http://mia:{mia_token}@{addr}/git/auth/repo.git");
    let work = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let (ok, refs, err) = try_git(&work, &["ls-remote", &owner_url]);
        assert!(ok && refs.contains("refs/heads/hush"), "{refs} {err}");
        let (ok, _, err) = try_git(&work, &["clone", "-q", "-b", "hush", &owner_url, "owner"]);
        assert!(ok, "{err}");
        let readme = std::fs::read_to_string(work.join("owner/README.md")).unwrap();
        assert_eq!(readme.trim_end(), "# Hush");

        let (ok, refs, err) = try_git(&work, &["ls-remote", &mia_url]);
        assert!(
            ok && refs.contains("refs/heads/main") && !refs.contains("hush"),
            "{refs} {err}"
        );
        let (ok, _, err) = try_git(&work, &["clone", "-q", &mia_url, "mia"]);
        assert!(ok, "{err}");
        let fetch = |name: &str| {
            let (ok, out, err) = try_git(
                &work.join("mia"),
                &["fetch", "origin", &format!("refs/heads/{name}")],
            );
            (ok, out.replace(name, "X"), err.replace(name, "X"))
        };
        let hidden = fetch("hush");
        assert!(!hidden.0, "{hidden:?}");
        assert_eq!(hidden, fetch("nope"));
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_projected_commit_has_an_attestation_in_its_own_view_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, _, mia, mia_token) = repo(&root);
    let (root_cookie, root_token) = state.auth.seed("root", crate::tests::PW);
    let router = build_router(state);
    let addr = serve(&router).await;
    let work = tmp.path().to_path_buf();
    let (owner_main, mia_main) = tokio::task::spawn_blocking(move || {
        let tip = |user: &str, token: &str| {
            let url = format!("http://{user}:{token}@{addr}/git/auth/repo.git");
            let (ok, refs, err) = try_git(&work, &["ls-remote", &url, "refs/heads/main"]);
            assert!(ok, "{err}");
            refs.split_whitespace().next().unwrap().to_owned()
        };
        (tip("root", &root_token), tip("mia", &mia_token))
    })
    .await
    .unwrap();
    // Mia's `main` has no billing/, so her commits are not the owner's.
    assert_ne!(owner_main, mia_main);

    for (oid, cookie) in [(&owner_main, &root_cookie), (&mia_main, &mia)] {
        let (status, body) = get(&router, &format!("/v1/attestations/{oid}"), cookie).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let mut keys: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "canonical_commit_commitment",
                "issued_at",
                "original_signature_verified",
                "policy_fingerprint",
                "version"
            ]
        );
        assert_eq!(body["original_signature_verified"], false);
    }
    // A commit of somebody else's view answers exactly like one that never existed.
    let foreign = get(&router, &format!("/v1/attestations/{owner_main}"), &mia).await;
    assert_eq!(foreign.0, StatusCode::NOT_FOUND);
    let unknown = "/v1/attestations/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    assert_eq!(foreign, get(&router, unknown, &mia).await);
}

#[tokio::test]
async fn commit_pages_are_full_and_offset_in_visible_commits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);
    for i in 0..5 {
        std::fs::write(root.join("billing/ledger.rs"), format!("// b{i}\n")).unwrap();
        git(root, &["commit", "-q", "-am", &format!("b{i}")]);
        std::fs::write(root.join("docs/guide.md"), format!("d{i}\n")).unwrap();
        git(root, &["commit", "-q", "-am", &format!("d{i}")]);
    }
    let router = build_router(state);
    let subjects = |body: &Value| -> Vec<String> {
        let rows = body.as_array().unwrap().iter();
        rows.map(|c| c["subject"].as_str().unwrap().to_owned())
            .collect()
    };

    // Every other commit is hidden from her: pages are still full, and do not overlap.
    let (_, body) = get(&router, "/v1/commits?limit=2", &mia).await;
    assert_eq!(subjects(&body), ["d4", "d3"]);
    assert_eq!(body[0]["files_changed"], 1);
    let (_, body) = get(&router, "/v1/commits?limit=2&skip=2", &mia).await;
    assert_eq!(subjects(&body), ["d2", "d1"]);
    let (_, body) = get(&router, "/v1/commits?limit=4&skip=4", &mia).await;
    assert_eq!(subjects(&body), ["d0", "initial"]);
    let (_, body) = get(&router, "/v1/commits?limit=0", &mia).await;
    assert_eq!(body, json!([]));
    let (_, body) = get(&router, "/v1/commits?limit=200", &mia).await;
    assert_eq!(subjects(&body), ["d4", "d3", "d2", "d1", "d0", "initial"]);
    let (_, body) = get(&router, "/v1/commits?limit=3&skip=1", &owner).await;
    assert_eq!(subjects(&body), ["b4", "d3", "b3"]);
}

#[tokio::test]
async fn search_takes_its_query_literally() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);
    std::fs::write(root.join("docs/draft.md"), "uncommitted\n").unwrap();
    let router = build_router(state);
    let hits = |body: &Value| -> Vec<String> {
        let rows = body["hits"].as_array().unwrap().iter();
        rows.map(|h| format!("{}:{}", h["path"].as_str().unwrap(), h["line"]))
            .collect()
    };

    // Every branch, the checked-out one included, is searched in its committed tree (never a
    // stray working-tree file), case-insensitively and in readable files only.
    let (_, body) = get(&router, "/v1/repo/search?q=UNCOMMITTED", &mia).await;
    assert_eq!(hits(&body), Vec::<String>::new(), "{body}");
    let (_, body) = get(&router, "/v1/repo/search?q=GUIDE", &mia).await;
    assert_eq!(hits(&body), ["docs/guide.md:1"], "{body}");
    let (_, body) = get(
        &router,
        "/v1/repo/search?q=uncommitted&ref_name=feature",
        &mia,
    )
    .await;
    assert_eq!(
        (&body["total_hits"], &body["files_scanned"]),
        (&json!(0), &json!(2)),
        "{body}"
    );
    let (_, body) = get(&router, "/v1/repo/search?q=GUIDE&ref_name=feature", &mia).await;
    assert_eq!(hits(&body), ["docs/guide.md:1"], "{body}");
    assert_eq!(body["hits"][0]["text"], "guide");
    for (who, expected) in [
        (&mia, vec![]),
        (&owner, vec!["billing/ledger.rs:1".to_owned()]),
    ] {
        let (_, body) = get(&router, "/v1/repo/search?q=V2&ref_name=feature", who).await;
        assert_eq!(hits(&body), expected, "{body}");
        let (_, body) = get(&router, "/v1/repo/search?q=v1", who).await;
        assert_eq!(hits(&body), expected, "{body}");
    }

    // Never a regex, an option, a revision or a pathspec.
    for q in [
        "g.ide",
        "--cached",
        "-v",
        "--no-index",
        "-e",
        "--",
        "HEAD",
        "-O%20calc",
    ] {
        let uri = format!("/v1/repo/search?q={q}&ref_name=feature");
        let (status, body) = get(&router, &uri, &owner).await;
        assert_eq!(
            (status, &body["total_hits"]),
            (StatusCode::OK, &json!(0)),
            "{q}: {body}"
        );
    }
    let (status, _) = get(
        &router,
        "/v1/repo/search?q=a%0A%0Ab&ref_name=feature",
        &owner,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- the canonical history is the single source of truth -----------------------------------

/// [`WRITER_POLICY`] without the rule that keeps `@mia` out of `billing/`.
fn open_policy() -> &'static str {
    WRITER_POLICY.split_once("[[rules]]\nid = \"mia").unwrap().0
}

fn lockout_policy() -> String {
    format!(
        "{}[[rules]]\nid = \"nobody\"\neffect = \"deny\"\nprincipals = [\"*\"]\npaths = [\"**\"]\n\
         refs = [\"*\"]\ncapabilities = [\"traverse\", \"list\", \"read\", \"write\", \"use\"]\n",
        open_policy()
    )
}

#[tokio::test]
async fn a_studio_write_is_a_commit_by_the_user_on_any_visible_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, _, mia, mia_token) = repo(&root);
    set_policy(&state, WRITER_POLICY);
    let router = build_router(state.clone());
    let addr = serve(&router).await;
    let tip = || git(&root, &["rev-parse", "refs/heads/feature"]);
    let stale = tip();
    // The same commits as her clone has them: what she is told and what she sends.
    let her_tip = || crate::tests::hers(&state, "refs/heads/feature");
    let her_stale = her_tip();

    // `feature` is not checked out: the commit is made on it all the same, as the caller.
    let write = json!({
        "path": "docs/new/deep.md", "content": "hi\n", "ref_name": "feature", "message": "Add deep"
    });
    let (status, body) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["commit"], her_tip().as_str());
    assert_eq!(
        git(
            &root,
            &["log", "-1", "--format=%an|%ae|%cn|%ce|%s|%P", "feature"]
        ),
        format!("mia|mia@users.noreply.premier|mia|mia@users.noreply.premier|Add deep|{stale}")
    );
    let write = json!({ "path": "docs/new/deep.md", "content": "hi 2\n", "ref_name": "feature" });
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        git(&root, &["log", "-1", "--format=%s", "feature"]),
        "Update docs/new/deep.md"
    );
    // What she cannot see is carried over untouched, and the working tree (on main) is not hers.
    assert_eq!(git(&root, &["show", "feature:billing/ledger.rs"]), "// v2");
    assert!(!root.join("docs/new").exists());

    // No WRITE, no commit; and a branch that moved under the edit is a conflict.
    let moved = tip();
    let write = json!({ "path": "billing/x.rs", "content": "pwned", "ref_name": "feature" });
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let delete = json!({ "path": "billing/ledger.rs", "ref_name": "feature" });
    let (status, _) = send(&router, Method::DELETE, "/v1/repo/file", &mia, delete).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let write = json!({
        "path": "docs/guide.md", "content": "late", "ref_name": "feature", "expected_tip": her_stale
    });
    let (status, body) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(tip(), moved);

    // A real clone by that user has the commit.
    let url = format!("http://mia:{mia_token}@{addr}/git/auth/repo.git");
    let work = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let (ok, _, err) = try_git(&work, &["clone", "-q", "-b", "feature", &url, "mia"]);
        assert!(ok, "{err}");
        let clone = work.join("mia");
        assert_eq!(
            std::fs::read_to_string(clone.join("docs/new/deep.md"))
                .unwrap()
                .trim_end(),
            "hi 2"
        );
        assert_eq!(
            git(&clone, &["log", "-2", "--format=%an %s"]),
            "mia Update docs/new/deep.md\nmia Add deep"
        );
        assert!(!clone.join("billing").exists());
    })
    .await
    .unwrap();

    // Deleting is a commit too.
    let delete = json!({ "path": "docs/new/deep.md", "ref_name": "feature" });
    let (status, body) = send(
        &router,
        Method::DELETE,
        "/v1/repo/file",
        &mia,
        delete.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        git(&root, &["log", "-1", "--format=%an %s", "feature"]),
        "mia Delete docs/new/deep.md"
    );
    assert_eq!(
        git(
            &root,
            &["ls-tree", "-r", "--name-only", "feature", "--", "docs"]
        ),
        "docs/guide.md"
    );
    let (status, _) = send(&router, Method::DELETE, "/v1/repo/file", &mia, delete).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_working_tree_follows_its_branch_only_while_clean_and_is_never_read() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // The tree only ever follows when the server's state is not in it.
    crate::tests::state_outside(root);
    let (state, owner, mia, _) = repo(root);
    set_policy(&state, WRITER_POLICY);
    let router = build_router(state);
    let readme = || std::fs::read_to_string(root.join("README.md")).unwrap();
    let save = |content: &str| json!({ "path": "README.md", "content": content });

    // Clean: a commit to the checked-out branch is checked out.
    let (status, body) = send(&router, Method::PUT, "/v1/repo/file", &mia, save("# New\n")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(readme(), "# New\n");
    assert_eq!(
        git(root, &["status", "--porcelain", "--untracked-files=no"]),
        ""
    );

    // Dirty (an agent session's work, or a developer's): left exactly as it is.
    std::fs::write(root.join("docs/guide.md"), "local edit\n").unwrap();
    std::fs::write(root.join("stray.txt"), "local edit\n").unwrap();
    let (status, _) = send(
        &router,
        Method::PUT,
        "/v1/repo/file",
        &mia,
        save("# Newer\n"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(git(root, &["show", "main:README.md"]), "# Newer");
    assert_eq!(readme(), "# New\n");
    assert_eq!(
        std::fs::read_to_string(root.join("docs/guide.md")).unwrap(),
        "local edit\n"
    );

    // File, tree and search on the checked-out branch are its committed tree.
    let (_, body) = get(&router, "/v1/repo/file?path=README.md", &mia).await;
    assert_eq!(body["content"], "# Newer\n");
    let (_, body) = get(&router, "/v1/repo/file?path=docs/guide.md", &mia).await;
    assert_eq!(body["content"], "guide\n");
    let (status, _) = get(&router, "/v1/repo/file?path=stray.txt", &mia).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, body) = get(&router, "/v1/repo/tree", &owner).await;
    assert!(!body.to_string().contains("stray.txt"), "{body}");
    let (_, body) = get(&router, "/v1/repo/search?q=local%20edit", &owner).await;
    assert_eq!(body["total_hits"], 0, "{body}");
    let (_, body) = get(&router, "/v1/repo/search?q=Newer", &owner).await;
    assert_eq!(body["total_hits"], 1, "{body}");
}

/// Clone `main` as `user`, commit `text` as `.access.toml` and push it: accepted?, git's stderr.
async fn push_policy(
    work: &Path,
    addr: std::net::SocketAddr,
    user: &str,
    token: &str,
    text: &str,
) -> (bool, String) {
    let url = format!("http://{user}:{token}@{addr}/git/auth/repo.git");
    let (work, text) = (work.to_path_buf(), text.to_owned());
    tokio::task::spawn_blocking(move || {
        let dir = tempfile::tempdir_in(&work).unwrap();
        let (ok, _, err) = try_git(dir.path(), &["clone", "-q", &url, "c"]);
        assert!(ok, "{err}");
        let clone = dir.path().join("c");
        std::fs::write(clone.join(".access.toml"), text).unwrap();
        git(&clone, &["add", ".access.toml"]);
        git(&clone, &["commit", "-q", "-m", "policy"]);
        let (ok, _, err) = try_git(&clone, &["push", "origin", "HEAD:main"]);
        (ok, err)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn a_pushed_policy_is_live_at_once_and_only_a_sound_one_from_an_owner_is_taken() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, owner, mia, mia_token) = repo(&root);
    set_policy(&state, WRITER_POLICY);
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    let router = build_router(state.clone());
    let addr = serve(&router).await;
    let work = tmp.path();
    let ledger = "/v1/repo/file?path=billing/ledger.rs";
    assert_ne!(get(&router, ledger, &mia).await.1["allowed"], true);

    // The owner pushes a policy that lets her in: no restart, no working-tree file involved.
    let (ok, err) = push_policy(work, addr, "root", &root_token, open_policy()).await;
    assert!(ok, "{err}");
    assert_eq!(state.current_repo_policy_toml(), open_policy());
    let (_, body) = get(&router, ledger, &mia).await;
    assert_eq!(body["content"], "// v1\n", "{body}");
    let tip = git(&root, &["rev-parse", "main"]);

    // She may write every path now, the policy included as far as path rules go: it is still
    // not hers to change, by push or from the Studio, and the refusal says nothing more.
    let hers = format!("{}# mine\n", open_policy());
    let (ok, err) = push_policy(work, addr, "mia", &mia_token, &hers).await;
    assert!(!ok && err.contains(premier_git_bridge::REJECT_REF), "{err}");
    let write = json!({ "path": ".access.toml", "content": hers });
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let delete = json!({ "path": ".access.toml" });
    let (status, _) = send(&router, Method::DELETE, "/v1/repo/file", &mia, delete).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An owner's push must compile, and must not lock the owners out; neither may "Apply".
    let (ok, err) = push_policy(
        work,
        addr,
        "root",
        &root_token,
        "version = 1\n[[rules]]\nid = 7\n",
    )
    .await;
    assert!(!ok && err.contains(".access.toml:"), "{err}");
    let (ok, err) = push_policy(work, addr, "root", &root_token, &lockout_policy()).await;
    assert!(!ok && err.contains("lock the owners out"), "{err}");
    let apply = json!({ "toml": lockout_policy() });
    let (status, body) = send(&router, Method::PUT, "/v1/policy/repo", &owner, apply).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("lock the owners out"),
        "{body}"
    );
    let write = json!({ "path": ".access.toml", "content": lockout_policy() });
    let (status, _) = send(&router, Method::PUT, "/v1/repo/file", &owner, write).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert_eq!(git(&root, &["rev-parse", "main"]), tip);
    assert_eq!(state.current_repo_policy_toml(), open_policy());
}

#[tokio::test]
async fn an_applied_policy_is_a_commit_and_survives_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = repo(root);
    let router = build_router(state.clone());

    let apply = json!({ "toml": WRITER_POLICY });
    let (status, body) = send(&router, Method::PUT, "/v1/policy/repo", &owner, apply).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["commit"], git(root, &["rev-parse", "main"]).as_str());
    assert_eq!(
        git(root, &["log", "-1", "--format=%an|%ae|%s", "main"]),
        "owner|owner@users.noreply.premier|Update access policy"
    );
    assert_eq!(state.current_repo_policy_toml(), WRITER_POLICY);

    // A restart rebuilds the state from the repository alone: no working-tree file is read.
    let _ = std::fs::remove_file(root.join(".access.toml"));
    let mut restarted = state.clone();
    restarted.policy = Arc::default();
    restarted.repo_policy_toml = Arc::default();
    restarted.repo_policy_file = Arc::default();
    restarted.reload_repo_config().unwrap();
    assert_eq!(restarted.current_repo_policy_toml(), WRITER_POLICY);
    let mia = DelegatedIdentity::human_only(Principal::parse("@mia").unwrap(), vec![]);
    let can_write = |path: &str| {
        let policy = restarted.current_policy().unwrap();
        policy
            .explain(&mia, &RepoPath::new(path).unwrap(), "main")
            .allows(Capability::WRITE)
    };
    assert!(can_write("docs/guide.md") && !can_write("billing/ledger.rs"));
}

#[tokio::test]
async fn owners_see_every_branch_in_the_api_and_over_git_and_members_get_no_omitted_count() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, owner, mia, mia_token) = repo(&root);
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    let (_, zoe_token) = state
        .auth
        .seed_as("zoe", crate::tests::PW, crate::auth::Role::Member);
    // A branch `@mia` declared personal.
    git(
        &root,
        &[
            "update-ref",
            "refs/premier-private/mine",
            "refs/heads/feature",
        ],
    );
    state.persisted.lock().unwrap().branch_metadata.insert(
        "refs/premier-private/mine".to_owned(),
        (Visibility::Personal("@mia".to_owned()), Readiness::Wip),
    );
    let router = build_router(state);
    let addr = serve(&router).await;

    let (_, body) = get(&router, "/v1/branches", &owner).await;
    assert!(
        body.as_array().unwrap().iter().any(|b| b["name"] == "mine"),
        "{body}"
    );
    let work = tmp.path().to_path_buf();
    tokio::task::spawn_blocking(move || {
        let refs = |user: &str, token: &str| {
            let url = format!("http://{user}:{token}@{addr}/git/auth/repo.git");
            let (ok, refs, err) = try_git(&work, &["ls-remote", &url]);
            assert!(ok, "{err}");
            refs
        };
        // What the owner is shown, the owner can fetch; another member still cannot.
        assert!(refs("root", &root_token).contains("refs/heads/mine"));
        assert!(refs("mia", &mia_token).contains("refs/heads/mine"));
        assert!(!refs("zoe", &zoe_token).contains("mine"));
    })
    .await
    .unwrap();

    // How much a member cannot see is not theirs to count.
    let (_, body) = get(&router, "/v1/repo/tree", &mia).await;
    assert_eq!(body["omitted_count"], 0, "{body}");
    let (_, body) = get(&router, "/v1/repo/tree?principal=@mia", &owner).await;
    assert_eq!(body["omitted_count"], 1, "{body}");
}

#[test]
fn a_session_time_limit_is_clamped_to_the_server_maximum() {
    let secs = |asked| runner::session_limit(asked).as_secs();
    assert_eq!(secs(None), 30 * 60);
    assert_eq!(secs(Some(90)), 90);
    assert_eq!(secs(Some(0)), 1);
    assert_eq!(secs(Some(u64::MAX)), 4 * 60 * 60);
}

// ---- a member the policy grants nothing (the starter policy is owners-only) -----------------

/// [`repo`] under the starter policy: `@mia` has no capability on any path.
fn no_access_repo(root: &Path) -> (ServerState, String, String) {
    let (state, owner, mia, _) = repo(root);
    set_policy(&state, crate::directory::DEFAULT_POLICY_TOML);
    (state, owner, mia)
}

#[tokio::test]
async fn member_branches_need_access_to_the_source_and_are_always_personal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia) = no_access_repo(root);
    let router = build_router(state.clone());
    let create = |who: &str, body: Value| {
        let (router, who) = (router.clone(), who.to_owned());
        async move { send(&router, Method::POST, "/v1/branches/create", &who, body).await }
    };
    let refs = || git(root, &["for-each-ref", "--format=%(refname)"]);
    let before = refs();

    // No access to the source: exactly a missing source. A visibility is never a member's to pass.
    let public = json!({ "name": "dana-x", "visibility": { "scope": "public" } });
    let (status, body) = create(&mia, public).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let no_access = create(&mia, json!({ "name": "dana-x" })).await;
    assert_eq!(no_access.0, StatusCode::NOT_FOUND, "{}", no_access.1);
    assert_eq!(
        no_access,
        create(&mia, json!({ "name": "dana-x", "from_ref": "nope" })).await
    );
    assert_eq!(refs(), before);

    // With access: still no visibility of her choosing, and the branch is hers alone.
    crate::tests::use_member_policy(&state);
    let mine = json!({ "scope": "personal", "allow": "@mia" });
    for asked in [json!({ "scope": "public" }), mine.clone()] {
        let (status, body) = create(&mia, json!({ "name": "p", "visibility": asked })).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
    let (status, body) = create(&mia, json!({ "name": "p" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["full_ref"], "refs/premier-private/p");
    // `allow` is a list for every scope; the bare string earlier versions wrote still reads.
    let listed = json!({ "scope": "personal", "allow": ["@mia"] });
    assert_eq!(body["visibility"], listed);
    let personal = Visibility::Personal("@mia".to_owned());
    assert_eq!(serde_json::to_value(&personal).unwrap(), listed);
    for wire in [mine.clone(), listed] {
        assert_eq!(
            serde_json::from_value::<Visibility>(wire).unwrap(),
            personal
        );
    }
    let two = json!({ "scope": "personal", "allow": ["@mia", "@dana"] });
    assert!(serde_json::from_value::<Visibility>(two).is_err());

    // A member holds a bounded number of personal branches; an owner is not counted.
    state
        .persisted
        .lock()
        .unwrap()
        .branch_metadata
        .extend((0..49).map(|i| {
            (
                format!("refs/premier-private/spam-{i}"),
                (Visibility::Personal("@mia".to_owned()), Readiness::Wip),
            )
        }));
    let (status, body) = create(&mia, json!({ "name": "one-too-many" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body["error"].as_str().unwrap().contains("50"), "{body}");
    let owned = json!({ "name": "owned", "visibility": { "scope": "public" } });
    let (status, body) = create(&owner, owned).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["full_ref"], "refs/heads/owned");
}

#[tokio::test]
async fn member_without_access_gets_no_branch_commit_or_review_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia) = no_access_repo(root);
    // A commit that changes no file has a subject all the same.
    git(
        root,
        &["commit", "-q", "--allow-empty", "-m", "secret plan"],
    );
    let router = build_router(state.clone());
    let main = git(root, &["rev-parse", "main"]);
    let billing = git(root, &["rev-parse", "main~1"]);
    let review = json!({ "title": "t", "branch": "feature" });
    let (status, _) = send(&router, Method::POST, "/v1/reviews", &owner, review.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let preview = |branch: &str| {
        let body = json!({ "branch": branch });
        send(
            &router,
            Method::POST,
            "/v1/branches/squash-preview",
            &mia,
            body,
        )
    };

    assert_eq!(get(&router, "/v1/branches", &mia).await.1, json!([]));
    assert_eq!(get(&router, "/v1/commits", &mia).await.1, json!([]));
    assert_eq!(
        get(&router, "/v1/commits?ref=feature", &mia).await.1,
        json!([])
    );
    assert_eq!(get(&router, "/v1/reviews", &mia).await.1, json!([]));
    let unknown = get(&router, "/v1/commits/deadbeef00", &mia).await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    for oid in [&main, &billing] {
        assert_eq!(
            get(&router, &format!("/v1/commits/{oid}"), &mia).await,
            unknown
        );
    }
    let hidden = preview("feature").await;
    assert_eq!(hidden.0, StatusCode::NOT_FOUND, "{}", hidden.1);
    assert_eq!(hidden, preview("nope").await);
    let (status, _) = send(&router, Method::POST, "/v1/reviews", &mia, review).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Partial access (everything but `billing/**`): a branch is described by the newest commit
    // she can list a change of, and a commit she can list nothing of does not exist.
    crate::tests::use_member_policy(&state);
    let (_, body) = get(&router, "/v1/branches", &mia).await;
    let subject = |name: &str| {
        let rows = body.as_array().unwrap();
        rows.iter().find(|b| b["name"] == name).unwrap()["subject"].clone()
    };
    assert_eq!(subject("main"), "secret plan");
    assert_eq!(subject("sandbox/x"), "initial");
    assert_eq!(
        get(&router, &format!("/v1/commits/{billing}"), &mia).await,
        unknown
    );
    let her_main = crate::tests::hers(&state, "main");
    let (status, body) = get(&router, &format!("/v1/commits/{her_main}"), &mia).await;
    assert_eq!(
        (status, &body["subject"]),
        (StatusCode::OK, &json!("secret plan"))
    );
    git(root, &["reset", "-q", "--hard", &billing]);
    let (_, body) = get(&router, "/v1/branches", &mia).await;
    let rows = body.as_array().unwrap();
    assert_eq!(
        rows.iter().find(|b| b["name"] == "main").unwrap()["subject"],
        "initial"
    );
    assert!(!body.to_string().contains("billing only"), "{body}");
    // The owner's view is unchanged.
    let (_, body) = get(&router, "/v1/branches", &owner).await;
    assert!(body.to_string().contains("billing only"), "{body}");
    let (status, body) = get(&router, &format!("/v1/commits/{billing}"), &owner).await;
    assert_eq!((status, &body["hidden_files"]), (StatusCode::OK, &json!(0)));
}

#[tokio::test]
async fn publish_validates_the_policy_before_the_default_branch_moves() {
    const OPEN: &str = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = repo(root);
    set_policy(&state, OPEN);
    let branch = |name: &str, policy: &str| {
        git(root, &["checkout", "-q", "-b", name, "main"]);
        std::fs::write(root.join(".access.toml"), policy).unwrap();
        git(root, &["add", ".access.toml"]);
        git(root, &["commit", "-q", "-m", name]);
        git(root, &["checkout", "-q", "main"]);
    };
    branch("broken", "this is [not toml");
    branch("lockout", &OPEN.replace("group:owners", "@nobody"));
    branch(
        "fine",
        &OPEN.replace("owners-full-access", "owners-everything"),
    );
    let router = build_router(state.clone());
    let publish = |source: &str| {
        let body = json!({ "source_branch": source });
        send(&router, Method::POST, "/v1/branches/publish", &owner, body)
    };
    let main = || git(root, &["rev-parse", "main"]);
    let before = main();

    let (status, body) = publish("broken").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains(".access.toml"),
        "{body}"
    );
    let (status, body) = publish("lockout").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("lock the owners out"),
        "{body}"
    );
    assert_eq!(main(), before);
    assert!(
        !state
            .current_repo_policy_toml()
            .contains("owners-everything")
    );

    let (status, body) = publish("fine").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(main(), before);
    assert!(
        state
            .current_repo_policy_toml()
            .contains("owners-everything")
    );
}

#[tokio::test]
async fn env_routes_answer_empty_without_a_schema() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, mia, _) = repo(tmp.path());
    let router = build_router(state);
    for who in [&owner, &mia] {
        let (status, body) = get(&router, "/v1/env/dashboard", who).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({ "schema": null, "reports": {} }));
        let (status, body) = get(&router, "/v1/env/schema", who).await;
        assert_eq!((status, body), (StatusCode::OK, Value::Null));
    }
}

// ---------------------------------------------------------------------------
// Second review: state outside the tree, ref-scoped commits, session-only administration,
// counts, and a repository with no default branch.
// ---------------------------------------------------------------------------

fn plumb(root: &Path, path: &str, content: &str) -> String {
    let who = ("T".to_owned(), "t@example.test".to_owned());
    let path = RepoPath::new(path).unwrap();
    crate::canon::commit_file(
        root,
        "refs/heads/main",
        None,
        &path,
        Some(content.as_bytes()),
        "pushed",
        &who,
    )
    .map_err(|e| format!("{e:?}"))
    .unwrap()
}

#[tokio::test]
async fn a_pushed_tree_never_replaces_server_state_or_an_ignored_file() {
    // Without a state directory the server's state is IN the working tree: never synced.
    let legacy = tempfile::tempdir().unwrap();
    let (state, _, _, _) = repo(legacy.path());
    let before = crate::canon::DefaultTip::capture(legacy.path());
    plumb(legacy.path(), "README.md", "# Pushed\n");
    state.default_branch_moved(before);
    assert_eq!(
        std::fs::read_to_string(legacy.path().join("README.md")).unwrap(),
        "# Demo\n"
    );
    assert!(legacy.path().join(".premier/premier.db").is_file());

    // With one, nothing of the server is in the tree, and a clean tree follows its branch.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    crate::tests::state_outside(root);
    let (state, _, _, _) = repo(root);
    assert!(!root.join(".premier").exists() && !root.join(".premier-local").exists());
    let auth = crate::store::account_dir(root).join("premier.db");
    assert!(auth.is_file() && !auth.starts_with(root), "{auth:?}");
    let readme = || std::fs::read_to_string(root.join("README.md")).unwrap();
    let before = crate::canon::DefaultTip::capture(root);
    plumb(root, "README.md", "# Pushed\n");
    state.default_branch_moved(before);
    assert_eq!(readme(), "# Pushed\n");

    // A tip that names a reserved component is never checked out, whatever let it in.
    for reserved in [
        ".premier/auth.json",
        ".premier-local/audit.jsonl",
        "docs/.PREMIER/x",
    ] {
        let tip = git(root, &["rev-parse", "main"]);
        let before = crate::canon::DefaultTip::capture(root);
        plumb(root, reserved, "{\"accounts\":[]}");
        plumb(root, "README.md", &format!("# after {reserved}\n"));
        state.default_branch_moved(before);
        assert_eq!(readme(), "# Pushed\n", "{reserved}");
        assert!(!root.join(reserved).exists(), "{reserved}");
        // Back to the tip the tree is still at.
        git(root, &["update-ref", "refs/heads/main", &tip]);
    }

    // A file git ignores makes the tree look clean; a tip that writes that path leaves it alone.
    std::fs::write(root.join(".gitignore"), "local.env\ncache/\n").unwrap();
    git(root, &["add", ".gitignore"]);
    git(root, &["commit", "-q", "-m", "ignore"]);
    std::fs::write(root.join("local.env"), "mine\n").unwrap();
    std::fs::create_dir(root.join("cache")).unwrap();
    std::fs::write(root.join("cache/x"), "mine\n").unwrap();
    for (path, kept) in [
        ("local.env", "local.env"),
        ("cache/x", "cache/x"),
        ("LOCAL.ENV", "local.env"),
    ] {
        let tip = git(root, &["rev-parse", "main"]);
        let before = crate::canon::DefaultTip::capture(root);
        plumb(root, path, "pushed\n");
        state.default_branch_moved(before);
        assert_eq!(
            std::fs::read_to_string(root.join(kept)).unwrap(),
            "mine\n",
            "{path}"
        );
        git(root, &["update-ref", "refs/heads/main", &tip]);
    }
    // ...while an ignored file the tip does not touch is no reason to fall behind.
    let before = crate::canon::DefaultTip::capture(root);
    plumb(root, "README.md", "# Still follows\n");
    state.default_branch_moved(before);
    assert_eq!(readme(), "# Still follows\n");
}

#[tokio::test]
async fn reserved_path_components_are_refused_by_the_file_api() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = repo(root);
    let router = build_router(state);
    let tip = git(root, &["rev-parse", "main"]);
    for path in [
        ".premier/auth.json",
        ".premier-local/audit.jsonl",
        ".git/config",
        "docs/.git/hooks/x",
        "docs/.Premier/x",
        "PREMIE~1/auth.json",
        "GIT~1/config",
        ".git ./config",
        ".premier::$DATA/x",
    ] {
        for method in [Method::PUT, Method::DELETE] {
            let body = json!({ "path": path, "content": "x" });
            let (status, body) = send(&router, method, "/v1/repo/file", &owner, body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        }
    }
    assert_eq!(git(root, &["rev-parse", "main"]), tip);
}

/// `@mia` reads everything, except `docs/**` on the branch `feature`.
const REF_SCOPED_POLICY: &str = r#"version = 1
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
[[rules]]
id = "mia-no-docs-on-feature"
effect = "deny"
principals = ["@mia"]
paths = ["docs/**"]
refs = ["feature"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#;

#[tokio::test]
async fn a_commit_is_judged_on_the_ref_that_shows_it_not_on_the_default_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);
    set_policy(&state, REF_SCOPED_POLICY);
    let router = build_router(state.clone());

    // On `feature`: one commit over docs only, one over docs and README.
    git(root, &["checkout", "-q", "feature"]);
    std::fs::write(root.join("docs/guide.md"), "embargoed guide\n").unwrap();
    git(root, &["commit", "-q", "-am", "embargoed docs"]);
    let docs_only = git(root, &["rev-parse", "HEAD"]);
    std::fs::write(root.join("docs/guide.md"), "embargoed guide 2\n").unwrap();
    std::fs::write(root.join("README.md"), "# Demo 3\n").unwrap();
    git(root, &["commit", "-q", "-am", "docs and readme"]);
    let mixed = git(root, &["rev-parse", "HEAD"]);
    // On `main`, where docs are readable: the control.
    git(root, &["checkout", "-q", "main"]);
    std::fs::write(root.join("docs/guide.md"), "public guide\n").unwrap();
    git(root, &["commit", "-q", "-am", "public docs"]);
    let on_main = git(root, &["rev-parse", "HEAD"]);

    // The owner sees the patch; the member, for whom docs are denied on that branch, sees
    // neither the commit nor its patch (on the default branch she could read docs/**).
    let (status, body) = get(&router, &format!("/v1/commits/{docs_only}"), &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.to_string().contains("embargoed guide"), "{body}");
    let (status, body) = get(&router, &format!("/v1/commits/{docs_only}"), &mia).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    let her_mixed = crate::tests::hers(&state, &mixed);
    let (status, body) = get(&router, &format!("/v1/commits/{her_mixed}"), &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.to_string().contains("embargoed"), "{body}");
    assert_eq!(body["hidden_files"], 1, "{body}");
    assert_eq!(body["files"][0]["path"], "README.md", "{body}");
    assert!(
        body["files"][0]["patch"]
            .as_str()
            .unwrap()
            .contains("Demo 3"),
        "{body}"
    );

    let (_, list) = get(&router, "/v1/commits?ref=feature", &mia).await;
    let listed = list.to_string();
    assert!(
        !listed.contains(&docs_only) && !listed.contains("embargoed docs"),
        "{list}"
    );
    let shown = list
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["oid"] == her_mixed.as_str())
        .unwrap();
    assert_eq!(shown["files_changed"], 1, "{list}");
    // By oid, the same.
    let (_, list) = get(&router, &format!("/v1/commits?ref={her_mixed}"), &mia).await;
    assert!(!list.to_string().contains(&docs_only), "{list}");

    // Where the rule does not apply she reads the same path as before.
    let (status, body) = get(&router, &format!("/v1/commits/{on_main}"), &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["files"][0]["patch"]
            .as_str()
            .unwrap()
            .contains("public guide"),
        "{body}"
    );
}

/// Every `(method, path)` a router source wraps in `owner(..)`: read from the declaration
/// itself, so a route added there is covered here without anyone remembering to.
fn owner_routes(source: &str) -> Vec<(Method, String)> {
    fn balanced(s: &str) -> &str {
        let mut depth = 1usize;
        for (i, c) in s.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &s[..i];
                    }
                }
                _ => {}
            }
        }
        s
    }
    let word = |s: &str, at: usize| {
        at == 0 || !s.as_bytes()[at - 1].is_ascii_alphanumeric() && s.as_bytes()[at - 1] != b'_'
    };
    let mut found = Vec::new();
    for chunk in source.split(".route(").skip(1) {
        let route = balanced(chunk);
        let Some(path) = route.split('"').nth(1).filter(|p| p.starts_with('/')) else {
            continue;
        };
        for (at, _) in route
            .match_indices("owner(")
            .filter(|(at, _)| word(route, *at))
        {
            let wrapped = balanced(&route[at + "owner(".len()..]);
            for (name, method) in [
                ("get(", Method::GET),
                ("post(", Method::POST),
                ("put(", Method::PUT),
                ("patch(", Method::PATCH),
                ("delete(", Method::DELETE),
            ] {
                if wrapped.match_indices(name).any(|(at, _)| word(wrapped, at)) {
                    found.push((method, path.to_owned()));
                }
            }
        }
    }
    found
}

#[tokio::test]
async fn every_owner_only_route_refuses_an_owner_access_token() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = repo(root);
    let (_, token) = state.auth.seed("olga", crate::tests::PW);
    let bearer = format!("Bearer {token}");
    let tip = git(root, &["rev-parse", "main"]);
    let policy = state.current_repo_policy_toml();
    let router = crate::repos::Registry::open(state.clone(), None, None).router();

    let mut routes = owner_routes(include_str!("lib.rs"));
    routes.extend(owner_routes(include_str!("repos.rs")));
    // The parser found the declarations: these are known to be among them.
    for known in [
        (Method::PUT, "/v1/policy/repo"),
        (Method::POST, "/v1/approvals/{id}/decide"),
        (Method::POST, "/v1/branches/publish"),
        (Method::POST, "/v1/branches/visibility"),
        (Method::DELETE, "/v1/branches/{*name}"),
        (Method::POST, "/v1/overlays/mount"),
        (Method::POST, "/v1/agents/sessions/{id}/commit"),
        (Method::DELETE, "/v1/agents/sessions/{id}"),
        (Method::GET, "/v1/audit"),
        (Method::POST, "/v1/users"),
        (Method::POST, "/v1/repos"),
        (Method::DELETE, "/v1/repos/{name}"),
        (Method::POST, "/v1/access/explain"),
        (Method::POST, "/v1/access/diff"),
        (Method::POST, "/v1/policy/diff"),
        (Method::POST, "/v1/policy/propose"),
        (Method::POST, "/v1/policy/explain-secrets"),
        (Method::GET, "/v1/overlays"),
        (Method::POST, "/v1/overlays/check"),
        (Method::GET, "/v1/secrets/status"),
    ] {
        assert!(
            routes.contains(&(known.0.clone(), known.1.to_owned())),
            "{known:?} not in {routes:?}"
        );
    }
    assert!(routes.len() >= 25, "{routes:?}");

    for (method, path) in routes {
        // `{id}` and `{*name}` filled in with something.
        let mut uri = String::new();
        for segment in path.split('/').skip(1) {
            uri.push('/');
            uri.push_str(if segment.starts_with('{') {
                "x"
            } else {
                segment
            });
        }
        let headers = [("authorization", bearer.as_str())];
        let (status, _, body) =
            call(&router, method.clone(), &uri, &headers, Some(json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("requires a browser session"),
            "{method} {uri}: {body}"
        );
    }

    // The files that configure the server, through the file API: a browser session too.
    for file in [".access.toml", ".env.schema"] {
        for method in [Method::PUT, Method::DELETE] {
            let headers = [("authorization", bearer.as_str())];
            let body = json!({ "path": file, "content": "version = 1\n" });
            let (status, _, body) =
                call(&router, method, "/v1/repo/file", &headers, Some(body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{file}: {body}");
            assert_eq!(
                body["error"], "this action requires a browser session",
                "{file}"
            );
        }
    }
    assert_eq!(git(root, &["rev-parse", "main"]), tip);
    assert_eq!(state.current_repo_policy_toml(), policy);
    // The X-ray lens is the owner's in a browser only: a token gets the plain tree, no rule
    // traces, no omitted count, and cannot impersonate another principal.
    let headers = [("authorization", bearer.as_str())];
    let (status, _, body) = call(
        &router,
        Method::GET,
        "/v1/repo/tree?xray=true&principal=@mia",
        &headers,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["xray"], false, "{body}");
    assert_eq!(body["omitted_count"], 0, "{body}");
    assert_eq!(body["principal"], "@olga", "{body}");
    for entry in body["entries"].as_array().unwrap() {
        assert_eq!(entry["matched_rules"], json!([]), "{entry}");
    }
    let (_, body) = get(&router, "/v1/repo/tree?xray=true", &owner).await;
    assert_eq!(body["xray"], true, "{body}");

    // Policy summary text and Public branch creation also require a browser session.
    let (status, _, summary) =
        call(&router, Method::GET, "/v1/policy/summary", &headers, None).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["repo_policy_toml"], "", "{summary}");
    assert!(summary["policy"].is_null(), "{summary}");

    let (status, _, body) = call(
        &router,
        Method::POST,
        "/v1/branches/create",
        &headers,
        Some(json!({ "name": "tok-pub", "visibility": { "scope": "public" } })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Directory is scoped to caller's own entry for owner access tokens too.
    let (status, _, dir) = call(&router, Method::GET, "/v1/directory", &headers, None).await;
    assert_eq!(status, StatusCode::OK, "{dir}");
    let principals: Vec<&str> = dir["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["principal"].as_str().unwrap())
        .collect();
    assert_eq!(principals, ["@olga"], "{dir}");

    // The token still does what a token is for, and the browser session still administers.
    let write = json!({ "path": "docs/by-token.md", "content": "ok" });
    let (status, _, body) =
        call(&router, Method::PUT, "/v1/repo/file", &headers, Some(write)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _) = get(&router, "/v1/audit", &owner).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_member_is_given_counts_of_what_she_is_shown_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);
    let router = build_router(state);
    // Two commits ahead of main: one over billing only (hidden from her), one over README.
    git(root, &["checkout", "-q", "-b", "work", "main"]);
    std::fs::write(root.join("billing/ledger.rs"), "// v9\n").unwrap();
    git(root, &["commit", "-q", "-am", "secret pricing change"]);
    std::fs::write(root.join("README.md"), "# Work\n").unwrap();
    git(root, &["commit", "-q", "-am", "readme"]);
    // A merge that only brings in billing is no more hers to hear of than the commit it merges.
    git(root, &["checkout", "-q", "-b", "side", "main"]);
    std::fs::write(root.join("billing/extra.rs"), "// extra\n").unwrap();
    git(root, &["add", "billing/extra.rs"]);
    git(root, &["commit", "-q", "-m", "side billing"]);
    git(root, &["checkout", "-q", "work"]);
    git(
        root,
        &[
            "merge",
            "-q",
            "--no-ff",
            "-m",
            "Merge acquisition-of-initech pricing",
            "side",
        ],
    );
    git(root, &["checkout", "-q", "main"]);

    let ahead = |list: &Value| {
        let work = list
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["name"] == "work")
            .unwrap();
        work["ahead_commits"].as_u64().unwrap()
    };
    let (_, list) = get(&router, "/v1/branches", &owner).await;
    assert_eq!(ahead(&list), 4, "{list}");
    let (_, list) = get(&router, "/v1/branches", &mia).await;
    assert_eq!(ahead(&list), 1, "{list}");

    let (_, commits) = get(&router, "/v1/commits?ref=work", &mia).await;
    let text = commits.to_string();
    assert!(
        text.contains("readme") && !text.contains("initech") && !text.contains("pricing"),
        "{commits}"
    );

    // main changes billing too: a conflict she may not list is not counted for her either.
    std::fs::write(root.join("billing/ledger.rs"), "// v10\n").unwrap();
    git(root, &["commit", "-q", "-am", "main billing"]);
    let preview = json!({ "branch": "work" });
    let (status, hers) = send(
        &router,
        Method::POST,
        "/v1/branches/squash-preview",
        &mia,
        preview.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{hers}");
    assert_eq!(hers["hidden_conflicts"], 0, "{hers}");
    assert_eq!(hers["private_commits_collapsed"], 1, "{hers}");
    let message = hers["clean_commit_message"].as_str().unwrap();
    assert!(
        message.starts_with(
            "Publish to main
"
        ) && !message.contains("work"),
        "{hers}"
    );
    let (_, theirs) = send(
        &router,
        Method::POST,
        "/v1/branches/squash-preview",
        &owner,
        preview,
    )
    .await;
    assert_eq!(theirs["private_commits_collapsed"], 4, "{theirs}");
}

/// Push one commit holding `file` from a fresh local repository to `refspec`: accepted?, stderr.
async fn push_new(
    work: &Path,
    url: String,
    file: &'static str,
    text: String,
    refspec: &'static str,
) -> (bool, String) {
    let work = work.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let dir = tempfile::tempdir_in(&work).unwrap();
        git(dir.path(), &["init", "-q", "-b", "main"]);
        std::fs::write(dir.path().join(file), text).unwrap();
        git(dir.path(), &["add", file]);
        git(dir.path(), &["commit", "-q", "-m", "first"]);
        let (ok, _, err) = try_git(dir.path(), &["push", &url, refspec]);
        (ok, err)
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn an_empty_repository_takes_its_first_push_from_an_owner_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    git(&root, &["init", "-q", "-b", "main"]);
    let (state, _, _, mia_token) = member_state(&root);
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    // An unborn default branch: the built-in owner-only policy is what is in force.
    state.reload_repo_config().unwrap();
    assert_eq!(
        state.current_repo_policy_toml(),
        crate::directory::DEFAULT_POLICY_TOML
    );
    let router = build_router(state.clone());
    let addr = serve(&router).await;
    let url = |user: &str, token: &str| format!("http://{user}:{token}@{addr}/git/auth/repo.git");

    let hers = "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\", \"write\"]\n"
        .to_owned();
    let (ok, err) = push_new(
        tmp.path(),
        url("mia", &mia_token),
        ".access.toml",
        hers.clone(),
        "HEAD:refs/heads/main",
    )
    .await;
    assert!(!ok, "{err}");
    let (ok, err) = push_new(
        tmp.path(),
        url("mia", &mia_token),
        ".access.toml",
        hers,
        "HEAD:refs/heads/mine",
    )
    .await;
    assert!(!ok, "{err}");
    assert_eq!(git(&root, &["for-each-ref"]), "");

    let (ok, err) = push_new(
        tmp.path(),
        url("root", &root_token),
        "README.md",
        "# first\n".to_owned(),
        "HEAD:refs/heads/main",
    )
    .await;
    assert!(ok, "{err}");
    assert_eq!(git(&root, &["log", "-1", "--format=%s", "main"]), "first");
    assert_eq!(
        state.current_repo_policy_toml(),
        crate::directory::DEFAULT_POLICY_TOML
    );
}

#[tokio::test]
async fn with_a_detached_head_policy_files_are_the_owners_on_every_ref() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, _, mia, mia_token) = repo(&root);
    // She may write everything but billing, and the policy is live...
    set_policy(&state, WRITER_POLICY);
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    let router = build_router(state.clone());
    let addr = serve(&router).await;
    let url = |user: &str, token: &str| format!("http://{user}:{token}@{addr}/git/auth/repo.git");
    // ...when HEAD stops naming a branch (an operator's `git checkout <commit>`).
    git(&root, &["checkout", "-q", "--detach", "main"]);
    let refs = git(&root, &["for-each-ref"]);

    // No ref is "the default branch" now, so her `.access.toml` is refused on every one of
    // them: none may go live when HEAD is attached again.
    let hers = open_policy().to_owned();
    for refspec in [
        "HEAD:refs/heads/main",
        "HEAD:refs/heads/feature",
        "HEAD:refs/heads/mine",
    ] {
        let (ok, err) = push_new(
            tmp.path(),
            url("mia", &mia_token),
            ".access.toml",
            hers.clone(),
            refspec,
        )
        .await;
        assert!(!ok, "{refspec}: {err}");
    }
    for branch in ["main", "feature"] {
        let write = json!({ "path": ".access.toml", "content": hers, "ref_name": branch });
        let (status, body) = send(&router, Method::PUT, "/v1/repo/file", &mia, write).await;
        assert!(status.is_client_error(), "{branch}: {status} {body}");
    }
    assert_eq!(git(&root, &["for-each-ref"]), refs);

    // (Re)loaded in that condition, the server enforces the built-in owner-only policy.
    state.reload_repo_config().unwrap();
    let her = DelegatedIdentity::human_only(Principal::parse("@mia").unwrap(), vec![]);
    let readme = RepoPath::new("README.md").unwrap();
    let policy = state.current_policy().unwrap();
    assert!(
        !policy
            .explain(&her, &readme, "main")
            .allows(Capability::READ)
    );

    // An owner still pushes.
    let (ok, err) = push_new(
        tmp.path(),
        url("root", &root_token),
        "NOTES.md",
        "notes\n".to_owned(),
        "HEAD:refs/heads/notes",
    )
    .await;
    assert!(ok, "{err}");
}

// ---- hands-on QA pass ------------------------------------------------------------------------

/// Owners have everything; `@mia` reads and writes `README.md` and `docs/**`; nobody else anything.
const QA_POLICY: &str = r#"version = 1
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
id = "mia-docs"
effect = "allow"
principals = ["@mia"]
paths = ["README.md", "docs/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write"]
"#;

/// Added to [`QA_POLICY`]: anonymous visitors read `docs/**`.
const QA_PUBLIC_DOCS: &str = r#"[[rules]]
id = "public-docs"
effect = "allow"
principals = ["*"]
paths = ["docs/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read"]
"#;

struct Qa {
    state: ServerState,
    owner: String,
    mia: String,
    mia_token: String,
    root_token: String,
}

/// Default branch `trunk`: `initial` (`.access.toml`, `README.md`, `docs/guide.md`,
/// `secret/key.txt`), then `policy note`, which changes `.access.toml` only and so is no commit
/// of `@mia`'s clone. The policy is live from the tip.
fn qa_repo(root: &Path, policy: &str) -> Qa {
    let (mut state, owner, mia, mia_token) = member_state(root);
    state.session_manager = Arc::new(runner::SessionManager::open(root));
    for (path, content) in [
        (".access.toml", policy),
        ("docs/guide.md", "guide\n"),
        ("secret/key.txt", "a key nobody but the owners may read\n"),
    ] {
        std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        std::fs::write(root.join(path), content).unwrap();
    }
    git(root, &["init", "-q", "-b", "trunk"]);
    git(root, &["config", "core.autocrlf", "false"]);
    git(
        root,
        &["add", ".access.toml", "README.md", "docs", "secret"],
    );
    git(root, &["commit", "-q", "-m", "initial"]);
    std::fs::write(root.join(".access.toml"), format!("{policy}# reviewed\n")).unwrap();
    git(root, &["commit", "-q", "-m", "policy note", ".access.toml"]);
    state.reload_repo_config().unwrap();
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    Qa {
        state,
        owner,
        mia,
        mia_token,
        root_token,
    }
}

fn row(list: &Value, name: &str) -> Value {
    let rows = list.as_array().unwrap();
    rows.iter()
        .find(|b| b["name"] == name)
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn a_clone_checks_out_the_default_branch_for_owner_member_and_anonymous() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let qa = qa_repo(&root, &format!("{QA_POLICY}{QA_PUBLIC_DOCS}"));
    // A second branch that sorts before the default one.
    git(&root, &["branch", "alpha", "trunk"]);
    let router = build_router(qa.state.clone());
    let addr = serve(&router).await;
    let urls = [
        (
            "owner",
            format!("http://root:{}@{addr}/git/auth/repo.git", qa.root_token),
        ),
        (
            "member",
            format!("http://mia:{}@{addr}/git/auth/repo.git", qa.mia_token),
        ),
        ("anonymous", format!("http://{addr}/git/repo.git")),
    ];
    let mia_url = urls[1].1.clone();
    let work = tmp.path().to_path_buf();
    let symref = |work: &Path, url: &str| {
        let (ok, out, err) = try_git(work, &["ls-remote", "--symref", url, "HEAD"]);
        assert!(ok, "{err}");
        out
    };
    let dir = work.clone();
    tokio::task::spawn_blocking(move || {
        for (who, url) in &urls {
            assert!(
                symref(&dir, url).contains("ref: refs/heads/trunk\tHEAD"),
                "{who}"
            );
            let (ok, _, err) = try_git(&dir, &["clone", "-q", url, who]);
            assert!(ok, "{who}: {err}");
            assert_eq!(
                git(&dir.join(who), &["symbolic-ref", "--short", "HEAD"]),
                "trunk",
                "{who}"
            );
        }
    })
    .await
    .unwrap();

    // A caller who cannot see the default branch is not told its name: HEAD is the first branch
    // of theirs, by name.
    qa.state.persisted.lock().unwrap().branch_metadata.insert(
        "refs/heads/trunk".to_owned(),
        (
            Visibility::Restricted(vec!["@owner".to_owned()]),
            Readiness::Ready,
        ),
    );
    let head = tokio::task::spawn_blocking(move || symref(&work, &mia_url))
        .await
        .unwrap();
    assert!(
        head.contains("ref: refs/heads/alpha\tHEAD") && !head.contains("trunk"),
        "{head}"
    );
}

#[tokio::test]
async fn a_member_is_given_and_gives_the_commit_ids_of_her_own_clone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let qa = qa_repo(&root, QA_POLICY);
    let (owner, mia) = (qa.owner.clone(), qa.mia.clone());
    let router = build_router(qa.state.clone());
    let addr = serve(&router).await;
    let url = |user: &str, token: &str| format!("http://{user}:{token}@{addr}/git/auth/repo.git");
    let (mia_url, root_url) = (url("mia", &qa.mia_token), url("root", &qa.root_token));
    let work = tmp.path().to_path_buf();
    let (hers, hers_subject, theirs) = tokio::task::spawn_blocking(move || {
        for (url, dir) in [(&mia_url, "mia"), (&root_url, "root")] {
            let (ok, _, err) = try_git(&work, &["clone", "-q", url, dir]);
            assert!(ok, "{err}");
        }
        let log = |dir: &str, format: &str| git(&work.join(dir), &["log", format, "origin/trunk"]);
        (
            log("mia", "--format=%H"),
            log("mia", "--format=%s"),
            log("root", "--format=%H"),
        )
    })
    .await
    .unwrap();
    let canonical = git(&root, &["log", "--format=%H", "trunk"]);
    let canonical_tip = canonical.lines().next().unwrap().to_owned();
    let her_tip = hers.lines().next().unwrap().to_owned();
    // An owner's clone has the canonical commits; hers has one commit, of an id of its own.
    assert_eq!(theirs, canonical);
    assert_eq!(hers.lines().count(), 1, "{hers}");
    assert!(!canonical.contains(&her_tip));
    let oids = |list: &Value| -> Vec<String> {
        let rows = list.as_array().unwrap().iter();
        rows.map(|c| c["oid"].as_str().unwrap().to_owned())
            .collect()
    };

    // Returned: the tip, the subject that goes with it, and the log are those of her clone.
    let (_, list) = get(&router, "/v1/branches", &mia).await;
    let trunk = row(&list, "trunk");
    assert_eq!(trunk["head_oid"], her_tip[..7], "{trunk}");
    assert_eq!(trunk["subject"], hers_subject.as_str(), "{trunk}");
    let (_, commits) = get(&router, "/v1/commits?ref=trunk", &mia).await;
    assert_eq!(oids(&commits), std::slice::from_ref(&her_tip), "{commits}");
    assert_eq!(commits[0]["short_oid"], her_tip[..7]);
    let (_, blame) = get(
        &router,
        "/v1/repo/blame?path=README.md&ref_name=trunk",
        &mia,
    )
    .await;
    assert_eq!(blame["lines"][0]["oid"], her_tip[..7], "{blame}");
    // The owner is unaffected.
    let (_, list) = get(&router, "/v1/branches", &owner).await;
    assert_eq!(row(&list, "trunk")["head_oid"], canonical_tip[..7]);
    let (_, commits) = get(&router, "/v1/commits?ref=trunk", &owner).await;
    assert_eq!(oids(&commits).join("\n"), canonical);

    // Accepted: her ids, whole or abbreviated. A canonical id is no commit of hers: it answers
    // like one that does not exist, whether or not she can see what it changed.
    for canonical in canonical.lines() {
        for uri in ["/v1/commits/", "/v1/commits?ref=", "/v1/attestations/"] {
            let (status, body) = get(&router, &format!("{uri}{canonical}"), &mia).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{uri}{canonical}: {body}");
        }
        let branch = json!({ "name": "nope", "from_ref": canonical });
        let (status, body) = send(&router, Method::POST, "/v1/branches/create", &mia, branch).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
    for id in [&her_tip[..], &her_tip[..9]] {
        let (status, body) = get(&router, &format!("/v1/commits/{id}"), &mia).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["subject"], hers_subject.as_str());
        let (status, body) = get(&router, &format!("/v1/commits?ref={id}"), &mia).await;
        assert_eq!(
            (status, oids(&body)),
            (StatusCode::OK, vec![her_tip.clone()])
        );
    }
    let (status, _) = get(&router, &format!("/v1/attestations/{her_tip}"), &mia).await;
    assert_eq!(status, StatusCode::OK);
    let branch = json!({ "name": "from-mine", "from_ref": her_tip });
    let (status, body) = send(&router, Method::POST, "/v1/branches/create", &mia, branch).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["oid"], her_tip.as_str());

    // `expected_tip` is the tip she has, and the commit she is told of is the one she will fetch.
    let edit = |tip: &str| json!({ "path": "README.md", "content": "# Hers\n", "ref_name": "trunk", "expected_tip": tip });
    let (status, body) = send(
        &router,
        Method::PUT,
        "/v1/repo/file",
        &mia,
        edit(&canonical_tip),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let (status, body) = send(&router, Method::PUT, "/v1/repo/file", &mia, edit(&her_tip)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let clone = tmp.path().join("mia");
    let fetched = tokio::task::spawn_blocking(move || {
        git(&clone, &["fetch", "-q", "origin"]);
        git(&clone, &["rev-parse", "origin/trunk"])
    })
    .await
    .unwrap();
    assert_eq!(body["commit"], fetched.as_str());
    assert_eq!(git(&root, &["rev-parse", "trunk~1"]), canonical_tip);
}

#[tokio::test]
async fn a_branch_label_says_who_sees_it_and_a_publish_leaves_visibility_alone() {
    assert_eq!(
        crate::default_ref_visibility("refs/heads/trunk"),
        Visibility::Public
    );
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let qa = qa_repo(&root, &format!("{QA_POLICY}{QA_PUBLIC_DOCS}"));
    git(&root, &["checkout", "-q", "-b", "work"]);
    std::fs::write(root.join("docs/guide.md"), "guide 2\n").unwrap();
    git(&root, &["commit", "-q", "-m", "guide", "docs/guide.md"]);
    git(&root, &["checkout", "-q", "trunk"]);
    let router = build_router(qa.state.clone());
    let addr = serve(&router).await;
    let anonymous_refs = || {
        let (work, url) = (
            tmp.path().to_path_buf(),
            format!("http://{addr}/git/repo.git"),
        );
        tokio::task::spawn_blocking(move || try_git(&work, &["ls-remote", &url]).1)
    };
    let label = |cookie: String| {
        let router = router.clone();
        async move { row(&get(&router, "/v1/branches", &cookie).await.1, "trunk")["visibility"].clone() }
    };

    // Nothing is stored for the default branch: it is public as a ref, and anonymous visitors
    // list `docs/**` on it, so that is what the label says and what Git serves.
    assert!(
        !qa.state
            .branch_visibility_map()
            .contains_key("refs/heads/trunk")
    );
    assert_eq!(label(qa.owner.clone()).await, json!({ "scope": "public" }));
    assert!(anonymous_refs().await.unwrap().contains("refs/heads/trunk"));

    // A publish moves the target, never its visibility.
    let before = qa.state.branch_visibility_map();
    let publish = json!({ "source_branch": "work" });
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/branches/publish",
        &qa.owner,
        publish,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(qa.state.branch_visibility_map(), before);
    assert_eq!(label(qa.owner.clone()).await, json!({ "scope": "public" }));

    // Without the public rule nobody anonymous lists anything: the same stored visibility now
    // reads restricted, naming who does see the branch (a member is only told of herself).
    let save = json!({ "toml": QA_POLICY });
    let headers = [
        ("cookie", qa.owner.as_str()),
        ("origin", "http://localhost"),
    ];
    let (status, _, body) = call(
        &router,
        Method::PUT,
        "/v1/policy/repo",
        &headers,
        Some(save),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(qa.state.branch_visibility_map(), before);
    assert_eq!(
        label(qa.owner.clone()).await,
        json!({ "scope": "restricted", "allow": ["group:owners", "@mia"] })
    );
    assert_eq!(
        label(qa.mia.clone()).await,
        json!({ "scope": "restricted", "allow": ["@mia"] })
    );
    assert!(!anonymous_refs().await.unwrap().contains("trunk"));
}

#[tokio::test]
async fn an_agent_session_needs_a_declared_profile_and_something_to_read() {
    let tmp = tempfile::tempdir().unwrap();
    let mut qa = qa_repo(tmp.path(), QA_POLICY);
    qa.state.allow_unsandboxed_agents = true;
    let router = build_router(qa.state.clone());
    let sessions = "/v1/agents/sessions";
    let spawn = |body: Value| send(&router, Method::POST, sessions, &qa.owner, body);

    // The starter policy declares no profile: the names are the owners' to read, and one that
    // is not there is refused by name.
    let (_, summary) = get(&router, "/v1/policy/summary", &qa.owner).await;
    assert_eq!(summary["policy"]["agent_profiles"], json!([]), "{summary}");
    let (_, summary) = get(&router, "/v1/policy/summary", &qa.mia).await;
    assert_eq!(summary["policy"], Value::Null);
    let (status, body) = spawn(json!({ "command": "ls", "agent_profile": "ui-agent" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"],
        "agent profile 'ui-agent' is not defined in this repository's policy"
    );

    // An identity that reads nothing on the branch has no workspace to run in.
    let (status, body) = spawn(json!({ "command": "ls", "principal": "@ghost" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["error"],
        "@ghost can read nothing on branch 'trunk': there is no workspace to run in"
    );
    assert_eq!(get(&router, sessions, &qa.owner).await.1, json!([]));

    // No profile: the human identity alone, in a workspace holding what it reads.
    let (status, body) = spawn(json!({ "command": "ls" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["agent_profile"], "");
    let mut done = Value::Null;
    for _ in 0..300 {
        let (_, list) = get(&router, sessions, &qa.owner).await;
        if list[0]["status"] != "running" {
            done = list[0].clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(done["exit_code"], 0, "{done}");
    assert!(
        done["output_lines"].to_string().contains("README.md"),
        "{done}"
    );
}

#[tokio::test]
async fn paths_touched_are_what_the_branch_changed_since_it_forked() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let qa = qa_repo(root, &format!("{QA_POLICY}{QA_PUBLIC_DOCS}"));
    git(root, &["checkout", "-q", "-b", "topic"]);
    std::fs::write(root.join("README.md"), "# Topic\n").unwrap();
    std::fs::write(root.join("docs/guide.md"), "guide 2\n").unwrap();
    std::fs::write(
        root.join("secret/key.txt"),
        "another key for the owners only\n",
    )
    .unwrap();
    git(root, &["commit", "-q", "-am", "topic"]);
    git(root, &["checkout", "-q", "trunk"]);
    // The default branch moves on after the fork: not something `topic` touched.
    std::fs::write(
        root.join(".access.toml"),
        format!("{QA_POLICY}{QA_PUBLIC_DOCS}# again\n"),
    )
    .unwrap();
    git(
        root,
        &["commit", "-q", "-m", "policy again", ".access.toml"],
    );
    let router = build_router(qa.state.clone());

    let touched = |list: Value| row(&list, "topic")["private_paths_touched"].clone();
    let (_, list) = get(&router, "/v1/branches", &qa.owner).await;
    assert_eq!(
        touched(list),
        json!(["README.md", "docs/guide.md", "secret/key.txt"])
    );
    let (_, list) = get(&router, "/v1/branches", &qa.mia).await;
    assert_eq!(touched(list), json!(["README.md", "docs/guide.md"]));
}

#[tokio::test]
async fn a_refused_policy_push_says_once_where_the_toml_is_broken() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let (state, ..) = repo(&root);
    set_policy(&state, WRITER_POLICY);
    let (_, root_token) = state.auth.seed("root", crate::tests::PW);
    let addr = serve(&build_router(state)).await;
    let (ok, err) = push_policy(
        tmp.path(),
        addr,
        "root",
        &root_token,
        "version = 1\nrules = [\n",
    )
    .await;
    assert!(!ok, "{err}");
    assert_eq!(err.matches("TOML parse error").count(), 1, "{err}");
    assert!(
        err.contains(".access.toml: TOML parse error at line 2, column 11: invalid array"),
        "{err}"
    );
}

#[tokio::test]
async fn a_member_is_told_that_the_branch_her_push_created_is_personal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let qa = qa_repo(&root, QA_POLICY);
    let addr = serve(&build_router(qa.state.clone())).await;
    let url = |user: &str, token: &str| format!("http://{user}:{token}@{addr}/git/auth/repo.git");
    let (mia_url, root_url) = (url("mia", &qa.mia_token), url("root", &qa.root_token));
    let work = tmp.path().to_path_buf();
    let (hers, theirs) = tokio::task::spawn_blocking(move || {
        let push = |url: &str, dir: &str, branch: &str| {
            let (ok, _, err) = try_git(&work, &["clone", "-q", url, dir]);
            assert!(ok, "{err}");
            let refspec = format!("origin/trunk:refs/heads/{branch}");
            let (ok, _, err) = try_git(&work.join(dir), &["push", "origin", &refspec]);
            assert!(ok, "{err}");
            err
        };
        (
            push(&mia_url, "mia", "mia-topic"),
            push(&root_url, "root", "root-topic"),
        )
    })
    .await
    .unwrap();
    let note = "remote: created 'mia-topic' as a personal branch (visible to you and owners)";
    assert!(hers.contains(note), "{hers}");
    assert_eq!(
        qa.state.branch_visibility_map()["refs/premier-private/mia-topic"],
        Visibility::Personal("@mia".to_owned())
    );
    // An owner's branch is as visible as what it forks from: nothing to point out.
    assert!(!theirs.contains("personal branch"), "{theirs}");
    assert_eq!(
        qa.state.branch_visibility_map()["refs/heads/root-topic"],
        Visibility::Public
    );
}

#[tokio::test]
async fn owner_branch_create_uses_cas_and_refuses_to_overwrite_existing_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    std::fs::create_dir(&root).unwrap();
    let qa = qa_repo(&root, QA_POLICY);
    let router = build_router(qa.state.clone());

    let create = |name: &str, from: &str| {
        let router = router.clone();
        let owner = qa.owner.clone();
        let body = json!({ "name": name, "from_ref": from });
        async move { send(&router, Method::POST, "/v1/branches/create", &owner, body).await }
    };

    // Creating a branch whose name is already taken (public or private) must fail with 409
    // instead of silently overwriting the existing ref.
    let (status, body) = create("trunk", "trunk").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (status, body) = create("cas-once", "trunk").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = create("cas-once", "trunk").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Two concurrent creates of the same branch: exactly one succeeds, the other gets 409.
    let ((s1, b1), (s2, b2)) =
        tokio::join!(create("cas-race", "trunk"), create("cas-race", "trunk"),);
    let mut statuses = [s1, s2];
    statuses.sort_by_key(|s| s.as_u16());
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::CONFLICT],
        "b1={b1}, b2={b2}"
    );
}

// ---------------------------------------------------------------------------
// Audit 1–4 regression tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn password_change_and_revoke_others_never_wipe_other_users_sessions() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, owner, mia, _) = repo(tmp.path());
    let router = build_router(state.clone());

    // Log Mia in a second time so she has two active sessions.
    let (status, set_cookie, _) = call(
        &router,
        Method::POST,
        "/v1/auth/login",
        &[],
        Some(json!({ "username": "mia", "password": crate::tests::PW })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mia_second = set_cookie.unwrap().split(';').next().unwrap().to_owned();

    // Mia revokes her other sessions -> her second session dies, owner's session survives.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/auth/sessions/revoke-others",
        &mia,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&router, "/v1/auth/sessions", &mia_second).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(&router, "/v1/auth/sessions", &mia).await.0,
        StatusCode::OK
    );
    assert_eq!(
        get(&router, "/v1/auth/sessions", &owner).await.0,
        StatusCode::OK
    );

    // Mia changes her password -> owner's session STILL survives.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/auth/password",
        &mia,
        json!({
            "current_password": crate::tests::PW,
            "new_password": "new correct horse battery"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        get(&router, "/v1/auth/sessions", &owner).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn host_env_never_leaks_into_dashboard_or_agent_sessions_and_dashboard_can_use_is_truthful() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, mia, _) = repo(root);
    state.allow_unsandboxed_agents = true;

    // `CARGO_PKG_NAME` is guaranteed present in the host test server process environment.
    assert!(std::env::var("CARGO_PKG_NAME").is_ok());

    let schema_toml = r#"
version = 1
repo_id = "acme/test"

[vars.CARGO_PKG_NAME]
type = "string"
sensitivity = "public"
required_in = ["prod"]

[vars.STRIPE_KEY]
type = "secret"
sensitivity = "secret"
zone = "billing"
required_in = ["prod"]
egress = { hosts = ["api.stripe.com"] }
"#;
    let schema = premier_secrets::EnvSchema::parse_toml(schema_toml).unwrap();
    *state.env_schema.write().unwrap() = Some(Arc::new(schema));

    let router = build_router(state.clone());

    // Dashboard must NOT treat host `CARGO_PKG_NAME` as configured (prod reports it missing).
    let (status, dash) = get(&router, "/v1/env/dashboard", &owner).await;
    assert_eq!(status, StatusCode::OK, "{dash}");
    let prod_issues = dash["reports"]["prod"]["issues"].as_array().unwrap();
    assert!(
        prod_issues
            .iter()
            .any(|i| i["var_name"] == "CARGO_PKG_NAME"),
        "host env leaked into dashboard validation: {dash}"
    );
    assert_eq!(dash["can_use"]["STRIPE_KEY"], true, "{dash}");

    // Owner inspecting `@mia` via `?principal=@mia` sees truthful `can_use = false` on billing secret.
    let (status, dash_as_mia) = get(&router, "/v1/env/dashboard?principal=@mia", &owner).await;
    assert_eq!(status, StatusCode::OK, "{dash_as_mia}");
    assert_eq!(dash_as_mia["can_use"]["STRIPE_KEY"], false, "{dash_as_mia}");

    // Member attempting `?principal=@owner` is ignored and cannot see billing secret.
    let (status, mia_dash) = get(&router, "/v1/env/dashboard?principal=@owner", &mia).await;
    assert_eq!(status, StatusCode::OK, "{mia_dash}");
    assert!(
        mia_dash["schema"]["vars"]["STRIPE_KEY"].is_null(),
        "member saw denied secret: {mia_dash}"
    );

    // Agent session must NOT receive host `CARGO_PKG_NAME` even though `.env.schema` lists it.
    let cmd = if cfg!(windows) {
        "Write-Output \"VAL=$env:CARGO_PKG_NAME\""
    } else {
        "echo \"VAL=$CARGO_PKG_NAME\""
    };
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": cmd }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut output: Vec<String> = Vec::new();
    for _ in 0..200 {
        let (_, list) = get(&router, "/v1/agents/sessions", &owner).await;
        if list[0]["status"] != "running" {
            output = serde_json::from_value(list[0]["output_lines"].clone()).unwrap();
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        output.iter().any(|l| l.trim() == "VAL="),
        "host CARGO_PKG_NAME leaked into agent session: {output:?}"
    );
}

#[tokio::test]
async fn reviews_enforce_ref_scoped_acl_multi_hunk_side_provenance_and_bounds() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = repo(root);

    // Policy: mia can READ `docs/guide.md` on `main`, NOT on `feature`; on `feature` she can READ
    // `multi.txt`, has ONLY `traverse` on `hidden/deep.txt` (via a rule that grants traverse only).
    let policy_toml = r#"
version = 1
[defaults]
public = []
authenticated = []
[[rules]]
id = "owners-all"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-docs-main-only"
effect = "allow"
principals = ["@mia"]
paths = ["docs/**"]
refs = ["main"]
capabilities = ["traverse", "list", "read"]
[[rules]]
id = "mia-multi-feature"
effect = "allow"
principals = ["@mia"]
paths = ["multi.txt"]
refs = ["feature"]
capabilities = ["traverse", "list", "read"]
[[rules]]
id = "mia-traverse-only"
effect = "allow"
principals = ["@mia"]
paths = ["secret_dir/clue.txt"]
refs = ["feature"]
capabilities = ["traverse"]
"#;
    set_policy(&state, policy_toml);

    // Create a multi-hunk commit on `feature` touching `multi.txt` (2 far-apart hunks),
    // `docs/guide.md` (readable on main, DENIED on feature!), and `secret_dir/clue.txt` (traverse-only).
    git(root, &["checkout", "-q", "feature"]);
    let mut lines: Vec<String> = (1..=40).map(|i| format!("line {i}")).collect();
    std::fs::write(root.join("multi.txt"), lines.join("\n") + "\n").unwrap();
    git(root, &["add", "multi.txt"]);
    git(root, &["commit", "-q", "-m", "base multi"]);

    lines[1] = "line 2 edited".to_owned();
    lines[37] = "line 38 edited".to_owned();
    std::fs::write(root.join("multi.txt"), lines.join("\n") + "\n").unwrap();
    std::fs::write(root.join("docs/guide.md"), "feature docs\n").unwrap();
    std::fs::create_dir_all(root.join("secret_dir")).unwrap();
    std::fs::write(root.join("secret_dir/clue.txt"), "clue\n").unwrap();
    git(
        root,
        &["add", "multi.txt", "docs/guide.md", "secret_dir/clue.txt"],
    );
    git(root, &["commit", "-q", "-m", "multi hunk change"]);
    git(root, &["checkout", "-q", "main"]);

    let router = build_router(state.clone());

    // Owner creates a review with captured provenance.
    let (status, created) = send(
        &router,
        Method::POST,
        "/v1/reviews",
        &owner,
        json!({
            "title": "Multi-hunk review",
            "branch": "feature",
            "prompt_summary": "Owner private prompt text"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let cid = created["change_id"].as_str().unwrap().to_owned();

    // Mia fetches reviews:
    // 1. `multi.txt` has TWO separate hunks with distinct `@@` headers!
    // 2. `docs/guide.md` is omitted (ref-scoped: readable on main, denied on feature!).
    // 3. `secret_dir/clue.txt` is omitted (`TRAVERSE`-only never leaks filename!).
    // 4. Owner's captured provenance is redacted from Mia, visible to Owner!
    let (status, mia_reviews) = get(&router, "/v1/reviews", &mia).await;
    assert_eq!(status, StatusCode::OK);
    let rev = &mia_reviews[0];
    let hunks = rev["rounds"][0]["hunks"].as_array().unwrap();
    assert_eq!(hunks.len(), 2, "expected 2 separate hunks: {hunks:?}");
    assert_eq!(hunks[0]["path"], "multi.txt");
    assert_eq!(hunks[1]["path"], "multi.txt");
    assert_ne!(hunks[0]["header"], hunks[1]["header"]);
    assert_ne!(hunks[0]["id"], hunks[1]["id"]);
    assert!(!mia_reviews.to_string().contains("docs/guide.md"));
    assert!(!mia_reviews.to_string().contains("secret_dir"));
    assert!(
        !mia_reviews
            .to_string()
            .contains("Owner private prompt text")
    );
    assert_eq!(hunks[0]["provenance"]["session_visible"], false);

    // Owner sees their own provenance.
    let (_, owner_reviews) = get(&router, "/v1/reviews", &owner).await;
    assert!(
        owner_reviews
            .to_string()
            .contains("Owner private prompt text")
    );

    // Commenting on `docs/guide.md` (allowed on main, denied on feature) is FORBIDDEN for Mia.
    let comment_uri = format!("/v1/reviews/{cid}/comments");
    let (status, _) = send(
        &router,
        Method::POST,
        &comment_uri,
        &mia,
        json!({ "path": "docs/guide.md", "line": 1, "side": "new", "body": "sneaky" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Valid comment on `multi.txt` with `side: "old"` persists cleanly; invalid side/size rejected.
    let (status, cmt) = send(
        &router,
        Method::POST,
        &comment_uri,
        &mia,
        json!({ "path": "multi.txt", "line": 2, "side": "old", "body": "old line note" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cmt}");
    assert_eq!(cmt["side"], "old");

    let (status, _) = send(
        &router,
        Method::POST,
        &comment_uri,
        &mia,
        json!({ "path": "multi.txt", "line": 2, "side": "invalid", "body": "x" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let big_body = "a".repeat(9 * 1024);
    let (status, _) = send(
        &router,
        Method::POST,
        &comment_uri,
        &mia,
        json!({ "path": "multi.txt", "body": big_body }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Verdict validation rejects unknown values and accepts canonical ones.
    let verdict_uri = format!("/v1/reviews/{cid}/verdict");
    assert_eq!(
        send(
            &router,
            Method::POST,
            &verdict_uri,
            &mia,
            json!({ "round": 1, "verdict": "lgtm" })
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(
            &router,
            Method::POST,
            &verdict_uri,
            &mia,
            json!({ "round": 1, "verdict": "approve" })
        )
        .await
        .0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn commit_session_enforces_overlay_guard_exposes_hidden_files_and_no_direct_declassify() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, _, _) = repo(root);
    state.allow_unsandboxed_agents = true;
    let policy_toml = r#"
version = 1
[defaults]
public = []
authenticated = []
[[rules]]
id = "owners-all"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[agent_profiles]]
name = "scoped"
allow_paths = ["README.md", "notes/**"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
"#;
    set_policy(&state, policy_toml);
    let router = build_router(state.clone());

    // Mount an overlay pattern `notes/*.local.md`.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/overlays/mount",
        &owner,
        json!({ "path": "notes/*.local.md", "scope": "personal" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Invalid overlay glob is rejected with 400.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/overlays/mount",
        &owner,
        json!({ "path": "notes/[unclosed", "scope": "personal" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Run a session that writes an overlay file -> commit MUST be blocked by OverlayGuard (403).
    let write_overlay = if cfg!(windows) {
        "New-Item -ItemType Directory -Force -Path notes | Out-Null; Set-Content -Path notes/todo.local.md -Value 'local only'"
    } else {
        "mkdir -p notes && printf 'local only' > notes/todo.local.md"
    };
    let (status, rec) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": write_overlay, "agent_profile": "scoped" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rec}");
    let sid = rec["id"].as_str().unwrap().to_owned();
    for _ in 0..200 {
        if state
            .session_manager
            .get(&sid)
            .is_some_and(|s| s.status != "running")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = send(
        &router,
        Method::POST,
        &format!("/v1/agents/sessions/{sid}/commit"),
        &owner,
        json!({ "message": "try leak overlay" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("overlay"),
        "{body}"
    );

    // Run a session on private branch `hush`, then try committing to a new Public branch -> 403!
    let edit_readme = if cfg!(windows) {
        "Set-Content -Path README.md -Value 'private edit'"
    } else {
        "printf 'private edit' > README.md"
    };
    let (status, rec2) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": edit_readme, "branch": "hush", "agent_profile": "scoped" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rec2}");
    let sid2 = rec2["id"].as_str().unwrap().to_owned();
    for _ in 0..200 {
        if state
            .session_manager
            .get(&sid2)
            .is_some_and(|s| s.status != "running")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = send(
        &router,
        Method::POST,
        &format!("/v1/agents/sessions/{sid2}/commit"),
        &owner,
        json!({ "new_branch": "escaped-pub", "visibility": { "scope": "public" } }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Ref-scoped `exposes_hidden_files` check on `new_branch`:
    // On `main`, `mia` cannot read `billing/**`, but on `sandbox/*` she CAN.
    // A session run as `mia` on `main` must NOT be committed onto `new_branch: "sandbox/unlock"`.
    let ref_scoped_policy = r#"
version = 1
[defaults]
public = []
authenticated = []
[[rules]]
id = "owners-all"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "mia-main-readme"
effect = "allow"
principals = ["@mia"]
paths = ["README.md"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write"]
[[rules]]
id = "mia-sandbox-all"
effect = "allow"
principals = ["@mia"]
paths = ["**"]
refs = ["sandbox/*"]
capabilities = ["traverse", "list", "read", "write"]
"#;
    set_policy(&state, ref_scoped_policy);
    let (status, rec3) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": edit_readme, "principal": "@mia", "branch": "main" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rec3}");
    let sid3 = rec3["id"].as_str().unwrap().to_owned();
    for _ in 0..200 {
        if state
            .session_manager
            .get(&sid3)
            .is_some_and(|s| s.status != "running")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = send(
        &router,
        Method::POST,
        &format!("/v1/agents/sessions/{sid3}/commit"),
        &owner,
        json!({ "new_branch": "sandbox/unlock" }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("expose files hidden"),
        "{body}"
    );
}

#[tokio::test]
async fn directory_member_scoping_secret_meta_env_keying_and_file_api_enhancements() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, mia, _) = repo(root);
    state.ssh_bind = Some("127.0.0.1:2222".parse().unwrap());
    let router = build_router(state.clone());

    // 1. `/health` reports `ssh_enabled` and `ssh_port` for authenticated users.
    let (status, health) = get(&router, "/health", &mia).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(health["ssh_enabled"], true);
    assert_eq!(health["ssh_port"], 2222);

    // 2. `/v1/directory`: owner sees everyone; member Mia sees ONLY herself.
    let (_, owner_dir) = get(&router, "/v1/directory", &owner).await;
    assert!(owner_dir["principals"].as_array().unwrap().len() >= 2);
    let (_, mia_dir) = get(&router, "/v1/directory", &mia).await;
    let mia_principals: Vec<&str> = mia_dir["principals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["principal"].as_str().unwrap())
        .collect();
    assert_eq!(mia_principals, ["@mia"], "{mia_dir}");

    // 3. `secret_meta` keyed by `env:var_name` keeps dev and prod independent.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/secrets/set",
        &owner,
        json!({ "key": "API_KEY", "value": "dev-val", "env": "dev" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/secrets/set",
        &owner,
        json!({ "key": "API_KEY", "value": "prod-val", "env": "prod" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sec_status) = get(&router, "/v1/secrets/status", &owner).await;
    assert_eq!(sec_status["entries"]["dev:API_KEY"]["env"], "dev");
    assert_eq!(sec_status["entries"]["prod:API_KEY"]["env"], "prod");

    let (status, _, _) = call(
        &router,
        Method::DELETE,
        "/v1/secrets/API_KEY?env=dev",
        &[("cookie", &owner)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, sec_status) = get(&router, "/v1/secrets/status", &owner).await;
    assert!(sec_status["entries"]["dev:API_KEY"].is_null());
    assert_eq!(sec_status["entries"]["prod:API_KEY"]["env"], "prod");

    // 4. `GET /v1/repo/file` returns `binary`, `tip_oid`, and respects `max_bytes`;
    //    `DELETE /v1/repo/file` works via query parameters without a body.
    let (status, file_resp) = get(
        &router,
        "/v1/repo/file?path=docs/guide.md&max_bytes=4",
        &owner,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{file_resp}");
    assert_eq!(file_resp["binary"], false);
    assert_eq!(file_resp["truncated"], true);
    assert_eq!(file_resp["content"], "guid");
    let tip = file_resp["tip_oid"].as_str().unwrap().to_owned();
    assert_eq!(tip.len(), 40);

    let (status, _, del_resp) = call(
        &router,
        Method::DELETE,
        &format!("/v1/repo/file?path=docs/guide.md&expected_tip={tip}"),
        &[("cookie", &owner)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{del_resp}");
    assert_eq!(del_resp["path"], "docs/guide.md");
}

// ---- policy intents (Two-Eyes Glass Wall) --------------------------------------------------

const PROPOSE_BASE: &str = r#"# Studio-authored policy: keep me
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]

[[rules]]
id = "owners-full-access" # owners first
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[agent_profiles]]
name = "ui-agent"
allow_paths = ["docs/**"]
capabilities = ["traverse", "list", "read"]
"#;

const SERVER_DOCS_PUBLIC: &str = r#"version = 1
[[rules]]
id = "server-docs-public"
effect = "allow"
principals = ["anonymous"]
paths = ["docs/**"]
capabilities = ["traverse", "list", "read"]
"#;

fn has_delta(body: &Value, principal: &str, profile: Option<&str>, path: &str, cap: &str) -> bool {
    body["deltas"].as_array().unwrap().iter().any(|d| {
        d["principal"] == principal
            && d["agent_profile"].as_str() == profile
            && d["path"] == path
            && d["revoked"].as_array().unwrap().contains(&json!(cap))
    })
}

#[tokio::test]
async fn policy_proposals_are_owner_only_and_report_revocations_and_server_overrides() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut state, owner, mia, mia_token) = repo(tmp.path());
    let (_, owner_token) = state.auth.seed("olga", crate::tests::PW);
    let router = build_router(state.clone());
    let intent = |kind: &str| json!({ "kind": kind, "target": { "kind": "dir", "path": "docs" } });
    let shield = json!({ "base_toml": PROPOSE_BASE, "intent": intent("shield_from_anonymous") });
    let plain_diff = json!({ "base_toml": PROPOSE_BASE, "head_toml": PROPOSE_BASE });

    // Members (session or token) and owner access tokens are refused.
    let mia_bearer = format!("Bearer {mia_token}");
    let owner_bearer = format!("Bearer {owner_token}");
    for headers in [
        [("cookie", mia.as_str())],
        [("authorization", mia_bearer.as_str())],
        [("authorization", owner_bearer.as_str())],
    ] {
        for (uri, body) in [
            ("/v1/policy/propose", &shield),
            ("/v1/policy/diff", &plain_diff),
            (
                "/v1/policy/explain-secrets",
                &json!({ "principal": "anonymous" }),
            ),
        ] {
            let (status, _, body) =
                call(&router, Method::POST, uri, &headers, Some(body.clone())).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri} {headers:?}: {body}");
        }
    }

    // The owner's proposal keeps the comments and changes nothing on disk.
    let before = state.current_repo_policy_toml();
    let propose = "/v1/policy/propose";
    let (status, body) = send(&router, Method::POST, propose, &owner, shield.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let proposed = body["proposed_toml"].as_str().unwrap().to_owned();
    assert!(
        proposed.contains("# Studio-authored policy: keep me"),
        "{proposed}"
    );
    assert!(proposed.contains("# owners first"), "{proposed}");
    let rule_id = body["rule_id"].as_str().unwrap();
    assert!(rule_id.starts_with("shield-anon-docs-"), "{body}");
    assert_eq!(body["validation_error"], Value::Null, "{body}");
    assert_eq!(body["server_policy_loaded"], false);
    assert_eq!(body["server_override_check"]["passed"], true);
    assert_eq!(body["target_paths"], json!(["docs"]));
    assert_eq!(state.current_repo_policy_toml(), before);

    // The diff reports the real revocation for anonymous, and nothing for agents.
    let diff = json!({
        "base_toml": PROPOSE_BASE, "head_toml": proposed, "include_agent_profiles": true,
    });
    let (status, body) = send(&router, Method::POST, "/v1/policy/diff", &owner, diff).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        has_delta(&body, "anonymous", None, "docs/guide.md", "read"),
        "{body}"
    );
    assert!(!body.to_string().contains("ui-agent"), "{body}");

    // Shielding docs from every agent shows up per (human, profile) only when asked for.
    let agents = json!({ "base_toml": PROPOSE_BASE, "intent": intent("shield_from_all_agents") });
    let (_, body) = send(&router, Method::POST, propose, &owner, agents).await;
    let head = body["proposed_toml"].as_str().unwrap().to_owned();
    let mut diff = json!({ "base_toml": PROPOSE_BASE, "head_toml": head });
    let (_, body) = send(
        &router,
        Method::POST,
        "/v1/policy/diff",
        &owner,
        diff.clone(),
    )
    .await;
    assert_eq!(body["deltas"], json!([]), "{body}");
    diff["include_agent_profiles"] = json!(true);
    diff["secret_probes"] = json!([{ "var_name": "STRIPE_API_KEY" }]);
    let (_, body) = send(
        &router,
        Method::POST,
        "/v1/policy/diff",
        &owner,
        diff.clone(),
    )
    .await;
    assert!(
        has_delta(&body, "@mia", Some("ui-agent"), "docs/guide.md", "read"),
        "{body}"
    );
    assert!(
        has_delta(&body, "@owner", Some("ui-agent"), "docs/guide.md", "read"),
        "{body}"
    );
    // `@user::profile` names one delegated identity.
    diff["include_agent_profiles"] = json!(false);
    diff["principals"] = json!(["@owner::ui-agent"]);
    let (_, body) = send(&router, Method::POST, "/v1/policy/diff", &owner, diff).await;
    assert!(
        has_delta(&body, "@owner", Some("ui-agent"), "docs/guide.md", "read"),
        "{body}"
    );
    assert!(!body.to_string().contains("@mia"), "{body}");

    // A proposal that leaves the owners without the policy file is flagged, not refused.
    let lockout = json!({
        "base_toml": "version = 1\n",
        "intent": {
            "kind": "shield_from_anonymous",
            "target": { "kind": "file", "path": "README.md" },
        },
    });
    let (status, body) = send(&router, Method::POST, propose, &owner, lockout).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let error = body["validation_error"].as_str().unwrap();
    assert!(error.contains("lock the owners out"), "{body}");

    // A malformed intent is a 400.
    let bad = json!({
        "base_toml": PROPOSE_BASE,
        "intent": {
            "kind": "shield_from_anonymous",
            "target": { "kind": "zone", "zone": "nope" },
        },
    });
    let (status, _) = send(&router, Method::POST, propose, &owner, bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A server rule that re-opens docs to anonymous is reported as an override.
    state.server_policy_toml = Some(SERVER_DOCS_PUBLIC.to_owned());
    let router = build_router(state.clone());
    let (status, body) = send(&router, Method::POST, propose, &owner, shield).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["server_policy_loaded"], true);
    let check = &body["server_override_check"];
    assert_eq!(check["passed"], false, "{body}");
    assert!(check["total_overrides"].as_u64().unwrap() >= 1, "{body}");
    let finding = check["overrides"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["principal"] == "anonymous" && f["path"] == "docs/guide.md")
        .unwrap();
    assert_eq!(finding["repo_only_effective"], json!([]));
    let with_server = finding["effective_with_server"].as_array().unwrap();
    assert!(with_server.contains(&json!("read")), "{body}");
    assert_eq!(finding["server_rules"][0]["id"], "server-docs-public");

    // `PUT /v1/policy/repo` rejects stale `expected_base_sha256` with 409 Conflict and accepts matching hash.
    let (_, current_prop) = send(
        &router,
        Method::POST,
        propose,
        &owner,
        json!({ "intent": intent("shield_from_anonymous") }),
    )
    .await;
    let base_sha = current_prop["base_sha256"].as_str().unwrap().to_owned();
    let new_toml = current_prop["proposed_toml"].as_str().unwrap().to_owned();
    let (status, _) = send(
        &router,
        Method::PUT,
        "/v1/policy/repo",
        &owner,
        json!({ "toml": new_toml, "expected_base_sha256": "0000000000000000" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &router,
        Method::PUT,
        "/v1/policy/repo",
        &owner,
        json!({ "toml": new_toml, "expected_base_sha256": base_sha }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Re-applying against the superseded base hash now conflicts with 409.
    let (status, _) = send(
        &router,
        Method::PUT,
        "/v1/policy/repo",
        &owner,
        json!({ "toml": new_toml, "expected_base_sha256": base_sha }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // `/v1/policy/explain-secrets` returns server-evaluated `can_use` (`use ≠ read`) per identity.
    let schema = premier_secrets::EnvSchema::parse_toml(
        r#"
version = 1
[vars.PUBLIC_FLAG]
type = "string"
sensitivity = "public"
[vars.STRIPE_API_KEY]
type = "secret"
sensitivity = "restricted"
zone = "billing"
[vars.STRIPE_API_KEY.egress]
hosts = ["api.stripe.com"]
approval = "jit"
"#,
    )
    .unwrap();
    *state.env_schema.write().unwrap() = Some(Arc::new(schema));
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/policy/explain-secrets",
        &owner,
        json!({ "principal": "anonymous" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let entries = body["entries"].as_array().unwrap();
    assert_eq!(
        entries.iter().find(|e| e["name"] == "PUBLIC_FLAG").unwrap()["can_use"],
        true
    );
    assert_eq!(
        entries
            .iter()
            .find(|e| e["name"] == "STRIPE_API_KEY")
            .unwrap()["can_use"],
        false
    );
}

#[tokio::test]
async fn hygiene_and_step_in_endpoints_are_strictly_owner_browser_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, mia_token) = repo(root);
    let (_, owner_token) = state.auth.seed("olga", crate::tests::PW);
    // Commit an unzoned sensitive directory (`payroll/`) while public defaults allow read.
    std::fs::create_dir_all(root.join("payroll")).unwrap();
    std::fs::write(root.join("payroll/salaries.csv"), "name,usd\n").unwrap();
    git(root, &["add", "payroll/salaries.csv"]);
    git(root, &["commit", "-q", "-m", "add payroll"]);
    set_policy(
        &state,
        r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
authenticated = ["traverse", "list", "read"]
[[rules]]
id = "owners-all"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#,
    );

    let router = build_router(state);
    let mia_bearer = format!("Bearer {mia_token}");
    let owner_bearer = format!("Bearer {owner_token}");

    let checks: Vec<(Method, &str, Option<Value>)> = vec![
        (Method::GET, "/v1/hygiene/insights", None),
        (
            Method::POST,
            "/v1/hygiene/dismiss",
            Some(json!({ "id": "unzoned-dir:payroll" })),
        ),
        (
            Method::POST,
            "/v1/hygiene/restore",
            Some(json!({ "id": "unzoned-dir:payroll" })),
        ),
        (
            Method::POST,
            "/v1/agents/sessions/cage-0001/pause",
            Some(json!({})),
        ),
        (
            Method::GET,
            "/v1/agents/sessions/cage-0001/workspace/files",
            None,
        ),
        (
            Method::GET,
            "/v1/agents/sessions/cage-0001/workspace/file?path=README.md",
            None,
        ),
        (
            Method::PUT,
            "/v1/agents/sessions/cage-0001/workspace/file",
            Some(json!({ "path": "README.md", "content": "x" })),
        ),
        (
            Method::POST,
            "/v1/agents/sessions/cage-0001/checkpoint",
            Some(json!({ "label": "cp" })),
        ),
        (
            Method::POST,
            "/v1/agents/sessions/cage-0001/resume",
            Some(json!({ "command": "echo hi" })),
        ),
    ];

    for (method, uri, body) in checks {
        let (s_mia, _, b_mia) = call(
            &router,
            method.clone(),
            uri,
            &[("cookie", mia.as_str())],
            body.clone(),
        )
        .await;
        assert_eq!(
            s_mia,
            StatusCode::FORBIDDEN,
            "mia cookie {method} {uri}: {b_mia}"
        );

        let (s_mtok, _, b_mtok) = call(
            &router,
            method.clone(),
            uri,
            &[("authorization", mia_bearer.as_str())],
            body.clone(),
        )
        .await;
        assert_eq!(
            s_mtok,
            StatusCode::FORBIDDEN,
            "mia token {method} {uri}: {b_mtok}"
        );

        let (s_otok, _, b_otok) = call(
            &router,
            method.clone(),
            uri,
            &[("authorization", owner_bearer.as_str())],
            body,
        )
        .await;
        assert_eq!(
            s_otok,
            StatusCode::FORBIDDEN,
            "owner token {method} {uri}: {b_otok}"
        );
    }

    // Owner browser session gets hygiene insights and dismiss/restore round-trips cleanly.
    let (status, body) = get(&router, "/v1/hygiene/insights", &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let insights = body["insights"].as_array().unwrap();
    assert!(
        insights.iter().any(|i| i["id"] == "unzoned-dir:payroll"),
        "{body}"
    );
    let initial_active = body["active_count"].as_u64().unwrap();
    assert_eq!(body["dismissed_count"], 0);

    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/hygiene/dismiss",
        &owner,
        json!({ "id": "unzoned-dir:payroll" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = get(&router, "/v1/hygiene/insights", &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active_count"], initial_active - 1, "{body}");
    assert_eq!(body["dismissed_count"], 1, "{body}");
    assert!(
        !body["insights"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["id"] == "unzoned-dir:payroll"),
        "{body}"
    );

    let (status, body) = get(
        &router,
        "/v1/hygiene/insights?include_dismissed=true",
        &owner,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let dismissed_item = body["insights"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == "unzoned-dir:payroll")
        .unwrap();
    assert_eq!(dismissed_item["dismissed"], true);

    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/hygiene/restore",
        &owner,
        json!({ "id": "unzoned-dir:payroll" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = get(&router, "/v1/hygiene/insights", &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["active_count"], initial_active, "{body}");
    assert_eq!(body["dismissed_count"], 0, "{body}");
}

#[tokio::test]
async fn members_never_receive_session_insights_or_checkpoints_in_api_or_sse() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, owner, mia, _) = repo(root);
    let main = git(root, &["rev-parse", "main"]);
    let insight = runner::SessionInsight {
        id: "cage-0001:repeated-blocks".to_owned(),
        session_id: "cage-0001".to_owned(),
        kind: runner::SessionInsightKind::RepeatedBlocks,
        severity: runner::InsightSeverity::Attention,
        title: "3 blocked actions in 60s".to_owned(),
        detail: "Owner-only thrashing telemetry".to_owned(),
        observed_at: "2026-11-22T20:00:00Z".to_owned(),
        metric_value: 3,
        threshold: 3,
    };
    let checkpoint = runner::SessionCheckpoint {
        id: "cp-1".to_owned(),
        label: "Owner secret step-in note".to_owned(),
        created_at: "2026-11-22T20:01:00Z".to_owned(),
        author: "@owner".to_owned(),
        edited_paths: vec!["README.md".to_owned()],
    };
    let session = runner::AgentSessionRecord {
        id: "cage-0001".to_owned(),
        principal: "@mia".to_owned(),
        status: "paused".to_owned(),
        branch: "main".to_owned(),
        base_commit: Some(main),
        output_lines: vec![
            "agent stdout".to_owned(),
            "[step-in] checkpoint cp-001: Owner secret step-in note (1 changed path)".to_owned(),
            "[cage] paused by owner for human step-in (workspace preserved)".to_owned(),
        ],
        insights: vec![insight.clone()],
        checkpoints: vec![checkpoint],
        resumed_from: Some("cage-0000".to_owned()),
        ..Default::default()
    };
    crate::store::save_json(root, "sessions.json", &[session]).unwrap();
    state.session_manager = Arc::new(runner::SessionManager::open(root));
    let router = build_router(state.clone());

    // Owner sees insights, checkpoints, resumed_from, and step-in log lines; member (@mia) sees
    // none of those even on her own session (while normal agent stdout remains).
    let (status, owner_list) = get(&router, "/v1/agents/sessions", &owner).await;
    assert_eq!(status, StatusCode::OK, "{owner_list}");
    assert_eq!(owner_list[0]["insights"].as_array().unwrap().len(), 1);
    assert_eq!(owner_list[0]["checkpoints"].as_array().unwrap().len(), 1);
    assert_eq!(owner_list[0]["resumed_from"], json!("cage-0000"));
    assert!(
        owner_list
            .to_string()
            .contains("[step-in] checkpoint cp-001")
    );

    let (status, mia_list) = get(&router, "/v1/agents/sessions", &mia).await;
    assert_eq!(status, StatusCode::OK, "{mia_list}");
    assert_eq!(mia_list[0]["insights"], json!([]), "{mia_list}");
    assert_eq!(mia_list[0]["checkpoints"], json!([]), "{mia_list}");
    assert_eq!(mia_list[0]["resumed_from"], Value::Null, "{mia_list}");
    assert_eq!(
        mia_list[0]["output_lines"],
        json!(["agent stdout"]),
        "{mia_list}"
    );
    assert!(
        !mia_list
            .to_string()
            .contains("Owner-only thrashing telemetry")
    );
    assert!(!mia_list.to_string().contains("Owner secret step-in note"));
    assert!(!mia_list.to_string().contains("cage-0000"));
    assert!(!mia_list.to_string().contains("[step-in]"));
    assert!(!mia_list.to_string().contains("[cage] paused by owner"));

    // Connect both owner and mia to live SSE and broadcast a session_insight.
    let open_sse = |cookie: &str| {
        let req = Request::builder()
            .uri("/v1/events/stream")
            .header("host", "localhost")
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap();
        oneshot(router.clone(), req)
    };
    let mut owner_stream = open_sse(&owner).await.into_body();
    let mut mia_stream = open_sse(&mia).await.into_body();

    // Drain initial ready frames so subscriptions are active before recording the insight.
    for stream in [&mut owner_stream, &mut mia_stream] {
        let first = tokio::time::timeout(Duration::from_secs(5), stream.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        assert!(String::from_utf8_lossy(&first).contains("ready"));
    }

    state
        .session_manager
        .record_insight(runner::SessionInsight {
            id: "cage-0001:error-loop-churn".to_owned(),
            kind: runner::SessionInsightKind::ErrorLoopChurn,
            title: "Repeated stderr loop".to_owned(),
            detail: "12 errors without progress".to_owned(),
            metric_value: 12,
            threshold: 12,
            ..insight
        });

    // Owner must receive `event: session_insight` and `event: session`.
    let mut owner_seen = String::new();
    while !owner_seen.contains("event: session_insight") {
        let frame = tokio::time::timeout(Duration::from_secs(5), owner_stream.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        owner_seen.push_str(&String::from_utf8_lossy(&frame));
    }
    assert!(owner_seen.contains("Repeated stderr loop"), "{owner_seen}");

    // Member receives `event: session` (stripped) and NEVER `event: session_insight`.
    let mut mia_seen = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(100), mia_stream.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(bytes) = frame.into_data() {
                    mia_seen.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
            _ => break,
        }
    }
    assert!(!mia_seen.contains("event: session_insight"), "{mia_seen}");
    assert!(!mia_seen.contains("Repeated stderr loop"), "{mia_seen}");
    assert!(
        !mia_seen.contains("Owner secret step-in note"),
        "{mia_seen}"
    );
    assert!(!mia_seen.contains("cage-0000"), "{mia_seen}");
    assert!(!mia_seen.contains("[step-in]"), "{mia_seen}");
    assert!(!mia_seen.contains("[cage] paused by owner"), "{mia_seen}");
    assert!(mia_seen.contains("event: session"), "{mia_seen}");
    assert!(mia_seen.contains("\"insights\":[]"), "{mia_seen}");
    assert!(mia_seen.contains("\"checkpoints\":[]"), "{mia_seen}");
}

// ---- Track B Wave 1 Security & Correctness P0 regressions ----------------------------------

const TRACK_B_AGENT_POLICY: &str = r#"version = 1
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

[[agent_profiles]]
name = "ui-agent"
allow_paths = ["docs/**"]
capabilities = ["traverse", "list", "read"]

[[agent_profiles]]
name = "ops-agent"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read", "use"]
"#;

#[tokio::test]
async fn track_b_agent_scoped_pat_enforced_across_http_git_and_oidc() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner_cookie, _, _) = repo(root);
    set_policy(&state, TRACK_B_AGENT_POLICY);
    let router = build_router(state.clone());

    // Mint a human PAT and an agent-scoped PAT (`ui-agent`) for the owner.
    let (st, human_tok_resp) = send(
        &router,
        Method::POST,
        "/v1/auth/tokens",
        &owner_cookie,
        json!({ "name": "human-ci" }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{human_tok_resp}");
    let human_pat = human_tok_resp["token"].as_str().unwrap().to_owned();

    let (st, agent_tok_resp) = send(
        &router,
        Method::POST,
        "/v1/auth/tokens",
        &owner_cookie,
        json!({ "name": "ui-bot", "agent_profile": "ui-agent" }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{agent_tok_resp}");
    let agent_pat = agent_tok_resp["token"].as_str().unwrap().to_owned();
    let agent_auth = format!("Bearer {agent_pat}");
    let human_auth = format!("Bearer {human_pat}");

    // 1. HTTP file read WITHOUT `?agent_profile=` MUST still enforce `ui-agent` (cannot read README.md).
    let (st, _, body) = call(
        &router,
        Method::GET,
        "/v1/repo/file?path=README.md",
        &[("authorization", &agent_auth)],
        None,
    )
    .await;
    assert!(
        st == StatusCode::FORBIDDEN
            || st == StatusCode::NOT_FOUND
            || (st == StatusCode::OK
                && body["allowed"] == false
                && body.get("content").is_none_or(Value::is_null)),
        "agent-scoped PAT must not read outside ui-agent allow_paths: {st} {body}"
    );

    // Reading inside `docs/**` succeeds without repeating `?agent_profile=`.
    let (st, _, body) = call(
        &router,
        Method::GET,
        "/v1/repo/file?path=docs/guide.md",
        &[("authorization", &agent_auth)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");

    // Passing a mismatched `?agent_profile=ops-agent` MUST be rejected with 403 Forbidden.
    let (st, _, body) = call(
        &router,
        Method::GET,
        "/v1/repo/file?path=docs/guide.md&agent_profile=ops-agent",
        &[("authorization", &agent_auth)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{body}");

    // Passing the matching `?agent_profile=ui-agent` succeeds.
    let (st, _, body) = call(
        &router,
        Method::GET,
        "/v1/repo/file?path=docs/guide.md&agent_profile=ui-agent",
        &[("authorization", &agent_auth)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");

    // 2. OIDC token minting enforces `user.agent_profile` (cannot mint human-only or different profile).
    let (st, _, oidc_resp) = call(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &[("authorization", &agent_auth)],
        Some(json!({})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{oidc_resp}");
    assert_eq!(
        oidc_resp["claims"]["act"]["profile"], "ui-agent",
        "agent-scoped PAT must not mint a human-only OIDC token: {oidc_resp}"
    );

    let (st, _, oidc_mismatch) = call(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &[("authorization", &agent_auth)],
        Some(json!({ "agent_profile": "ops-agent" })),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN, "{oidc_mismatch}");

    let (st, _, oidc_same) = call(
        &router,
        Method::POST,
        "/v1/oidc/token",
        &[("authorization", &agent_auth)],
        Some(json!({ "agent_profile": "ui-agent" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{oidc_same}");
    assert_eq!(oidc_same["claims"]["act"]["profile"], "ui-agent");

    // 3. Git HTTP propagates `agent_profile` into `DelegatedIdentity` (projected OID differs from human).
    let mut ls_refs = premier_git_bridge::http_v2::encode_pkt_line(b"command=ls-refs\n");
    ls_refs.extend_from_slice(b"00010000");
    let req_git = |auth_hdr: &str| {
        Request::builder()
            .method(Method::POST)
            .uri("/git/repo.git/git-upload-pack")
            .header("host", "localhost")
            .header("authorization", auth_hdr)
            .header("git-protocol", "version=2")
            .body(Body::from(ls_refs.clone()))
            .unwrap()
    };
    let human_git = oneshot(router.clone(), req_git(&human_auth)).await;
    assert_eq!(human_git.status(), StatusCode::OK);
    let human_bytes = human_git.into_body().collect().await.unwrap().to_bytes();
    let human_refs = String::from_utf8_lossy(&human_bytes).into_owned();

    let agent_git = oneshot(router.clone(), req_git(&agent_auth)).await;
    assert_eq!(agent_git.status(), StatusCode::OK);
    let agent_bytes = agent_git.into_body().collect().await.unwrap().to_bytes();
    let agent_refs = String::from_utf8_lossy(&agent_bytes).into_owned();

    let real_main_oid = git(root, &["rev-parse", "refs/heads/main"]);
    assert!(
        human_refs.contains(&real_main_oid),
        "human PAT sees full main OID: {human_refs}"
    );
    assert!(
        agent_refs.contains("refs/heads/main") && !agent_refs.contains(&real_main_oid),
        "agent-scoped PAT must receive a narrowed projection, never the full human tree: {agent_refs}"
    );
}

#[tokio::test]
async fn track_b_envelope_kms_schema_dashboard_mcp_and_github_vault_isolation() {
    use premier_secrets::{EnvSchema, SecretCoord, SecretLayer};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner_cookie, _, _) = repo(root);
    set_policy(&state, TRACK_B_AGENT_POLICY);
    let schema = EnvSchema::parse_toml(
        r#"
repo_id = "acme/app"
[vars.API_KEY]
type = "secret"
sensitivity = "secret"
required_in = ["dev"]
"#,
    )
    .unwrap();
    *state.env_schema.write().unwrap() = Some(Arc::new(schema.clone()));

    // 1. Store workspace secret AND GitHub companion token: zero `repo_id` collision!
    {
        let mut st = state.persisted.lock().unwrap();
        crate::store::set_workspace_secret(
            root,
            "acme/app",
            "dev",
            "API_KEY",
            "sk_live_trackb_secret",
            &mut st,
        )
        .unwrap();
    }
    crate::store::store_github_token(
        root,
        crate::store::GITHUB_VAULT_REPO_ID,
        "ghp_isolated_trackb_token",
    )
    .unwrap();
    assert!(crate::store::age_vault_path(root).exists());
    assert!(crate::store::github_age_vault_path(root).exists());
    assert_eq!(
        crate::store::load_github_token(root, crate::store::GITHUB_VAULT_REPO_ID)
            .unwrap()
            .unwrap()
            .as_str(),
        "ghp_isolated_trackb_token"
    );

    // 2. Migrate to Envelope KMS: both workspace vault and GitHub vault migrate cleanly,
    //    and `vault.toml` / `github.vault.toml` are retired.
    let (migrated, already) =
        crate::lifecycle::migrate_to_envelope(root, "acme/app", "@owner").unwrap();
    assert_eq!(migrated, 1);
    assert!(!already);
    assert!(crate::store::envelope_vault_path(root).exists());
    assert!(!crate::store::age_vault_path(root).exists());
    assert!(crate::store::github_envelope_vault_path(root).exists());
    assert!(!crate::store::github_age_vault_path(root).exists());

    // DEK rotation rotates both workspace and GitHub envelope vaults cleanly.
    let ver = crate::lifecycle::rotate_workspace_dek(root, "acme/app").unwrap();
    assert_eq!(ver, 2);
    assert_eq!(
        crate::store::load_github_token(root, crate::store::GITHUB_VAULT_REPO_ID)
            .unwrap()
            .unwrap()
            .as_str(),
        "ghp_isolated_trackb_token"
    );

    // 3. `schema_dashboard_handler` reads from Envelope KMS even though `vault.toml` is gone.
    let router = build_router(state.clone());
    let (st, dash) = get(&router, "/v1/env/dashboard", &owner_cookie).await;
    assert_eq!(st, StatusCode::OK, "{dash}");
    assert_eq!(
        dash["reports"]["dev"]["issues"],
        json!([]),
        "dashboard must validate secrets stored in Envelope KMS: {dash}"
    );

    // 4. `resolve_vault_backend` (used by `mcp_gateway::resolve_secrets`) reads from Envelope KMS.
    let backend = crate::store::resolve_vault_backend(root, "acme/app").unwrap();
    let val = backend
        .get(&SecretCoord {
            repo_id: "acme/app".to_owned(),
            layer: SecretLayer::Env,
            scope: "dev".to_owned(),
            var_name: "API_KEY".to_owned(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(val.as_str(), "sk_live_trackb_secret");
}

#[tokio::test]
async fn track_b_fail_closed_state_age_key_aad_backup_lock_approvals_and_proxy_ca() {
    use premier_secrets::{AgeSovereignBackend, SecretBackend, SecretCoord, SecretLayer};

    // 1. Fail-closed `load_state`.
    let state_tmp = tempfile::tempdir().unwrap();
    assert!(
        crate::store::load_state(state_tmp.path())
            .unwrap()
            .branch_metadata
            .is_empty()
    );
    let sp = crate::store::state_file_path(state_tmp.path());
    std::fs::create_dir_all(sp.parent().unwrap()).unwrap();
    std::fs::write(&sp, "{not-valid-json").unwrap();
    assert!(
        crate::store::load_state(state_tmp.path()).is_err(),
        "corrupt state.json must fail closed"
    );

    // 2. `load_or_create_workspace_age_identity`: never overwrite corrupt key; concurrent race safe.
    let age_corrupt = tempfile::tempdir().unwrap();
    let kp = crate::store::age_key_path(age_corrupt.path());
    std::fs::create_dir_all(kp.parent().unwrap()).unwrap();
    std::fs::write(&kp, "# corrupt key without AGE-SECRET-KEY\n").unwrap();
    assert!(crate::store::load_or_create_workspace_age_identity(age_corrupt.path()).is_err());
    assert_eq!(
        std::fs::read_to_string(&kp).unwrap(),
        "# corrupt key without AGE-SECRET-KEY\n",
        "corrupt age.key must never be overwritten"
    );

    let age_race = tempfile::tempdir().unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let p = age_race.path().to_path_buf();
        let b = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            b.wait();
            crate::store::load_or_create_workspace_age_identity(&p)
                .unwrap()
                .to_public()
                .to_string()
        }));
    }
    let pubs: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(
        pubs.iter().all(|pk| pk == &pubs[0]),
        "concurrent age.key creation must converge to a single identity: {pubs:?}"
    );

    // 3. Path-decoupled AEAD AAD + backup/restore of oidc.key, oidc_revoked.json, github.vault.toml.
    let src_tmp = tempfile::tempdir().unwrap();
    let dst_tmp = tempfile::tempdir().unwrap();
    let dst_state_tmp = tempfile::tempdir().unwrap();
    let coord = SecretCoord {
        repo_id: "acme/portable".to_owned(),
        layer: SecretLayer::Env,
        scope: "prod".to_owned(),
        var_name: "DB_PASS".to_owned(),
    };
    crate::store::open_workspace_vault(src_tmp.path(), "acme/portable")
        .unwrap()
        .set(&coord, "portable_secret_value")
        .unwrap();
    crate::store::store_github_token(
        src_tmp.path(),
        crate::store::GITHUB_VAULT_REPO_ID,
        "ghp_portable_backup_tok",
    )
    .unwrap();
    let _issuer = crate::lifecycle::load_oidc_issuer(src_tmp.path(), true);
    crate::store::save_json_in(
        &crate::store::account_dir(src_tmp.path()),
        "oidc_revoked.json",
        &json!({ "@revoked": 1_700_000_000_i64 }),
    )
    .unwrap();

    let archive_bytes = crate::ops::build_backup(src_tmp.path(), None, &[]).unwrap();
    let archive_path = dst_tmp.path().join("backup.tar.gz");
    std::fs::write(&archive_path, archive_bytes).unwrap();
    let restored_ws = dst_tmp.path().join("restored-repo");
    crate::store::bind_state_dir(&restored_ws, dst_state_tmp.path(), "restored", true);
    crate::ops::restore_archive(&archive_path, &restored_ws, false).unwrap();

    // `oidc.key` and `oidc_revoked.json` must be restored into `account_dir` (ACCOUNT_FILES).
    let restored_account = crate::store::account_dir(&restored_ws);
    assert!(restored_account.join("oidc.key").exists());
    assert!(restored_account.join("oidc_revoked.json").exists());
    // Vault and GitHub vault must decrypt cleanly at the new host path (path-decoupled AAD).
    let decrypted = crate::store::open_workspace_vault(&restored_ws, "acme/portable")
        .unwrap()
        .get(&coord)
        .unwrap()
        .unwrap();
    assert_eq!(decrypted.as_str(), "portable_secret_value");
    assert_eq!(
        crate::store::load_github_token(&restored_ws, crate::store::GITHUB_VAULT_REPO_ID)
            .unwrap()
            .unwrap()
            .as_str(),
        "ghp_portable_backup_tok"
    );
    crate::store::unbind_state_dir(&restored_ws);

    // `adopt_legacy_state` routes `oidc.key` and `oidc_revoked.json` into `account/`.
    let legacy_adopt = tempfile::tempdir().unwrap();
    let adopt_state = tempfile::tempdir().unwrap();
    let legacy_dir = legacy_adopt.path().join(".premier");
    std::fs::create_dir_all(&legacy_dir).unwrap();
    std::fs::write(legacy_dir.join("oidc.key"), "00".repeat(32)).unwrap();
    std::fs::write(legacy_dir.join("oidc_revoked.json"), "{}").unwrap();
    crate::store::bind_state_dir(legacy_adopt.path(), adopt_state.path(), "adopt", true);
    crate::store::adopt_legacy_state(legacy_adopt.path()).unwrap();
    assert!(
        crate::store::account_dir(legacy_adopt.path())
            .join("oidc.key")
            .exists()
    );
    assert!(
        crate::store::account_dir(legacy_adopt.path())
            .join("oidc_revoked.json")
            .exists()
    );
    crate::store::unbind_state_dir(legacy_adopt.path());

    // Legacy absolute-path vault read-fallback still decrypts existing vaults.
    let legacy_aad = tempfile::tempdir().unwrap();
    let id = crate::store::load_or_create_workspace_age_identity(legacy_aad.path()).unwrap();
    let vpath = crate::store::age_vault_path(legacy_aad.path());
    AgeSovereignBackend::new(&vpath, "acme/legacy", vpath.to_string_lossy(), id, vec![])
        .with_key_transparency(crate::store::kt_path(legacy_aad.path()))
        .set(
            &SecretCoord {
                repo_id: "acme/legacy".to_owned(),
                layer: SecretLayer::Env,
                scope: "dev".to_owned(),
                var_name: "OLD_SECRET".to_owned(),
            },
            "legacy_abs_value",
        )
        .unwrap();
    let legacy_val = crate::store::open_workspace_vault(legacy_aad.path(), "acme/legacy")
        .unwrap()
        .get(&SecretCoord {
            repo_id: "acme/legacy".to_owned(),
            layer: SecretLayer::Env,
            scope: "dev".to_owned(),
            var_name: "OLD_SECRET".to_owned(),
        })
        .unwrap()
        .unwrap();
    assert_eq!(legacy_val.as_str(), "legacy_abs_value");

    // 4. `AuthStore::txn` OS-level lock prevents lost updates across concurrent store handles.
    let auth_tmp = tempfile::tempdir().unwrap();
    let seed_store = crate::auth::AuthStore::open(auth_tmp.path());
    let _ = seed_store.seed("owner", "StrongPass!123");
    let auth_barrier = Arc::new(std::sync::Barrier::new(8));
    let mut auth_handles = Vec::new();
    for i in 0..8 {
        let p = auth_tmp.path().to_path_buf();
        let b = Arc::clone(&auth_barrier);
        auth_handles.push(std::thread::spawn(move || {
            let store = crate::auth::AuthStore::open(&p);
            b.wait();
            store
                .txn(|d| {
                    let _ = d.new_token("owner", &format!("tok-{i}"), None, None);
                })
                .unwrap();
        }));
    }
    for h in auth_handles {
        h.join().unwrap();
    }
    let raw_auth = crate::auth::AuthStore::open(auth_tmp.path())
        .txn(|d| serde_json::to_string(d).unwrap())
        .unwrap();
    for i in 0..8 {
        assert!(
            raw_auth.contains(&format!("tok-{i}")),
            "concurrent AuthStore::txn lost tok-{i}"
        );
    }

    // 5. `GET /v1/approvals` uses `owner_only()`: owner PAT cannot view another user's approvals.
    let ap_tmp = tempfile::tempdir().unwrap();
    let (mut state, owner_cookie, _, _) = repo(ap_tmp.path());
    set_policy(&state, TRACK_B_AGENT_POLICY);
    state.allow_unsandboxed_agents = true;
    let router = build_router(state.clone());
    let (st, pat_resp) = send(
        &router,
        Method::POST,
        "/v1/auth/tokens",
        &owner_cookie,
        json!({ "name": "owner-pat" }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{pat_resp}");
    let owner_pat = format!("Bearer {}", pat_resp["token"].as_str().unwrap());

    let _mia_pending = state.approval_hub.enqueue(premier_proxy::ApprovalRequest {
        principal: "@mia".to_owned(),
        agent_profile: Some("ui-agent".to_owned()),
        var_name: "STRIPE_KEY".to_owned(),
        host: "api.example.com".to_owned(),
        method: "POST".to_owned(),
        path: "/v1/charge".to_owned(),
        ttl_secs: 60,
        ..premier_proxy::ApprovalRequest::default()
    });

    let (st, owner_session_approvals) = get(&router, "/v1/approvals", &owner_cookie).await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        owner_session_approvals
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["principal"] == "@mia"),
        "owner browser session should see @mia approval: {owner_session_approvals}"
    );

    let (st, _, owner_pat_approvals) = call(
        &router,
        Method::GET,
        "/v1/approvals",
        &[("authorization", &owner_pat)],
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        owner_pat_approvals
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["principal"] != "@mia"),
        "owner PAT must not see other users' approvals: {owner_pat_approvals}"
    );

    // 6. Server-launched agents receive the proxy ephemeral CA cert env vars.
    let probe_cmd = if cfg!(windows) {
        "Write-Output \"SSL=$($env:SSL_CERT_FILE)\"; Write-Output \"NODE=$($env:NODE_EXTRA_CA_CERTS)\"; Write-Output \"CURL=$($env:CURL_CA_BUNDLE)\"; Get-Content -First 1 $env:SSL_CERT_FILE"
    } else {
        "echo SSL=$SSL_CERT_FILE; echo NODE=$NODE_EXTRA_CA_CERTS; echo CURL=$CURL_CA_BUNDLE; head -n 1 \"$SSL_CERT_FILE\""
    };
    let (st, launched) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner_cookie,
        json!({
            "principal": "@owner",
            "agent_profile": "ui-agent",
            "command": probe_cmd,
        }),
    )
    .await;
    assert!(st.is_success(), "{st}: {launched}");
    let sid = launched["id"].as_str().unwrap().to_owned();
    let mut final_output = String::new();
    for _ in 0..80 {
        let (list_st, list_body) = get(&router, "/v1/agents/sessions", &owner_cookie).await;
        assert_eq!(list_st, StatusCode::OK, "{list_body}");
        let detail = list_body
            .as_array()
            .and_then(|arr| arr.iter().find(|s| s["id"].as_str() == Some(sid.as_str())))
            .cloned()
            .unwrap();
        if detail["status"].as_str() != Some("running") {
            final_output = detail["output_lines"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        final_output.contains("SSL=")
            && final_output.contains("proxy-ca.pem")
            && final_output.contains("NODE=")
            && final_output.contains("CURL=")
            && final_output.contains("-----BEGIN CERTIFICATE-----"),
        "agent session must receive proxy ephemeral CA cert env vars: {final_output}"
    );
}

#[tokio::test]
async fn track_b_serve_fail_fast_ssh_bind_and_graceful_shutdown() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut state, _, _, _) = repo(root);

    // 1. Occupied SSH port must fail fast before starting HTTP.
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_addr = occupied.local_addr().unwrap();
    state.ssh_bind = Some(occupied_addr);
    let err = crate::serve_with_shutdown(
        "127.0.0.1:0".parse().unwrap(),
        state.clone(),
        None,
        None,
        std::future::pending(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("SSH"),
        "expected SSH bind error, got: {err}"
    );
    drop(occupied);

    // 2. Valid ephemeral SSH port starts cleanly and exits promptly on shutdown signal.
    state.ssh_bind = Some("127.0.0.1:0".parse().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let srv = tokio::spawn(crate::serve_with_shutdown(
        "127.0.0.1:0".parse().unwrap(),
        state,
        None,
        None,
        async move {
            let _ = rx.await;
        },
    ));
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !srv.is_finished(),
        "server should stay running until shutdown"
    );
    let _ = tx.send(());
    let timed = tokio::time::timeout(Duration::from_secs(5), srv).await;
    assert!(timed.is_ok(), "server must shut down promptly");
    let res = timed.unwrap().unwrap();
    assert!(res.is_ok(), "clean shutdown expected: {res:?}");
}
