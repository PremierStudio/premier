//! Publish (Squash-Declassify) applies a branch's changes to the target and never replaces the
//! target's tree; requests that name no branch mean the repository's default branch.

use std::path::Path;

use axum::Router;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use crate::tests::{call, member_state};
use crate::{ServerState, build_router};

/// Owners have everything; everyone else (the anonymous public included) reads `pub/**` only,
/// so `.access.toml`, `README.md` and `private/**` are never published.
const POLICY: &str = r#"version = 1
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
id = "public-tree"
effect = "allow"
principals = ["*"]
paths = ["pub/**"]
refs = ["*"]
capabilities = ["traverse", "list", "read"]
"#;

fn git(root: &Path, args: &[&str]) -> String {
    let out = premier_git_bridge::git_command(root)
        .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// `default` (checked out, policy live from its tip): `.access.toml`, `README.md`,
/// `private/key.txt`, `pub/a.txt`, `pub/b.txt`. Returns the state and the owner's cookie.
fn repo(root: &Path, default: &str) -> (ServerState, String) {
    repo_with(root, default, POLICY)
}

/// [`repo`] under `policy`.
fn repo_with(root: &Path, default: &str, policy: &str) -> (ServerState, String) {
    // The working tree only follows its branch when the server's state is not in it.
    crate::tests::state_outside(root);
    let (state, owner, _, _) = member_state(root);
    for (path, content) in [
        (".access.toml", policy),
        ("private/key.txt", "key v1\n"),
        ("pub/a.txt", "a v1\n"),
        ("pub/b.txt", "b v1\n"),
    ] {
        std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        std::fs::write(root.join(path), content).unwrap();
    }
    git(root, &["init", "-q", "-b", default]);
    git(root, &["config", "core.autocrlf", "false"]);
    git(
        root,
        &["add", ".access.toml", "README.md", "private", "pub"],
    );
    git(root, &["commit", "-q", "-m", "initial"]);
    state.reload_repo_config().unwrap();
    (state, owner)
}

/// One commit on `branch` (created from the default branch if new) writing `files` (`None`
/// deletes), then back to `back`.
fn commit_on(root: &Path, branch: &str, back: &str, files: &[(&str, Option<&str>)]) {
    if premier_git_bridge::git_command(root)
        .args(["checkout", "-q", branch])
        .output()
        .is_ok_and(|o| !o.status.success())
    {
        git(root, &["checkout", "-q", "-b", branch]);
    }
    for (path, content) in files {
        match content {
            Some(text) => std::fs::write(root.join(path), text).unwrap(),
            None => std::fs::remove_file(root.join(path)).unwrap(),
        }
    }
    git(root, &["add", "-A", "private", "pub"]);
    git(root, &["commit", "-q", "-m", branch]);
    git(root, &["checkout", "-q", back]);
}

async fn post(router: &Router, uri: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
    let (status, _, body) =
        call(router, Method::POST, uri, &[("cookie", cookie)], Some(body)).await;
    (status, body)
}

/// Preview, then publish `work` onto the default branch; the preview must say exactly what the
/// publish then does (to the response and to the target's tree).
async fn publish(root: &Path, router: &Router, owner: &str) -> (StatusCode, Value) {
    let before = git(root, &["rev-parse", "HEAD"]);
    let (status, preview) = post(
        router,
        "/v1/branches/squash-preview",
        owner,
        json!({ "branch": "work" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let (status, body) = post(
        router,
        "/v1/branches/publish",
        owner,
        json!({ "source_branch": "work" }),
    )
    .await;
    let after = git(root, &["rev-parse", "HEAD"]);
    if status == StatusCode::OK {
        assert_eq!(preview["declassification_gate_passed"], true, "{preview}");
        assert_eq!(preview["conflicts"], json!([]));
        for field in ["published_paths", "scrubbed_paths"] {
            assert_eq!(preview[field], body[field], "{field}: {preview} vs {body}");
        }
        assert_eq!(body["new_commit_oid"], after.as_str());
        let message = git(root, &["log", "-1", "--format=%B", &after]);
        assert_eq!(
            preview["clean_commit_message"].as_str().unwrap().trim_end(),
            message
        );
        assert_eq!(git(root, &["rev-parse", "HEAD^"]), before);
        let changed = git(root, &["diff", "--name-only", &before, &after]);
        let changed: Vec<&str> = changed.lines().collect();
        assert_eq!(json!(changed), body["published_paths"]);
    } else {
        assert_eq!(preview["declassification_gate_passed"], false, "{preview}");
        assert_eq!(
            preview["conflicts"], body["conflicts"],
            "{preview} vs {body}"
        );
        assert_eq!(after, before, "a refused publish moved the target");
    }
    (status, body)
}

fn blob(root: &Path, rev: &str, path: &str) -> String {
    git(root, &["rev-parse", &format!("{rev}:{path}")])
}

#[tokio::test]
async fn publish_keeps_private_files_and_the_policy_on_the_target() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(root, "work", "main", &[("pub/a.txt", Some("a v2\n"))]);
    let before = git(root, &["rev-parse", "main"]);
    let router = build_router(state.clone());

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["target_ref"], "refs/heads/main");
    assert_eq!(body["published_paths"], json!(["pub/a.txt"]));
    assert_eq!(body["scrubbed_paths"], json!([]));
    for kept in [".access.toml", "README.md", "private/key.txt", "pub/b.txt"] {
        assert_eq!(
            blob(root, "main", kept),
            blob(root, &before, kept),
            "{kept}"
        );
    }
    assert_eq!(
        blob(root, "main", "pub/a.txt"),
        blob(root, "work", "pub/a.txt")
    );
    // The policy is still the repository's own, loaded from the target tip; the working tree
    // followed; the commit is the publishing owner's.
    state.reload_repo_config().unwrap();
    assert_eq!(state.current_repo_policy_toml(), POLICY);
    assert_eq!(
        std::fs::read_to_string(root.join("pub/a.txt")).unwrap(),
        "a v2\n"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("private/key.txt")).unwrap(),
        "key v1\n"
    );
    let author = git(root, &["log", "-1", "--format=%an <%ae>|%s", "main"]);
    assert_eq!(
        author,
        "owner <owner@users.noreply.premier>|Publish to main"
    );
    // Public on the target: neither the source branch nor anything held back is named.
    let message = git(root, &["log", "-1", "--format=%B", "main"]);
    assert!(
        !message.contains("work") && !message.contains("scrubbed"),
        "{message}"
    );
}

#[tokio::test]
async fn a_file_changed_on_the_target_after_the_fork_survives_a_publish() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(root, "work", "main", &[("pub/a.txt", Some("a v2\n"))]);
    commit_on(
        root,
        "main",
        "main",
        &[
            ("pub/b.txt", Some("b on main\n")),
            ("pub/c.txt", Some("c\n")),
        ],
    );
    let router = build_router(state);

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["published_paths"], json!(["pub/a.txt"]));
    let show = |path: &str| git(root, &["show", &format!("main:{path}")]);
    assert_eq!(
        (show("pub/a.txt"), show("pub/b.txt"), show("pub/c.txt")),
        ("a v2".into(), "b on main".into(), "c".into())
    );
}

#[tokio::test]
async fn a_file_changed_on_both_sides_refuses_the_publish_with_409() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/a.txt", Some("a work\n")),
            ("pub/b.txt", Some("b work\n")),
        ],
    );
    commit_on(root, "main", "main", &[("pub/a.txt", Some("a main\n"))]);
    let router = build_router(state);

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["conflicts"], json!(["pub/a.txt"]));
    assert_eq!(body["hidden_conflicts"], 0);
    // No partial result: the non-conflicting change did not land either.
    assert_eq!(git(root, &["show", "main:pub/b.txt"]), "b v1");
    assert_eq!(
        std::fs::read_to_string(root.join("pub/a.txt")).unwrap(),
        "a main\n"
    );
}

#[tokio::test]
async fn a_private_path_changed_on_the_source_is_scrubbed_and_the_target_keeps_its_own() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    let changes = [
        ("private/key.txt", Some("key v2\n")),
        ("private/new.txt", Some("new\n")),
        ("pub/a.txt", Some("a v2\n")),
    ];
    commit_on(root, "work", "main", &changes);
    // Changed on the target too: no conflict, a scrubbed path is not part of the publish.
    commit_on(
        root,
        "main",
        "main",
        &[("private/key.txt", Some("key on main\n"))],
    );
    let router = build_router(state);

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["published_paths"], json!(["pub/a.txt"]));
    assert_eq!(
        body["scrubbed_paths"],
        json!(["private/key.txt", "private/new.txt"])
    );
    assert_eq!(git(root, &["show", "main:private/key.txt"]), "key on main");
    assert!(!git(root, &["ls-tree", "-r", "--name-only", "main"]).contains("private/new.txt"));

    // Only scrubbed changes left: nothing to publish, and nothing moves.
    let tip = git(root, &["rev-parse", "main"]);
    let (status, body) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({ "source_branch": "work" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(git(root, &["rev-parse", "main"]), tip);
}

#[tokio::test]
async fn private_content_copied_to_a_public_path_refuses_the_publish_with_409() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    let secret = "a secret long enough to be worth matching\n";
    commit_on(root, "main", "main", &[("private/long.txt", Some(secret))]);
    // However short: `private/key.txt` is 7 bytes. Only the empty blob is everyone's.
    let changes = [
        ("pub/copy.txt", Some(secret)),
        ("pub/short.txt", Some("key v1\n")),
        ("pub/empty.txt", Some("")),
        ("pub/a.txt", Some("a v2\n")),
    ];
    std::fs::write(root.join("private/empty.txt"), "").unwrap();
    git(root, &["add", "private/empty.txt"]);
    git(root, &["commit", "-q", "-m", "empty private file"]);
    let tip = git(root, &["rev-parse", "main"]);
    commit_on(root, "work", "main", &changes);
    let router = build_router(state);

    let (status, preview) = post(
        &router,
        "/v1/branches/squash-preview",
        &owner,
        json!({ "branch": "work" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["blocked"], json!(["pub/copy.txt", "pub/short.txt"]));
    assert_eq!(preview["hidden_blocked"], 0);
    assert_eq!(preview["declassification_gate_passed"], false);
    assert_eq!(
        preview["published_paths"],
        json!(["pub/a.txt", "pub/empty.txt"])
    );

    let (status, body) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({ "source_branch": "work" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["blocked"], json!(["pub/copy.txt", "pub/short.txt"]));
    assert_eq!(body["hidden_blocked"], 0);
    // Nothing landed, the honest change included.
    assert_eq!(git(root, &["rev-parse", "main"]), tip);
}

#[tokio::test]
async fn a_delete_is_published_for_a_public_file_and_scrubbed_for_a_private_one() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(
        root,
        "work",
        "main",
        &[("pub/b.txt", None), ("private/key.txt", None)],
    );
    let router = build_router(state);

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["published_paths"], json!(["pub/b.txt"]));
    assert_eq!(body["scrubbed_paths"], json!(["private/key.txt"]));
    let files = git(root, &["ls-tree", "-r", "--name-only", "main"]);
    let files: Vec<&str> = files.lines().collect();
    assert_eq!(
        files,
        [".access.toml", "README.md", "private/key.txt", "pub/a.txt"]
    );
    assert!(!root.join("pub/b.txt").exists());
}

#[tokio::test]
async fn an_omitted_branch_is_the_default_branch_not_main() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "trunk");
    commit_on(root, "work", "trunk", &[("pub/a.txt", Some("a v2\n"))]);
    let router = build_router(state);
    let get = |uri: &'static str| {
        let (router, owner) = (router.clone(), owner.clone());
        async move {
            let (status, _, body) =
                call(&router, Method::GET, uri, &[("cookie", &owner)], None).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body}");
            body
        }
    };

    let tree = get("/v1/repo/tree").await;
    assert_eq!(tree["ref_name"], "trunk");
    assert!(
        tree["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["path"] == "pub/a.txt"),
        "{tree}"
    );
    let file = get("/v1/repo/file?path=pub/a.txt").await;
    assert_eq!(file["allowed"], true, "{file}");
    assert!(file.to_string().contains("a v1"), "{file}");
    assert_eq!(get("/v1/commits").await.as_array().unwrap().len(), 1);
    let hits = get("/v1/repo/search?q=key").await;
    assert_eq!(hits["hits"][0]["path"], "private/key.txt", "{hits}");
    let branches = get("/v1/branches").await;
    let work = branches
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "work")
        .unwrap();
    assert_eq!(work["ahead_commits"], 1, "{branches}");

    let explain = json!({ "principal": "anonymous", "path": "pub/a.txt" });
    let (status, body) = post(&router, "/v1/access/explain", &owner, explain).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = post(
        &router,
        "/v1/branches/create",
        &owner,
        json!({ "name": "next" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["oid"], git(root, &["rev-parse", "trunk"]).as_str());

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["target_ref"], "refs/heads/trunk");
    assert_eq!(git(root, &["show", "trunk:pub/a.txt"]), "a v2");
    assert_eq!(get("/v1/commits").await.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_preview_says_why_a_publish_is_blocked_and_why_paths_are_held_back() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    let (mia, _) = state
        .auth
        .seed_as("mia2", crate::tests::PW, crate::auth::Role::Member);
    git(root, &["branch", "same"]);
    commit_on(
        root,
        "hush",
        "main",
        &[("private/key.txt", Some("key v2\n"))],
    );
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/a.txt", Some("a v2\n")),
            ("private/key.txt", Some("key v3\n")),
        ],
    );
    let router = build_router(state);
    let preview = |cookie: String, branch: &'static str| {
        let router = router.clone();
        async move {
            let (status, body) = post(
                &router,
                "/v1/branches/squash-preview",
                &cookie,
                json!({ "branch": branch }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };

    // Goes through: no reason, the rule, and why each held-back path is held back.
    let body = preview(owner.clone(), "work").await;
    assert_eq!(body["declassification_gate_passed"], true, "{body}");
    assert_eq!(body["reason"], Value::Null, "{body}");
    assert_eq!(
        body["publish_rule"],
        "A path is published only if anonymous may read it."
    );
    assert_eq!(body["scrubbed_paths"], json!(["private/key.txt"]));
    assert_eq!(
        body["held_back_reasons"],
        json!({ "private/key.txt": "not readable by anonymous visitors" })
    );

    // Each blocking cause has its sentence.
    let body = preview(owner.clone(), "same").await;
    assert_eq!(body["declassification_gate_passed"], false, "{body}");
    assert_eq!(
        body["reason"],
        "nothing to publish: 'same' has no changes that 'main' lacks"
    );
    let body = preview(owner.clone(), "hush").await;
    assert_eq!(body["declassification_gate_passed"], false, "{body}");
    assert_eq!(
        body["reason"],
        "no public-readable changes: every path 'hush' changed is held back"
    );

    // A member's preview covers the paths she lists, and never says more than that publishing is
    // an owner's call: with nothing blocking...
    let generic = "an owner must review this publish";
    let hers = preview(mia.clone(), "work").await;
    assert_eq!(hers["published_paths"], json!(["pub/a.txt"]));
    assert_eq!(hers["scrubbed_paths"], json!([]));
    assert_eq!(hers["held_back_reasons"], json!({}));
    assert_eq!(
        (&hers["declassification_gate_passed"], &hers["reason"]),
        (&json!(false), &json!(generic))
    );
    // No airlock detail either, though the branch has a public diff and a held-back path.
    assert_airlock_neutral(&hers);

    // ...and whatever blocks it, seen by her or not: her answer has one shape.
    commit_on(root, "main", "main", &[("pub/a.txt", Some("a on main\n"))]);
    let hers = [
        preview(mia.clone(), "work").await,
        preview(mia.clone(), "hush").await,
        preview(mia, "same").await,
    ];
    assert_eq!(hers[0]["conflicts"], json!(["pub/a.txt"]));
    for body in &hers {
        assert_eq!(body["declassification_gate_passed"], false, "{body}");
        assert_eq!(body["reason"], generic, "{body}");
        assert_eq!(
            (&body["hidden_conflicts"], &body["hidden_blocked"]),
            (&json!(0), &json!(0))
        );
        assert_airlock_neutral(body);
    }
    for field in [
        "published_paths",
        "scrubbed_paths",
        "conflicts",
        "blocked",
        "held_back_reasons",
    ]
    .into_iter()
    .chain(AIRLOCK_FIELDS)
    {
        assert_eq!(hers[1][field], hers[2][field], "{field}");
    }

    let body = preview(owner, "work").await;
    assert_eq!(body["declassification_gate_passed"], false, "{body}");
    assert_eq!(body["conflicts"], json!(["pub/a.txt"]));
    assert_eq!(
        body["reason"],
        "1 path changed on both 'work' and 'main': bring the branch up to date first"
    );
}

// ---------------------------------------------------------------------------
// Declassification Airlock: what an owner reviews before a publish.

/// The airlock fields of a preview: an owner's only.
const AIRLOCK_FIELDS: [&str; 13] = [
    "public_commits_collapsed",
    "collapsed_commits",
    "source_head_oid",
    "target_head_oid",
    "source_commit_oid",
    "target_commit_oid",
    "three_way_merged_paths",
    "quarantine_paths",
    "overlay_blocked_paths",
    "held_back_rules",
    "restricted_zones",
    "public_diff",
    "public_diff_truncated",
];

/// A member's preview carries every airlock field, each empty.
fn assert_airlock_neutral(body: &Value) {
    let neutral = json!({
        "public_commits_collapsed": 0,
        "collapsed_commits": [],
        "source_head_oid": null,
        "target_head_oid": null,
        "source_commit_oid": null,
        "target_commit_oid": null,
        "three_way_merged_paths": [],
        "quarantine_paths": [],
        "overlay_blocked_paths": [],
        "held_back_rules": {},
        "restricted_zones": [],
        "public_diff": [],
        "public_diff_truncated": false,
    });
    for field in AIRLOCK_FIELDS {
        assert!(body.get(field).is_some(), "{field} missing: {body}");
        assert_eq!(body[field], neutral[field], "{field}: {body}");
    }
}

async fn preview_of(router: &Router, cookie: &str, branch: &str) -> Value {
    let (status, body) = post(
        router,
        "/v1/branches/squash-preview",
        cookie,
        json!({ "branch": branch }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// `public_diff` entry for `path`.
fn diff_of<'a>(preview: &'a Value, path: &str) -> &'a Value {
    preview["public_diff"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == path)
        .unwrap_or_else(|| panic!("{path} not in public_diff: {preview}"))
}

fn diff_paths(preview: &Value) -> Vec<String> {
    preview["public_diff"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn an_owner_preview_shows_the_exact_public_diff_and_the_collapsed_commits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/a.txt", Some("a v2\n")),
            ("pub/new.txt", Some("n1\nn2\n")),
            ("pub/b.txt", None),
            ("private/key.txt", Some("key v2 SECRET\n")),
        ],
    );
    // Newest: a commit that touches only a private path.
    commit_on(
        root,
        "work",
        "main",
        &[("private/key.txt", Some("key v3 SECRET\n"))],
    );
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(body["declassification_gate_passed"], true, "{body}");
    assert_eq!(diff_paths(&body), ["pub/a.txt", "pub/b.txt", "pub/new.txt"]);
    let a = diff_of(&body, "pub/a.txt");
    assert_eq!(a["kind"], "modified");
    assert_eq!(
        a["patch"],
        "--- a/pub/a.txt\n+++ b/pub/a.txt\n@@ -1,1 +1,1 @@\n-a v1\n+a v2\n"
    );
    assert_eq!((&a["additions"], &a["deletions"]), (&json!(1), &json!(1)));
    let b = diff_of(&body, "pub/b.txt");
    assert_eq!(b["kind"], "deleted");
    assert_eq!(
        b["patch"],
        "--- a/pub/b.txt\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-b v1\n"
    );
    assert_eq!((&b["additions"], &b["deletions"]), (&json!(0), &json!(1)));
    let new = diff_of(&body, "pub/new.txt");
    assert_eq!(new["kind"], "added");
    assert_eq!(
        new["patch"],
        "--- /dev/null\n+++ b/pub/new.txt\n@@ -0,0 +1,2 @@\n+n1\n+n2\n"
    );
    assert_eq!(
        (&new["additions"], &new["deletions"]),
        (&json!(2), &json!(0))
    );
    for file in body["public_diff"].as_array().unwrap() {
        assert_eq!(
            (
                &file["binary"],
                &file["truncated"],
                &file["three_way_merged"]
            ),
            (&json!(false), &json!(false), &json!(false)),
            "{file}"
        );
        assert_eq!(file["is_instruction_file"], false, "{file}");
    }
    assert_eq!(body["public_diff_truncated"], false);
    // The restricted path is held back, and nothing of its content is anywhere in the preview.
    assert_eq!(body["scrubbed_paths"], json!(["private/key.txt"]));
    assert!(!body.to_string().contains("SECRET"), "{body}");

    // Two commits collapse, one of them public; newest first.
    assert_eq!(body["private_commits_collapsed"], 2);
    assert_eq!(body["public_commits_collapsed"], 1);
    let commits = body["collapsed_commits"].as_array().unwrap();
    assert_eq!(commits.len(), 2, "{body}");
    assert_eq!(
        commits
            .iter()
            .map(|c| &c["touches_public"])
            .collect::<Vec<_>>(),
        [&json!(false), &json!(true)]
    );
    let work_tip = git(root, &["rev-parse", "work"]);
    let short = git(root, &["rev-parse", "--short", "work"]);
    assert_eq!(commits[0]["short_oid"], short.as_str());
    assert_eq!(commits[0]["subject"], "work");
    assert_eq!(body["source_head_oid"], &work_tip[..10]);
    assert_eq!(
        body["target_head_oid"],
        &git(root, &["rev-parse", "main"])[..10]
    );
    for field in [
        "three_way_merged_paths",
        "quarantine_paths",
        "overlay_blocked_paths",
    ] {
        assert_eq!(body[field], json!([]), "{field}");
    }
}

#[tokio::test]
async fn the_public_diff_never_carries_scrubbed_blocked_or_conflicting_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    let secret = "a secret long enough to be worth matching\n";
    commit_on(root, "main", "main", &[("private/long.txt", Some(secret))]);
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/copy.txt", Some(secret)),
            ("pub/a.txt", Some("a work\n")),
            ("pub/b.txt", Some("b v2\n")),
            ("private/key.txt", Some("key v2 HIDDEN\n")),
        ],
    );
    commit_on(root, "main", "main", &[("pub/a.txt", Some("a main\n"))]);
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(body["declassification_gate_passed"], false, "{body}");
    assert_eq!(body["blocked"], json!(["pub/copy.txt"]));
    assert_eq!(body["conflicts"], json!(["pub/a.txt"]));
    assert_eq!(body["scrubbed_paths"], json!(["private/key.txt"]));
    assert_eq!(diff_paths(&body), ["pub/b.txt"]);
    let diff = body["public_diff"].to_string();
    for leaked in [
        "worth matching",
        "HIDDEN",
        "a work",
        "a main",
        "copy.txt",
        "key.txt",
    ] {
        assert!(!diff.contains(leaked), "{leaked} in {diff}");
    }
    assert!(!body.to_string().contains("worth matching"), "{body}");
}

#[tokio::test]
async fn a_clean_three_way_merge_is_listed_and_its_merged_payload_diffed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    let lines = |first: &str, last: &str| {
        let mut out = format!("{first}\n");
        for i in 2..10 {
            out.push_str(&format!("l{i}\n"));
        }
        out.push_str(&format!("{last}\n"));
        out
    };
    let (base, ours, theirs) = (
        lines("l1", "l10"),
        lines("L1 work", "l10"),
        lines("l1", "L10 main"),
    );
    commit_on(root, "main", "main", &[("pub/m.txt", Some(&base))]);
    commit_on(root, "work", "main", &[("pub/m.txt", Some(&ours))]);
    commit_on(root, "main", "main", &[("pub/m.txt", Some(&theirs))]);
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(body["declassification_gate_passed"], true, "{body}");
    assert_eq!(body["three_way_merged_paths"], json!(["pub/m.txt"]));
    let m = diff_of(&body, "pub/m.txt");
    assert_eq!(
        (&m["kind"], &m["three_way_merged"]),
        (&json!("modified"), &json!(true))
    );
    // Against the target, which has `L10 main` already: only the source's line changes.
    let patch = m["patch"].as_str().unwrap();
    assert!(patch.contains("-l1\n+L1 work\n"), "{patch}");
    assert!(
        !patch.contains("+L10") && !patch.contains("-L10"),
        "{patch}"
    );
    assert_eq!((&m["additions"], &m["deletions"]), (&json!(1), &json!(1)));

    let (status, published) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({ "source_branch": "work" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{published}");
    assert_eq!(
        git(root, &["show", "main:pub/m.txt"]),
        lines("L1 work", "L10 main").trim_end()
    );
}

#[tokio::test]
async fn an_instruction_file_in_the_public_changes_is_quarantined() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/AGENTS.md", Some("be nice\n")),
            ("pub/a.txt", Some("a v2\n")),
        ],
    );
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(body["quarantine_paths"], json!(["pub/AGENTS.md"]));
    assert_eq!(diff_of(&body, "pub/AGENTS.md")["is_instruction_file"], true);
    assert_eq!(diff_of(&body, "pub/a.txt")["is_instruction_file"], false);
    // Quarantine only flags.
    assert_eq!(body["declassification_gate_passed"], true, "{body}");
}

/// `pub/**` is the `docs` zone, `private/key.txt` the `secrets` zone, which anonymous is denied.
const ZONED_POLICY: &str = r#"version = 1
[defaults]
public = []
authenticated = []
[zones.secrets]
paths = ["private/key.txt"]
[zones.docs]
paths = ["pub/**"]
[[rules]]
id = "owners-full-access"
effect = "allow"
principals = ["group:owners"]
paths = ["**"]
refs = ["*"]
capabilities = ["traverse", "list", "read", "write", "use"]
[[rules]]
id = "public-tree"
effect = "allow"
principals = ["*"]
zones = ["docs"]
refs = ["*"]
capabilities = ["traverse", "list", "read"]
[[rules]]
id = "hide-secrets"
effect = "deny"
principals = ["anonymous"]
zones = ["secrets"]
refs = ["*"]
capabilities = ["read"]
reason = "Keys stay home"
"#;

#[tokio::test]
async fn held_back_rules_and_restricted_zones_name_the_rule_layer_and_zone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo_with(root, "main", ZONED_POLICY);
    commit_on(
        root,
        "work",
        "main",
        &[
            ("private/key.txt", Some("key v2\n")),
            ("private/other.txt", Some("other\n")),
            ("pub/a.txt", Some("a v2\n")),
        ],
    );
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(
        body["scrubbed_paths"],
        json!(["private/key.txt", "private/other.txt"])
    );
    assert_eq!(
        body["held_back_rules"],
        json!({
            "private/key.txt": {
                "reason": "Keys stay home",
                "rule_id": "hide-secrets",
                "layer": "repo",
                "zones": ["secrets"],
            },
            "private/other.txt": {
                "reason": "No allow rule grants anonymous read (default deny)",
                "rule_id": null,
                "layer": null,
                "zones": [],
            },
        })
    );
    // The public `docs` zone is not restricted.
    assert_eq!(body["restricted_zones"], json!(["secrets"]));
    // The plain reasons are unchanged.
    assert_eq!(
        body["held_back_reasons"],
        json!({
            "private/key.txt": "not readable by anonymous visitors",
            "private/other.txt": "not readable by anonymous visitors",
        })
    );
}

#[tokio::test]
async fn an_overlay_file_in_the_public_changes_fails_the_gate_and_is_not_diffed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    state
        .persisted
        .lock()
        .unwrap()
        .overlays
        .entries
        .push(premier_overlay::OverlayEntry {
            kind: premier_core::OverlayKind::Team("core".to_owned()),
            path: "pub/team.env".to_owned(),
            encrypted: false,
        });
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/AGENTS.local.md", Some("mine\n")),
            ("pub/team.env", Some("TEAM=1\n")),
            ("pub/a.txt", Some("a v2\n")),
        ],
    );
    let tip = git(root, &["rev-parse", "main"]);
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(
        body["overlay_blocked_paths"],
        json!(["pub/AGENTS.local.md", "pub/team.env"])
    );
    assert_eq!(body["declassification_gate_passed"], false, "{body}");
    assert_eq!(
        body["reason"],
        "2 public paths would publish team or personal overlay files"
    );
    assert_eq!(diff_paths(&body), ["pub/a.txt"]);
    assert!(!body["public_diff"].to_string().contains("TEAM=1"));

    // The publish agrees: refused, nothing moved.
    let (status, refused) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({ "source_branch": "work" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(git(root, &["rev-parse", "main"]), tip);
}

#[tokio::test]
async fn a_large_change_set_truncates_the_public_diff_and_flags_binaries() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    let big: String = (0..2000)
        .map(|i| format!("line {i:05} of a big file\n"))
        .collect();
    let mut files: Vec<(String, String)> = vec![
        ("pub/0big.txt".to_owned(), big),
        ("pub/0bin.dat".to_owned(), "bin\0ary\n".to_owned()),
    ];
    files.extend((0..60).map(|i| (format!("pub/f{i:02}.txt"), format!("f{i}\n"))));
    let refs: Vec<(&str, Option<&str>)> = files
        .iter()
        .map(|(p, c)| (p.as_str(), Some(c.as_str())))
        .collect();
    commit_on(root, "work", "main", &refs);
    let router = build_router(state);

    let body = preview_of(&router, &owner, "work").await;
    assert_eq!(body["published_paths"].as_array().unwrap().len(), 62);
    assert_eq!(body["public_diff"].as_array().unwrap().len(), 50);
    assert_eq!(body["public_diff_truncated"], true);
    let big = diff_of(&body, "pub/0big.txt");
    assert_eq!(
        (&big["truncated"], &big["additions"]),
        (&json!(true), &json!(2000))
    );
    let patch = big["patch"].as_str().unwrap();
    assert!(patch.ends_with("\n... (truncated)"));
    assert!(patch.len() <= 32_768 + "\n... (truncated)".len());
    let bin = diff_of(&body, "pub/0bin.dat");
    assert_eq!(
        (&bin["binary"], &bin["patch"], &bin["truncated"]),
        (&json!(true), &json!(""), &json!(false))
    );
}

#[tokio::test]
async fn a_publish_returns_its_record_and_writes_a_branch_publish_audit_event() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/a.txt", Some("a v2\n")),
            ("private/key.txt", Some("key v2\n")),
        ],
    );
    let router = build_router(state.clone());

    let (status, body) = publish(root, &router, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let message = git(root, &["log", "-1", "--format=%B", "main"]);
    let commit_message = body["commit_message"].as_str().unwrap();
    assert_eq!(commit_message.trim_end(), message);
    assert!(commit_message.contains(body["attestation_trailer"].as_str().unwrap()));
    let at = body["published_at"].as_str().unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(at).is_ok(), "{at}");
    assert_eq!(body["actor"], "@owner");
    let fp = premier_policy::sha256_hex(POLICY.as_bytes());
    assert_eq!(body["policy_fingerprint"], &fp[..16]);

    let event = state
        .audit_sink
        .snapshot()
        .into_iter()
        .rev()
        .find(|e| e.action == "branch_publish")
        .unwrap();
    assert_eq!(event.principal, "@owner");
    assert_eq!(event.component, "premier-git-bridge");
    assert_eq!(event.target.as_deref(), Some("refs/heads/main"));
    assert_eq!(event.decision, premier_core::AuditDecision::Allowed);
    let new_oid = body["new_commit_oid"].as_str().unwrap();
    // `auth::audit` stamps the authenticated account after the handler's sentence.
    assert_eq!(
        event.reason,
        format!(
            "Declassified and published {} onto refs/heads/main (1 path, 1 scrubbed) [actor: @owner]",
            &new_oid[..10]
        )
    );
}

#[tokio::test]
async fn publish_refuses_stale_expected_oids_and_public_diff_reports_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner) = repo(root, "main");
    commit_on(
        root,
        "work",
        "main",
        &[
            ("pub/a.txt", Some("a v2\n")),
            ("pub/new.txt", Some("new\n")),
            ("pub/b.txt", None),
        ],
    );
    git(root, &["checkout", "-q", "work"]);
    git(root, &["update-index", "--chmod=+x", "pub/a.txt"]);
    git(root, &["commit", "-q", "-m", "chmod pub/a.txt"]);
    git(root, &["checkout", "-q", "main"]);
    let router = build_router(state);

    let first = preview_of(&router, &owner, "work").await;
    let src_oid = first["source_commit_oid"].as_str().unwrap().to_owned();
    let tgt_oid = first["target_commit_oid"].as_str().unwrap().to_owned();
    assert_eq!(src_oid, git(root, &["rev-parse", "work"]));
    assert_eq!(tgt_oid, git(root, &["rev-parse", "main"]));
    assert_eq!(
        (
            &diff_of(&first, "pub/a.txt")["old_mode"],
            &diff_of(&first, "pub/a.txt")["new_mode"]
        ),
        (&json!("100644"), &json!("100755"))
    );
    assert_eq!(
        (
            &diff_of(&first, "pub/new.txt")["old_mode"],
            &diff_of(&first, "pub/new.txt")["new_mode"]
        ),
        (&Value::Null, &json!("100644"))
    );
    assert_eq!(
        (
            &diff_of(&first, "pub/b.txt")["old_mode"],
            &diff_of(&first, "pub/b.txt")["new_mode"]
        ),
        (&json!("100644"), &Value::Null)
    );

    // Advance source: publishing with stale expected_source_oid returns 409 and leaves main unchanged.
    commit_on(root, "work", "main", &[("pub/extra.txt", Some("extra\n"))]);
    let main_before = git(root, &["rev-parse", "main"]);
    let (status, body) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({
            "source_branch": "work",
            "expected_source_oid": src_oid,
            "expected_target_oid": tgt_oid,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(git(root, &["rev-parse", "main"]), main_before);

    // Re-preview, then advance target: publishing with stale expected_target_oid returns 409.
    let second = preview_of(&router, &owner, "work").await;
    let src_oid2 = second["source_commit_oid"].as_str().unwrap().to_owned();
    let tgt_oid2 = second["target_commit_oid"].as_str().unwrap().to_owned();
    commit_on(root, "main", "main", &[("pub/other.txt", Some("other\n"))]);
    let main_after_advance = git(root, &["rev-parse", "main"]);
    let (status, body) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({
            "source_branch": "work",
            "expected_source_oid": src_oid2,
            "expected_target_oid": tgt_oid2,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(git(root, &["rev-parse", "main"]), main_after_advance);

    // Fresh preview OIDs succeed cleanly.
    let third = preview_of(&router, &owner, "work").await;
    let (status, body) = post(
        &router,
        "/v1/branches/publish",
        &owner,
        json!({
            "source_branch": "work",
            "expected_source_oid": third["source_commit_oid"],
            "expected_target_oid": third["target_commit_oid"],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
