//! End-to-end tests of agent lanes, three-way auto-rebase, first-class lane conflicts, stacked
//! lanes, closed-loop review steering, round interdiffs and provenance: real routers, real Git
//! repositories on disk and real (unconfined, `allow_unsandboxed_agents`) agent sessions.

use std::io::Write as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use premier_core::{DelegatedIdentity, Principal};
use premier_git_bridge::{CanonicalGitRepo, project_repository, render_receive_pack_refs};
use premier_policy::{CompiledPolicy, parse_policy_toml};
use serde_json::{Value, json};

use crate::tests::{MEMBER_POLICY, PW, call, hers, member_state, oneshot};
use crate::{ServerState, build_router, runner};

/// [`MEMBER_POLICY`] (`@mia` reads all but `billing/**`) plus agent profiles: `coder` may read and
/// write everything but `billing/**`, `writer` everything.
const PROFILES: &str = r#"
[[agent_profiles]]
name = "coder"
allow_paths = ["**"]
deny_paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write"]
[[agent_profiles]]
name = "writer"
allow_paths = ["**"]
capabilities = ["traverse", "list", "read", "write"]
"#;

const README: &str = "# Demo\n\nHello wrold\n";
const SECRET: &str = "old secret bytes\n";
const OWNER_ONLY: &str = "this action requires an owner account";

// ---- fixture & helpers ---------------------------------------------------------------------

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

fn try_git(root: &Path, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The exact bytes of `rev:path`.
fn blob(root: &Path, rev: &str, path: &str) -> String {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(["cat-file", "blob", &format!("{rev}:{path}")])
        .output()
        .unwrap();
    assert!(out.status.success(), "{rev}:{path}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

fn set_policy(state: &ServerState, toml: &str) {
    let file = parse_policy_toml(toml).unwrap();
    *state.policy.write().unwrap() = Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
    state.set_repo_policy_metadata(Some(toml.to_owned()), Some(Arc::new(file)));
}

/// `notes.txt`: twelve numbered lines, with `edits` (1-based line, text) applied.
fn notes(edits: &[(usize, &str)]) -> String {
    (1..=12)
        .map(|n| {
            let text = edits
                .iter()
                .find(|(at, _)| *at == n)
                .map_or_else(|| format!("line {n}"), |(_, t)| (*t).to_owned());
            format!("{text}\n")
        })
        .collect()
}

/// `main`: README.md, notes.txt, docs/guide.md and billing/secret.rs, under [`MEMBER_POLICY`] +
/// [`PROFILES`], with sessions run unconfined when the host has no sandbox. Returns the state,
/// the owner's cookie, `@mia`'s cookie and her access token.
fn fixture(root: &Path) -> (ServerState, String, String, String) {
    let (mut state, owner, mia, mia_token) = member_state(root);
    set_policy(&state, &format!("{MEMBER_POLICY}{PROFILES}"));
    state.session_manager = Arc::new(runner::SessionManager::open(root));
    state.allow_unsandboxed_agents = true;
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::create_dir_all(root.join("billing")).unwrap();
    std::fs::write(root.join("README.md"), README).unwrap();
    std::fs::write(root.join("notes.txt"), notes(&[])).unwrap();
    std::fs::write(root.join("docs/guide.md"), "guide\n").unwrap();
    std::fs::write(root.join("billing/secret.rs"), SECRET).unwrap();
    git(root, &["init", "-q", "-b", "main"]);
    git(root, &["config", "core.autocrlf", "false"]);
    git(root, &["add", "README.md", "notes.txt", "docs", "billing"]);
    git(root, &["commit", "-q", "-m", "initial"]);
    (state, owner, mia, mia_token)
}

static INDEX_SEQ: AtomicU64 = AtomicU64::new(0);

/// Commit `files` on top of `full_ref` without touching the working tree or its index (someone
/// else moving the branch under a running session). Returns the new tip.
fn commit_on(root: &Path, full_ref: &str, files: &[(&str, &str)]) -> String {
    let index = root.join(".git").join(format!(
        "lane-test-index-{}",
        INDEX_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let run = |args: &[&str], input: Option<&str>| -> String {
        let mut child = std::process::Command::new("git")
            .current_dir(root)
            .env("GIT_INDEX_FILE", &index)
            .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if let Some(text) = input {
            stdin.write_all(text.as_bytes()).unwrap();
        }
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let parent = run(&["rev-parse", full_ref], None);
    run(&["read-tree", &parent], None);
    for (path, text) in files {
        let oid = run(&["hash-object", "-w", "--stdin"], Some(text));
        let info = format!("100644,{oid},{path}");
        run(&["update-index", "--add", "--cacheinfo", &info], None);
    }
    let tree = run(&["write-tree"], None);
    let msg = format!("upstream on {full_ref}");
    let commit = run(&["commit-tree", &tree, "-p", &parent, "-m", &msg], None);
    run(&["update-ref", full_ref, &commit, &parent], None);
    let _ = std::fs::remove_file(&index);
    commit
}

/// A command (PowerShell on Windows, `sh` elsewhere) that writes `text` to `path` exactly.
fn write_cmd(path: &str, text: &str) -> String {
    let parent = path.rsplit_once('/').map(|(dir, _)| dir);
    if cfg!(windows) {
        let mk = parent
            .map(|d| format!("New-Item -ItemType Directory -Force -Path '{d}' | Out-Null; "))
            .unwrap_or_default();
        format!(
            "{mk}[IO.File]::WriteAllText((Join-Path (Get-Location) '{path}'), \"{}\")",
            text.replace('\n', "`n")
        )
    } else {
        let mk = parent
            .map(|d| format!("mkdir -p '{d}' && "))
            .unwrap_or_default();
        format!("{mk}printf '{}' > '{path}'", text.replace('\n', "\\n"))
    }
}

fn then(cmds: &[String]) -> String {
    cmds.join(if cfg!(windows) { "; " } else { " && " })
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

async fn wait_session(state: &ServerState, id: &str) -> runner::AgentSessionRecord {
    for _ in 0..900 {
        let rec = state.session_manager.get(id).unwrap();
        if rec.status != "running" {
            return rec;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {id} never ended");
}

/// Start a session (`body` as `POST /v1/agents/sessions` takes it) and wait for it to end.
async fn run_session(
    state: &ServerState,
    router: &Router,
    owner: &str,
    body: Value,
) -> runner::AgentSessionRecord {
    let (status, body) = send(router, Method::POST, "/v1/agents/sessions", owner, body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rec = wait_session(state, body["id"].as_str().unwrap()).await;
    assert_eq!(
        (rec.status.as_str(), rec.exit_code),
        ("completed", Some(0)),
        "{rec:#?}"
    );
    rec
}

fn commit_uri(id: &str) -> String {
    format!("/v1/agents/sessions/{id}/commit")
}

fn main_tip(root: &Path) -> String {
    git(root, &["rev-parse", "refs/heads/main"])
}

/// Create `feature` off `main` with round 1 changing README.md and billing/secret.rs, and a review
/// of it delegated to `coder`. Returns `(change_id, round 1 commit)`.
async fn review_fixture(root: &Path, router: &Router, owner: &str) -> (String, String) {
    git(root, &["branch", "feature", "main"]);
    let r1 = commit_on(
        root,
        "refs/heads/feature",
        &[
            ("README.md", "# Demo\n\nHello wrold R1\n"),
            ("billing/secret.rs", "r1 secret bytes\n"),
        ],
    );
    let body = json!({ "title": "Feature", "branch": "feature", "delegated_agent": "coder" });
    let (status, body) = send(router, Method::POST, "/v1/reviews", owner, body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (body["change_id"].as_str().unwrap().to_owned(), r1)
}

async fn wait_rounds(state: &ServerState, change_id: &str, rounds: usize) {
    for _ in 0..600 {
        let n = state
            .persisted
            .lock()
            .unwrap()
            .reviews
            .iter()
            .find(|r| r.change_id == change_id)
            .map_or(0, |r| r.round_oids.len());
        if n >= rounds {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("review {change_id} never reached round {rounds}");
}

fn review_of<'a>(body: &'a Value, change_id: &str) -> &'a Value {
    body.as_array()
        .unwrap()
        .iter()
        .find(|r| r["change_id"] == change_id)
        .unwrap_or_else(|| panic!("{change_id} not in {body}"))
}

// ---- 1. parallel non-blocking auto-rebase --------------------------------------------------

#[tokio::test]
async fn parallel_sessions_auto_rebase_disjoint_files_and_non_overlapping_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = fixture(root);
    let router = build_router(state.clone());
    let session = |cmd: String| json!({ "command": cmd, "agent_profile": "writer" });

    // A. Disjoint files: both sessions start at the same tip.
    let start = main_tip(root);
    let s1 = run_session(&state, &router, &owner, session(write_cmd("a.txt", "A\n"))).await;
    let s2 = run_session(&state, &router, &owner, session(write_cmd("b.txt", "B\n"))).await;
    assert_eq!(s1.base_commit.as_deref(), Some(start.as_str()));
    assert_eq!(s2.base_commit.as_deref(), Some(start.as_str()));
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&s1.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], false, "{body}");
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&s2.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], true, "{body}");
    let tip = main_tip(root);
    assert_eq!(body["commit"], json!(tip));
    assert_eq!(blob(root, &tip, "a.txt"), "A\n");
    assert_eq!(blob(root, &tip, "b.txt"), "B\n");

    // B. Same file, lines 1 and 12: merged three ways, no 409.
    let first = notes(&[(1, "agent one")]);
    let last = notes(&[(12, "agent twelve")]);
    let s3 = run_session(
        &state,
        &router,
        &owner,
        session(write_cmd("notes.txt", &first)),
    )
    .await;
    let s4 = run_session(
        &state,
        &router,
        &owner,
        session(write_cmd("notes.txt", &last)),
    )
    .await;
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&s3.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&s4.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], true, "{body}");
    assert_eq!(body["merged_paths"], json!(["notes.txt"]), "{body}");
    let tip = main_tip(root);
    assert_eq!(
        blob(root, &tip, "notes.txt"),
        notes(&[(1, "agent one"), (12, "agent twelve")])
    );
    assert_eq!(blob(root, &tip, "a.txt"), "A\n");

    // Strict compare-and-swap on request; the default rebases.
    let s5 = run_session(&state, &router, &owner, session(write_cmd("c.txt", "C\n"))).await;
    let s6 = run_session(&state, &router, &owner, session(write_cmd("d.txt", "D\n"))).await;
    let (status, _) = send(
        &router,
        Method::POST,
        &commit_uri(&s5.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let moved = main_tip(root);
    let strict = json!({ "auto_rebase": false });
    let (status, body) = send(&router, Method::POST, &commit_uri(&s6.id), &owner, strict).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.get("lane_conflicts").is_none(), "{body}");
    assert_eq!(main_tip(root), moved);
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&s6.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], true);
    let tip = main_tip(root);
    assert_eq!(blob(root, &tip, "c.txt"), "C\n");
    assert_eq!(blob(root, &tip, "d.txt"), "D\n");
}

// ---- 2. hidden files survive, and cannot be written ----------------------------------------

#[tokio::test]
async fn hidden_files_survive_auto_rebase_and_a_restricted_agent_cannot_write_them() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = fixture(root);
    let router = build_router(state.clone());
    let coder = |cmd: String| json!({ "command": cmd, "agent_profile": "coder" });
    let probe = if cfg!(windows) {
        "Test-Path billing".to_owned()
    } else {
        "(test -e billing && echo True || echo False)".to_owned()
    };

    // The base branch changes billing/secret.rs while the session (which cannot see it) runs.
    let cmd = then(&[probe, write_cmd("README.md", "# Demo agent\n")]);
    let rec = run_session(&state, &router, &owner, coder(cmd)).await;
    assert!(
        rec.output_lines.iter().any(|l| l.trim() == "False"),
        "{rec:#?}"
    );
    let listed: Vec<&str> = rec.changes.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(listed, ["README.md"]);
    let upstream = commit_on(
        root,
        "refs/heads/main",
        &[("billing/secret.rs", "new secret bytes\n")],
    );
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], true, "{body}");
    let commit = body["commit"].as_str().unwrap();
    assert_eq!(git(root, &["rev-parse", &format!("{commit}~1")]), upstream);
    assert_eq!(blob(root, commit, "README.md"), "# Demo agent\n");
    assert_eq!(
        blob(root, commit, "billing/secret.rs"),
        "new secret bytes\n"
    );
    assert_eq!(
        git(root, &["rev-parse", &format!("{commit}:billing/secret.rs")]),
        git(
            root,
            &["rev-parse", &format!("{upstream}:billing/secret.rs")]
        ),
    );

    // Writing the hidden file from inside the workspace: 403, nothing committed (README neither).
    for cmd in [
        write_cmd("billing/secret.rs", "pwned\n"),
        then(&[
            write_cmd("README.md", "# Demo again\n"),
            write_cmd("billing/new.rs", "new\n"),
        ]),
    ] {
        let rec = run_session(&state, &router, &owner, coder(cmd)).await;
        let before = main_tip(root);
        let (status, body) = send(
            &router,
            Method::POST,
            &commit_uri(&rec.id),
            &owner,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("policy denied WRITE"),
            "{body}"
        );
        assert_eq!(main_tip(root), before);
        assert_eq!(
            blob(root, &before, "billing/secret.rs"),
            "new secret bytes\n"
        );
        assert!(
            try_git(
                root,
                &["cat-file", "-e", &format!("{before}:billing/new.rs")]
            )
            .is_none()
        );
        let after = state.session_manager.get(&rec.id).unwrap();
        assert!(after.commit.is_none());
    }
}

// ---- 3. overlapping edits: 409 with lane conflicts, then resolution -------------------------

/// A writer session rewrites README.md while `main` rewrites it too: the commit answers 409.
async fn conflicted_session(
    state: &ServerState,
    router: &Router,
    owner: &str,
    tag: &str,
) -> (String, Value) {
    let root = state.workspace_root.clone();
    let cmd = write_cmd("README.md", &format!("# Demo\n\nagent {tag}\n"));
    let rec = run_session(
        state,
        router,
        owner,
        json!({ "command": cmd, "agent_profile": "writer" }),
    )
    .await;
    let upstream_text = format!("# Demo\n\nupstream {tag}\n");
    let moved = commit_on(&root, "refs/heads/main", &[("README.md", &upstream_text)]);
    let (status, body) = send(router, Method::POST, &commit_uri(&rec.id), owner, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(main_tip(&root), moved, "nothing landed");
    (rec.id, body)
}

#[tokio::test]
async fn overlapping_edits_become_lane_conflicts_that_resolve_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = fixture(root);
    let router = build_router(state.clone());
    let resolve = |lane: &str| format!("/v1/lanes/{lane}/resolve");

    let (sid, body) = conflicted_session(&state, &router, &owner, "ours").await;
    let lane_id = body["lane_id"].as_str().unwrap().to_owned();
    assert_eq!(lane_id, format!("lane-{sid}"));
    assert_eq!(
        body["lane_ref"],
        json!(format!("refs/premier-lanes/{lane_id}"))
    );
    let lane_tip = body["lane_tip"].as_str().unwrap();
    assert_eq!(
        git(
            root,
            &["rev-parse", &format!("refs/premier-lanes/{lane_id}")]
        ),
        lane_tip
    );
    assert_eq!(blob(root, lane_tip, "README.md"), "# Demo\n\nagent ours\n");
    let conflict = &body["lane_conflicts"][0];
    assert_eq!(
        (&conflict["path"], &conflict["kind"], &conflict["allowed"]),
        (&json!("README.md"), &json!("content_overlap"), &json!(true)),
        "{body}"
    );
    let hunk = &conflict["hunks"][0];
    assert_eq!(hunk["ours_lines"], json!(["upstream ours"]), "{body}");
    assert_eq!(hunk["theirs_lines"], json!(["agent ours"]), "{body}");
    assert_eq!(hunk["base_lines"], json!(["Hello wrold"]), "{body}");
    assert!(
        hunk["markers"].as_str().unwrap().contains("<<<<<<<"),
        "{body}"
    );
    // The workspace is kept, and the session knows why it did not land.
    let kept = state.session_manager.get(&sid).unwrap();
    assert!(!kept.discarded && kept.commit.is_none() && kept.conflicts.len() == 1);
    let (status, _) = get(&router, &format!("/v1/agents/sessions/{sid}/diff"), &owner).await;
    assert_eq!(status, StatusCode::OK);
    let (_, lane) = get(&router, &format!("/v1/lanes/{lane_id}"), &owner).await;
    assert_eq!(lane["status"], "conflicted");

    // A resolution must name every conflicted path, with a known strategy.
    let (status, _) = send(
        &router,
        Method::POST,
        &resolve(&lane_id),
        &owner,
        json!({ "resolutions": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let bad = json!({ "resolutions": [{ "path": "README.md", "strategy": "both" }] });
    let (status, _) = send(&router, Method::POST, &resolve(&lane_id), &owner, bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = send(
        &router,
        Method::POST,
        &resolve("lane-nope"),
        &owner,
        json!({ "resolutions": [] }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // "ours": the branch's side wins.
    let ours = json!({ "resolutions": [{ "path": "README.md", "strategy": "ours" }] });
    let (status, body) = send(&router, Method::POST, &resolve(&lane_id), &owner, ours).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        blob(root, &main_tip(root), "README.md"),
        "# Demo\n\nupstream ours\n"
    );
    assert_eq!(body["lane"]["conflicts"], json!([]));
    assert_eq!(body["lane"]["status"], "active");
    let done = state.session_manager.get(&sid).unwrap();
    assert!(done.conflicts.is_empty() && done.commit.is_some());

    // "theirs": the agent's side lands.
    let (sid, body) = conflicted_session(&state, &router, &owner, "theirs").await;
    let lane_id = body["lane_id"].as_str().unwrap().to_owned();
    let theirs = json!({ "resolutions": [{ "path": "README.md", "strategy": "theirs" }] });
    let (status, body) = send(&router, Method::POST, &resolve(&lane_id), &owner, theirs).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let tip = main_tip(root);
    assert_eq!(body["commit_oid"], json!(tip));
    assert_eq!(blob(root, &tip, "README.md"), "# Demo\n\nagent theirs\n");
    assert_eq!(
        git(
            root,
            &["rev-parse", &format!("refs/premier-lanes/{lane_id}")]
        ),
        tip
    );
    assert!(
        state
            .session_manager
            .get(&sid)
            .unwrap()
            .conflicts
            .is_empty()
    );

    // Custom content.
    let (_, body) = conflicted_session(&state, &router, &owner, "custom").await;
    let lane_id = body["lane_id"].as_str().unwrap().to_owned();
    let custom = json!({ "resolutions": [{
        "path": "README.md", "strategy": "custom", "content": "# Demo\n\nmerged by hand\n"
    }] });
    let (status, body) = send(&router, Method::POST, &resolve(&lane_id), &owner, custom).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        blob(root, &main_tip(root), "README.md"),
        "# Demo\n\nmerged by hand\n"
    );
    let (_, lane) = get(&router, &format!("/v1/lanes/{lane_id}"), &owner).await;
    assert_eq!(
        (&lane["status"], &lane["conflicts"]),
        (&json!("active"), &json!([]))
    );
    // What nobody touched is still there.
    assert_eq!(blob(root, &main_tip(root), "billing/secret.rs"), SECRET);

    // A lane whose agent profile may not write billing cannot resolve into it.
    let make = json!({ "lane_id": "lane-coder", "agent_profile": "coder" });
    let (status, body) = send(&router, Method::POST, "/v1/lanes", &owner, make).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let before = main_tip(root);
    let sneaky = json!({ "resolutions": [{
        "path": "billing/secret.rs", "strategy": "custom", "content": "pwned\n"
    }] });
    let (status, body) = send(
        &router,
        Method::POST,
        &resolve("lane-coder"),
        &owner,
        sneaky,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(main_tip(root), before);
    assert_eq!(blob(root, &before, "billing/secret.rs"), SECRET);
}

// ---- 4. stacked lanes, cascaded rebase -----------------------------------------------------

#[tokio::test]
async fn stacked_lanes_cascade_onto_a_moved_base() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = fixture(root);
    let router = build_router(state.clone());
    let m0 = main_tip(root);
    let lane_tip = |lane: &str| git(root, &["rev-parse", &format!("refs/premier-lanes/{lane}")]);
    let keep = |path: &str, text: &str| json!({ "apply_to_branch": false, "resolutions": [{ "path": path, "content": text }] });

    // Lane A on main, with a.txt kept on the lane only.
    let make = json!({ "lane_id": "lane-a", "agent_profile": "writer" });
    let (status, body) = send(&router, Method::POST, "/v1/lanes", &owner, make).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["base_commit"], json!(m0));
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/lanes/lane-a/resolve",
        &owner,
        keep("a.txt", "A\n"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let a1 = lane_tip("lane-a");
    assert_eq!(body["lane"]["tip_oid"], json!(a1));
    assert_eq!(
        main_tip(root),
        m0,
        "a lane-only resolution leaves the branch alone"
    );
    assert_eq!(git(root, &["rev-parse", &format!("{a1}~1")]), m0);

    // Lane B stacked on A, with its own b.txt on top of A's tip.
    let cyclic = json!({ "lane_id": "lane-x", "parent_lane_id": "lane-x" });
    let (status, _) = send(&router, Method::POST, "/v1/lanes", &owner, cyclic).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let make =
        json!({ "lane_id": "lane-b", "parent_lane_id": "lane-a", "agent_profile": "writer" });
    let (status, body) = send(&router, Method::POST, "/v1/lanes", &owner, make).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["base_commit"], json!(a1));
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/lanes/lane-b/resolve",
        &owner,
        keep("b.txt", "B\n"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let b1 = lane_tip("lane-b");
    assert_eq!(body["lane"]["base_commit"], json!(a1), "{body}");
    assert_eq!(git(root, &["rev-parse", &format!("{b1}~1")]), a1);
    assert_eq!(blob(root, &b1, "a.txt"), "A\n");
    assert_eq!(blob(root, &b1, "b.txt"), "B\n");

    // main moves; rebasing A cascades to B.
    let m1 = commit_on(root, "refs/heads/main", &[("c.txt", "C\n")]);
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/lanes/lane-a/rebase",
        &owner,
        json!({ "cascade": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], true, "{body}");
    let a2 = lane_tip("lane-a");
    assert_eq!(
        (&body["lane"]["base_commit"], &body["lane"]["tip_oid"]),
        (&json!(m1), &json!(a2)),
        "{body}"
    );
    assert_eq!(git(root, &["rev-parse", &format!("{a2}~1")]), m1);
    assert_eq!(blob(root, &a2, "a.txt"), "A\n");
    assert_eq!(blob(root, &a2, "c.txt"), "C\n");
    let cascaded = body["cascaded_lanes"].as_array().unwrap();
    assert_eq!(cascaded.len(), 1, "{body}");
    assert_eq!(cascaded[0]["lane_id"], "lane-b");
    assert_eq!(cascaded[0]["base_commit"], json!(a2), "{body}");
    let b2 = lane_tip("lane-b");
    assert_eq!(cascaded[0]["tip_oid"], json!(b2));
    assert_eq!(git(root, &["rev-parse", &format!("{b2}~1")]), a2);
    for (path, text) in [("a.txt", "A\n"), ("b.txt", "B\n"), ("c.txt", "C\n")] {
        assert_eq!(blob(root, &b2, path), text);
    }
    assert!(try_git(root, &["cat-file", "-e", &format!("{a2}:b.txt")]).is_none());
    assert_eq!(main_tip(root), m1, "lanes never move the branch");
}

// ---- 5. closed-loop steering, R1 -> R2 on one Change-Id ------------------------------------

/// Checks the steering packet (comment 1 in, comment 2 completely out) then fixes README.md.
fn steer_command(readme: &str) -> String {
    let check = if cfg!(windows) {
        "$j = Get-Content -Raw $env:PREMIER_STEERING_FILE; $m = Get-Content -Raw $env:PREMIER_STEERING_MD; \
         if (-not $j.Contains('Fix heading typo') -or -not $m.Contains('Fix heading typo')) { exit 3 }; \
         foreach ($s in @($j, $m)) { if ($s.Contains('TOP_SECRET_TOKEN_XYZ') -or $s.Contains('billing/secret.rs')) { exit 4 } }"
            .to_owned()
    } else {
        "{ grep -q 'Fix heading typo' \"$PREMIER_STEERING_FILE\" && grep -q 'Fix heading typo' \"$PREMIER_STEERING_MD\"; } || exit 3; \
         if grep -q -e TOP_SECRET_TOKEN_XYZ -e billing/secret.rs \"$PREMIER_STEERING_FILE\" \"$PREMIER_STEERING_MD\"; then exit 4; fi"
            .to_owned()
    };
    format!("{check}; {}", write_cmd("README.md", readme))
}

#[tokio::test]
async fn steering_packages_only_readable_comments_and_lands_round_two_as_the_owner() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _) = fixture(root);
    let router = build_router(state.clone());
    let (cid, r1) = review_fixture(root, &router, &owner).await;
    let secret_before = git(root, &["rev-parse", "feature:billing/secret.rs"]);

    let comment = |path: &str, body: &str| json!({ "path": path, "line": 1, "body": body });
    let uri = format!("/v1/reviews/{cid}/comments");
    let (status, c1) = send(
        &router,
        Method::POST,
        &uri,
        &owner,
        comment("README.md", "Fix heading typo"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{c1}");
    let secret_comment = comment("billing/secret.rs", "Do not expose TOP_SECRET_TOKEN_XYZ");
    let (status, c2) = send(&router, Method::POST, &uri, &owner, secret_comment).await;
    assert_eq!(status, StatusCode::OK, "{c2}");
    assert_ne!(c1["id"], c2["id"], "comment ids are unique");

    let fixed = "# Demo\n\nHello world\n";
    let steer = json!({
        "agent_profile": "coder",
        "mark_changes_requested": true,
        "auto_commit": true,
        "instruction": "Address the review",
        "command": steer_command(fixed),
    });
    let (status, body) = send(
        &router,
        Method::POST,
        &format!("/v1/reviews/{cid}/steer"),
        &owner,
        steer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (
            &body["packaged_comments"],
            &body["redacted_comments"],
            &body["target_round"]
        ),
        (&json!(1), &json!(1), &json!(2)),
        "{body}"
    );
    let lane_id = body["lane_id"].as_str().unwrap().to_owned();
    let sid = body["session"]["id"].as_str().unwrap().to_owned();
    let rec = wait_session(&state, &sid).await;
    assert_eq!(
        (rec.status.as_str(), rec.exit_code),
        ("completed", Some(0)),
        "{rec:#?}"
    );
    wait_rounds(&state, &cid, 2).await;

    let (_, reviews) = get(&router, "/v1/reviews", &owner).await;
    let review = review_of(&reviews, &cid);
    let rounds = review["rounds"].as_array().unwrap();
    assert_eq!(rounds.len(), 2, "{review}");
    assert_eq!(rounds[1]["round"], 2);
    assert_eq!(rounds[1]["session_id"], json!(sid));
    assert_eq!(rounds[1]["addressed_comment_ids"], json!([c1["id"]]));
    assert_eq!(rounds[1]["steering_prompt"], "Address the review");
    assert_eq!(review["verdicts"]["r1:@owner"], "changes", "{review}");
    assert_eq!(review["lane_id"], json!(lane_id));
    let comments = review["comments"].as_array().unwrap();
    let addressed = |id: &Value| {
        comments.iter().find(|c| c["id"] == *id).unwrap()["addressed_in_round"].clone()
    };
    assert_eq!(addressed(&c1["id"]), json!(2));
    assert_eq!(addressed(&c2["id"]), Value::Null);

    // Round 2 is one commit on `feature` on top of round 1, by the owner (not `anonymous`), and
    // the file the agent could not see is untouched.
    let r2 = git(root, &["rev-parse", "refs/heads/feature"]);
    assert_eq!(git(root, &["rev-parse", &format!("{r2}~1")]), r1);
    assert_eq!(
        git(root, &["log", "-1", "--format=%an|%cn|%s", &r2]),
        format!("owner|owner|Review {cid} R2: Address the review")
    );
    assert_eq!(blob(root, &r2, "README.md"), fixed);
    assert_eq!(
        git(root, &["rev-parse", "feature:billing/secret.rs"]),
        secret_before
    );
    let done = state.session_manager.get(&sid).unwrap();
    assert_eq!(done.commit.as_deref(), Some(r2.as_str()));
    assert_eq!(done.review_round, Some(2));
    assert_eq!(
        git(
            root,
            &["rev-parse", &format!("refs/premier-lanes/{lane_id}")]
        ),
        r2
    );
}

// ---- 6. real interdiffs --------------------------------------------------------------------

#[tokio::test]
async fn interdiff_shows_the_round_delta_skips_upstream_noise_and_filters_for_members() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = fixture(root);
    let router = build_router(state.clone());
    let (cid, r1) = review_fixture(root, &router, &owner).await;
    let interdiff =
        |from: u32, to: u32| format!("/v1/reviews/{cid}/interdiff?from_round={from}&to_round={to}");

    // Round 2: a steered session (not auto-committed); upstream.txt lands on the branch meanwhile.
    let steer = json!({
        "agent_profile": "coder",
        "auto_commit": false,
        "command": write_cmd("README.md", "# Demo\n\nHello world R2\n"),
    });
    let (status, body) = send(
        &router,
        Method::POST,
        &format!("/v1/reviews/{cid}/steer"),
        &owner,
        steer,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let sid = body["session"]["id"].as_str().unwrap().to_owned();
    let rec = wait_session(&state, &sid).await;
    assert_eq!(rec.exit_code, Some(0), "{rec:#?}");
    let u1 = commit_on(
        root,
        "refs/heads/feature",
        &[
            ("upstream.txt", "upstream\n"),
            ("billing/upstream.rs", "u\n"),
        ],
    );
    let (status, body) = send(&router, Method::POST, &commit_uri(&sid), &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (&body["rebased"], &body["review_round"]),
        (&json!(true), &json!(2)),
        "{body}"
    );
    let r2 = body["commit"].as_str().unwrap().to_owned();
    assert_eq!(git(root, &["rev-parse", &format!("{r2}~1")]), u1);

    let (status, body) = get(&router, &interdiff(1, 2), &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (&body["from_oid"], &body["to_oid"]),
        (&json!(r1), &json!(r2))
    );
    assert_eq!(body["rebased_between_rounds"], true, "{body}");
    assert_eq!(body["upstream_files_skipped"], 2, "{body}");
    let paths: Vec<&str> = body["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["README.md"], "{body}");
    let readme = &body["files"][0];
    assert!(
        readme["patch"]
            .as_str()
            .unwrap()
            .contains("+Hello world R2"),
        "{body}"
    );
    assert_eq!(
        (&readme["additions"], &readme["deletions"]),
        (&json!(1), &json!(1))
    );
    let (status, _) = get(&router, &interdiff(2, 2), &owner).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = get(&router, &interdiff(1, 9), &owner).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Round 3 touches README.md and billing/secret.rs (an owner's unrestricted session).
    let cmd = then(&[
        write_cmd("README.md", "# Demo\n\nHello world R3\n"),
        write_cmd("billing/secret.rs", "r3 secret bytes\n"),
    ]);
    let body =
        json!({ "command": cmd, "agent_profile": "writer", "branch": "feature", "change_id": cid });
    let rec = run_session(&state, &router, &owner, body).await;
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["review_round"], 3, "{body}");
    let r3 = body["commit"].as_str().unwrap().to_owned();

    let (_, body) = get(&router, &interdiff(2, 3), &owner).await;
    let paths: Vec<&str> = body["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["README.md", "billing/secret.rs"], "{body}");

    // @mia: only what she may read, no count of the rest, and the commit ids of her own clone.
    let (status, body) = get(&router, &interdiff(2, 3), &mia).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let paths: Vec<&str> = body["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["README.md"], "{body}");
    assert_eq!(body["hidden_files"], 0, "{body}");
    assert!(!body.to_string().contains("billing"), "{body}");
    let (her_r2, her_r3) = (hers(&state, &r2), hers(&state, &r3));
    assert_eq!(
        (&body["from_oid"], &body["to_oid"]),
        (&json!(her_r2), &json!(her_r3)),
        "{body}"
    );
    assert_ne!(her_r3, r3);
    assert!(!body.to_string().contains(&r3) && !body.to_string().contains(&r2));
    // Upstream noise is counted for her only where she may list it (not billing/upstream.rs).
    let (_, body) = get(&router, &interdiff(1, 2), &mia).await;
    assert_eq!(body["upstream_files_skipped"], 1, "{body}");
    assert!(!body.to_string().contains("billing"), "{body}");
}

// ---- 7. provenance -------------------------------------------------------------------------

#[tokio::test]
async fn provenance_is_chronological_structured_and_scoped_per_viewer() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = fixture(root);
    let schema: premier_secrets::EnvSchema = serde_json::from_value(json!({
        "vars": { "API_TOKEN": { "egress": { "hosts": ["api.example.test"] } } }
    }))
    .unwrap();
    *state.env_schema.write().unwrap() = Some(Arc::new(schema));
    let router = build_router(state.clone());
    let (cid, _) = review_fixture(root, &router, &owner).await;

    // Egress to a host nobody allowed (blocked by the session's proxy), then two edits.
    let egress = if cfg!(windows) {
        "curl.exe -s -m 5 -x $env:PREMIER_PROXY_URL http://blocked.example.test/ | Out-Null"
            .to_owned()
    } else {
        "(curl -s -m 5 -x \"$PREMIER_PROXY_URL\" http://blocked.example.test/ >/dev/null 2>&1 || true)".to_owned()
    };
    let cmd = then(&[
        egress,
        write_cmd("README.md", "# Demo\n\nHello world P\n"),
        write_cmd("billing/secret.rs", "p secret bytes\n"),
    ]);
    let body =
        json!({ "command": cmd, "agent_profile": "writer", "branch": "feature", "change_id": cid });
    let rec = run_session(&state, &router, &owner, body).await;
    commit_on(root, "refs/heads/feature", &[("docs/guide.md", "moved\n")]);
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (&body["rebased"], &body["review_round"]),
        (&json!(true), &json!(2)),
        "{body}"
    );
    let commit = body["commit"].as_str().unwrap().to_owned();

    let uri = format!("/v1/agents/sessions/{}/provenance", rec.id);
    let (status, body) = get(&router, &uri, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let steps = body["steps"].as_array().unwrap();
    let seqs: Vec<u64> = steps.iter().map(|s| s["seq"].as_u64().unwrap()).collect();
    assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{body}");
    let first = |kind: &str| {
        steps
            .iter()
            .position(|s| s["kind"] == kind)
            .unwrap_or_else(|| panic!("no {kind} step in {body}"))
    };
    let order = [
        "session_start",
        "command_exec",
        "egress_blocked",
        "file_change",
        "session_exit",
        "auto_rebase",
        "round_commit",
    ]
    .map(first);
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?} {body}");
    assert_eq!(steps[order[2]]["decision"], "denied", "{body}");
    assert!(
        steps[order[2]]["target"]
            .as_str()
            .unwrap()
            .contains("blocked.example.test")
    );
    let changed: Vec<&str> = steps
        .iter()
        .filter(|s| s["kind"] == "file_change")
        .map(|s| s["path"].as_str().unwrap())
        .collect();
    assert_eq!(changed, ["README.md", "billing/secret.rs"]);
    // Someone else's session does not exist for @mia.
    let (status, _) = get(&router, &uri, &mia).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The review round carries the same steps: all of them for the owner...
    let round_steps = |reviews: &Value, path: &str| -> Option<Value> {
        let round = &review_of(reviews, &cid)["rounds"][1];
        round["hunks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["path"] == path)
            .map(|h| h["provenance"]["steps"].clone())
    };
    let (_, reviews) = get(&router, "/v1/reviews", &owner).await;
    let owner_steps = round_steps(&reviews, "README.md").unwrap();
    assert!(
        owner_steps.to_string().contains("billing/secret.rs"),
        "{owner_steps}"
    );
    assert!(
        owner_steps
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["kind"] == "round_commit")
    );
    // ...and for @mia nothing of billing, no hunk of it, and no canonical commit id.
    let (_, reviews) = get(&router, "/v1/reviews", &mia).await;
    assert!(
        round_steps(&reviews, "billing/secret.rs").is_none(),
        "{reviews}"
    );
    let mia_steps = round_steps(&reviews, "README.md").unwrap();
    let kinds: Vec<&str> = mia_steps
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["kind"].as_str().unwrap())
        .collect();
    for kind in [
        "session_start",
        "command_exec",
        "egress_blocked",
        "file_change",
        "session_exit",
        "auto_rebase",
        "round_commit",
    ] {
        assert!(
            kinds.contains(&kind),
            "{kind} missing for @mia: {mia_steps}"
        );
    }
    let text = mia_steps.to_string();
    assert!(!text.contains("billing"), "{text}");
    assert!(!text.contains(&commit[..12]), "{text}");
    assert!(!reviews.to_string().contains(&commit[..12]), "{reviews}");

    // Anonymous: no steps at all.
    let anonymous = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
    let stored = state.session_manager.get(&rec.id).unwrap().provenance_steps;
    assert!(!stored.is_empty());
    let policy = state.current_policy();
    assert!(
        crate::lanes::filter_steps_for_viewer(policy.as_deref(), &anonymous, "feature", &stored)
            .is_empty()
    );
}

// ---- 8. anti-CFOR, anti-oracle, owner-only routes and the live feed -------------------------

#[tokio::test]
async fn lane_refs_are_never_advertised_and_hidden_lanes_and_reviews_answer_like_missing_ones() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, mia_token) = fixture(root);
    let (_, olga_token) = state.auth.seed("olga", PW);
    let router = build_router(state.clone());

    // A lane with a commit of its own, and a conflicted session lane.
    let make = json!({ "lane_id": "lane-pub", "agent_profile": "writer" });
    let (status, _) = send(&router, Method::POST, "/v1/lanes", &owner, make).await;
    assert_eq!(status, StatusCode::OK);
    let keep = json!({ "apply_to_branch": false, "resolutions": [{ "path": "lane-only.txt", "content": "x\n" }] });
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/lanes/lane-pub/resolve",
        &owner,
        keep,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, conflict) = conflicted_session(&state, &router, &owner, "cfor").await;
    let lane_only = git(root, &["rev-parse", "refs/premier-lanes/lane-pub"]);
    let snapshot = conflict["lane_tip"].as_str().unwrap().to_owned();

    // Not in any projection, ref advertisement, branch list or clone.
    let canonical = CanonicalGitRepo::open(root);
    let policy = state.current_policy().unwrap();
    let visibility = state.branch_visibility_map();
    let mia_id = DelegatedIdentity::human_only(Principal::User("mia".to_owned()), vec![]);
    let owner_id = DelegatedIdentity::human_only(
        Principal::User("owner".to_owned()),
        vec!["owners".to_owned()],
    );
    for who in [&owner_id, &mia_id] {
        let view = project_repository(&canonical, &policy, "t", who, &visibility).unwrap();
        assert!(
            view.refs.keys().all(|r| !r.contains("premier-lanes")),
            "{:?}",
            view.refs
        );
        assert!(!view.canonical_to_projected.contains_key(&lane_only));
        assert!(!view.canonical_to_projected.contains_key(&snapshot));
        let advertised = String::from_utf8_lossy(&render_receive_pack_refs(&view)).into_owned();
        assert!(!advertised.contains("premier-lanes"), "{advertised}");
    }
    for cookie in [&owner, &mia] {
        let (_, body) = get(&router, "/v1/branches", cookie).await;
        assert!(!body.to_string().contains("premier-lanes"), "{body}");
        assert!(!body.to_string().contains("lane-"), "{body}");
    }
    let addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, served).await;
        });
        addr
    };
    for (user, token) in [("olga", olga_token.as_str()), ("mia", mia_token.as_str())] {
        let url = format!("http://{user}:{token}@{addr}/git/auth/repo.git");
        let dir = root.to_path_buf();
        let refs = tokio::task::spawn_blocking(move || try_git(&dir, &["ls-remote", &url]))
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("ls-remote as {user} failed"));
        assert!(refs.contains("refs/heads/main"), "{refs}");
        assert!(
            !refs.contains("premier-lanes")
                && !refs.contains(&lane_only)
                && !refs.contains(&snapshot),
            "{refs}"
        );
    }

    // A personal lane is a 404 to @mia exactly like a lane that does not exist.
    let personal = json!({
        "lane_id": "lane-hidden", "visibility": { "scope": "personal", "allow": ["@owner"] }
    });
    let (status, _) = send(&router, Method::POST, "/v1/lanes", &owner, personal).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(&router, "/v1/lanes/lane-hidden", &owner).await;
    assert_eq!(status, StatusCode::OK);
    let hidden = get(&router, "/v1/lanes/lane-hidden", &mia).await;
    let missing = get(&router, "/v1/lanes/lane-missing", &mia).await;
    assert_eq!(hidden.0, StatusCode::NOT_FOUND);
    assert_eq!(hidden, missing);
    let (_, listed) = get(&router, "/v1/lanes", &mia).await;
    assert!(!listed.to_string().contains("lane-hidden"), "{listed}");
    assert!(listed.to_string().contains("lane-pub"), "{listed}");
    // Her copy of a visible lane: no canonical ids, conflicts only as she may see them.
    let (_, pub_lane) = get(&router, "/v1/lanes/lane-pub", &mia).await;
    assert_ne!(pub_lane["tip_oid"], json!(lane_only));
    assert!(!listed.to_string().contains(&snapshot), "{listed}");

    // A review of a branch @mia cannot see: its interdiff is a 404 like a missing review's.
    let hush = commit_on(root, "refs/heads/main", &[("hush.txt", "hush\n")]);
    git(root, &["update-ref", "refs/premier-private/hush", &hush]);
    git(
        root,
        &["update-ref", "refs/heads/main", &format!("{hush}~1")],
    );
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/reviews",
        &owner,
        json!({ "title": "Hush", "branch": "hush" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hush_cid = body["change_id"].as_str().unwrap().to_owned();
    let hidden = get(
        &router,
        &format!("/v1/reviews/{hush_cid}/interdiff?from_round=0&to_round=1"),
        &mia,
    )
    .await;
    let missing = get(
        &router,
        "/v1/reviews/I0000000000/interdiff?from_round=0&to_round=1",
        &mia,
    )
    .await;
    assert_eq!(hidden.0, StatusCode::NOT_FOUND);
    assert_eq!(hidden, missing);
    let (status, _) = get(
        &router,
        &format!("/v1/reviews/{hush_cid}/interdiff?from_round=0&to_round=1"),
        &owner,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Every lane and steering mutation is the owners'.
    for (method, uri, body) in [
        (
            Method::POST,
            "/v1/lanes".to_owned(),
            json!({ "lane_id": "lane-mia" }),
        ),
        (
            Method::POST,
            "/v1/lanes/lane-pub/rebase".to_owned(),
            json!({ "cascade": true }),
        ),
        (
            Method::POST,
            "/v1/lanes/lane-pub/resolve".to_owned(),
            json!({ "resolutions": [] }),
        ),
        (Method::DELETE, "/v1/lanes/lane-pub".to_owned(), json!({})),
        (
            Method::POST,
            format!("/v1/reviews/{hush_cid}/steer"),
            json!({ "command": "echo hi" }),
        ),
    ] {
        let (status, body) = send(&router, method, &uri, &mia, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}");
        assert_eq!(body["error"], OWNER_ONLY, "{uri}");
    }
    assert!(
        state
            .persisted
            .lock()
            .unwrap()
            .lanes
            .iter()
            .all(|l| l.lane_id != "lane-mia")
    );
    assert_eq!(
        git(root, &["rev-parse", "refs/premier-lanes/lane-pub"]),
        lane_only
    );

    // Deleting a lane removes its snapshot ref.
    let (status, _) = send(
        &router,
        Method::DELETE,
        "/v1/lanes/lane-pub",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        try_git(
            root,
            &["rev-parse", "-q", "--verify", "refs/premier-lanes/lane-pub"]
        )
        .is_none()
    );
    let (status, _) = get(&router, "/v1/lanes/lane-pub", &owner).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The `(event, data)` frames of an SSE text.
fn frames(text: &str) -> Vec<(String, Value)> {
    text.split("\n\n")
        .filter_map(|block| {
            let mut event = None;
            let mut data = String::new();
            for line in block.lines() {
                if let Some(e) = line.strip_prefix("event:") {
                    event = Some(e.trim().to_owned());
                } else if let Some(d) = line.strip_prefix("data:") {
                    data.push_str(d.trim_start());
                }
            }
            Some((event?, serde_json::from_str(&data).ok()?))
        })
        .collect()
}

/// Read `stream` into `buf` until `done` holds of it or `within` passes.
async fn read_until(
    stream: &mut hyper::body::Incoming,
    buf: &mut String,
    within: Duration,
    done: impl Fn(&str) -> bool,
) {
    let _ = tokio::time::timeout(within, async {
        while !done(buf) {
            match stream.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        buf.push_str(&String::from_utf8_lossy(&data));
                    }
                }
                _ => break,
            }
        }
    })
    .await;
}

#[tokio::test]
async fn the_live_feed_gives_members_only_visible_lanes_reviews_and_stripped_sessions() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _) = fixture(root);
    let router = build_router(state.clone());
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
    let (mut owner_feed, mut mia_feed) = (open(&owner).await, open(&mia).await);
    let (mut owner_buf, mut mia_buf) = (String::new(), String::new());
    for (feed, buf) in [
        (&mut owner_feed, &mut owner_buf),
        (&mut mia_feed, &mut mia_buf),
    ] {
        read_until(feed, buf, Duration::from_secs(5), |b| b.contains("ready")).await;
        assert!(buf.contains("ready"), "{buf}");
    }

    // A personal lane, a conflicted public lane, a public and a hidden review, and a session of
    // @mia's own.
    let personal = json!({ "lane_id": "lane-secret", "visibility": { "scope": "personal", "allow": ["@owner"] } });
    let (status, _) = send(&router, Method::POST, "/v1/lanes", &owner, personal).await;
    assert_eq!(status, StatusCode::OK);
    let (_, conflict) = conflicted_session(&state, &router, &owner, "sse").await;
    let public_lane = conflict["lane_id"].as_str().unwrap().to_owned();
    let lane_tip = conflict["lane_tip"].as_str().unwrap().to_owned();
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/reviews",
        &owner,
        json!({ "title": "Main", "branch": "main" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let public_cid = body["change_id"].as_str().unwrap().to_owned();
    let hush = commit_on(root, "refs/heads/main", &[("hush.txt", "hush\n")]);
    git(root, &["update-ref", "refs/premier-private/hush", &hush]);
    git(
        root,
        &["update-ref", "refs/heads/main", &format!("{hush}~1")],
    );
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/reviews",
        &owner,
        json!({ "title": "Hush", "branch": "hush" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hidden_cid = body["change_id"].as_str().unwrap().to_owned();

    let mia_id = DelegatedIdentity::human_only(Principal::User("mia".to_owned()), vec![]);
    let mia_session = state
        .session_manager
        .spawn_session(runner::SessionRequest {
            workspace_root: root.to_path_buf(),
            identity: mia_id,
            env_name: "dev".to_owned(),
            command: "echo hi".to_owned(),
            branch: "main".to_owned(),
            full_ref: Some("refs/heads/main".to_owned()),
            ref_visibility: state.branch_visibility_map(),
            policy: state.current_policy(),
            schema: None,
            audit_sink: Arc::clone(&state.audit_sink),
            approval_hub: Arc::clone(&state.approval_hub),
            cage: runner::Cage {
                mode: runner::sandbox_mode(true),
                hidden: Vec::new(),
            },
            limit: Duration::from_secs(120),
            quarantine_approvals: std::collections::BTreeMap::new(),
            budget: None,
            base_commit_override: None,
            lane_id: None,
            change_id: None,
            steering_packet: None,
            on_complete: None,
        })
        .await
        .unwrap();
    let done = wait_session(&state, &mia_session.id).await;
    assert!(done.base_commit.is_some() && !done.provenance_steps.is_empty());

    let owner_saw = |b: &str| {
        [
            "lane-secret",
            public_lane.as_str(),
            public_cid.as_str(),
            hidden_cid.as_str(),
        ]
        .iter()
        .all(|needle| b.contains(needle))
    };
    read_until(
        &mut owner_feed,
        &mut owner_buf,
        Duration::from_secs(20),
        owner_saw,
    )
    .await;
    assert!(owner_saw(&owner_buf), "{owner_buf}");
    let mia_saw = |b: &str| {
        b.contains(public_lane.as_str())
            && b.contains(public_cid.as_str())
            && frames(b)
                .iter()
                .any(|(e, d)| e == "session" && d["status"] == "completed")
    };
    read_until(
        &mut mia_feed,
        &mut mia_buf,
        Duration::from_secs(20),
        mia_saw,
    )
    .await;
    assert!(mia_saw(&mia_buf), "{mia_buf}");
    // Give anything that should not arrive a moment to.
    read_until(
        &mut mia_feed,
        &mut mia_buf,
        Duration::from_millis(500),
        |_| false,
    )
    .await;

    // The owner gets canonical ids and conflicts.
    let owner_frames = frames(&owner_buf);
    assert!(owner_frames.iter().any(|(e, d)| e == "lane"
        && d["lane_id"] == public_lane.as_str()
        && d["tip_oid"] == lane_tip.as_str()
        && !d["conflicts"].as_array().unwrap().is_empty()));

    // @mia: nothing of the personal lane or the hidden review, and stripped visible frames.
    assert!(!mia_buf.contains("lane-secret"), "{mia_buf}");
    assert!(!mia_buf.contains(&hidden_cid), "{mia_buf}");
    assert!(!mia_buf.contains(&lane_tip), "{mia_buf}");
    let mia_frames = frames(&mia_buf);
    let lanes: Vec<&Value> = mia_frames
        .iter()
        .filter(|(e, _)| e == "lane")
        .map(|(_, d)| d)
        .collect();
    assert!(!lanes.is_empty(), "{mia_buf}");
    for lane in lanes {
        assert!(
            lane.get("tip_oid").is_none() && lane.get("base_commit").is_none(),
            "{lane}"
        );
        assert_eq!(lane["conflicts"], json!([]), "{lane}");
    }
    for (_, review) in mia_frames.iter().filter(|(e, _)| e == "review") {
        assert_eq!(review["change_id"], json!(public_cid), "{review}");
        assert!(review.get("lane_id").is_none(), "{review}");
    }
    let sessions: Vec<&Value> = mia_frames
        .iter()
        .filter(|(e, _)| e == "session")
        .map(|(_, d)| d)
        .collect();
    assert!(!sessions.is_empty());
    for session in sessions {
        assert_eq!(session["principal"], "@mia", "{session}");
        assert!(
            session["base_commit"].is_null() && session["commit"].is_null(),
            "{session}"
        );
        assert_eq!(session["conflicts"], json!([]), "{session}");
        assert_eq!(session["provenance_steps"], json!([]), "{session}");
    }
}
