use std::time::Duration;

use axum::http::Method;
use premier_core::Principal;
use premier_policy::parse_policy_toml;
use serde_json::{Value, json};

use super::*;
use crate::build_router;
use crate::tests::{call, member_state};

/// Owners may do everything; agent profile `reader` reads all but `secret/**`, `writer` may
/// also write (still not `secret/**`).
const POLICY: &str = r#"
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
name = "reader"
allow_paths = ["**"]
deny_paths = ["secret/**"]
capabilities = ["traverse", "list", "read"]
[[agent_profiles]]
name = "writer"
allow_paths = ["**"]
deny_paths = ["secret/**"]
capabilities = ["traverse", "list", "read", "write"]
allow_egress_hosts = ["127.0.0.1"]
"#;

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new("git")
        .current_dir(root)
        .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
        .args(args)
        .output()
        .unwrap();
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Removes the sessions' workspaces of a test repository from the temp directory.
struct Sessions(PathBuf);

impl Drop for Sessions {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(sessions_root(&self.0));
    }
}

/// A repository whose `main` holds README.md, docs/guide.md and secret/plan.md, under [`POLICY`],
/// where sessions run unconfined when the host has no sandbox. Returns the owner's and a
/// member's cookie.
fn fixture(root: &Path) -> (ServerState, String, String, Sessions) {
    let (mut state, owner, mia, _) = member_state(root);
    let file = parse_policy_toml(POLICY).unwrap();
    *state.policy.write().unwrap() = Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));
    state.set_repo_policy_metadata(Some(POLICY.to_owned()), Some(Arc::new(file)));
    state.session_manager = Arc::new(SessionManager::open(root));
    state.allow_unsandboxed_agents = true;
    for (path, text) in [
        ("docs/guide.md", "guide\n"),
        ("secret/plan.md", "the plan\n"),
    ] {
        std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
        std::fs::write(root.join(path), text).unwrap();
    }
    git(root, &["init", "-q", "-b", "main"]).unwrap();
    git(root, &["config", "core.autocrlf", "false"]).unwrap();
    git(root, &["add", "README.md", "docs", "secret"]).unwrap();
    git(root, &["commit", "-q", "-m", "initial"]).unwrap();
    (state, owner, mia, Sessions(root.to_path_buf()))
}

fn agent(profile: &str) -> DelegatedIdentity {
    DelegatedIdentity::delegated(
        Principal::parse("@owner").unwrap(),
        vec!["owners".to_owned()],
        profile,
        "t-1",
    )
}

#[test]
fn cage_arguments_bind_nothing_canonical_and_leave_no_network() {
    let hidden = [
        "/home/premier",
        "/root",
        "/run",
        "/srv/repo",
        "/srv/repos",
        "/tmp/premier-sessions",
        "/var/lib",
    ]
    .map(PathBuf::from);
    let plan = |user| CagePlan {
        workspace: Path::new("/var/sessions/cage-0001/ws"),
        proxy_dir: Path::new("/var/sessions/cage-0001/proxy"),
        exe: Path::new("/usr/local/bin/premier"),
        hidden: &hidden,
        user,
    };
    let text = |user| -> Vec<String> {
        cage_args(&plan(user))
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    };
    let args = text(CageUser::Unprivileged);
    let at = |needle: &[&str]| {
        args.windows(needle.len())
            .position(|w| w == needle)
            .unwrap_or_else(|| panic!("{needle:?} not in {args:?}"))
    };

    // Every namespace is private, the network included.
    at(&["--unshare-all"]);
    assert!(!args.iter().any(|a| a == "--share-net"), "{args:?}");
    // Not root.
    at(&["--unshare-user", "--uid", "1000", "--gid", "1000"]);
    for flag in ["--die-with-parent", "--new-session"] {
        at(&[flag]);
    }
    at(&["--dev", "/dev"]);
    let tmp = at(&["--tmpfs", "/tmp"]);
    // The host root is NOT in the sandbox: only an allow-list of it is, read-only. What is not
    // mounted needs no hiding: `/etc/shadow`, the state directory, the repositories, `/run`
    // (the Docker socket), every home.
    assert!(
        !args
            .windows(3)
            .any(|w| w[0].ends_with("bind") && w[1] == "/"),
        "{args:?}"
    );
    let allowed = [
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/etc/ssl/certs",
        "/etc/ssl/openssl.cnf",
        "/etc/ca-certificates",
        "/etc/alternatives",
        "/etc/passwd",
        "/etc/group",
        "/tmp/workspace",
        "/tmp/premier-proxy",
        "/tmp/premier",
    ];
    let mut mounted = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--bind" || arg == "--ro-bind" || arg == "--symlink" {
            mounted.push(args[i + 2].as_str());
        }
    }
    assert!(
        mounted.iter().all(|dest| allowed.contains(dest)),
        "{mounted:?}"
    );
    for gone in [
        "/home/premier",
        "/root",
        "/run",
        "/srv/repo",
        "/srv/repos",
        "/var/lib",
        "/etc/shadow",
        "/etc/resolv.conf",
    ] {
        assert!(!args.iter().any(|a| a == gone), "{gone} in {args:?}");
    }
    assert!(!args.iter().any(|a| a.contains("docker.sock")), "{args:?}");
    // The account files are generated ones, never the host's.
    assert!(
        mounted.contains(&"/etc/passwd") && mounted.contains(&"/etc/group"),
        "{mounted:?}"
    );
    // The empty root is sealed last.
    assert!(tmp < at(&["--remount-ro", "/"]));
    // Its own process ids and a `/proc` of them: `/proc/1` is the sandbox's first process, so
    // the server's `/proc/<pid>/environ` is not there to read.
    at(&["--proc", "/proc"]);
    assert!(
        !args
            .iter()
            .any(|a| a.starts_with("--share") || a == "--as-pid-1"),
        "{args:?}"
    );
    // A home of its own, in the private `/tmp`.
    assert!(tmp < at(&["--dir", CAGE_HOME]));
    assert!(Path::new(CAGE_HOME).starts_with("/tmp"));
    // The one writable host directory is the session workspace, the proxy socket is bound in.
    assert!(tmp < at(&["--bind", "/var/sessions/cage-0001/ws", "/tmp/workspace"]));
    assert!(
        tmp < at(&[
            "--ro-bind",
            "/var/sessions/cage-0001/proxy",
            "/tmp/premier-proxy"
        ])
    );
    assert!(tmp < at(&["--ro-bind", "/usr/local/bin/premier", "/tmp/premier"]));
    at(&["--chdir", "/tmp/workspace"]);
    // No path of the canonical repository, the repos directory or server state is a bind source.
    let writable: Vec<_> = args
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "--bind")
        .collect();
    assert_eq!(writable.len(), 1, "{args:?}");
    for (i, arg) in args.iter().enumerate() {
        if arg == "--bind" || arg == "--ro-bind" {
            let source = &args[i + 1];
            assert!(
                !source.starts_with("/srv") && !source.contains(".premier/"),
                "{source}"
            );
        }
    }

    // Without user namespaces: still no capability, still no network.
    let args = text(CageUser::RootNoCaps);
    assert!(
        args.windows(2).any(|w| w == ["--cap-drop", "ALL"]),
        "{args:?}"
    );
    assert!(
        !args.iter().any(|a| a == "--uid" || a == "--share-net"),
        "{args:?}"
    );

    // The command runs behind the relay to the bound socket.
    let command = cage_command(&plan(CageUser::Unprivileged), &["sh", "-c", "true"]);
    let argv: Vec<String> = command
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let tail = &argv[argv.len() - 11..];
    assert_eq!(
        tail,
        [
            "--",
            "/tmp/premier",
            "__cage-exec",
            "--proxy-socket",
            "/tmp/premier-proxy/proxy.sock",
            "--listen",
            "127.0.0.1:3128",
            "--",
            "sh",
            "-c",
            "true"
        ]
    );
}

#[test]
fn hidden_directories_are_real_outermost_and_include_the_server_home() {
    let tmp = tempfile::tempdir().unwrap();
    let (outer, inner) = (tmp.path().join("a"), tmp.path().join("a/b"));
    std::fs::create_dir_all(&inner).unwrap();
    let hidden = hidden_dirs([
        inner.clone(),
        outer.clone(),
        outer.clone(),
        tmp.path().join("missing"),
    ]);
    let covered = |dir: &Path| {
        hidden
            .iter()
            .any(|h| dir.canonicalize().unwrap().starts_with(h))
    };
    assert!(covered(&outer) && covered(&inner), "{hidden:?}");
    assert!(
        !hidden.contains(&inner.canonicalize().unwrap()),
        "{hidden:?}"
    );
    // Nothing twice, nothing under another entry, nothing that is not a directory, never `/`.
    for (i, dir) in hidden.iter().enumerate() {
        assert!(dir.is_dir() && dir.parent().is_some(), "{hidden:?}");
        assert!(
            !hidden
                .iter()
                .enumerate()
                .any(|(j, other)| i != j && dir.starts_with(other)),
            "{hidden:?}"
        );
    }
    // The server user's home, wherever it really is.
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_dir());
    if let Some(home) = home.filter(|h| h.canonicalize().unwrap().parent().is_some()) {
        assert!(covered(&home), "{hidden:?}");
    }
}

#[test]
fn a_hidden_directory_under_an_allowed_one_is_emptied() {
    let hidden = [
        PathBuf::from("/usr/local/premier-state"),
        PathBuf::from("/srv/repo"),
    ];
    let plan = CagePlan {
        workspace: Path::new("/s/ws"),
        proxy_dir: Path::new("/s/proxy"),
        exe: Path::new("/usr/local/bin/premier"),
        hidden: &hidden,
        user: CageUser::Unprivileged,
    };
    let args: Vec<String> = cage_args(&plan)
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert!(
        args.windows(2)
            .any(|w| w == ["--tmpfs", "/usr/local/premier-state"]),
        "{args:?}"
    );
    // Not mounted at all, so not named at all.
    assert!(!args.iter().any(|a| a == "/srv/repo"), "{args:?}");
}

#[test]
fn session_workspaces_are_private_and_never_a_predictable_shared_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = sessions_root(tmp.path());
    let shared = std::env::temp_dir().join("premier-sessions");
    assert!(!root.starts_with(&shared), "{root:?}");
    // Under the state directory once the repository has one.
    let ws = tmp.path().join("repo");
    crate::store::bind_state_dir(&ws, &tmp.path().join("state"), "repo", true);
    let bound = sessions_root(&ws);
    assert!(
        bound.starts_with(tmp.path().join("state/repos/repo")),
        "{bound:?}"
    );
    crate::store::unbind_state_dir(&ws);

    let dir = tmp.path().join("private");
    private_dir(&dir).unwrap();
    private_dir(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        // Someone else's idea of that directory is refused, not adopted.
        let open = tmp.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(private_dir(&open).is_err());
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert!(private_dir(&link).is_err());
    }
}

#[tokio::test]
async fn shutdown_keeps_session_workspace_until_repository_removal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let manager = SessionManager::open(root);
    let id = "cage-0001";
    let workspace = session_dir(root, id).join("ws");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("recovery.txt"), "pending changes").unwrap();
    manager.upsert(AgentSessionRecord {
        id: id.to_owned(),
        status: "running".to_owned(),
        ..AgentSessionRecord::default()
    });
    manager.shutdown().await;
    assert!(workspace.join("recovery.txt").is_file());
    let reopened = SessionManager::open(root);
    assert_eq!(reopened.get(id).unwrap().status, "interrupted");
    assert!(workspace.join("recovery.txt").is_file());
    reopened.stop_all().await;
    assert!(!workspace.exists());
}

#[test]
fn change_set_work_is_bounded_before_anything_is_read() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path();
    std::fs::write(ws.join("small.txt"), "ok\n").unwrap();
    // Sparse: 9 MiB by its metadata, never written. Over the per-file cap and new: not opened.
    let big = std::fs::File::create(ws.join("huge.bin")).unwrap();
    big.set_len(MAX_CHANGE_FILE_BYTES + 1024 * 1024).unwrap();
    drop(big);
    let (changes, truncated, skipped, _) = diff_workspace_full(ws, &Base::new());
    let paths: Vec<&str> = changes.iter().map(|(c, _)| c.path.as_str()).collect();
    assert_eq!(paths, ["small.txt"]);
    assert!(truncated && skipped.is_empty());

    #[cfg(unix)]
    {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir(&ws).unwrap();
        let outside = tmp.path().join("outside-secret");
        std::fs::write(&outside, "host secret\n").unwrap();
        // A second name for a file outside the walk, and two links that leave the workspace.
        std::fs::hard_link(&outside, ws.join("alias")).unwrap();
        std::os::unix::fs::symlink(&outside, ws.join("abs-link")).unwrap();
        std::os::unix::fs::symlink("../outside-secret", ws.join("up-link")).unwrap();
        std::os::unix::fs::symlink("kept.txt", ws.join("in-link")).unwrap();
        std::fs::write(ws.join("kept.txt"), "kept\n").unwrap();
        let (changes, truncated, skipped, _) = diff_workspace_full(&ws, &Base::new());
        let got: Vec<(&str, &str)> = changes
            .iter()
            .map(|(c, _)| (c.path.as_str(), c.mode.as_str()))
            .collect();
        // The inside link is a link (its target text), never the file it names.
        assert_eq!(got, [("in-link", MODE_LINK), ("kept.txt", MODE_FILE)]);
        assert_eq!(changes[0].1.as_deref(), Some(b"kept.txt".as_slice()));
        assert_eq!(skipped, ["abs-link", "up-link"]);
        assert!(truncated, "a hard-linked file marks the set incomplete");
        assert!(!changes.iter().any(|(_, content)| {
            content
                .as_deref()
                .is_some_and(|c| c.starts_with(b"host secret"))
        }));
    }
}

fn link(target: &str, at: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    return std::os::unix::fs::symlink(target, at);
    #[cfg(windows)]
    return std::os::windows::fs::symlink_file(target, at);
}

#[test]
fn many_escaping_links_are_walked_quickly_and_recorded_capped() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path();
    if link("/etc/passwd", &ws.join("probe")).is_err() {
        eprintln!("skipped: this host cannot make symbolic links");
        return;
    }
    for i in 0..10_000 {
        link("/etc/passwd", &ws.join(format!("l{i:05}"))).unwrap();
    }
    let started = std::time::Instant::now();
    let left = diff_workspace_full(ws, &Base::new());
    let (changes, _, skipped, more) = &left;
    assert!(changes.is_empty());
    assert_eq!((skipped.len(), skipped.len() + more), (MAX_SKIPPED, 10_001));
    let mut rec = AgentSessionRecord {
        skipped: vec!["l00000".to_owned(), "from-branch".to_owned()],
        ..Default::default()
    };
    note_changes(&mut rec, left);
    assert_eq!(rec.skipped.len(), MAX_SKIPPED);
    // The branch's own link and every one the session made are accounted for, once each.
    assert_eq!(rec.skipped.len() + rec.skipped_truncated, 10_002);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn the_running_workspace_budget_counts_bytes_without_following_links() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws");
    std::fs::create_dir_all(ws.join("sub")).unwrap();
    std::fs::write(ws.join("sub/a"), vec![0u8; 600]).unwrap();
    assert!(!workspace_over_budget(&ws, 1000));
    let big = tmp.path().join("outside");
    std::fs::write(&big, vec![0u8; 4096]).unwrap();
    // A link to something large is the link's size, never its target's.
    let _ = link(big.to_str().unwrap(), &ws.join("ln"));
    assert!(!workspace_over_budget(&ws, 1000));
    std::fs::write(ws.join("b"), vec![0u8; 600]).unwrap();
    assert!(workspace_over_budget(&ws, 1000));
}

#[test]
fn a_bwrap_failure_names_the_container_options() {
    let why = explain_bwrap_failure(
        "bwrap: Can't mount proc on /newroot/proc: Operation not permitted\n",
    );
    assert!(why.starts_with("bwrap: Can't mount proc"), "{why}");
    assert!(
        why.contains("--security-opt seccomp=unconfined --security-opt systempaths=unconfined")
    );
    assert_eq!(
        explain_bwrap_failure("bwrap: unknown option"),
        "bwrap: unknown option"
    );
    // What this host reports is what a session would get.
    let detail = sandbox_detail(false);
    assert_eq!(
        sandbox_mode(false) == SandboxMode::Bwrap,
        probe().user.is_some()
    );
    if !cfg!(target_os = "linux") {
        assert_eq!(sandbox_mode(false), SandboxMode::None);
        assert!(detail.contains("Linux"), "{detail}");
        assert!(sandbox_detail(true).contains("unconfined"));
    }
}

#[test]
fn workspace_holds_only_what_the_session_identity_may_read() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _, _, _sessions) = fixture(tmp.path());
    let secret_blob = git(tmp.path(), &["rev-parse", "HEAD:secret/plan.md"]).unwrap();
    let tip = git(tmp.path(), &["rev-parse", "HEAD"]).unwrap();
    let out = tempfile::tempdir().unwrap();
    let ws = out.path().join("ws");

    let (base_tip, base, skipped) = materialise(
        tmp.path(),
        Some("refs/heads/main"),
        "main",
        state.current_policy().as_deref(),
        &agent("reader"),
        &HashMap::new(),
        &ws,
        None,
    )
    .unwrap();
    assert_eq!(base_tip.as_deref(), Some(tip.as_str()));
    assert_eq!(
        base.keys().collect::<Vec<_>>(),
        ["README.md", "docs/guide.md"]
    );
    assert!(skipped.is_empty());
    assert_eq!(
        std::fs::read_to_string(ws.join("README.md")).unwrap(),
        "# Demo\n"
    );
    assert_eq!(
        std::fs::read_to_string(ws.join("docs/guide.md")).unwrap(),
        "guide\n"
    );
    // The denied file is not there in any form: not as a file, not as an object, not in history.
    assert!(!ws.join("secret").exists());
    assert!(git(&ws, &["cat-file", "-e", &secret_blob]).is_err());
    assert!(git(&ws, &["cat-file", "-e", "HEAD:secret/plan.md"]).is_err());
    assert!(
        git(&ws, &["cat-file", "-e", &tip]).is_err(),
        "canonical history must not be there"
    );
    // A standalone repository: one commit, clean, and `git diff` sees an edit.
    assert_eq!(git(&ws, &["rev-list", "--count", "HEAD"]).unwrap(), "1");
    assert_eq!(git(&ws, &["status", "--porcelain"]).unwrap(), "");
    std::fs::write(ws.join("README.md"), "# Edited\n").unwrap();
    assert!(git(&ws, &["diff"]).unwrap().contains("+# Edited"));
    assert!(!ws.join(".premier").exists() && !ws.join(".premier-local").exists());

    // An unknown profile reads nothing: an empty workspace, never the whole tree.
    let empty = out.path().join("empty");
    let (base_tip, base, skipped) = materialise(
        tmp.path(),
        Some("refs/heads/main"),
        "main",
        state.current_policy().as_deref(),
        &agent("nobody"),
        &HashMap::new(),
        &empty,
        None,
    )
    .unwrap();
    assert_eq!(
        (base_tip.as_deref(), base.len(), skipped.len()),
        (Some(tip.as_str()), 0, 0)
    );
    let listed: Vec<_> = std::fs::read_dir(&empty)
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(listed, [".git"]);
    // No policy: nothing is shown to be readable, so nothing is handed out.
    let refused = materialise(
        tmp.path(),
        Some("refs/heads/main"),
        "main",
        None,
        &agent("reader"),
        &HashMap::new(),
        &empty,
        None,
    );
    assert!(refused.is_err());
}

#[test]
fn change_set_is_added_modified_deleted_without_git_or_links() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path();
    let oid = |text: &str| {
        (
            "100644".to_owned(),
            hash_git_object(GitObjectKind::Blob, text.as_bytes()),
        )
    };
    let base = BTreeMap::from([
        ("README.md".to_owned(), oid("# Demo\n")),
        ("docs/guide.md".to_owned(), oid("guide\n")),
        ("docs/same.md".to_owned(), oid("same\n")),
    ]);
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    std::fs::create_dir_all(ws.join(".git")).unwrap();
    std::fs::create_dir_all(ws.join("sub/.git")).unwrap();
    std::fs::write(ws.join(".git/config"), "[core]\n").unwrap();
    std::fs::write(ws.join("sub/.git/HEAD"), "x").unwrap();
    std::fs::write(ws.join("README.md"), "# Changed\n").unwrap();
    std::fs::write(ws.join("docs/same.md"), "same\n").unwrap();
    std::fs::write(ws.join("sub/new.txt"), "new").unwrap();
    // A link to a file outside the workspace is not read into the change set.
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/passwd", ws.join("stolen")).unwrap();

    let (changes, truncated, _, _) = diff_workspace_full(ws, &base);
    assert!(!truncated);
    let listed: Vec<(&str, &str, u64)> = changes
        .iter()
        .map(|(c, _)| (c.path.as_str(), c.kind.as_str(), c.size))
        .collect();
    assert_eq!(
        listed,
        [
            ("README.md", "modified", 10),
            ("docs/guide.md", "deleted", 0),
            ("sub/new.txt", "added", 3)
        ]
    );
    assert_eq!(changes[0].1.as_deref(), Some(b"# Changed\n".as_slice()));
    assert_eq!(changes[1].1, None);
    assert_eq!(changes[2].1.as_deref(), Some(b"new".as_slice()));
    assert!(
        changes[0].0.mode == "100644"
            && changes[1].0.mode.is_empty()
            && changes[2].0.mode == "100644"
    );

    // A file too large to carry makes the set incomplete, and is not even opened.
    std::fs::write(
        ws.join("big.bin"),
        vec![0u8; (MAX_CHANGE_FILE_BYTES + 1) as usize],
    )
    .unwrap();
    let (changes, truncated, _, _) = diff_workspace_full(ws, &base);
    assert!(truncated);
    assert!(!changes.iter().any(|(c, _)| c.path == "big.bin"));
}

#[test]
fn modes_and_links_are_carried_through_a_workspace() {
    for (link, target) in [
        ("docs/l", "guide.md"),
        ("docs/l", "../README.md"),
        ("a/b/l", "../../x/./y"),
        ("l", "."),
    ] {
        assert!(link_stays_inside(link, target), "{link} -> {target}");
    }
    for (link, target) in [
        ("l", ""),
        ("l", "/etc/passwd"),
        ("l", "../x"),
        ("docs/l", "../../x"),
        // Contained on paper; through a link behind `s` it is not.
        ("a/b/l", "s/../../../x"),
        ("docs/l", "../.git/config"),
        ("l", ".GIT"),
        ("l", "a//b"),
    ] {
        assert!(!link_stays_inside(link, target), "{link} -> {target}");
    }

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, _, _, _sessions) = fixture(root);
    // An executable and three links, written as index entries: this host's filesystem may have
    // neither.
    std::fs::write(root.join("run.sh"), "#!/bin/sh\n").unwrap();
    git(root, &["add", "run.sh"]).unwrap();
    git(root, &["update-index", "--chmod=+x", "run.sh"]).unwrap();
    let scratch = tempfile::tempdir().unwrap();
    for (path, target) in [
        ("docs/inside", "guide.md"),
        ("docs/climbs", "../../x"),
        ("outside", "/etc/passwd"),
    ] {
        let text = scratch.path().join("target");
        std::fs::write(&text, target).unwrap();
        let blob = git(
            root,
            &["hash-object", "-w", "--no-filters", text.to_str().unwrap()],
        )
        .unwrap();
        git(
            root,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("120000,{blob},{path}"),
            ],
        )
        .unwrap();
    }
    git(root, &["commit", "-q", "-m", "modes"]).unwrap();
    let tip = git(root, &["rev-parse", "HEAD"]).unwrap();
    let mode_of = |path: &str| {
        let listed = git(root, &["ls-tree", "refs/heads/main", "--", path]).unwrap();
        listed.split(' ').next().unwrap().to_owned()
    };

    let out = tempfile::tempdir().unwrap();
    let ws = out.path().join("ws");
    let policy = state.current_policy();
    let (_, base, skipped) = materialise(
        root,
        Some("refs/heads/main"),
        "main",
        policy.as_deref(),
        &agent("writer"),
        &HashMap::new(),
        &ws,
        None,
    )
    .unwrap();
    assert_eq!(
        (base["run.sh"].0.as_str(), base["README.md"].0.as_str()),
        ("100755", "100644")
    );
    // Only a link that stays inside is made, where the host can make one; the rest is named.
    let is_link = |path: &str| {
        std::fs::symlink_metadata(ws.join(path)).is_ok_and(|m| m.file_type().is_symlink())
    };
    if cfg!(unix) {
        assert_eq!(skipped, ["docs/climbs", "outside"]);
        assert_eq!(base["docs/inside"].0, "120000");
        assert!(is_link("docs/inside"));
        assert_eq!(
            std::fs::read_to_string(ws.join("docs/inside")).unwrap(),
            "guide\n"
        );
    } else {
        assert_eq!(skipped, ["docs/climbs", "docs/inside", "outside"]);
    }
    assert!(!is_link("outside") && !is_link("docs/climbs"));
    assert!(skipped.iter().all(|path| !base.contains_key(path)));
    // Untouched, nothing differs: not the modes, not the links (made or skipped).
    assert_eq!(
        diff_workspace_full(&ws, &base),
        (Vec::new(), false, Vec::new(), 0)
    );

    std::fs::write(ws.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    std::fs::write(ws.join("new.sh"), "#!/bin/sh\n").unwrap();
    #[cfg(unix)]
    for path in ["run.sh", "new.sh", "README.md"] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(ws.join(path), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(unix)]
    {
        // A link the agent made that stays inside is carried as a link; one that leaves is not.
        std::os::unix::fs::symlink("docs/guide.md", ws.join("shortcut")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", ws.join("stolen")).unwrap();
    }
    let (changes, truncated, _, _) = diff_workspace_full(&ws, &base);
    assert!(!truncated);
    let listed: Vec<(&str, &str, &str)> = changes
        .iter()
        .map(|(c, _)| (c.path.as_str(), c.kind.as_str(), c.mode.as_str()))
        .collect();
    if cfg!(unix) {
        // README.md changed in nothing but its executable bit.
        assert_eq!(
            listed,
            [
                ("README.md", "modified", "100755"),
                ("new.sh", "added", "100755"),
                ("run.sh", "modified", "100755"),
                ("shortcut", "added", "120000"),
            ]
        );
    } else {
        // No executable bit to read here: a file keeps the mode it came with, a new one has none.
        assert_eq!(
            listed,
            [
                ("new.sh", "added", "100644"),
                ("run.sh", "modified", "100755")
            ]
        );
    }

    // Committed, the modes are what the change set says, and the skipped links are still links.
    let paths: Vec<RepoPath> = changes
        .iter()
        .map(|(c, _)| RepoPath::new(&c.path).unwrap())
        .collect();
    let files: Vec<canon::FileChange<'_>> = paths
        .iter()
        .zip(&changes)
        .map(|(path, (change, content))| (path, content.as_deref(), Some(change.mode.as_str())))
        .collect();
    let who = ("T".to_owned(), "t@example.test".to_owned());
    canon::commit_changes(root, "refs/heads/main", Some(&tip), &files, "session", &who).unwrap();
    assert_eq!(mode_of("run.sh"), "100755");
    assert_eq!(
        mode_of("new.sh"),
        if cfg!(unix) { "100755" } else { "100644" }
    );
    assert_eq!(
        git(root, &["show", "refs/heads/main:run.sh"]).unwrap(),
        "#!/bin/sh\necho hi"
    );
    for link in ["docs/inside", "docs/climbs", "outside"] {
        assert_eq!(mode_of(link), "120000");
    }
    if cfg!(unix) {
        assert_eq!(
            (mode_of("README.md"), mode_of("shortcut")),
            ("100755".to_owned(), "120000".to_owned())
        );
        assert_eq!(
            git(root, &["show", "refs/heads/main:shortcut"]).unwrap(),
            "docs/guide.md"
        );
    }
    // A mode git has no file for is refused, not written.
    let bad = [(&paths[0], Some(b"x".as_slice()), Some("160000"))];
    let refused = canon::commit_changes(root, "refs/heads/main", None, &bad, "bad", &who);
    assert!(
        matches!(refused, Err(canon::CommitError::Invalid(_))),
        "{refused:?}"
    );
}

async fn send(
    router: &axum::Router,
    method: Method,
    uri: &str,
    cookie: &str,
    body: Value,
) -> (StatusCode, Value) {
    let (status, _, body) = call(router, method, uri, &[("cookie", cookie)], Some(body)).await;
    (status, body)
}

/// Run `command` as agent `profile` and wait for it to end.
async fn run_session(
    state: &ServerState,
    router: &axum::Router,
    owner: &str,
    profile: &str,
    command: &str,
) -> AgentSessionRecord {
    let body = json!({ "command": command, "agent_profile": profile });
    let (status, body) = send(router, Method::POST, "/v1/agents/sessions", owner, body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    for _ in 0..600 {
        let rec = state.session_manager.get(&id).unwrap();
        if rec.status != "running" {
            return rec;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {id} never ended");
}

/// Rewrites README.md, adds new.txt, removes docs/guide.md, and says where it runs.
const EDIT: &str = if cfg!(windows) {
    "Set-Content -NoNewline -Path README.md -Value 'changed'; Set-Content -NoNewline -Path new.txt -Value 'n'; Remove-Item docs/guide.md; (Get-Location).Path; Test-Path secret"
} else {
    "printf changed > README.md && printf n > new.txt && rm docs/guide.md && pwd && (test -e secret && echo True || echo False)"
};

#[tokio::test]
async fn session_changes_are_committed_only_with_write_for_the_session_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _sessions) = fixture(root);
    let router = build_router(state.clone());
    let tip = || git(root, &["rev-parse", "refs/heads/main"]).unwrap();
    let start = tip();
    let commit_uri = |id: &str| format!("/v1/agents/sessions/{id}/commit");

    // 1. The profile may read but not write: the change set is known, nothing is committed.
    let rec = run_session(&state, &router, &owner, "reader", EDIT).await;
    assert_eq!(
        (rec.status.as_str(), rec.ended_reason.as_deref()),
        ("completed", Some("exit code 0")),
        "{rec:?}"
    );
    assert_eq!(
        rec.sandbox,
        if sandbox_mode(true) == SandboxMode::Bwrap {
            "bwrap"
        } else {
            "none"
        }
    );
    assert_eq!(
        (rec.branch.as_str(), rec.base_commit.as_deref()),
        ("main", Some(start.as_str()))
    );
    let listed: Vec<(&str, &str)> = rec
        .changes
        .iter()
        .map(|c| (c.path.as_str(), c.kind.as_str()))
        .collect();
    assert_eq!(
        listed,
        [
            ("README.md", "modified"),
            ("docs/guide.md", "deleted"),
            ("new.txt", "added")
        ]
    );
    assert!(!rec.changes_truncated);
    // It ran in its private workspace, not in the repository, and the denied directory was not there.
    let cwd = rec
        .output_lines
        .iter()
        .find(|l| l.contains("cage-0001"))
        .unwrap_or_else(|| panic!("{rec:?}"));
    assert!(
        !Path::new(cwd.trim()).starts_with(root.canonicalize().unwrap()),
        "{cwd}"
    );
    assert!(
        rec.output_lines.iter().any(|l| l.trim() == "False"),
        "{rec:?}"
    );
    if rec.sandbox == "none" {
        assert!(
            rec.output_lines.iter().any(|l| l.contains("NOT CONFINED")),
            "{rec:?}"
        );
    }
    // The repository itself is untouched.
    assert_eq!(
        std::fs::read_to_string(root.join("README.md")).unwrap(),
        "# Demo\n"
    );
    assert!(root.join("docs/guide.md").exists() && !root.join("new.txt").exists());

    // Owner-only; and the human's own write does not make up for the agent profile's lack of it.
    let (status, _) = send(&router, Method::POST, &commit_uri(&rec.id), &mia, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
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
    assert_eq!(tip(), start);
    let (status, _) = send(
        &router,
        Method::POST,
        &commit_uri("cage-9999"),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // 2. A profile with write: one commit on the branch, authored by the human.
    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;
    let dir = session_dir(root, &rec.id);
    assert!(dir.join("ws/new.txt").exists());
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let commit = body["commit"].as_str().unwrap().to_owned();
    assert_eq!(commit, tip());
    assert_eq!(git(root, &["rev-parse", "HEAD~1"]).unwrap(), start);
    let log = git(root, &["log", "-1", "--format=%an|%ae|%cn|%s"]).unwrap();
    assert_eq!(
        log,
        format!(
            "owner|owner@{}|owner|Agent session {}",
            canon::COMMIT_EMAIL_DOMAIN,
            rec.id
        )
    );
    assert_eq!(git(root, &["show", "HEAD:README.md"]).unwrap(), "changed");
    assert_eq!(git(root, &["show", "HEAD:new.txt"]).unwrap(), "n");
    assert!(git(root, &["cat-file", "-e", "HEAD:docs/guide.md"]).is_err());
    // What the session could not see is still there.
    assert_eq!(
        git(root, &["show", "HEAD:secret/plan.md"]).unwrap(),
        "the plan"
    );
    let rec = state.session_manager.get(&rec.id).unwrap();
    assert_eq!(rec.commit.as_deref(), Some(commit.as_str()));
    assert!(!dir.exists(), "a committed workspace is removed");
    let (status, _) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 3. The branch moved under the session: 409, nothing applied; then it is discarded.
    let other = if cfg!(windows) {
        "Set-Content -NoNewline -Path other.txt -Value 'o'"
    } else {
        "printf o > other.txt"
    };
    let rec = run_session(&state, &router, &owner, "writer", other).await;
    git(
        root,
        &["commit", "-q", "--allow-empty", "-m", "someone else"],
    )
    .unwrap();
    let moved = tip();
    let body = json!({ "message": "late", "auto_rebase": false });
    let (status, body) = send(&router, Method::POST, &commit_uri(&rec.id), &owner, body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(tip(), moved);
    let uri = format!("/v1/agents/sessions/{}", rec.id);
    let (status, _) = send(&router, Method::DELETE, &uri, &mia, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, body) = send(&router, Method::DELETE, &uri, &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        (&body["discarded"], &body["id"]),
        (&json!(true), &json!(rec.id))
    );
    assert!(!session_dir(root, &rec.id).exists());
    let (status, _) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);

    // Records survive a restart with their new fields; forgotten workspaces are collected.
    let kept = run_session(&state, &router, &owner, "writer", other).await;
    let stray = sessions_root(root).join("cage-0777");
    std::fs::create_dir_all(&stray).unwrap();
    let reopened = SessionManager::open(root);
    assert!(!stray.exists());
    assert!(
        session_dir(root, &kept.id).join("ws/other.txt").exists(),
        "an uncommitted workspace is kept"
    );
    let restored = reopened.get(&rec.id).unwrap();
    assert!(restored.discarded && restored.changes.len() == 1 && restored.sandbox == rec.sandbox);
}

#[tokio::test]
async fn a_session_that_cannot_start_says_why() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _, _, _sessions) = fixture(tmp.path());
    let refused = state
        .session_manager
        .spawn_session(SessionRequest {
            workspace_root: tmp.path().to_path_buf(),
            identity: agent("reader"),
            env_name: "dev".to_owned(),
            command: "true".to_owned(),
            branch: "main".to_owned(),
            full_ref: Some("refs/heads/main".to_owned()),
            ref_visibility: HashMap::new(),
            policy: state.current_policy(),
            schema: None,
            audit_sink: Arc::clone(&state.audit_sink),
            approval_hub: Arc::clone(&state.approval_hub),
            cage: Cage {
                mode: SandboxMode::None,
                hidden: Vec::new(),
            },
            limit: session_limit(Some(5)),
            quarantine_approvals: BTreeMap::new(),
            budget: None,
            base_commit_override: None,
            lane_id: None,
            change_id: None,
            steering_packet: None,
            on_complete: None,
        })
        .await;
    assert_eq!(refused.unwrap_err(), NO_SANDBOX);
    assert!(state.session_manager.list().is_empty());
}

const LONG_SLEEP: &str = if cfg!(windows) {
    "Start-Sleep -Seconds 30"
} else {
    "exec sleep 30"
};

/// Any owner may open any session's diff, but only the files that owner may READ on the
/// session's branch: a deny rule for @bob hides `docs/**` from him, not from @owner.
#[tokio::test]
async fn session_diff_shows_each_owner_only_files_they_may_read() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _sessions) = fixture(root);
    let (bob, _) = state
        .auth
        .seed_as("bob", crate::tests::PW, crate::auth::Role::Owner);
    let router = build_router(state.clone());
    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;

    let toml = format!(
        "{POLICY}
[[rules]]
id = \"bob-no-docs\"
effect = \"deny\"
principals = [\"@bob\"]
paths = [\"docs/**\"]
refs = [\"*\"]
capabilities = [\"read\"]
"
    );
    let file = parse_policy_toml(&toml).unwrap();
    *state.policy.write().unwrap() = Some(Arc::new(CompiledPolicy::compile(None, &file).unwrap()));

    let diff_uri = format!("/v1/agents/sessions/{}/diff", rec.id);
    let paths = |body: &Value| {
        let mut p: Vec<String> = body["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap().to_owned())
            .collect();
        p.sort();
        p
    };
    let (status, _, body) =
        call(&router, Method::GET, &diff_uri, &[("cookie", &owner)], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(paths(&body), ["README.md", "docs/guide.md", "new.txt"]);
    assert_eq!(body["hidden_files"], 0);

    let (status, _, body) = call(&router, Method::GET, &diff_uri, &[("cookie", &bob)], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(paths(&body), ["README.md", "new.txt"]);
    assert_eq!(body["hidden_files"], 1);
    assert!(!body.to_string().contains("guide"), "{body}");
}

#[tokio::test]
async fn session_diff_returns_unified_patches_and_enforces_session_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _sessions) = fixture(root);
    let router = build_router(state.clone());

    // 404 on unknown session, 403 for non-owner.
    let (status, _, _) = call(
        &router,
        Method::GET,
        "/v1/agents/sessions/cage-9999/diff",
        &[("cookie", &owner)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Run a session that modifies README.md, deletes docs/guide.md, and adds new.txt.
    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;
    let diff_uri = format!("/v1/agents/sessions/{}/diff", rec.id);

    // Also drop a binary file and an oversized text file directly into the finished workspace
    // to verify binary and oversized handling.
    let ws = session_dir(root, &rec.id).join("ws");
    std::fs::write(ws.join("img.bin"), b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    std::fs::write(ws.join("big.txt"), "a".repeat(MAX_DIFF_FILE_BYTES + 64)).unwrap();

    let (status, _, _) = call(&router, Method::GET, &diff_uri, &[("cookie", &mia)], None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, body) =
        call(&router, Method::GET, &diff_uri, &[("cookie", &owner)], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["session_id"], json!(rec.id));
    assert_eq!(body["truncated"], json!(false));

    let files = body["files"].as_array().unwrap();
    let find = |path: &str| {
        files
            .iter()
            .find(|f| f["path"] == path)
            .unwrap_or_else(|| panic!("{path} missing in {files:?}"))
    };

    // Modified file
    let readme = find("README.md");
    assert_eq!(
        (&readme["kind"], &readme["binary"], &readme["truncated"]),
        (&json!("modified"), &json!(false), &json!(false))
    );
    let readme_patch = readme["patch"].as_str().unwrap();
    assert!(
        readme_patch.contains("--- a/README.md\n+++ b/README.md\n"),
        "{readme_patch}"
    );
    assert!(
        readme_patch.contains("@@ -1,1 +1,1 @@\n-# Demo\n+changed\n"),
        "{readme_patch}"
    );

    // Added file
    let added = find("new.txt");
    assert_eq!(
        (&added["kind"], &added["binary"], &added["truncated"]),
        (&json!("added"), &json!(false), &json!(false))
    );
    let added_patch = added["patch"].as_str().unwrap();
    assert!(
        added_patch.contains("--- /dev/null\n+++ b/new.txt\n"),
        "{added_patch}"
    );
    assert!(
        added_patch.contains("@@ -0,0 +1,1 @@\n+n\n"),
        "{added_patch}"
    );

    // Deleted file
    let deleted = find("docs/guide.md");
    assert_eq!(
        (&deleted["kind"], &deleted["binary"], &deleted["truncated"]),
        (&json!("deleted"), &json!(false), &json!(false))
    );
    let deleted_patch = deleted["patch"].as_str().unwrap();
    assert!(
        deleted_patch.contains("--- a/docs/guide.md\n+++ /dev/null\n"),
        "{deleted_patch}"
    );
    assert!(
        deleted_patch.contains("@@ -1,1 +0,0 @@\n-guide\n"),
        "{deleted_patch}"
    );

    // Binary file
    let bin = find("img.bin");
    assert_eq!(
        (&bin["binary"], &bin["truncated"], &bin["patch"]),
        (&json!(true), &json!(false), &json!(""))
    );

    // Oversized file
    let big = find("big.txt");
    assert_eq!(
        (&big["binary"], &big["truncated"], &big["patch"]),
        (&json!(false), &json!(true), &json!(""))
    );

    // Discarded session -> 410 GONE.
    let (status, _) = send(
        &router,
        Method::DELETE,
        &format!("/v1/agents/sessions/{}", rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&router, Method::GET, &diff_uri, &[("cookie", &owner)], None).await;
    assert_eq!(status, StatusCode::GONE);

    // Running session -> 409 CONFLICT (then stop it cleanly).
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": LONG_SLEEP, "agent_profile": "writer" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let running_id = body["id"].as_str().unwrap().to_owned();
    let (status, _, _) = call(
        &router,
        Method::GET,
        &format!("/v1/agents/sessions/{running_id}/diff"),
        &[("cookie", &owner)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = send(
        &router,
        Method::POST,
        &format!("/v1/agents/sessions/{running_id}/stop"),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn stop_session_kills_running_session_and_marks_stopped() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _sessions) = fixture(root);
    let router = build_router(state.clone());

    // 404 on missing session.
    let (status, _) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions/cage-9999/stop",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Spawn a long-running session.
    let (status, body) = send(
        &router,
        Method::POST,
        "/v1/agents/sessions",
        &owner,
        json!({ "command": LONG_SLEEP, "agent_profile": "writer" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["id"].as_str().unwrap().to_owned();
    let stop_uri = format!("/v1/agents/sessions/{id}/stop");

    // Non-owner gets 403.
    let (status, _) = send(&router, Method::POST, &stop_uri, &mia, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Owner stops the running session -> transitions cleanly to "stopped".
    let (status, body) = send(&router, Method::POST, &stop_uri, &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("stopped"), "{body}");
    assert_eq!(body["ended_reason"], json!("stopped by owner"), "{body}");
    assert!(
        body["output_lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str() == Some("[cage] stopped by owner")),
        "{body}"
    );
    assert!(
        state
            .session_manager
            .cancel
            .lock()
            .unwrap()
            .get(&id)
            .is_none(),
        "cancel map entry must be cleaned up"
    );

    // Stopping an already-ended session returns 409 CONFLICT.
    let (status, _) = send(&router, Method::POST, &stop_uri, &owner, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// A review opened from a session carries its transcript (commands and their output, which can
/// quote any file the session read). Only owners and the session's own principal see it.
#[tokio::test]
async fn review_provenance_transcript_is_for_owners_and_the_session_principal_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _sessions) = fixture(root);
    let router = build_router(state.clone());
    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;
    let (status, body) = send(
        &router,
        Method::POST,
        &format!("/v1/agents/sessions/{}/commit", rec.id),
        &owner,
        json!({ "new_branch": "agent/transcript" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let review = json!({ "title": "t", "branch": "agent/transcript", "session_id": rec.id });
    let (status, body) = send(&router, Method::POST, "/v1/reviews", &owner, review).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let transcript: Vec<String> = state
        .session_manager
        .get(&rec.id)
        .unwrap()
        .output_lines
        .into_iter()
        .take(8)
        .filter(|l| l.trim().len() > 8)
        .collect();
    assert!(!transcript.is_empty());

    let reviews = |cookie: String| {
        let router = router.clone();
        async move {
            let (status, _, body) = call(
                &router,
                Method::GET,
                "/v1/reviews",
                &[("cookie", &cookie)],
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body
        }
    };
    let as_owner = reviews(owner.clone()).await;
    let prov = &as_owner[0]["rounds"][0]["hunks"][0]["provenance"];
    assert_eq!(prov["provenance_hidden"], false, "{as_owner}");
    assert!(!prov["tool_calls"].as_array().unwrap().is_empty());

    // Mia may read every changed file, but not the owner's session transcript.
    let as_mia = reviews(mia.clone()).await;
    let hunks = as_mia[0]["rounds"][0]["hunks"].as_array().unwrap();
    assert!(!hunks.is_empty(), "{as_mia}");
    for hunk in hunks {
        assert_eq!(hunk["provenance"]["provenance_hidden"], true, "{hunk}");
        assert_eq!(hunk["provenance"]["tool_calls"], json!([]));
    }
    let text = as_mia.to_string();
    for line in &transcript {
        assert!(
            !text.contains(line.trim()),
            "transcript line {line:?} leaked: {text}"
        );
    }
}

#[tokio::test]
async fn commit_session_to_new_branch_leaves_source_untouched_and_rejects_duplicates() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _sessions) = fixture(root);
    let router = build_router(state.clone());
    let main_tip = git(root, &["rev-parse", "refs/heads/main"]).unwrap();

    // 1. Commit to a new public branch (inherited from public `main`).
    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;
    let commit_uri = format!("/v1/agents/sessions/{}/commit", rec.id);

    // Invalid branch name -> 400.
    let (status, _) = send(
        &router,
        Method::POST,
        &commit_uri,
        &owner,
        json!({ "new_branch": "refs/heads/bad" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Existing branch name (`main`) -> 409.
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri,
        &owner,
        json!({ "new_branch": "main" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Valid new branch -> creates branch at base_commit, commits changes there, leaves main untouched.
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri,
        &owner,
        json!({ "new_branch": "agent/phase2", "message": "Agent work on new branch" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let commit = body["commit"].as_str().unwrap().to_owned();
    assert_eq!(body["branch"], json!("agent/phase2"));

    // Original branch is completely untouched.
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/main"]).unwrap(),
        main_tip
    );
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/agent/phase2"]).unwrap(),
        commit
    );
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/agent/phase2~1"]).unwrap(),
        main_tip
    );
    assert_eq!(
        git(root, &["show", "refs/heads/agent/phase2:README.md"]).unwrap(),
        "changed"
    );
    assert_eq!(
        git(root, &["show", "refs/heads/agent/phase2:new.txt"]).unwrap(),
        "n"
    );
    assert!(
        git(
            root,
            &["cat-file", "-e", "refs/heads/agent/phase2:docs/guide.md"]
        )
        .is_err()
    );

    // Session record and persisted branch metadata updated.
    let updated = state.session_manager.get(&rec.id).unwrap();
    assert_eq!(updated.branch, "agent/phase2");
    assert_eq!(updated.commit.as_deref(), Some(commit.as_str()));
    assert_eq!(
        state.ref_visibility("refs/heads/agent/phase2"),
        Visibility::Public
    );

    // 2. Second session: duplicate branch name is rejected (409), private visibility goes under refs/premier-private/.
    let rec2 = run_session(&state, &router, &owner, "writer", EDIT).await;
    let commit_uri2 = format!("/v1/agents/sessions/{}/commit", rec2.id);

    let (status, _) = send(
        &router,
        Method::POST,
        &commit_uri2,
        &owner,
        json!({ "new_branch": "agent/phase2" }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri2,
        &owner,
        json!({
            "new_branch": "agent/private-fix",
            "visibility": Visibility::Personal("@owner".to_owned())
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["branch"], json!("agent/private-fix"));
    let priv_commit = body["commit"].as_str().unwrap().to_owned();
    assert_eq!(
        git(
            root,
            &["rev-parse", "refs/premier-private/agent/private-fix"]
        )
        .unwrap(),
        priv_commit
    );
    assert!(
        git(
            root,
            &["rev-parse", "--verify", "refs/heads/agent/private-fix"]
        )
        .is_err()
    );
    assert_eq!(
        state.ref_visibility("refs/premier-private/agent/private-fix"),
        Visibility::Personal("@owner".to_owned())
    );
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/main"]).unwrap(),
        main_tip
    );
}

/// Needs Linux with a working bubblewrap, `curl`, and the CLI built first
/// (`cargo build -p premier-cli`): run with `cargo test -p premier-server -- --ignored cage`.
/// In Docker: `--security-opt seccomp=unconfined --security-opt systempaths=unconfined`.
#[cfg(target_os = "linux")]
#[ignore = "needs bubblewrap, curl and a built premier binary"]
#[tokio::test(flavor = "multi_thread")]
async fn cage_confines_files_and_network_under_bubblewrap() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // `target/<profile>/premier`, some directories above this test binary (how many depends on
    // cargo's layout).
    let exe = std::env::current_exe().unwrap();
    let premier = exe
        .ancestors()
        .map(|dir| dir.join("premier"))
        .find(|p| p.is_file());
    let premier = premier.unwrap_or_else(|| panic!("build the CLI first, above {}", exe.display()));
    set_cage_exe(premier);
    assert_eq!(
        sandbox_mode(false),
        SandboxMode::Bwrap,
        "{}",
        sandbox_detail(false)
    );

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    // The server's state lives in a state directory, as in the container image: a real host
    // path outside `/tmp`, which the server user can read.
    let state_dir = PathBuf::from(std::env::var_os("HOME").unwrap())
        .canonicalize()
        .unwrap()
        .join(format!(".premier-cage-state-{}", std::process::id()));
    crate::store::bind_state_dir(&root, &state_dir, "repo", true);
    let (state, _, _, _sessions) = fixture(&root);
    let auth_json = crate::store::account_dir(&root).join("auth.json");
    assert!(
        auth_json.starts_with(&state_dir) && auth_json.is_file(),
        "{auth_json:?}"
    );
    let shadow_exists = Path::new("/etc/shadow").exists();

    // A host service the agent profile may reach through the proxy (`allow_egress_hosts`), on
    // the host's loopback: the sandbox's own loopback has nothing listening there.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = conn.read(&mut buf).await;
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        }
    });

    // What a server user keeps at home and what a host keeps in `/run` (where this test may).
    let home = PathBuf::from(std::env::var_os("HOME").unwrap())
        .canonicalize()
        .unwrap();
    assert!(
        home.parent().is_some() && !home.starts_with("/tmp"),
        "HOME must be a real home: {home:?}"
    );
    let token = home.join(format!(".premier-cage-test-{}", std::process::id()));
    std::fs::write(&token, "credential").unwrap();
    let docker = Path::new("/run/docker.sock");
    let made_docker = !docker.exists() && std::fs::write(docker, "").is_ok();
    assert!(hidden_dirs([]).contains(&home), "{:?}", hidden_dirs([]));

    let canonical = root.display();
    let (home, token_path) = (home.display(), token.display());
    let (state_path, auth_path) = (state_dir.display(), auth_json.display());
    let command = format!(
        "pwd; echo UID=$(id -u); \
         test -e /etc/shadow && echo SHADOW_SEEN || echo SHADOW_ABSENT; \
         cat /etc/shadow >/dev/null 2>&1 && echo SHADOW_READ || echo SHADOW_UNREADABLE; \
         test -e {state_path} && echo STATE_DIR_SEEN || echo STATE_DIR_ABSENT; \
         cat {auth_path} >/dev/null 2>&1 && echo STATE_READ || echo STATE_UNREADABLE; \
         test -e /etc/resolv.conf && echo RESOLV_SEEN || echo RESOLV_ABSENT; \
         grep -c . /etc/passwd | sed s/^/PASSWD_LINES=/; \
         echo ROOT=$(ls /); \
         test -e {token_path} && echo HOME_TOKEN_SEEN || echo HOME_TOKEN_ABSENT; \
         for d in {home} /root /run /var/run /var/lib; do test -z \"$(ls -A $d 2>/dev/null)\" || echo HOST_STATE_SEEN:$d; done; \
         test -e /var/run/docker.sock -o -e /run/docker.sock && echo DOCKER_SOCK_SEEN || echo DOCKER_SOCK_ABSENT; \
         echo HOME=$HOME; touch \"$HOME/.probe\" && echo HOME_WRITABLE; \
         echo PID1=$(cat /proc/1/comm); \
         cat secret/plan.md 2>/dev/null && echo SECRET_READ || echo SECRET_ABSENT; \
         git cat-file -e HEAD:secret/plan.md 2>/dev/null && echo OBJECT_READ || echo OBJECT_ABSENT; \
         test -e {canonical}/.git && echo CANONICAL_GIT_SEEN || echo CANONICAL_GIT_ABSENT; \
         ls {canonical} 2>/dev/null | grep -q . && echo CANONICAL_SEEN || echo CANONICAL_EMPTY; \
         touch /etc/premier-zz 2>/dev/null && echo HOST_WRITTEN || echo HOST_READ_ONLY; \
         touch {canonical}/zz 2>/dev/null; touch inside.txt && echo WORKSPACE_WRITABLE; \
         curl -s -o /dev/null --max-time 5 --noproxy '*' http://127.0.0.1:{port}/ && echo DIRECT_OK || echo DIRECT_REFUSED; \
         curl -s -o /dev/null --max-time 5 --noproxy '*' http://1.1.1.1/ && echo INTERNET_OK || echo INTERNET_REFUSED; \
         echo PROXIED=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 -x \"$HTTP_PROXY\" --noproxy '' http://127.0.0.1:{port}/); \
         echo DENIED=$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 -x \"$HTTP_PROXY\" --noproxy '' http://example.com/)"
    );
    let rec = state
        .session_manager
        .spawn_session(SessionRequest {
            workspace_root: root.clone(),
            identity: agent("writer"),
            env_name: "dev".to_owned(),
            command,
            branch: "main".to_owned(),
            full_ref: Some("refs/heads/main".to_owned()),
            ref_visibility: HashMap::new(),
            policy: state.current_policy(),
            schema: None,
            audit_sink: Arc::clone(&state.audit_sink),
            approval_hub: Arc::clone(&state.approval_hub),
            cage: Cage {
                mode: SandboxMode::Bwrap,
                hidden: Vec::new(),
            },
            limit: session_limit(Some(60)),
            quarantine_approvals: BTreeMap::new(),
            budget: None,
            base_commit_override: None,
            lane_id: None,
            change_id: None,
            steering_packet: None,
            on_complete: None,
        })
        .await
        .unwrap();
    let mut done = rec.clone();
    for _ in 0..700 {
        done = state.session_manager.get(&rec.id).unwrap();
        if done.status != "running" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = std::fs::remove_file(&token);
    if made_docker {
        let _ = std::fs::remove_file(docker);
    }
    let out = &done.output_lines;
    let has = |line: &str| out.iter().any(|l| l.trim() == line);
    assert!(
        !out.iter().any(|l| l.starts_with("HOST_STATE_SEEN")),
        "{out:#?}"
    );
    assert_eq!(done.sandbox, "bwrap", "{done:?}");
    let _ = std::fs::remove_dir_all(&state_dir);
    crate::store::unbind_state_dir(&root);
    assert!(shadow_exists, "this test must run where /etc/shadow exists");
    // Nothing of the host but the allow-list is in the sandbox's root.
    let listed_root = out
        .iter()
        .find_map(|l| l.trim().strip_prefix("ROOT="))
        .unwrap_or_default();
    for name in listed_root.split_whitespace() {
        let known = [
            "bin", "dev", "etc", "lib", "lib32", "lib64", "libx32", "proc", "sbin", "tmp", "usr",
        ];
        assert!(
            known.contains(&name),
            "unexpected /{name} in the sandbox: {out:#?}"
        );
    }
    for expected in [
        CAGE_WORKSPACE,
        "SHADOW_ABSENT",
        "SHADOW_UNREADABLE",
        "STATE_DIR_ABSENT",
        "STATE_UNREADABLE",
        "RESOLV_ABSENT",
        "PASSWD_LINES=2",
        "HOME_TOKEN_ABSENT",
        "DOCKER_SOCK_ABSENT",
        "HOME=/tmp/home",
        "HOME_WRITABLE",
        // The first process in there is the sandbox itself, not the server.
        "PID1=bwrap",
        "SECRET_ABSENT",
        "OBJECT_ABSENT",
        "CANONICAL_GIT_ABSENT",
        "CANONICAL_EMPTY",
        "HOST_READ_ONLY",
        "WORKSPACE_WRITABLE",
        "DIRECT_REFUSED",
        "INTERNET_REFUSED",
        "PROXIED=200",
        "DENIED=403",
    ] {
        assert!(has(expected), "{expected} missing: {out:#?}");
    }
    if probe().user == Some(CageUser::Unprivileged) {
        assert!(has("UID=1000"), "{out:#?}");
    }
    assert!(!root.join("zz").exists() && !Path::new("/etc/premier-zz").exists());
    // The one thing that came out: the file it made in its workspace.
    let listed: Vec<&str> = done.changes.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(listed, ["inside.txt"]);
}

/// Write `text` to `path` in the repository and commit it there: the branch moving under a session.
fn upstream_commit(root: &Path, path: &str, text: &str) -> String {
    std::fs::write(root.join(path), text).unwrap();
    git(root, &["add", path]).unwrap();
    git(root, &["commit", "-q", "-m", &format!("upstream {path}")]).unwrap();
    git(root, &["rev-parse", "refs/heads/main"]).unwrap()
}

#[tokio::test]
async fn a_moved_branch_is_rebased_onto_and_overlap_is_kept_on_the_lane() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _mia, _sessions) = fixture(root);
    let router = build_router(state.clone());
    let commit_uri = |id: &str| format!("/v1/agents/sessions/{id}/commit");
    let readme = |text: &str| {
        if cfg!(windows) {
            format!("Set-Content -NoNewline -Path README.md -Value '{text}'")
        } else {
            format!("printf {text} > README.md")
        }
    };

    // 1. Disjoint: the session changed README.md, the branch changed docs/guide.md.
    let rec = run_session(&state, &router, &owner, "writer", &readme("agent")).await;
    let kinds: Vec<&str> = rec
        .provenance_steps
        .iter()
        .map(|s| s.kind.as_str())
        .collect();
    assert_eq!(
        kinds,
        [
            "session_start",
            "command_exec",
            "file_change",
            "session_exit"
        ],
        "{rec:?}"
    );
    assert!(
        rec.provenance_steps
            .windows(2)
            .all(|w| w[1].seq == w[0].seq + 1)
    );
    let moved = upstream_commit(root, "docs/guide.md", "upstream guide\n");
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rebased"], json!(true), "{body}");
    let lane = format!("lane-{}", rec.id);
    assert_eq!(body["lane_id"], json!(lane));
    let commit = body["commit"].as_str().unwrap();
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/main"]).unwrap(),
        commit
    );
    assert_eq!(
        git(root, &["rev-parse", &format!("{commit}~1")]).unwrap(),
        moved
    );
    assert_eq!(
        git(root, &["show", &format!("{commit}:README.md")]).unwrap(),
        "agent"
    );
    assert_eq!(
        git(root, &["show", &format!("{commit}:docs/guide.md")]).unwrap(),
        "upstream guide"
    );
    assert_eq!(
        git(root, &["rev-parse", &format!("refs/premier-lanes/{lane}")]).unwrap(),
        commit
    );
    let done = state.session_manager.get(&rec.id).unwrap();
    assert!(
        done.rebased
            && done
                .provenance_steps
                .iter()
                .any(|s| s.kind == "auto_rebase")
    );

    // 2. Overlapping: both changed README.md. Nothing lands; the work is on the lane, the
    // workspace stays.
    let rec = run_session(&state, &router, &owner, "writer", &readme("mine")).await;
    let moved = upstream_commit(root, "README.md", "theirs\n");
    let (status, body) = send(
        &router,
        Method::POST,
        &commit_uri(&rec.id),
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(git(root, &["rev-parse", "refs/heads/main"]).unwrap(), moved);
    assert_eq!(body["conflicts"], json!(["README.md"]), "{body}");
    assert_eq!(
        body["lane_conflicts"][0]["kind"],
        json!("content_overlap"),
        "{body}"
    );
    let lane = format!("lane-{}", rec.id);
    let snapshot = body["lane_tip"].as_str().unwrap();
    assert_eq!(
        git(root, &["rev-parse", &format!("refs/premier-lanes/{lane}")]).unwrap(),
        snapshot
    );
    assert_eq!(
        git(root, &["show", &format!("{snapshot}:README.md")]).unwrap(),
        "mine"
    );
    assert!(session_dir(root, &rec.id).join("ws/README.md").exists());
    let kept = state.session_manager.get(&rec.id).unwrap();
    assert!(kept.commit.is_none() && kept.conflicts.len() == 1);
    let lanes = state.persisted.lock().unwrap().lanes.clone();
    let saved = lanes.iter().find(|l| l.lane_id == lane).unwrap();
    assert_eq!(saved.status, "conflicted");
    assert_eq!(saved.tip_oid.as_deref(), Some(snapshot));

    // A lane id that is not one safe ref component is refused.
    let body = json!({ "lane_id": "../heads/main" });
    let (status, _) = send(&router, Method::POST, &commit_uri(&rec.id), &owner, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[test]
fn materialise_from_a_commit_writes_only_its_readable_files() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, _, _, _sessions) = fixture(tmp.path());
    let first = git(tmp.path(), &["rev-parse", "HEAD"]).unwrap();
    upstream_commit(tmp.path(), "docs/guide.md", "later\n");
    let out = tempfile::tempdir().unwrap();
    let ws = out.path().join("ws");
    let (tip, base, _) = materialise(
        tmp.path(),
        Some("refs/heads/main"),
        "main",
        state.current_policy().as_deref(),
        &agent("reader"),
        &HashMap::new(),
        &ws,
        Some(&first),
    )
    .unwrap();
    assert_eq!(tip.as_deref(), Some(first.as_str()));
    assert_eq!(
        base.keys().collect::<Vec<_>>(),
        ["README.md", "docs/guide.md"]
    );
    assert_eq!(
        std::fs::read_to_string(ws.join("docs/guide.md")).unwrap(),
        "guide\n"
    );
    assert!(!ws.join("secret").exists());
    assert!(git(&ws, &["cat-file", "-e", &first]).is_err());
    // Not an object id: refused.
    let bad = materialise(
        tmp.path(),
        None,
        "main",
        state.current_policy().as_deref(),
        &agent("reader"),
        &HashMap::new(),
        &out.path().join("bad"),
        Some("--output=x"),
    );
    assert!(bad.is_err());
}

#[test]
fn steering_markdown_names_comments_and_conflicts() {
    let packet = SteeringPacket {
        change_id: "I1".to_owned(),
        target_round: 2,
        lane_id: Some("lane-a".to_owned()),
        branch: "main".to_owned(),
        instruction: "fix it".to_owned(),
        comments: vec![SteeringComment {
            id: "cmt-1".to_owned(),
            author: "@mia".to_owned(),
            path: "README.md".to_owned(),
            line: Some(3),
            body: "typo".to_owned(),
            round: Some(1),
        }],
        redacted_comments: 1,
        ..SteeringPacket::default()
    };
    let md = packet.to_markdown();
    for needle in [
        "round 2",
        "fix it",
        "`README.md:3`",
        "typo",
        "1 comment not shown",
    ] {
        assert!(md.contains(needle), "{needle} not in {md}");
    }
}

// ---------------------------------------------------------------------------
// Ambient telemetry and human step-in
// ---------------------------------------------------------------------------

/// The step-in routes as the server mounts them: behind the gate, owners only.
fn step_in_router(state: &ServerState) -> axum::Router {
    use axum::routing::{MethodRouter, get, post};
    let owner = |m: MethodRouter<ServerState>| {
        m.route_layer(axum::middleware::from_fn(crate::auth::require_owner))
    };
    axum::Router::new()
        .route(
            "/v1/agents/sessions/{id}/pause",
            owner(post(pause_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/workspace/files",
            owner(get(session_workspace_files_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/workspace/file",
            owner(
                get(session_workspace_read_file_handler).put(session_workspace_write_file_handler),
            ),
        )
        .route(
            "/v1/agents/sessions/{id}/checkpoint",
            owner(post(checkpoint_session_handler)),
        )
        .route(
            "/v1/agents/sessions/{id}/resume",
            owner(post(resume_session_handler)),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::auth::gate,
        ))
        .with_state(state.clone())
}

async fn get_json(router: &axum::Router, uri: &str, cookie: &str) -> (StatusCode, Value) {
    let (status, _, body) = call(router, Method::GET, uri, &[("cookie", cookie)], None).await;
    (status, body)
}

async fn spawn(router: &axum::Router, owner: &str, profile: &str, command: &str) -> String {
    let body = json!({ "command": command, "agent_profile": profile });
    let (status, body) = send(router, Method::POST, "/v1/agents/sessions", owner, body).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["id"].as_str().unwrap().to_owned()
}

async fn wait_ended(state: &ServerState, id: &str) -> AgentSessionRecord {
    for _ in 0..600 {
        let rec = state.session_manager.get(id).unwrap();
        if rec.status != "running" {
            return rec;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {id} never ended");
}

/// Writes agent.txt, then waits to be paused.
const WRITE_THEN_SLEEP: &str = if cfg!(windows) {
    "Set-Content -NoNewline -Path agent.txt -Value 'agent'; Start-Sleep -Seconds 30"
} else {
    "printf agent > agent.txt && exec sleep 30"
};

/// Pause a session running [`WRITE_THEN_SLEEP`] once agent.txt is there.
async fn pause_after_write(
    state: &ServerState,
    step: &axum::Router,
    owner: &str,
    id: &str,
) -> Value {
    let written = session_dir(&state.workspace_root, id).join("ws/agent.txt");
    for _ in 0..300 {
        if std::fs::read(&written).is_ok_and(|b| b == b"agent") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let uri = format!("/v1/agents/sessions/{id}/pause");
    let (status, body) = send(step, Method::POST, &uri, owner, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::to_value(wait_ended(state, id).await).unwrap()
}

#[tokio::test]
async fn repeated_egress_blocks_of_a_session_raise_one_insight() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _sessions) = fixture(root);
    let router = build_router(state.clone());
    let mut insights = state.session_manager.subscribe_insights();
    let id = spawn(&router, &owner, "writer", LONG_SLEEP).await;

    let rec = state.session_manager.get(&id).unwrap();
    assert_eq!(rec.limit_secs, DEFAULT_SESSION_SECS);
    assert!(rec.insights.is_empty());
    // The session's identity carries its id: its proxy's events say which session they are.
    assert!(
        state
            .audit_sink
            .snapshot()
            .iter()
            .any(|e| e.action == "session_started"
                && e.agent_task_id.as_deref() == Some(id.as_str())),
        "{:?}",
        state.audit_sink.snapshot()
    );

    let block = |task: &str, decision| {
        let who = DelegatedIdentity::delegated(
            Principal::parse("@owner").unwrap(),
            vec!["owners".to_owned()],
            "writer",
            task,
        );
        AuditEvent::now(&who, "premier-proxy", "egress", decision, "blocked")
    };
    // Another session's blocks, and this session's allowed requests, do not count.
    for _ in 0..3 {
        state
            .audit_sink
            .record(block("cage-9999", AuditDecision::Denied));
        state.audit_sink.record(block(&id, AuditDecision::Allowed));
    }
    for decision in [
        AuditDecision::Denied,
        AuditDecision::ExfiltrationBlocked,
        AuditDecision::RateLimited,
    ] {
        state.audit_sink.record(block(&id, decision));
    }
    let insight = tokio::time::timeout(Duration::from_secs(5), insights.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(insight.kind, SessionInsightKind::RepeatedBlocks);
    assert_eq!(insight.severity, InsightSeverity::Attention);
    assert_eq!(insight.session_id, id);
    assert_eq!(insight.id, format!("{id}:repeated-blocks"));
    assert_eq!(insight.metric_value, 3);
    let rec = state.session_manager.get(&id).unwrap();
    assert_eq!(rec.insights, std::slice::from_ref(&insight));

    // Blocks 4 and 5 are throttled; doubling to 6 updates the same insight in place.
    state.audit_sink.record(block(&id, AuditDecision::Denied));
    state.audit_sink.record(block(&id, AuditDecision::Denied));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), insights.recv())
            .await
            .is_err()
    );
    state.audit_sink.record(block(&id, AuditDecision::Denied));
    let again = tokio::time::timeout(Duration::from_secs(5), insights.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (again.id.as_str(), again.metric_value),
        (insight.id.as_str(), 6)
    );
    let rec = state.session_manager.get(&id).unwrap();
    assert_eq!(rec.insights.len(), 1);
    assert_eq!(rec.insights[0].metric_value, 6);

    let stop = format!("/v1/agents/sessions/{id}/stop");
    let (status, _) = send(&router, Method::POST, &stop, &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn pausing_a_running_session_keeps_its_workspace_and_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _sessions) = fixture(root);
    let (router, step) = (build_router(state.clone()), step_in_router(&state));

    let (status, _) = send(
        &step,
        Method::POST,
        "/v1/agents/sessions/cage-9999/pause",
        &owner,
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let id = spawn(&router, &owner, "writer", WRITE_THEN_SLEEP).await;
    let pause = format!("/v1/agents/sessions/{id}/pause");
    let (status, _) = send(&step, Method::POST, &pause, &mia, json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Nothing to inspect while it runs.
    let files = format!("/v1/agents/sessions/{id}/workspace/files");
    assert_eq!(
        get_json(&step, &files, &owner).await.0,
        StatusCode::CONFLICT
    );

    let body = pause_after_write(&state, &step, &owner, &id).await;
    assert_eq!(body["status"], json!("paused"), "{body}");
    assert_eq!(body["ended_reason"], json!(PAUSED_REASON));
    assert_eq!(body["exit_code"], Value::Null);
    assert!(
        body["output_lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str() == Some(PAUSED_LINE)),
        "{body}"
    );
    assert!(
        body["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["path"] == json!("agent.txt") && c["kind"] == json!("added")),
        "{body}"
    );
    let dir = session_dir(root, &id);
    assert_eq!(std::fs::read(dir.join("ws/agent.txt")).unwrap(), b"agent");
    assert!(dir.join(BASE_FILE).is_file());
    assert!(!dir.join("proxy").exists() && !dir.join("home").exists());
    assert!(
        state
            .session_manager
            .cancel
            .lock()
            .unwrap()
            .get(&id)
            .is_none()
    );
    assert!(
        state
            .audit_sink
            .snapshot()
            .iter()
            .any(|e| e.action == "session_paused")
    );

    // Pausing again is a no-op; it is not running, so it cannot be stopped.
    let (status, body) = send(&step, Method::POST, &pause, &owner, json!({})).await;
    assert_eq!(
        (status, &body["status"]),
        (StatusCode::OK, &json!("paused"))
    );
    let stop = format!("/v1/agents/sessions/{id}/stop");
    let (status, _) = send(&router, Method::POST, &stop, &owner, json!({})).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // An ended session with its workspace can be paused too.
    let done = run_session(&state, &router, &owner, "writer", EDIT).await;
    let uri = format!("/v1/agents/sessions/{}/pause", done.id);
    let (status, body) = send(&step, Method::POST, &uri, &owner, json!({})).await;
    assert_eq!(
        (status, &body["status"]),
        (StatusCode::OK, &json!("paused"))
    );
    assert_eq!(body["changes"].as_array().unwrap().len(), 3, "{body}");
}

#[tokio::test]
async fn a_human_reads_and_edits_a_paused_workspace_as_the_session_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, mia, _sessions) = fixture(root);
    let (router, step) = (build_router(state.clone()), step_in_router(&state));
    let main_tip = git(root, &["rev-parse", "refs/heads/main"]).unwrap();

    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;
    let id = rec.id.clone();
    let ws = session_dir(root, &id).join("ws");
    // Something the session identity may not read, put there behind policy's back.
    std::fs::create_dir_all(ws.join("secret")).unwrap();
    std::fs::write(ws.join("secret/x.md"), "hidden").unwrap();
    let pause = format!("/v1/agents/sessions/{id}/pause");
    assert_eq!(
        send(&step, Method::POST, &pause, &owner, json!({})).await.0,
        StatusCode::OK
    );

    // The listing: only readable files, never `.git`, with their change kinds.
    let files = format!("/v1/agents/sessions/{id}/workspace/files");
    assert_eq!(get_json(&step, &files, &mia).await.0, StatusCode::FORBIDDEN);
    let (status, body) = get_json(&step, &files, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["branch"], json!("main"));
    let listed: Vec<&str> = body["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(listed, ["README.md", "new.txt"], "{body}");
    assert_eq!(body["files"][0]["change_kind"], json!("modified"));
    assert_eq!(body["files"][1]["change_kind"], json!("added"));
    assert_eq!(body["files"][0]["can_write"], json!(true));

    // Reading.
    let file = |path: &str| format!("/v1/agents/sessions/{id}/workspace/file?path={path}");
    let (status, body) = get_json(&step, &file("README.md"), &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["content"], json!("changed"));
    assert_eq!(body["binary"], json!(false));
    assert_eq!(
        body["sha256"],
        json!(premier_policy::sha256_hex(b"changed"))
    );
    for bad in [
        "../outside",
        ".git/config",
        ".premier/x",
        "docs/../README.md",
    ] {
        let (status, body) = get_json(&step, &file(bad), &owner).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    assert_eq!(
        get_json(&step, &file("nope.md"), &owner).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, _) = get_json(&step, &file("secret/x.md"), &owner).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Writing: an existing file, and a new one in a new directory.
    let write = format!("/v1/agents/sessions/{id}/workspace/file");
    let put = |path: &str, content: &str| {
        let body = json!({ "path": path, "content": content });
        let (step, write, owner) = (step.clone(), write.clone(), owner.clone());
        async move {
            let (status, _, body) = call(
                &step,
                Method::PUT,
                &write,
                &[("cookie", &owner)],
                Some(body),
            )
            .await;
            (status, body)
        }
    };
    let (status, body) = put("README.md", "human").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["bytes_written"], json!(5));
    assert_eq!(std::fs::read(ws.join("README.md")).unwrap(), b"human");
    let (status, body) = put("docs/new/human.md", "by hand").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let changed: Vec<&str> = body["session"]["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        changed,
        // secret/x.md too: it is in the workspace (a commit would refuse it, see below).
        [
            "README.md",
            "docs/guide.md",
            "docs/new/human.md",
            "new.txt",
            "secret/x.md"
        ]
    );
    // No temp file is left behind.
    assert_eq!(std::fs::read_dir(ws.join("docs/new")).unwrap().count(), 1);

    // Refused: what the session identity may not write, reserved paths, oversized content.
    let (status, _) = put("secret/x.md", "leak").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(std::fs::read(ws.join("secret/x.md")).unwrap(), b"hidden");
    assert!(state.audit_sink.snapshot().iter().any(|e| {
        e.action == "session_workspace_edit"
            && e.decision == AuditDecision::Denied
            && e.target.as_deref() == Some("secret/x.md")
    }));
    for bad in [
        "../outside.md",
        ".git/config",
        ".git/hooks/pre-commit",
        "docs",
    ] {
        let (status, body) = put(bad, "x").await;
        assert!(status == StatusCode::BAD_REQUEST, "{bad}: {status} {body}");
    }
    assert!(!root.join("outside.md").exists() && !session_dir(root, "outside.md").exists());
    let (status, _) = put("big.txt", &"x".repeat(MAX_STEP_IN_FILE_BYTES + 1)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), ws.join("escape")).unwrap();
        let (status, _) = put("escape/x.md", "out").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        std::os::unix::fs::symlink("README.md", ws.join("alias.md")).unwrap();
        let (status, _) = put("alias.md", "through").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            get_json(&step, &file("alias.md"), &owner).await.0,
            StatusCode::BAD_REQUEST
        );
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
        std::fs::remove_file(ws.join("escape")).unwrap();
        std::fs::remove_file(ws.join("alias.md")).unwrap();
    }
    // Non-UTF-8 and binary files are flagged binary and never silently lossy-overwritten.
    std::fs::write(ws.join("latin1.txt"), b"caf\xe9").unwrap();
    std::fs::write(ws.join("img.bin"), b"\x89PNG\r\n\x1a\n\0\0").unwrap();
    let (status, body) = get_json(&step, &file("latin1.txt"), &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["binary"], json!(true));
    assert_eq!(body["content"], json!(""));
    let (status, _) = put("latin1.txt", "overwrite").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read(ws.join("latin1.txt")).unwrap(), b"caf\xe9");
    let (status, _) = put("img.bin", "overwrite").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        std::fs::read(ws.join("img.bin")).unwrap(),
        b"\x89PNG\r\n\x1a\n\0\0"
    );
    std::fs::remove_file(ws.join("latin1.txt")).unwrap();
    std::fs::remove_file(ws.join("img.bin")).unwrap();

    std::fs::remove_dir_all(ws.join("secret")).unwrap();

    // Committing applies the agent's and the human's edits together.
    let commit = format!("/v1/agents/sessions/{id}/commit");
    let (status, body) = send(&router, Method::POST, &commit, &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        git(root, &["show", "refs/heads/main:README.md"]).unwrap(),
        "human"
    );
    assert_eq!(
        git(root, &["show", "refs/heads/main:new.txt"]).unwrap(),
        "n"
    );
    assert_eq!(
        git(root, &["show", "refs/heads/main:docs/new/human.md"]).unwrap(),
        "by hand"
    );
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/main~1"]).unwrap(),
        main_tip
    );
    // A committed session is closed to step-in.
    assert_eq!(
        get_json(&step, &files, &owner).await.0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn step_in_edits_are_bounded_by_the_agent_profile_and_hidden_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _sessions) = fixture(root);
    let (router, step) = (build_router(state.clone()), step_in_router(&state));
    let write = |id: &str| format!("/v1/agents/sessions/{id}/workspace/file");

    // `reader` may read but not write: the human stepping in is held to that.
    let rec = run_session(&state, &router, &owner, "reader", "echo hi").await;
    let files = format!("/v1/agents/sessions/{}/workspace/files", rec.id);
    let (status, body) = get_json(&step, &files, &owner).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["can_write"] == json!(false)),
        "{body}"
    );
    let (status, _, _) = call(
        &step,
        Method::PUT,
        &write(&rec.id),
        &[("cookie", &owner)],
        Some(json!({ "path": "README.md", "content": "no" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A path the branch has but the session was never shown is not written.
    let rec = run_session(&state, &router, &owner, "writer", "echo hi").await;
    let base_file = session_dir(root, &rec.id).join(BASE_FILE);
    let mut base: Base =
        serde_json::from_str(&std::fs::read_to_string(&base_file).unwrap()).unwrap();
    base.remove("docs/guide.md").unwrap();
    std::fs::remove_file(session_dir(root, &rec.id).join("ws/docs/guide.md")).unwrap();
    std::fs::write(&base_file, serde_json::to_string(&base).unwrap()).unwrap();
    let (status, _, body) = call(
        &step,
        Method::PUT,
        &write(&rec.id),
        &[("cookie", &owner)],
        Some(json!({ "path": "docs/guide.md", "content": "replaced" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!session_dir(root, &rec.id).join("ws/docs/guide.md").exists());

    // Unknown and discarded sessions.
    assert_eq!(
        get_json(
            &step,
            "/v1/agents/sessions/cage-9999/workspace/files",
            &owner
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, _, _) = call(
        &router,
        Method::DELETE,
        &format!("/v1/agents/sessions/{}", rec.id),
        &[("cookie", &owner)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let files = format!("/v1/agents/sessions/{}/workspace/files", rec.id);
    assert_eq!(get_json(&step, &files, &owner).await.0, StatusCode::GONE);
    let pause = format!("/v1/agents/sessions/{}/pause", rec.id);
    assert_eq!(
        send(&step, Method::POST, &pause, &owner, json!({})).await.0,
        StatusCode::GONE
    );
}

#[cfg(unix)]
#[test]
fn a_session_workspace_path_never_goes_through_a_link() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws");
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    std::fs::write(ws.join("docs/a.md"), "a").unwrap();
    std::os::unix::fs::symlink(tmp.path(), ws.join("up")).unwrap();
    std::os::unix::fs::symlink("docs", ws.join("docs-link")).unwrap();
    let rp = |p: &str| RepoPath::new(p).unwrap();
    let (abs, folded) = safe_session_workspace_path(&ws, &rp("docs/a.md")).unwrap();
    assert_eq!(folded, rp("docs/a.md"));
    assert!(abs.ends_with("docs/a.md"));
    // A path that does not exist yet resolves too.
    assert!(safe_session_workspace_path(&ws, &rp("docs/new/b.md")).is_some());
    for refused in ["up/ws/docs/a.md", "docs-link/a.md", "up", ".git/config"] {
        assert!(
            safe_session_workspace_path(&ws, &rp(refused)).is_none(),
            "{refused}"
        );
    }
}

#[tokio::test]
async fn a_checkpoint_is_a_manifest_beside_the_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _sessions) = fixture(root);
    let (router, step) = (build_router(state.clone()), step_in_router(&state));
    let rec = run_session(&state, &router, &owner, "writer", EDIT).await;
    let id = rec.id.clone();
    let ws = session_dir(root, &id).join("ws");
    let head_before = git(&ws, &["rev-parse", "HEAD"]).unwrap();

    let uri = format!("/v1/agents/sessions/{id}/checkpoint");
    let (status, body) = send(
        &step,
        Method::POST,
        &uri,
        &owner,
        json!({ "label": "  after review  " }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["checkpoint"]["id"], json!("cp-001"));
    assert_eq!(body["checkpoint"]["label"], json!("after review"));
    assert_eq!(body["checkpoint"]["author"], json!("@owner"));
    assert_eq!(
        body["checkpoint"]["edited_paths"],
        json!(["README.md", "docs/guide.md", "new.txt"])
    );
    let manifest = session_dir(root, &id).join("checkpoints/cp-001.json");
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(manifest).unwrap()).unwrap();
    assert_eq!(manifest["checkpoint"]["id"], json!("cp-001"));
    assert_eq!(manifest["changes"].as_array().unwrap().len(), 3);
    assert!(
        body["session"]["output_lines"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str()
                == Some("[step-in] checkpoint cp-001: after review (3 changed paths)")),
        "{body}"
    );

    // No body: the default label. Bad labels are refused.
    let (status, _, body) = call(&step, Method::POST, &uri, &[("cookie", &owner)], None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["checkpoint"]["id"], json!("cp-002"));
    assert_eq!(body["checkpoint"]["label"], json!(DEFAULT_CHECKPOINT_LABEL));
    for bad in ["bell\u{7}".to_owned(), "x".repeat(201)] {
        let (status, _) = send(&step, Method::POST, &uri, &owner, json!({ "label": bad })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let rec = state.session_manager.get(&id).unwrap();
    assert_eq!(rec.checkpoints.len(), 2);

    // Concurrent checkpoints receive distinct sequential IDs and manifests never collide.
    let ((s1, b1), (s2, b2)) = tokio::join!(
        send(
            &step,
            Method::POST,
            &uri,
            &owner,
            json!({ "label": "race-1" })
        ),
        send(
            &step,
            Method::POST,
            &uri,
            &owner,
            json!({ "label": "race-2" })
        ),
    );
    assert_eq!(
        (s1, s2),
        (StatusCode::OK, StatusCode::OK),
        "b1={b1} b2={b2}"
    );
    let mut ids = [
        b1["checkpoint"]["id"].as_str().unwrap().to_owned(),
        b2["checkpoint"]["id"].as_str().unwrap().to_owned(),
    ];
    ids.sort();
    assert_eq!(ids, ["cp-003", "cp-004"]);
    assert!(
        session_dir(root, &id)
            .join("checkpoints/cp-003.json")
            .is_file()
    );
    assert!(
        session_dir(root, &id)
            .join("checkpoints/cp-004.json")
            .is_file()
    );

    let rec = state.session_manager.get(&id).unwrap();
    assert_eq!(rec.checkpoints.len(), 4);
    // Kept across a server restart.
    let reopened = SessionManager::open(root);
    assert_eq!(reopened.get(&id).unwrap().checkpoints, rec.checkpoints);
    std::mem::forget(reopened);
    // Pure file system work: the workspace's own git was never run.
    assert_eq!(git(&ws, &["rev-parse", "HEAD"]).unwrap(), head_before);
    assert!(
        state
            .audit_sink
            .snapshot()
            .iter()
            .any(|e| e.action == "session_checkpoint")
    );
}

#[tokio::test]
async fn resuming_a_human_edited_paused_session_commits_both_edits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (state, owner, _, _sessions) = fixture(root);
    let (router, step) = (build_router(state.clone()), step_in_router(&state));
    let main_tip = git(root, &["rev-parse", "refs/heads/main"]).unwrap();

    let id = spawn(&router, &owner, "writer", WRITE_THEN_SLEEP).await;
    pause_after_write(&state, &step, &owner, &id).await;
    let (status, _, body) = call(
        &step,
        Method::PUT,
        &format!("/v1/agents/sessions/{id}/workspace/file"),
        &[("cookie", &owner)],
        Some(json!({ "path": "README.md", "content": "human" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cp = format!("/v1/agents/sessions/{id}/checkpoint");
    assert_eq!(
        send(&step, Method::POST, &cp, &owner, json!({})).await.0,
        StatusCode::OK
    );

    let resume = format!("/v1/agents/sessions/{id}/resume");
    let (status, _) = send(
        &step,
        Method::POST,
        &resume,
        &owner,
        json!({ "command": "  " }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let more = if cfg!(windows) {
        "Set-Content -NoNewline -Path more.txt -Value (Get-Content -Raw README.md)"
    } else {
        "cat README.md > more.txt"
    };
    let (status, body) = send(
        &step,
        Method::POST,
        &resume,
        &owner,
        json!({ "command": more, "max_secs": 60 }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_id = body["id"].as_str().unwrap().to_owned();
    assert_ne!(new_id, id);
    assert_eq!(body["resumed_from"], json!(id));
    assert_eq!(body["limit_secs"], json!(60));
    assert_eq!(body["checkpoints"].as_array().unwrap().len(), 1);

    let done = wait_ended(&state, &new_id).await;
    assert_eq!(done.status, "completed", "{done:?}");
    assert_eq!(done.base_commit.as_deref(), Some(main_tip.as_str()));
    let changed: Vec<(&str, &str)> = done
        .changes
        .iter()
        .map(|c| (c.path.as_str(), c.kind.as_str()))
        .collect();
    assert_eq!(
        changed,
        [
            ("README.md", "modified"),
            ("agent.txt", "added"),
            ("more.txt", "added")
        ]
    );
    // The resumed agent saw the human's edit; its workspace git is a fresh one of the server's.
    let ws = session_dir(root, &new_id).join("ws");
    assert_eq!(std::fs::read(ws.join("more.txt")).unwrap(), b"human");
    assert_eq!(
        git(&ws, &["log", "--format=%s"]).unwrap(),
        "Session resumed"
    );
    assert!(
        state
            .session_manager
            .get(&id)
            .unwrap()
            .output_lines
            .iter()
            .any(|l| l == &format!("[step-in] resumed as {new_id}"))
    );

    let commit = format!("/v1/agents/sessions/{new_id}/commit");
    let (status, body) = send(&router, Method::POST, &commit, &owner, json!({})).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    for (path, text) in [
        ("README.md", "human"),
        ("agent.txt", "agent"),
        ("more.txt", "human"),
    ] {
        assert_eq!(
            git(root, &["show", &format!("refs/heads/main:{path}")]).unwrap(),
            text
        );
    }
    assert_eq!(
        git(root, &["rev-parse", "refs/heads/main~1"]).unwrap(),
        main_tip
    );
}

#[test]
fn materialise_full_hydrates_authorized_encrypted_overlays_without_dirtying_diff() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    crate::store::bind_state_dir(root, &root.join(".premier"), "overlay-test", true);
    git(root, &["init", "-q", "-b", "main"]).unwrap();
    std::fs::write(root.join("README.md"), "hello\n").unwrap();
    git(root, &["add", "README.md"]).unwrap();
    git(root, &["commit", "-q", "-m", "init"]).unwrap();

    let store = crate::overlay_store(root).unwrap();
    store
        .mount(premier_overlay::MountOverlayInput {
            kind: premier_core::OverlayKind::Personal,
            path: "AGENTS.local.md".to_owned(),
            owner_principal: Some("@alice".to_owned()),
            team_group: None,
            encrypted: true,
            payload: Some(b"alice personal instructions\n".to_vec()),
        })
        .unwrap();
    store
        .mount(premier_overlay::MountOverlayInput {
            kind: premier_core::OverlayKind::Personal,
            path: "AGENTS.local.md".to_owned(),
            owner_principal: Some("@bob".to_owned()),
            team_group: None,
            encrypted: true,
            payload: Some(b"bob private instructions\n".to_vec()),
        })
        .unwrap();
    store
        .mount(premier_overlay::MountOverlayInput {
            kind: premier_core::OverlayKind::Team("core".to_owned()),
            path: ".run/dev.env".to_owned(),
            owner_principal: None,
            team_group: Some("core".to_owned()),
            encrypted: true,
            payload: Some(b"TEAM_FLAG=1\n".to_vec()),
        })
        .unwrap();

    let policy_file = parse_policy_toml(POLICY).unwrap();
    let policy = CompiledPolicy::compile(None, &policy_file).unwrap();
    let alice = premier_core::DelegatedIdentity::human_only(
        premier_core::Principal::User("alice".to_owned()),
        vec!["core".to_owned()],
    );
    let bob = premier_core::DelegatedIdentity::human_only(
        premier_core::Principal::User("bob".to_owned()),
        vec!["other".to_owned()],
    );
    let ws_alice = tmp.path().join("ws-alice");
    let ws_bob = tmp.path().join("ws-bob");
    let vis = std::collections::HashMap::new();
    let qa = std::collections::BTreeMap::new();

    let (_, base_alice, _, _) = materialise_full(
        root,
        Some("refs/heads/main"),
        "main",
        Some(&policy),
        &alice,
        &vis,
        &ws_alice,
        None,
        &qa,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(ws_alice.join("AGENTS.local.md")).unwrap(),
        "alice personal instructions\n"
    );
    assert_eq!(
        std::fs::read_to_string(ws_alice.join(".run/dev.env")).unwrap(),
        "TEAM_FLAG=1\n"
    );
    // Untouched overlays must not appear in workspace diff or git status.
    let (changes_alice, _, _, _) = diff_workspace_full(&ws_alice, &base_alice);
    assert!(
        changes_alice.is_empty(),
        "expected no diff: {changes_alice:?}"
    );
    assert!(!root.join("AGENTS.local.md").exists());

    let (_, base_bob, _, _) = materialise_full(
        root,
        Some("refs/heads/main"),
        "main",
        Some(&policy),
        &bob,
        &vis,
        &ws_bob,
        None,
        &qa,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(ws_bob.join("AGENTS.local.md")).unwrap(),
        "bob private instructions\n"
    );
    assert!(
        !ws_bob.join(".run/dev.env").exists(),
        "bob is not in group core and must not receive core team overlay"
    );
    let (changes_bob, _, _, _) = diff_workspace_full(&ws_bob, &base_bob);
    assert!(changes_bob.is_empty(), "expected no diff: {changes_bob:?}");
}
