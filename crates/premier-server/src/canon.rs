//! The canonical Git history as the single source of truth: Studio edits become commits, the
//! repository's policy and env schema are read from the default branch tip, and the server's
//! working tree only follows that branch (agent sessions run in it).

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use premier_core::{Capability, DelegatedIdentity, Principal, RepoPath};
use premier_git_bridge::git_command;
use premier_policy::{AccessPolicyFile, CompiledPolicy, PolicyError, parse_policy_toml};
use premier_secrets::EnvSchema;

use crate::repos::git_out;
use crate::{ServerState, directory};

pub(crate) const POLICY_FILE: &str = ".access.toml";
/// Root-level files of the default branch the server is configured by.
pub(crate) const CONFIG_FILES: [&str; 2] = [POLICY_FILE, ".env.schema"];

/// The repository's default branch: the ref `HEAD` names (also before its first commit). `None`
/// with a detached `HEAD` or no repository.
pub(crate) fn default_ref(root: &Path) -> Option<String> {
    git_out(root, &["symbolic-ref", "-q", "HEAD"])
}

pub(crate) fn tip_of(root: &Path, full_ref: &str) -> Option<String> {
    git_out(
        root,
        &[
            "rev-parse",
            "-q",
            "--verify",
            &format!("{full_ref}^{{commit}}"),
        ],
    )
}

fn run(cmd: &mut Command, stdin: Option<&[u8]>) -> Result<String, String> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| format!("failed to run git: {e}"))?;
    if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(bytes)
            .map_err(|e| format!("failed to feed git: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("failed to run git: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// The repository's ref lock: held across every update of its canonical refs the server makes
/// (Studio commit, policy apply, publish, agent-session commit, receive-pack) and the working-tree
/// sync after it, so a sync never interleaves with a ref update. [`DefaultTip::capture`] takes it.
/// Every holder is a blocking thread running git, so a plain mutex is the right kind.
// shortcut: one leaked mutex per repository path the process touches (a few bytes each); key
// them by an id that dies with the repository if repositories ever churn by the million.
pub(crate) fn ref_lock(root: &Path) -> MutexGuard<'static, ()> {
    static LOCKS: LazyLock<Mutex<HashMap<PathBuf, &'static Mutex<()>>>> =
        LazyLock::new(Default::default);
    let lock = *LOCKS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(root.to_path_buf())
        .or_insert_with(|| Box::leak(Box::default()));
    lock.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The default branch as it was before a ref update, so [`ServerState::default_branch_moved`]
/// can tell afterwards whether it moved and whether the working tree may follow. Holds the
/// repository's [`ref_lock`] until it is consumed (or dropped).
pub(crate) struct DefaultTip {
    full_ref: String,
    tip: Option<String>,
    /// Nothing tracked or untracked in the working tree differed from `tip` (a failing
    /// `git status` counts as a difference).
    clean: bool,
    /// Ignored files and directories (`dir/`) present in the working tree: git calls a tree with
    /// those clean, but a checkout that writes one of these paths would replace it.
    ignored: Vec<String>,
    _lock: MutexGuard<'static, ()>,
}

impl DefaultTip {
    pub(crate) fn capture(root: &Path) -> Option<Self> {
        let _lock = ref_lock(root);
        let full_ref = default_ref(root)?;
        let status = run(
            git_command(root).args(["status", "--porcelain", "-z", "--ignored"]),
            None,
        );
        let mut clean = status.is_ok();
        let mut ignored = Vec::new();
        for entry in status
            .unwrap_or_default()
            .split('\0')
            .filter(|e| !e.is_empty())
        {
            match entry.strip_prefix("!! ") {
                Some(path) => ignored.push(path.to_owned()),
                None => clean = false,
            }
        }
        Some(Self {
            tip: tip_of(root, &full_ref),
            full_ref,
            clean,
            ignored,
            _lock,
        })
    }
}

/// Why the working tree must not be checked out at `rev`, if it must not: the tree names a
/// reserved component (server state, `.git`, an alias of either), or would write over, or
/// replace with a file or directory, a file or directory git ignores. Fails closed when the tree
/// cannot be listed.
pub(crate) fn unsafe_to_check_out(root: &Path, rev: &str, ignored: &[String]) -> Option<String> {
    let Some(listed) = git_out(root, &["ls-tree", "-r", "--name-only", "-z", rev]) else {
        return Some("its tree could not be listed".to_owned());
    };
    let ignored: Vec<String> = ignored.iter().map(|p| p.to_lowercase()).collect();
    listed
        .split('\0')
        .filter(|p| !p.is_empty())
        .find_map(|path| {
            if path
                .split('/')
                .any(premier_git_bridge::is_reserved_path_component)
            {
                return Some(format!("it holds the reserved path '{path}'"));
            }
            let lower = path.to_lowercase();
            // The same path, one inside the other (a file `x` and the tip's `x/y`), or the other way.
            let hit = ignored.iter().map(|ig| ig.trim_end_matches('/')).any(|ig| {
                lower == ig
                    || lower.starts_with(&format!("{ig}/"))
                    || ig.starts_with(&format!("{lower}/"))
            });
            hit.then(|| format!("it would write over the ignored file at '{path}'"))
        })
}

#[derive(Debug)]
pub(crate) enum CommitError {
    /// The branch moved under the edit (lost compare-and-swap).
    Moved,
    /// The path cannot hold this change in the branch's tree.
    Invalid(String),
    Internal(String),
}

/// Commit one file change (`content: None` deletes) on top of `full_ref` with plumbing only: no
/// checkout, no working tree, every other file of the tree untouched. Returns the new tip, or the
/// current one when the change is a no-op. With `expected_tip`, the branch must still be there.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_file(
    root: &Path,
    full_ref: &str,
    expected_tip: Option<&str>,
    path: &RepoPath,
    content: Option<&[u8]>,
    message: &str,
    who: &(String, String),
) -> Result<String, CommitError> {
    commit_changes(
        root,
        full_ref,
        expected_tip,
        &[(path, content, None)],
        message,
        who,
    )
}

/// One path of a commit: its new content (`None` deletes it) and git mode (`100644`, `100755`,
/// or `120000` with the link target as content). Without a mode the path keeps its executable
/// bit, and a new one is `100644`.
pub(crate) type FileChange<'a> = (&'a RepoPath, Option<&'a [u8]>, Option<&'a str>);

/// [`commit_file`] for several files: all of `changes` land as ONE commit, or none does.
// shortcut: two git processes per file; batch through `update-index --index-info` if change
// sets of thousands of files become usual.
pub(crate) fn commit_changes(
    root: &Path,
    full_ref: &str,
    expected_tip: Option<&str>,
    changes: &[FileChange<'_>],
    message: &str,
    (name, email): &(String, String),
) -> Result<String, CommitError> {
    if expected_tip.is_some_and(|tip| tip_of(root, full_ref).as_deref() != Some(tip)) {
        return Err(CommitError::Moved);
    }
    let tmp_dir = tempfile::Builder::new()
        .prefix("premier-index-")
        .tempdir()
        .map_err(|e| CommitError::Internal(format!("create temp index dir failed: {e}")))?;
    let index = tmp_dir.path().join("index");
    commit_with_index(root, &index, full_ref, changes, message, name, email)
}

fn commit_with_index(
    root: &Path,
    index: &Path,
    full_ref: &str,
    changes: &[FileChange<'_>],
    message: &str,
    name: &str,
    email: &str,
) -> Result<String, CommitError> {
    let git = |args: &[&str], stdin: Option<&[u8]>| {
        run(
            git_command(root).env("GIT_INDEX_FILE", index).args(args),
            stdin,
        )
    };
    let internal = CommitError::Internal;
    let old = tip_of(root, full_ref);
    let mut old_tree = None;
    if let Some(old) = &old {
        git(&["read-tree", old], None).map_err(internal)?;
        old_tree = git(&["rev-parse", &format!("{old}^{{tree}}")], None).ok();
    }
    for (path, content, mode) in changes {
        let path = path.as_str();
        // `<mode> <type> <oid>\t<path>` of the entry itself (a directory is listed as one tree).
        let existing = match &old {
            Some(old) => git(&["ls-tree", old, "--", path], None).map_err(internal)?,
            None => String::new(),
        };
        match content {
            Some(bytes) => {
                let mode = match mode {
                    Some(mode @ ("100644" | "100755" | "120000")) => mode,
                    Some(other) => {
                        return Err(CommitError::Invalid(format!(
                            "'{path}': unsupported file mode {other}"
                        )));
                    }
                    None if existing.starts_with("100755") => "100755",
                    None => "100644",
                };
                let blob = git(&["hash-object", "-w", "--stdin"], Some(bytes)).map_err(internal)?;
                // Refused by git when the path is, or runs through, something that is not a directory.
                git(
                    &[
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        &format!("{mode},{blob},{path}"),
                    ],
                    None,
                )
                .map_err(|_| {
                    CommitError::Invalid(format!(
                        "'{path}' cannot be written: it collides with an existing file or directory"
                    ))
                })?;
            }
            None => {
                if existing.split_whitespace().nth(1) != Some("blob") {
                    return Err(CommitError::Invalid(format!(
                        "'{path}' is not a file on this branch"
                    )));
                }
                git(&["update-index", "--force-remove", "--", path], None).map_err(internal)?;
            }
        }
    }
    let tree = git(&["write-tree"], None).map_err(internal)?;
    if let (Some(old), true) = (&old, old_tree.as_ref() == Some(&tree)) {
        return Ok(old.clone());
    }
    let mut commit = git_command(root);
    commit.args(["commit-tree", &tree, "-m", message]);
    if let Some(old) = &old {
        commit.args(["-p", old]);
    }
    for who in ["AUTHOR", "COMMITTER"] {
        commit
            .env(format!("GIT_{who}_NAME"), name)
            .env(format!("GIT_{who}_EMAIL"), email);
    }
    let new = run(&mut commit, None).map_err(internal)?;
    // Compare-and-swap: a zero old value means "must not exist yet".
    let expected = old.unwrap_or_else(|| "0".repeat(40));
    git(&["update-ref", full_ref, &new, &expected], None).map_err(|_| CommitError::Moved)?;
    Ok(new)
}

/// Domain of the address on commits the server makes on a user's behalf: fixed, never taken
/// from the request.
pub(crate) const COMMIT_EMAIL_DOMAIN: &str = "users.noreply.premier";

/// Author and committer of a Studio commit: the authenticated account, never a claimed principal.
pub(crate) fn committer(state: &ServerState) -> (String, String) {
    let me = crate::auth::actor_principal();
    let username = me.trim_start_matches('@').to_owned();
    let display = state
        .auth
        .accounts()
        .ok()
        .and_then(|all| all.into_iter().find(|(id, _, _)| *id == me))
        .map(|(_, display, _)| display)
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| username.clone());
    (display, format!("{username}@{COMMIT_EMAIL_DOMAIN}"))
}

/// On a filesystem that folds case (git records it as `core.ignorecase`), whether the tree of
/// `rev` holds two names that differ only by case: checked out, one would overwrite the other,
/// which is how a file a pusher may write could replace one they may not.
// shortcut: ASCII/Unicode case only, not normalisation forms (HFS+ NFD) or 8.3 short names;
// compare with the filesystem's own folding if such a server filesystem is ever supported.
fn folds_together(root: &Path, rev: &str) -> bool {
    if git_out(root, &["config", "--get", "core.ignorecase"]).as_deref() != Some("true") {
        return false;
    }
    let listed = git_out(root, &["ls-tree", "-r", "--name-only", "-z", rev]).unwrap_or_default();
    let mut spelled: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    listed.split('\0').filter(|p| !p.is_empty()).any(|path| {
        // The file itself and every directory above it.
        path.match_indices('/')
            .map(|(i, _)| i)
            .chain([path.len()])
            .any(|end| {
                let name = &path[..end];
                *spelled.entry(name.to_lowercase()).or_insert(name) != name
            })
    })
}

impl ServerState {
    pub fn current_env_schema(&self) -> Option<Arc<EnvSchema>> {
        self.env_schema.read().ok().and_then(|g| g.clone())
    }

    fn server_policy_file(&self) -> Result<Option<AccessPolicyFile>, String> {
        self.server_policy_toml
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(parse_policy_toml)
            .transpose()
            .map_err(|e| format!("server policy: {e}"))
    }

    /// The built-in owner-only policy under the server policy: what is enforced while the
    /// repository has no policy of its own, or no default branch to take one from.
    pub(crate) fn builtin_policy(&self) -> Result<Arc<CompiledPolicy>, String> {
        let file = parse_policy_toml(directory::DEFAULT_POLICY_TOML)
            .map_err(|e| format!("built-in policy: {e}"))?;
        CompiledPolicy::compile(self.server_policy_file()?.as_ref(), &file)
            .map(Arc::new)
            .map_err(|e| format!("built-in policy: {e}"))
    }

    /// Whether `toml` may become this repository's policy: it parses, compiles under the server
    /// policy, and (on its own; what the host operator's server policy adds is their choice)
    /// leaves the owners group `read` and `write` on `.access.toml` of the default branch.
    pub(crate) fn validate_repo_policy(
        &self,
        toml: &str,
    ) -> Result<(AccessPolicyFile, CompiledPolicy), String> {
        let file = parse_policy_toml(toml).map_err(|e| match e {
            // One line: where, and what the parser expected (its own text repeats the heading
            // and quotes the source over several lines).
            PolicyError::TomlParse(e) => {
                let text = e.to_string();
                let heading = text
                    .lines()
                    .next()
                    .filter(|l| l.starts_with("TOML parse error"));
                format!("{}: {}", heading.unwrap_or("TOML parse error"), e.message())
            }
            e => e.to_string(),
        })?;
        let compiled = CompiledPolicy::compile(self.server_policy_file()?.as_ref(), &file)
            .map_err(|e| format!("policy compile error: {e}"))?;
        let branch = default_ref(&self.workspace_root)
            .and_then(|r| r.strip_prefix("refs/heads/").map(str::to_owned))
            .unwrap_or_else(|| "main".to_owned());
        let probe = DelegatedIdentity::human_only(
            Principal::User("premier-owner-probe".to_owned()),
            vec![directory::OWNERS_GROUP.to_owned()],
        );
        let kept = CompiledPolicy::compile(None, &file)
            .ok()
            .zip(RepoPath::new(POLICY_FILE).ok())
            .is_some_and(|(alone, path)| {
                alone
                    .explain(&probe, &path, &branch)
                    .allows(Capability::READ | Capability::WRITE)
            });
        if !kept {
            return Err(format!(
                "this policy would lock the owners out: group '{}' must keep read and write on {POLICY_FILE} (branch '{branch}')",
                directory::OWNERS_GROUP
            ));
        }
        Ok((file, compiled))
    }

    /// The server's say over a change to one of [`CONFIG_FILES`] on the default branch (`None`:
    /// deleted, which falls back to the built-in policy / no schema). Owners only; anyone else
    /// gets `Err(None)`, to be answered generically.
    pub(crate) fn check_config_change(
        &self,
        is_owner: bool,
        name: &str,
        content: Option<&[u8]>,
    ) -> Result<(), Option<String>> {
        if !is_owner {
            return Err(None);
        }
        let Some(bytes) = content else {
            return Ok(());
        };
        let text =
            std::str::from_utf8(bytes).map_err(|_| Some(format!("{name} is not valid UTF-8")))?;
        if name == POLICY_FILE {
            self.validate_repo_policy(text)
                .map(drop)
                .map_err(|e| Some(format!("{name}: {e}")))
        } else {
            EnvSchema::parse_toml(text)
                .map(drop)
                .map_err(|e| Some(format!("{name}: {e}")))
        }
    }

    /// [`Self::check_config_change`] for every config file that differs between commits `old`
    /// and `new`: what must hold before the default branch may move from one to the other.
    pub(crate) fn check_config_commit(
        &self,
        is_owner: bool,
        old: Option<&str>,
        new: &str,
    ) -> Result<(), String> {
        let root = &self.workspace_root;
        let blob = |rev: &str, name: &str| {
            git_out(
                root,
                &["rev-parse", "-q", "--verify", &format!("{rev}:{name}")],
            )
        };
        for name in CONFIG_FILES {
            crate::repos::require_regular_config(root, new, name)?;
            let now = blob(new, name);
            if now == old.and_then(|old| blob(old, name)) {
                continue;
            }
            let content = match &now {
                Some(oid) => Some(
                    git_command(root)
                        .args(["cat-file", "blob", oid])
                        .output()
                        .ok()
                        .filter(|o| o.status.success())
                        .map(|o| o.stdout)
                        .ok_or_else(|| format!("{name} could not be read"))?,
                ),
                None => None,
            };
            self.check_config_change(is_owner, name, content.as_deref())
                .map_err(|why| {
                    why.unwrap_or_else(|| {
                        format!("only an owner can change {name} on the default branch")
                    })
                })?;
        }
        Ok(())
    }

    /// Load `.access.toml` and `.env.schema` from the default branch tip (`HEAD`) and make them
    /// live. No `.access.toml` there, no default branch (detached `HEAD`), or an imported policy
    /// the owner has not applied yet ([`crate::repos::PENDING_POLICY`]): the built-in owner-only
    /// policy is enforced. On error nothing changes.
    pub fn reload_repo_config(&self) -> Result<(), String> {
        let root = &self.workspace_root;
        let head = |name: &str| -> Result<Option<String>, String> {
            crate::repos::require_regular_config(root, "HEAD", name)?;
            let out = git_command(root)
                .args(["cat-file", "blob", &format!("HEAD:{name}")])
                .output()
                .ok()
                .filter(|o| o.status.success());
            out.map(|o| {
                String::from_utf8(o.stdout).map_err(|_| format!("{name} is not valid UTF-8"))
            })
            .transpose()
        };
        let toml = head(POLICY_FILE)?.unwrap_or_else(|| directory::DEFAULT_POLICY_TOML.to_owned());
        // A detached `HEAD` names no default branch: nothing says whose `.access.toml` this is
        // (config-file protection is per default branch), so it is shown, not enforced.
        let pending = default_ref(root).is_none()
            || crate::store::state_dir(root)
                .join(crate::repos::PENDING_POLICY)
                .exists();
        let (enforced, shown) = if pending {
            let builtin = parse_policy_toml(directory::DEFAULT_POLICY_TOML)
                .map_err(|e| format!("built-in policy: {e}"))?;
            (builtin, parse_policy_toml(&toml).ok())
        } else {
            let file = parse_policy_toml(&toml).map_err(|e| format!("{POLICY_FILE}: {e}"))?;
            (file.clone(), Some(file))
        };
        let compiled = CompiledPolicy::compile(self.server_policy_file()?.as_ref(), &enforced)
            .map_err(|e| format!("{POLICY_FILE}: {e}"))?;
        let schema = head(CONFIG_FILES[1])?
            .map(|text| EnvSchema::parse_toml(&text).map(Arc::new))
            .transpose()
            .map_err(|e| format!("{}: {e}", CONFIG_FILES[1]))?;

        if let Ok(mut g) = self.policy.write() {
            *g = Some(Arc::new(compiled));
        }
        self.set_repo_policy_metadata(Some(toml), shown.map(Arc::new));
        if let Ok(mut g) = self.env_schema.write() {
            *g = schema;
        }
        Ok(())
    }

    /// Call after anything that may have moved the default branch, with what
    /// [`DefaultTip::capture`] saw before it. If the tip moved, policy and schema are reloaded
    /// when the commit changed them, and the working tree follows, but only when all of this
    /// holds (otherwise it is left exactly as it is): the server's state is outside the tree
    /// (`--state-dir`), the tree was clean, and the new tip names no reserved path and writes
    /// over nothing git ignores. Pushed content must never be able to replace a server file.
    ///
    /// Runs under the ref lock `before` holds, and only ever writes the index and the files:
    /// never a ref, so it cannot move the branch back under a concurrent update.
    pub(crate) fn default_branch_moved(&self, before: Option<DefaultTip>) {
        let root = &self.workspace_root;
        let Some(before) = before else { return };
        let Some(now) =
            tip_of(root, &before.full_ref).filter(|now| Some(now) != before.tip.as_ref())
        else {
            return;
        };
        if crate::store::state_root(root).is_none() {
            // Server state lives in this tree (a local checkout): it is never checked out over.
            tracing::debug!(repo = %root.display(), tip = %now, "no state directory: working tree not synced");
        } else if !before.clean {
            tracing::warn!(repo = %root.display(), branch = %before.full_ref, tip = %now,
                "working tree has local changes: left as it is, now behind its branch");
        } else if folds_together(root, &now) {
            tracing::warn!(repo = %root.display(), branch = %before.full_ref, tip = %now,
                "tip has paths this filesystem cannot tell apart: working tree left as it is");
        } else if let Some(why) = unsafe_to_check_out(root, &now, &before.ignored) {
            tracing::warn!(repo = %root.display(), branch = %before.full_ref, tip = %now,
                "working tree left as it is: the new tip cannot be checked out safely, {why}");
        } else if let Err(e) = run(
            git_command(root).args(["read-tree", "-u", "--reset", &now]),
            None,
        ) {
            tracing::warn!(repo = %root.display(), error = %e, "working tree not updated to the new tip");
        }
        let blob = |rev: Option<&String>, name: &str| {
            rev.and_then(|rev| {
                git_out(
                    root,
                    &["rev-parse", "-q", "--verify", &format!("{rev}:{name}")],
                )
            })
        };
        if CONFIG_FILES
            .iter()
            .any(|f| blob(before.tip.as_ref(), f) != blob(Some(&now), f))
            && let Err(e) = self.reload_repo_config()
        {
            tracing::error!(repo = %root.display(), error = %e, "committed policy/schema not loaded; the previous one stays in force");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) -> String {
        let mut cmd = Command::new("git");
        cmd.current_dir(root)
            .args(["-c", "user.name=T", "-c", "user.email=t@example.test"])
            .args(args);
        run(&mut cmd, None).unwrap()
    }

    fn plumb(root: &Path, path: &str, content: &str) -> Result<String, CommitError> {
        let who = ("T".to_owned(), "t@example.test".to_owned());
        commit_file(
            root,
            "refs/heads/main",
            None,
            &RepoPath::new(path).unwrap(),
            Some(content.as_bytes()),
            "m",
            &who,
        )
    }

    /// A repository on `main` whose server state is outside the tree, so the tree follows it.
    fn synced_repo(root: &Path) -> ServerState {
        git(root, &["init", "-q", "-b", "main"]);
        std::fs::write(root.join("README.md"), "# r\n").unwrap();
        git(root, &["add", "README.md"]);
        git(root, &["commit", "-q", "-m", "init"]);
        crate::tests::state_outside(root);
        let sink = Arc::new(premier_proxy::AuditSink::new(None));
        let mut state = ServerState::minimal(None, None, sink);
        state.workspace_root = root.to_path_buf();
        state
    }

    #[test]
    fn the_sync_never_moves_a_ref_and_never_rewinds_a_concurrent_update() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let state = Arc::new(synced_repo(root));
        // Server updates (under the ref lock, as every handler takes it) racing updates that move
        // the branch without it: the sync must never put the branch back.
        let race = |locked: &dyn Fn(usize) -> bool, rounds: usize, tag: &str| {
            let threads: Vec<_> = (0..4)
                .map(|t| {
                    let (state, root, lock) = (Arc::clone(&state), root.to_path_buf(), locked(t));
                    let tag = tag.to_owned();
                    std::thread::spawn(move || {
                        for i in 0..rounds {
                            let file = format!("{tag}{t}-{i}.txt");
                            let before = lock.then(|| DefaultTip::capture(&root)).flatten();
                            while let Err(CommitError::Moved) = plumb(&root, &file, "x\n") {}
                            state.default_branch_moved(before);
                        }
                    })
                })
                .collect();
            for t in threads {
                t.join().unwrap();
            }
        };
        race(&|t| t % 2 == 0, 3, "m");
        assert_eq!(
            git(root, &["rev-list", "--count", "main"]),
            "13",
            "an update was lost"
        );
        assert_eq!(git(root, &["symbolic-ref", "HEAD"]), "refs/heads/main");

        // With every update the server's, the tree ends exactly at the tip.
        git(root, &["read-tree", "-u", "--reset", "main"]);
        race(&|_| true, 2, "s");
        assert_eq!(git(root, &["rev-list", "--count", "main"]), "21");
        assert_eq!(git(root, &["status", "--porcelain"]), "");
        assert!(root.join("s3-1.txt").is_file() && root.join("m1-2.txt").is_file());

        // The sync writes files and the index, never the ref (no reflog gains an entry).
        let before = DefaultTip::capture(root);
        plumb(root, "last.txt", "x\n").unwrap();
        let logged = git(root, &["reflog", "show", "HEAD"]).lines().count();
        state.default_branch_moved(before);
        assert!(root.join("last.txt").is_file());
        assert_eq!(
            git(root, &["reflog", "show", "HEAD"]).lines().count(),
            logged,
            "the sync wrote a ref"
        );

        // A sync handed a stale `before` re-reads the tip under the lock, and never moves the ref.
        let tip = git(root, &["rev-parse", "main"]);
        let mut before = DefaultTip::capture(root).unwrap();
        before.tip = Some(git(root, &["rev-parse", "main~1"]));
        state.default_branch_moved(Some(before));
        assert_eq!(git(root, &["rev-parse", "main"]), tip);
        assert_eq!(git(root, &["status", "--porcelain"]), "");
    }

    #[test]
    fn an_ignored_path_is_never_replaced_by_a_directory_or_a_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let state = synced_repo(root);
        std::fs::write(root.join(".gitignore"), ".env\nbuild/\n").unwrap();
        git(root, &["add", ".gitignore"]);
        git(root, &["commit", "-q", "-m", "ignore"]);
        std::fs::write(root.join(".env"), "SECRET=mine\n").unwrap();
        std::fs::create_dir_all(root.join("build/out")).unwrap();
        std::fs::write(root.join("build/out/x"), "mine\n").unwrap();
        for path in [".env/y", ".ENV/y", "build", "build/out", "build/out/x/z"] {
            let tip = git(root, &["rev-parse", "main"]);
            let before = DefaultTip::capture(root);
            plumb(root, path, "pushed\n").unwrap();
            state.default_branch_moved(before);
            assert_eq!(
                std::fs::read_to_string(root.join(".env")).unwrap(),
                "SECRET=mine\n",
                "{path}"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("build/out/x")).unwrap(),
                "mine\n",
                "{path}"
            );
            git(root, &["update-ref", "refs/heads/main", &tip]);
        }
        // An ignored directory one level down, replaced by a file named like its parent.
        let ignored = ["a/b/".to_owned()];
        let tip = plumb(root, "a", "file\n").unwrap();
        assert!(unsafe_to_check_out(root, &tip, &ignored).is_some());
        // ...while a sibling of an ignored path is fine.
        let tip = plumb(root, "a2/c", "file\n").unwrap();
        assert!(unsafe_to_check_out(root, &tip, &["a2/b".to_owned()]).is_none());
    }
}
