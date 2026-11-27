//! Agent lanes: a lane is an agent's change set held on a server-internal snapshot ref
//! ([`crate::LANE_REF_PREFIX`]), rebased three ways onto its target branch, with first-class
//! conflicts (diff3 hunks) and round-to-round interdiffs.
//!
//! Only the paths a lane changed are ever inspected or rewritten: every other file of the target,
//! whoever may read it, stays exactly as it is.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::objects::{CanonicalGitRepo, CommitObj, GitObjectKind, git_command, hash_git_object};
use crate::projector::{GITLINK_MODE, RefUpdateCheck, TreeListing, git_stdout, tree_files};
use crate::{GitBridgeError, LANE_REF_PREFIX, is_reserved_path_component};

const SYMLINK_MODE: &str = "120000";
/// How far into a file git looks for a NUL to call it binary.
const BINARY_SNIFF_BYTES: usize = 8192;
/// Largest patch text kept per interdiff entry.
const MAX_PATCH_BYTES: usize = 32 * 1024;

fn default_true() -> bool {
    true
}

/// One diff3 conflict block of a merged file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictHunk {
    /// 1-based line of `<<<<<<<` in the merged text.
    pub start_line: usize,
    /// 1-based line of `>>>>>>>` in the merged text.
    pub end_line: usize,
    pub base_lines: Vec<String>,
    /// The target (base branch) side.
    pub ours_lines: Vec<String>,
    /// The lane (agent) side.
    pub theirs_lines: Vec<String>,
    /// The whole block, markers included, as `git merge-file --diff3` wrote it.
    pub markers: String,
}

/// A path a lane cannot be rebased onto its target without someone deciding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneConflict {
    pub path: String,
    /// `content_overlap`, `modify_delete`, `delete_modify`, `add_add`, `binary_conflict`,
    /// `mode_conflict` or `path_type_collision`.
    pub kind: String,
    pub summary: String,
    #[serde(default)]
    pub hunks: Vec<ConflictHunk>,
    /// Whether the caller may be shown this conflict's content (callers filter by policy).
    #[serde(default = "default_true")]
    pub allowed: bool,
}

/// One file a lane changed: `None` deletes it, `Some((mode, bytes))` adds or modifies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneFileChange {
    pub path: String,
    pub new_content: Option<(String, Vec<u8>)>,
}

/// A path and its new `(mode, bytes)`; `None` deletes it.
pub type ResolvedChange = (String, Option<(String, Vec<u8>)>);

/// What rebasing a lane onto its target would do. Reads only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebasePlan {
    /// Changes to write on the target tip (3-way merged where both sides changed a file).
    pub resolved_changes: Vec<ResolvedChange>,
    /// Paths both sides changed that merged cleanly.
    pub merged_paths: Vec<String>,
    pub conflicts: Vec<LaneConflict>,
    /// Whether the target moved since the lane's base.
    pub rebased: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebaseApplyResult {
    pub commit_oid: String,
    pub rebased: bool,
    pub merged_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterdiffEntry {
    pub path: String,
    /// `added`, `modified`, `deleted`, `renamed` or `typechange`.
    pub status: String,
    pub additions: usize,
    pub deletions: usize,
    pub binary: bool,
    /// Unified diff (3 lines of context), cut at 32 KiB.
    pub patch: String,
}

/// What changed between two rounds of a lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitInterdiff {
    pub from_oid: String,
    pub to_oid: String,
    pub rebased_between_rounds: bool,
    /// Files that differ only because the target moved between rounds (left out of `files`).
    pub upstream_files_skipped: usize,
    /// The paths behind `upstream_files_skipped`, so a caller can count only what a viewer may list.
    #[serde(default)]
    pub upstream_skipped_paths: Vec<String>,
    pub files: Vec<InterdiffEntry>,
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(BINARY_SNIFF_BYTES)].contains(&0)
}

/// The tree entry oid of a change: a gitlink's bytes are the commit oid it names.
fn entry_oid(mode: &str, bytes: &[u8]) -> String {
    if mode == GITLINK_MODE {
        String::from_utf8_lossy(bytes).trim().to_owned()
    } else {
        hash_git_object(GitObjectKind::Blob, bytes)
    }
}

/// Parse the conflict blocks of `git merge-file -p --diff3` output (`\n` or `\r\n` lines). A block
/// without a `|||||||` base section (plain `merge` style) is read with empty `base_lines`.
pub fn parse_diff3_conflicts(merged_text: &str) -> Vec<ConflictHunk> {
    enum Section {
        Outside,
        Ours,
        Base,
        Theirs,
    }
    let mut hunks = Vec::new();
    let mut section = Section::Outside;
    let mut current = ConflictHunk {
        start_line: 0,
        end_line: 0,
        base_lines: Vec::new(),
        ours_lines: Vec::new(),
        theirs_lines: Vec::new(),
        markers: String::new(),
    };
    for (idx, raw) in merged_text.split('\n').enumerate() {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let line_no = idx + 1;
        match section {
            Section::Outside => {
                if line.starts_with("<<<<<<<") {
                    current = ConflictHunk {
                        start_line: line_no,
                        end_line: line_no,
                        base_lines: Vec::new(),
                        ours_lines: Vec::new(),
                        theirs_lines: Vec::new(),
                        markers: String::new(),
                    };
                    section = Section::Ours;
                } else {
                    continue;
                }
            }
            Section::Ours if line.starts_with("|||||||") => section = Section::Base,
            Section::Ours | Section::Base if line.starts_with("=======") => {
                section = Section::Theirs;
            }
            Section::Ours => current.ours_lines.push(line.to_owned()),
            Section::Base => current.base_lines.push(line.to_owned()),
            Section::Theirs if line.starts_with(">>>>>>>") => {
                current.markers.push_str(line);
                current.markers.push('\n');
                current.end_line = line_no;
                hunks.push(current.clone());
                section = Section::Outside;
                continue;
            }
            Section::Theirs => current.theirs_lines.push(line.to_owned()),
        }
        current.markers.push_str(line);
        current.markers.push('\n');
    }
    hunks
}

/// Merge one file three ways with `git merge-file --diff3`: `Ok(Ok(bytes))` when clean,
/// `Ok(Err(hunks))` on conflict (no hunks for a binary file both sides changed differently).
pub fn merge_file_diff3(
    canonical: &CanonicalGitRepo,
    target_bytes: &[u8],
    base_bytes: &[u8],
    lane_bytes: &[u8],
) -> Result<Result<Vec<u8>, Vec<ConflictHunk>>, GitBridgeError> {
    if target_bytes == lane_bytes || lane_bytes == base_bytes {
        return Ok(Ok(target_bytes.to_vec()));
    }
    if target_bytes == base_bytes {
        return Ok(Ok(lane_bytes.to_vec()));
    }
    if [target_bytes, base_bytes, lane_bytes]
        .into_iter()
        .any(is_binary)
    {
        return Ok(Err(Vec::new()));
    }
    let io = |what: &str, e: std::io::Error| GitBridgeError::Io(format!("{what}: {e}"));
    let tmp = tempfile::tempdir().map_err(|e| io("tempdir for 3-way merge", e))?;
    let paths = ["target", "base", "lane"].map(|name| tmp.path().join(name));
    for (path, bytes) in paths.iter().zip([target_bytes, base_bytes, lane_bytes]) {
        std::fs::write(path, bytes).map_err(|e| io("write merge input", e))?;
    }
    let out = git_command(canonical.root())
        .args([
            "merge-file",
            "-p",
            "--diff3",
            "-L",
            "target",
            "-L",
            "base",
            "-L",
            "lane",
        ])
        .args(&paths)
        .output()
        .map_err(|e| io("git merge-file", e))?;
    match out.status.code() {
        Some(0) => Ok(Ok(out.stdout)),
        Some(1..=127) => Ok(Err(parse_diff3_conflicts(&String::from_utf8_lossy(
            &out.stdout,
        )))),
        _ => Err(GitBridgeError::Io(format!(
            "git merge-file failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
    }
}

fn text_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// One hunk spanning whole files, for conflicts `git merge-file` never sees (add/add,
/// modify/delete, delete/modify): the same diff3 layout, numbered as if it were the whole file.
fn whole_file_hunk(base: &[u8], ours: &[u8], theirs: &[u8]) -> ConflictHunk {
    let (base_lines, ours_lines, theirs_lines) =
        (text_lines(base), text_lines(ours), text_lines(theirs));
    let mut markers = String::from("<<<<<<< target\n");
    let mut section = |lines: &[String], close: &str| {
        for line in lines {
            markers.push_str(line);
            markers.push('\n');
        }
        markers.push_str(close);
        markers.push('\n');
    };
    section(&ours_lines, "||||||| base");
    section(&base_lines, "=======");
    section(&theirs_lines, ">>>>>>> lane");
    ConflictHunk {
        start_line: 1,
        end_line: ours_lines.len() + base_lines.len() + theirs_lines.len() + 4,
        base_lines,
        ours_lines,
        theirs_lines,
        markers,
    }
}

/// A file's bytes, or `None` for a gitlink (no object of ours behind it).
fn read_entry(
    canonical: &CanonicalGitRepo,
    (mode, oid): &(String, String),
) -> Result<Option<Vec<u8>>, GitBridgeError> {
    if mode == GITLINK_MODE {
        return Ok(None);
    }
    Ok(Some(canonical.read_object(oid)?.data.to_vec()))
}

/// Whether writing a file at `path` on `target` would collide with a directory, or run through a
/// file, that the target has and the lane's base did not.
fn collides(path: &str, base: &TreeListing, target: &TreeListing) -> bool {
    let is_new_dir = target.dirs.contains_key(path) && !base.dirs.contains_key(path);
    is_new_dir
        || path.match_indices('/').any(|(end, _)| {
            let dir = &path[..end];
            target.files.contains_key(dir) && !base.files.contains_key(dir)
        })
}

/// Plan rebasing a lane (its `changes` against `base_commit`) onto `target_tip`, three ways per
/// changed file. Reads only; [`execute_three_way_rebase`] applies exactly this.
pub fn plan_three_way_rebase(
    canonical: &CanonicalGitRepo,
    base_commit: Option<&str>,
    target_tip: Option<&str>,
    changes: &[LaneFileChange],
) -> Result<RebasePlan, GitBridgeError> {
    let all_changes = || {
        changes
            .iter()
            .map(|c| (c.path.clone(), c.new_content.clone()))
            .collect()
    };
    if base_commit == target_tip {
        return Ok(RebasePlan {
            resolved_changes: all_changes(),
            merged_paths: Vec::new(),
            conflicts: Vec::new(),
            rebased: false,
        });
    }
    let root = canonical.root();
    let base = tree_files(root, base_commit)?;
    let target = tree_files(root, target_tip)?;
    let mut plan = RebasePlan {
        resolved_changes: Vec::new(),
        merged_paths: Vec::new(),
        conflicts: Vec::new(),
        rebased: true,
    };
    let conflict =
        |path: &str, kind: &str, summary: String, hunks: Vec<ConflictHunk>| LaneConflict {
            path: path.to_owned(),
            kind: kind.to_owned(),
            summary,
            hunks,
            allowed: true,
        };

    for change in changes {
        let path = change.path.as_str();
        if change.new_content.is_some() && collides(path, &base, &target) {
            plan.conflicts.push(conflict(
                path,
                "path_type_collision",
                format!(
                    "the target turned `{path}` or a directory above it into another kind of entry"
                ),
                Vec::new(),
            ));
            continue;
        }
        let (was, there) = (base.files.get(path), target.files.get(path));
        let new = change
            .new_content
            .as_ref()
            .map(|(mode, bytes)| (mode.clone(), entry_oid(mode, bytes)));
        if there == was {
            plan.resolved_changes
                .push((change.path.clone(), change.new_content.clone()));
            continue;
        }
        if there == new.as_ref() {
            continue; // The target already has this change.
        }
        match (was, there, &change.new_content) {
            (None, Some(t), Some((_, lane_bytes))) => {
                let target_bytes = read_entry(canonical, t)?;
                match target_bytes.filter(|t| !is_binary(t) && !is_binary(lane_bytes)) {
                    Some(t) => plan.conflicts.push(conflict(
                        path,
                        "add_add",
                        format!("both the target and the lane added `{path}`"),
                        vec![whole_file_hunk(b"", &t, lane_bytes)],
                    )),
                    None => plan.conflicts.push(conflict(
                        path,
                        "binary_conflict",
                        format!("both the target and the lane added binary `{path}`"),
                        Vec::new(),
                    )),
                }
            }
            (Some(b), Some(t), None) => {
                let hunks = match (read_entry(canonical, b)?, read_entry(canonical, t)?) {
                    (Some(b), Some(t)) if !is_binary(&b) && !is_binary(&t) => {
                        vec![whole_file_hunk(&b, &t, b"")]
                    }
                    _ => Vec::new(),
                };
                plan.conflicts.push(conflict(
                    path,
                    "modify_delete",
                    format!("the target changed `{path}`, which the lane deleted"),
                    hunks,
                ));
            }
            (Some(b), None, Some((_, lane_bytes))) => {
                let hunks = match read_entry(canonical, b)? {
                    Some(b) if !is_binary(&b) && !is_binary(lane_bytes) => {
                        vec![whole_file_hunk(&b, b"", lane_bytes)]
                    }
                    _ => Vec::new(),
                };
                plan.conflicts.push(conflict(
                    path,
                    "delete_modify",
                    format!("the target deleted `{path}`, which the lane changed"),
                    hunks,
                ));
            }
            (Some(b), Some(t), Some((am, lane_bytes))) => {
                let (bm, tm) = (&b.0, &t.0);
                let special = [bm, tm, am]
                    .iter()
                    .any(|m| *m == SYMLINK_MODE || *m == GITLINK_MODE);
                let mode = if tm == bm || am == tm {
                    Some(am)
                } else if am == bm {
                    Some(tm)
                } else {
                    None
                };
                let Some(mode) = mode.filter(|_| !special) else {
                    plan.conflicts.push(conflict(
                        path,
                        "mode_conflict",
                        format!("the target and the lane changed the kind or mode of `{path}`"),
                        Vec::new(),
                    ));
                    continue;
                };
                let base_bytes = canonical.read_object(&b.1)?.data;
                let target_bytes = canonical.read_object(&t.1)?.data;
                if [base_bytes.as_ref(), target_bytes.as_ref(), lane_bytes]
                    .into_iter()
                    .any(is_binary)
                {
                    plan.conflicts.push(conflict(
                        path,
                        "binary_conflict",
                        format!("the target and the lane both changed binary `{path}`"),
                        Vec::new(),
                    ));
                    continue;
                }
                match merge_file_diff3(canonical, &target_bytes, &base_bytes, lane_bytes)? {
                    Ok(merged) => {
                        plan.resolved_changes
                            .push((change.path.clone(), Some((mode.clone(), merged))));
                        plan.merged_paths.push(change.path.clone());
                    }
                    Err(hunks) => plan.conflicts.push(conflict(
                        path,
                        "content_overlap",
                        format!(
                            "the target and the lane changed the same lines of `{path}` ({})",
                            crate::plural(hunks.len(), "hunk")
                        ),
                        hunks,
                    )),
                }
            }
            // The lane deleted a file its base never had: nothing of the lane's to keep.
            (None, Some(_), None) | (None, None, _) | (Some(_), None, None) => {}
        }
    }
    Ok(plan)
}

static LANE_INDEX_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Write `changes` onto the tree of `parent` (none: an empty tree) in a throwaway index, with no
/// checkout, and return the new tree's oid.
fn write_tree_with_changes(
    canonical: &CanonicalGitRepo,
    parent: Option<&str>,
    changes: &[ResolvedChange],
) -> Result<String, GitBridgeError> {
    if let Some((path, _)) = changes
        .iter()
        .find(|(path, _)| path.split('/').any(is_reserved_path_component))
    {
        return Err(GitBridgeError::Rejected(format!(
            "lane path `{path}` is reserved"
        )));
    }
    let mut entries: Vec<(&str, Option<(&str, String)>)> = Vec::with_capacity(changes.len());
    for (path, content) in changes {
        let entry = match content {
            Some((mode, bytes)) if mode == GITLINK_MODE => {
                Some((mode.as_str(), entry_oid(mode, bytes)))
            }
            Some((mode, bytes)) => Some((
                mode.as_str(),
                canonical.write_object(GitObjectKind::Blob, bytes)?,
            )),
            None => None,
        };
        entries.push((path.as_str(), entry));
    }
    // Deletions first, so a file that became a directory (or the reverse) can be written.
    entries.sort_by_key(|(_, entry)| entry.is_some());
    let zero = "0".repeat(40);
    let input: String = entries
        .iter()
        .map(|(path, entry)| match entry {
            Some((mode, oid)) => format!("{mode} {oid}\t{path}\0"),
            None => format!("0 {zero}\t{path}\0"),
        })
        .collect();

    let root = canonical.root();
    let index = std::env::temp_dir().join(format!(
        "premier-lane-index-{}-{}",
        std::process::id(),
        LANE_INDEX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&index);
    let tree = (|| {
        if let Some(parent) = parent {
            git_stdout(root, Some(&index), &["read-tree", parent], b"")?;
        }
        // Refused by git when a path is, or runs through, something that is not a directory.
        git_stdout(
            root,
            Some(&index),
            &["update-index", "-z", "--index-info"],
            input.as_bytes(),
        )
        .map_err(|_| {
            GitBridgeError::Rejected(
                "a lane path collides with a file or directory on the target".to_owned(),
            )
        })?;
        Ok(git_stdout(root, Some(&index), &["write-tree"], b"")?
            .trim()
            .to_owned())
    })();
    let _ = std::fs::remove_file(&index);
    tree
}

/// Where `full_ref` points now (`None` when it does not exist).
fn current_ref(root: &Path, full_ref: &str) -> Option<String> {
    git_stdout(
        root,
        None,
        &["rev-parse", "--verify", "-q", "--end-of-options", full_ref],
        b"",
    )
    .ok()
    .map(|oid| oid.trim().to_owned())
}

/// Rebase a lane onto `target_tip` (the tip of `target_ref`, `None` when the branch does not
/// exist yet) and land it there as one commit: `Ok(Err(conflicts))` when any path needs someone
/// to decide, and nothing is written to any ref. The target moves by compare-and-swap from
/// `target_tip`, unless `before_ref_update` (given the new commit's oid) refuses.
#[allow(clippy::too_many_arguments)]
pub fn execute_three_way_rebase(
    canonical: &CanonicalGitRepo,
    base_commit: Option<&str>,
    target_ref: &str,
    target_tip: Option<&str>,
    changes: &[LaneFileChange],
    message: &str,
    author_line: &str,
    before_ref_update: Option<RefUpdateCheck<'_>>,
) -> Result<Result<RebaseApplyResult, Vec<LaneConflict>>, GitBridgeError> {
    let plan = plan_three_way_rebase(canonical, base_commit, target_tip, changes)?;
    if !plan.conflicts.is_empty() {
        return Ok(Err(plan.conflicts));
    }
    let new_tree_oid = write_tree_with_changes(canonical, target_tip, &plan.resolved_changes)?;
    if let Some(tip) = target_tip {
        let tip_tree = CommitObj::parse(&canonical.read_object(tip)?.data)?.tree;
        if tip_tree == new_tree_oid {
            return Ok(Ok(RebaseApplyResult {
                commit_oid: tip.to_owned(),
                rebased: plan.rebased,
                merged_paths: plan.merged_paths,
            }));
        }
    }
    let commit = CommitObj {
        tree: new_tree_oid,
        parents: target_tip.map(|p| vec![p.to_owned()]).unwrap_or_default(),
        author: author_line.to_owned(),
        committer: author_line.to_owned(),
        message: message.to_owned(),
    };
    let new_commit_oid = canonical.write_object(GitObjectKind::Commit, &commit.encode())?;
    if let Some(check) = before_ref_update {
        check(&new_commit_oid).map_err(GitBridgeError::Rejected)?;
    }
    // A zero old value means "must not exist yet".
    let expected = target_tip.map_or_else(|| "0".repeat(40), str::to_owned);
    if let Err(failed) = canonical.update_ref_cas(target_ref, &new_commit_oid, &expected) {
        // "Moved" only when the ref really is elsewhere; any other failure of git is itself.
        return Err(
            if current_ref(canonical.root(), target_ref).as_deref() == target_tip {
                failed
            } else {
                GitBridgeError::RefMoved
            },
        );
    }
    Ok(Ok(RebaseApplyResult {
        commit_oid: new_commit_oid,
        rebased: plan.rebased,
        merged_paths: plan.merged_paths,
    }))
}

/// Snapshot a lane: `changes` on top of `base_commit` as one commit parented on it, with
/// `lane_ref` (under [`LANE_REF_PREFIX`]) moved to it. Returns the commit's oid.
pub fn create_lane_snapshot_commit(
    canonical: &CanonicalGitRepo,
    lane_ref: &str,
    base_commit: Option<&str>,
    changes: &[LaneFileChange],
    message: &str,
    author_line: &str,
) -> Result<String, GitBridgeError> {
    if !lane_ref.starts_with(LANE_REF_PREFIX) || lane_ref.len() == LANE_REF_PREFIX.len() {
        return Err(GitBridgeError::Rejected(format!(
            "a lane snapshot ref must be under {LANE_REF_PREFIX}"
        )));
    }
    let changes: Vec<_> = changes
        .iter()
        .map(|c| (c.path.clone(), c.new_content.clone()))
        .collect();
    let tree = write_tree_with_changes(canonical, base_commit, &changes)?;
    let commit = CommitObj {
        tree,
        parents: base_commit.map(|p| vec![p.to_owned()]).unwrap_or_default(),
        author: author_line.to_owned(),
        committer: author_line.to_owned(),
        message: message.to_owned(),
    };
    let commit_oid = canonical.write_object(GitObjectKind::Commit, &commit.encode())?;
    canonical.update_ref(lane_ref, &commit_oid)?;
    Ok(commit_oid)
}

/// The changes that take `base_commit`'s tree to `tip_commit`'s (to rebase an existing lane).
pub fn diff_commits_to_changes(
    canonical: &CanonicalGitRepo,
    base_commit: &str,
    tip_commit: &str,
) -> Result<Vec<LaneFileChange>, GitBridgeError> {
    let root = canonical.root();
    let base = tree_files(root, Some(base_commit))?;
    let tip = tree_files(root, Some(tip_commit))?;
    let paths: BTreeSet<&String> = base.files.keys().chain(tip.files.keys()).collect();
    let mut changes = Vec::new();
    for path in paths {
        let now = tip.files.get(path);
        if now == base.files.get(path) {
            continue;
        }
        let new_content = match now {
            Some((mode, oid)) if mode == GITLINK_MODE => {
                Some((mode.clone(), oid.clone().into_bytes()))
            }
            Some((mode, oid)) => Some((mode.clone(), canonical.read_object(oid)?.data.to_vec())),
            None => None,
        };
        changes.push(LaneFileChange {
            path: path.clone(),
            new_content,
        });
    }
    Ok(changes)
}

/// What changed from one round of a lane (`from_oid`) to the next (`to_oid`). When the lane was
/// rebased between rounds (`from_base` != `to_base`), files that differ only because the target
/// moved are left out and counted in `upstream_files_skipped`.
pub fn compute_commit_interdiff(
    canonical: &CanonicalGitRepo,
    from_oid: &str,
    to_oid: &str,
    from_base: Option<&str>,
    to_base: Option<&str>,
) -> Result<CommitInterdiff, GitBridgeError> {
    let root = canonical.root();
    let diff = [
        "diff",
        "--no-renames",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
    ];
    let revs = ["--end-of-options", from_oid, to_oid];
    let args: Vec<&str> = diff
        .into_iter()
        .chain(["--name-status", "-z"])
        .chain(revs)
        .collect();
    let names = git_stdout(root, None, &args, b"")?;
    let mut fields = names.split('\0').filter(|f| !f.is_empty());
    let mut changed = Vec::new();
    while let (Some(status), Some(path)) = (fields.next(), fields.next()) {
        let status = match status.chars().next() {
            Some('A') => "added",
            Some('D') => "deleted",
            Some('R') => "renamed",
            Some('T') => "typechange",
            _ => "modified",
        };
        changed.push((status, path.to_owned()));
    }

    let rebased_between_rounds = from_base.is_some() && to_base.is_some() && from_base != to_base;
    let mut upstream_skipped_paths = Vec::new();
    let upstream = if rebased_between_rounds {
        Some([
            tree_files(root, from_base)?,
            tree_files(root, to_base)?,
            tree_files(root, Some(from_oid))?,
            tree_files(root, Some(to_oid))?,
        ])
    } else {
        None
    };

    let mut files = Vec::new();
    for (status, path) in changed {
        if let Some([fb, tb, from, to]) = &upstream
            && from.files.get(&path) == fb.files.get(&path)
            && to.files.get(&path) == tb.files.get(&path)
        {
            upstream_skipped_paths.push(path);
            continue;
        }
        let args: Vec<&str> = diff
            .into_iter()
            .chain(["-U3"])
            .chain(revs)
            .chain(["--", path.as_str()])
            .collect();
        let mut patch = git_stdout(root, None, &args, b"")?;
        let binary = patch.contains('\0')
            || patch
                .lines()
                .any(|l| l.starts_with("Binary files ") || l == "GIT binary patch");
        let (mut additions, mut deletions) = (0, 0);
        if !binary {
            for line in patch.lines() {
                if line.starts_with('+') && !line.starts_with("+++ ") {
                    additions += 1;
                } else if line.starts_with('-') && !line.starts_with("--- ") {
                    deletions += 1;
                }
            }
        }
        if patch.len() > MAX_PATCH_BYTES {
            let mut end = MAX_PATCH_BYTES;
            while !patch.is_char_boundary(end) {
                end -= 1;
            }
            patch.truncate(end);
        }
        files.push(InterdiffEntry {
            path,
            status: status.to_owned(),
            additions,
            deletions,
            binary,
            patch,
        });
    }
    Ok(CommitInterdiff {
        from_oid: from_oid.to_owned(),
        to_oid: to_oid.to_owned(),
        rebased_between_rounds,
        upstream_files_skipped: upstream_skipped_paths.len(),
        upstream_skipped_paths,
        files,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use premier_core::{DelegatedIdentity, Principal};
    use premier_policy::{CompiledPolicy, parse_policy_toml};

    use super::*;
    use crate::objects::parse_tree;
    use crate::project_commit_tree_for_workspace;

    const AUTHOR: &str = "Agent <agent@premier.test> 1732200000 +0000";

    struct Repo {
        _tmp: tempfile::TempDir,
        repo: CanonicalGitRepo,
    }

    fn repo() -> Repo {
        let tmp = tempfile::tempdir().unwrap();
        let out = git_command(tmp.path())
            .args(["init", "-q", "-b", "main"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let repo = CanonicalGitRepo::open(tmp.path());
        Repo { _tmp: tmp, repo }
    }

    fn changes(files: &[(&str, Option<&str>)]) -> Vec<LaneFileChange> {
        files
            .iter()
            .map(|(path, text)| LaneFileChange {
                path: (*path).to_owned(),
                new_content: text.map(|t| ("100644".to_owned(), t.as_bytes().to_vec())),
            })
            .collect()
    }

    /// A commit of `files` on top of `parent`.
    fn commit(
        repo: &CanonicalGitRepo,
        parent: Option<&str>,
        files: &[(&str, Option<&str>)],
    ) -> String {
        create_lane_snapshot_commit(
            repo,
            "refs/premier-lanes/scratch",
            parent,
            &changes(files),
            "commit",
            AUTHOR,
        )
        .unwrap()
    }

    fn show(repo: &CanonicalGitRepo, rev: &str, path: &str) -> Option<String> {
        let out = git_command(repo.root())
            .args(["show", &format!("{rev}:{path}")])
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn numbered(lines: usize, edits: &[(usize, &str)]) -> String {
        (1..=lines)
            .map(|n| {
                let text = edits
                    .iter()
                    .find(|(at, _)| *at == n)
                    .map_or_else(|| format!("line {n}"), |(_, t)| (*t).to_owned());
                format!("{text}\n")
            })
            .collect()
    }

    #[test]
    fn non_overlapping_rebase_keeps_every_file_it_did_not_touch() {
        let Repo { repo, .. } = &repo();
        let base = commit(
            repo,
            None,
            &[
                ("README.md", Some("# hi\n")),
                ("app.txt", Some("v1\n")),
                ("secret/key.txt", Some("old secret\n")),
            ],
        );
        let tip = commit(
            repo,
            Some(&base),
            &[
                ("secret/key.txt", Some("rotated secret\n")),
                ("other.txt", Some("new\n")),
            ],
        );
        repo.update_ref("refs/heads/main", &tip).unwrap();

        let lane = changes(&[("app.txt", Some("v2\n")), ("lane/new.txt", Some("added\n"))]);
        let done = execute_three_way_rebase(
            repo,
            Some(&base),
            "refs/heads/main",
            Some(&tip),
            &lane,
            "lane: land",
            AUTHOR,
            None,
        )
        .unwrap()
        .unwrap();
        assert!(done.rebased);
        assert!(done.merged_paths.is_empty());
        let new = &done.commit_oid;
        assert_eq!(
            current_ref(repo.root(), "refs/heads/main").as_deref(),
            Some(new.as_str())
        );
        assert_eq!(show(repo, new, "app.txt").unwrap(), "v2\n");
        assert_eq!(show(repo, new, "lane/new.txt").unwrap(), "added\n");
        assert_eq!(
            show(repo, new, "secret/key.txt").unwrap(),
            "rotated secret\n"
        );
        assert_eq!(show(repo, new, "other.txt").unwrap(), "new\n");
        let parent = CommitObj::parse(&repo.read_object(new).unwrap().data)
            .unwrap()
            .parents;
        assert_eq!(parent, std::slice::from_ref(&tip));

        // The ref moved under us: compare-and-swap refuses.
        let moved = execute_three_way_rebase(
            repo,
            Some(&base),
            "refs/heads/main",
            Some(&tip),
            &changes(&[("app.txt", Some("v3\n"))]),
            "stale",
            AUTHOR,
            None,
        );
        assert_eq!(moved.unwrap_err(), GitBridgeError::RefMoved);

        let fsck = git_command(repo.root())
            .args(["fsck", "--strict"])
            .output()
            .unwrap();
        assert!(
            fsck.status.success(),
            "{}",
            String::from_utf8_lossy(&fsck.stderr)
        );
    }

    #[test]
    fn same_file_changes_on_different_lines_merge() {
        let Repo { repo, .. } = &repo();
        let base = commit(repo, None, &[("f.txt", Some(&numbered(10, &[])))]);
        let tip = commit(
            repo,
            Some(&base),
            &[("f.txt", Some(&numbered(10, &[(1, "TARGET")])))],
        );
        let lane = changes(&[("f.txt", Some(&numbered(10, &[(10, "LANE")])))]);
        let plan = plan_three_way_rebase(repo, Some(&base), Some(&tip), &lane).unwrap();
        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.merged_paths, ["f.txt"]);
        let merged = plan.resolved_changes[0].1.clone().unwrap().1;
        assert_eq!(
            String::from_utf8(merged).unwrap(),
            numbered(10, &[(1, "TARGET"), (10, "LANE")])
        );
    }

    #[test]
    fn overlapping_lines_conflict_with_diff3_hunks_and_move_nothing() {
        let Repo { repo, .. } = &repo();
        let base = commit(repo, None, &[("f.txt", Some(&numbered(9, &[])))]);
        let tip = commit(
            repo,
            Some(&base),
            &[("f.txt", Some(&numbered(9, &[(5, "TARGET")])))],
        );
        repo.update_ref("refs/heads/main", &tip).unwrap();
        let lane = changes(&[("f.txt", Some(&numbered(9, &[(5, "LANE")])))]);
        let conflicts = execute_three_way_rebase(
            repo,
            Some(&base),
            "refs/heads/main",
            Some(&tip),
            &lane,
            "lane",
            AUTHOR,
            None,
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(conflicts.len(), 1);
        let c = &conflicts[0];
        assert_eq!(
            (c.path.as_str(), c.kind.as_str(), c.allowed),
            ("f.txt", "content_overlap", true)
        );
        assert_eq!(c.hunks.len(), 1);
        let h = &c.hunks[0];
        assert_eq!(h.ours_lines, ["TARGET"]);
        assert_eq!(h.base_lines, ["line 5"]);
        assert_eq!(h.theirs_lines, ["LANE"]);
        assert_eq!(h.start_line, 5);
        assert_eq!(h.end_line, 11);
        for marker in ["<<<<<<< target", "||||||| base", "=======", ">>>>>>> lane"] {
            assert!(
                h.markers.contains(marker),
                "{marker} missing in {}",
                h.markers
            );
        }
        assert_eq!(
            current_ref(repo.root(), "refs/heads/main").as_deref(),
            Some(tip.as_str())
        );
    }

    #[test]
    fn delete_and_add_conflicts_are_named() {
        let Repo { repo, .. } = &repo();
        let base = commit(
            repo,
            None,
            &[
                ("changed-then-deleted.txt", Some("a\n")),
                ("deleted-then-changed.txt", Some("b\n")),
            ],
        );
        let tip = commit(
            repo,
            Some(&base),
            &[
                ("changed-then-deleted.txt", Some("a, target\n")),
                ("deleted-then-changed.txt", None),
                ("both-added.txt", Some("target\n")),
            ],
        );
        let lane = changes(&[
            ("changed-then-deleted.txt", None),
            ("deleted-then-changed.txt", Some("b, lane\n")),
            ("both-added.txt", Some("lane\n")),
        ]);
        let plan = plan_three_way_rebase(repo, Some(&base), Some(&tip), &lane).unwrap();
        let kinds: Vec<(&str, &str)> = plan
            .conflicts
            .iter()
            .map(|c| (c.path.as_str(), c.kind.as_str()))
            .collect();
        assert_eq!(
            kinds,
            [
                ("changed-then-deleted.txt", "modify_delete"),
                ("deleted-then-changed.txt", "delete_modify"),
                ("both-added.txt", "add_add"),
            ]
        );
        let hunk = |i: usize| plan.conflicts[i].hunks[0].clone();
        assert_eq!(
            (hunk(0).ours_lines, hunk(0).theirs_lines),
            (vec!["a, target".to_owned()], vec![])
        );
        assert_eq!(
            (hunk(1).base_lines, hunk(1).theirs_lines),
            (vec!["b".to_owned()], vec!["b, lane".to_owned()])
        );
        assert_eq!(
            (hunk(2).ours_lines, hunk(2).theirs_lines),
            (vec!["target".to_owned()], vec!["lane".to_owned()])
        );
        assert!(hunk(2).base_lines.is_empty());
        assert_eq!(parse_diff3_conflicts(&hunk(2).markers), [hunk(2)]);
    }

    #[test]
    fn a_file_where_the_target_now_has_a_directory_collides() {
        let Repo { repo, .. } = &repo();
        let base = commit(repo, None, &[("README.md", Some("x\n"))]);
        let tip = commit(repo, Some(&base), &[("docs/a.md", Some("a\n"))]);
        let plan = plan_three_way_rebase(
            repo,
            Some(&base),
            Some(&tip),
            &changes(&[("docs", Some("file\n")), ("README.md/x", Some("no\n"))]),
        )
        .unwrap();
        let kinds: Vec<&str> = plan.conflicts.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["path_type_collision"]);
        // `README.md` was already a file on the base: git refuses it when writing instead.
        assert_eq!(plan.resolved_changes.len(), 1);
    }

    #[test]
    fn unchanged_base_takes_the_fast_path_and_reserved_paths_are_refused() {
        let Repo { repo, .. } = &repo();
        let base = commit(repo, None, &[("a.txt", Some("a\n"))]);
        let lane = changes(&[("a.txt", Some("b\n"))]);
        let plan = plan_three_way_rebase(repo, Some(&base), Some(&base), &lane).unwrap();
        assert!(!plan.rebased);
        assert_eq!(plan.resolved_changes.len(), 1);
        let bad = create_lane_snapshot_commit(
            repo,
            "refs/premier-lanes/x",
            Some(&base),
            &changes(&[(".git/hooks/pre-commit", Some("evil\n"))]),
            "m",
            AUTHOR,
        );
        assert!(matches!(bad, Err(GitBridgeError::Rejected(_))));
        let not_a_lane =
            create_lane_snapshot_commit(repo, "refs/heads/main", None, &lane, "m", AUTHOR);
        assert!(matches!(not_a_lane, Err(GitBridgeError::Rejected(_))));
    }

    #[test]
    fn diff3_parser_reads_crlf_and_blocks_without_a_base() {
        let text = "keep\r\n<<<<<<< target\r\nours\r\n=======\r\ntheirs\r\n>>>>>>> lane\r\nend\r\n";
        let hunks = parse_diff3_conflicts(text);
        assert_eq!(hunks.len(), 1);
        assert_eq!((hunks[0].start_line, hunks[0].end_line), (2, 6));
        assert_eq!(hunks[0].ours_lines, ["ours"]);
        assert!(hunks[0].base_lines.is_empty());
        assert_eq!(hunks[0].theirs_lines, ["theirs"]);
        assert!(parse_diff3_conflicts("no conflicts\n").is_empty());
    }

    #[test]
    fn diff_commits_to_changes_round_trips_a_lane() {
        let Repo { repo, .. } = &repo();
        let base = commit(
            repo,
            None,
            &[("a.txt", Some("a\n")), ("b.txt", Some("b\n"))],
        );
        let tip = commit(
            repo,
            Some(&base),
            &[
                ("a.txt", Some("A\n")),
                ("b.txt", None),
                ("c.txt", Some("c\n")),
            ],
        );
        let got = diff_commits_to_changes(repo, &base, &tip).unwrap();
        assert_eq!(
            got,
            changes(&[
                ("a.txt", Some("A\n")),
                ("b.txt", None),
                ("c.txt", Some("c\n"))
            ])
        );
    }

    #[test]
    fn interdiff_drops_upstream_noise_only_when_rebased_between_rounds() {
        let Repo { repo, .. } = &repo();
        let b1 = commit(
            repo,
            None,
            &[("a.txt", Some("a\n")), ("u.txt", Some("u1\n"))],
        );
        let round1 = commit(repo, Some(&b1), &[("a.txt", Some("a, round 1\n"))]);
        let b2 = commit(repo, Some(&b1), &[("u.txt", Some("u2\n"))]);
        let round2 = commit(
            repo,
            Some(&b2),
            &[("a.txt", Some("a, round 2\n")), ("b.bin", Some("bin\0ary"))],
        );

        let filtered =
            compute_commit_interdiff(repo, &round1, &round2, Some(&b1), Some(&b2)).unwrap();
        assert!(filtered.rebased_between_rounds);
        assert_eq!(filtered.upstream_files_skipped, 1);
        let paths: Vec<(&str, &str)> = filtered
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.status.as_str()))
            .collect();
        assert_eq!(paths, [("a.txt", "modified"), ("b.bin", "added")]);
        let a = &filtered.files[0];
        assert_eq!((a.additions, a.deletions, a.binary), (1, 1, false));
        assert!(a.patch.contains("+a, round 2"));
        assert!(filtered.files[1].binary);

        let raw = compute_commit_interdiff(repo, &round1, &round2, None, None).unwrap();
        assert!(!raw.rebased_between_rounds);
        assert_eq!(raw.upstream_files_skipped, 0);
        assert_eq!(raw.files.len(), 3);
    }

    #[test]
    fn workspace_projection_hides_restricted_paths() {
        let Repo { repo, .. } = &repo();
        let tip = commit(
            repo,
            None,
            &[
                ("README.md", Some("# public\n")),
                ("billing/ledger.rs", Some("secret\n")),
            ],
        );
        let policy = parse_policy_toml(
            r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]
[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#,
        )
        .unwrap();
        let policy = CompiledPolicy::compile(None, &policy).unwrap();
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let (tree, odb) = project_commit_tree_for_workspace(repo, &policy, &anon, "main", &tip)
            .unwrap()
            .unwrap();
        let names: Vec<String> = parse_tree(&odb.get(&tree).unwrap().data)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["README.md"]);
        let secret_blob = hash_git_object(GitObjectKind::Blob, b"secret\n");
        assert!(odb.get(&secret_blob).is_none());
        assert!(
            odb.iter()
                .all(|o| !String::from_utf8_lossy(&o.data).contains("billing"))
        );

        let only_billing = commit(repo, None, &[("billing/ledger.rs", Some("secret\n"))]);
        let none = project_commit_tree_for_workspace(repo, &policy, &anon, "main", &only_billing);
        assert!(none.unwrap().is_none());
    }

    #[test]
    fn lane_refs_are_never_listed() {
        let Repo { repo, .. } = &repo();
        let base = commit(repo, None, &[("a.txt", Some("a\n"))]);
        repo.update_ref("refs/heads/main", &base).unwrap();
        let lane = create_lane_snapshot_commit(
            repo,
            "refs/premier-lanes/cage-0001",
            Some(&base),
            &changes(&[("a.txt", Some("lane\n"))]),
            "snapshot",
            AUTHOR,
        )
        .unwrap();
        assert_eq!(
            current_ref(repo.root(), "refs/premier-lanes/cage-0001").as_deref(),
            Some(lane.as_str())
        );
        let refs = repo.list_refs().unwrap();
        assert_eq!(refs, [("refs/heads/main".to_owned(), base)]);
        assert!(
            refs.iter()
                .all(|(name, _)| !name.starts_with(LANE_REF_PREFIX))
        );
    }
}
