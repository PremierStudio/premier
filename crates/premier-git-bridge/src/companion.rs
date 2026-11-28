//! GitHub companion: what may leave for GitHub and come back from it, Squash-Declassify to a
//! GitHub pull request, and the bidirectional zone sync between a canonical branch and its
//! public GitHub mirror.
//!
//! Everything here works on a local *staging* bare repository the caller fetches into from GitHub
//! and pushes to GitHub from; nothing here talks to the network. Only vetted public blobs ever
//! enter the staging repository, and only vetted public changes ever come back into the
//! canonical one. Every check fails closed: an unknown zone exports nothing.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use premier_core::RepoPath;
use premier_overlay::OverlayGuard;
use premier_policy::CompiledPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::objects::{
    CanonicalGitRepo, CommitObj, GitObject, GitObjectKind, ObjectReader, TreeEntry, encode_tree,
    git_command, hash_git_object, is_hex_oid,
};
use crate::projector::{
    GITLINK_MODE, PrivateContent, TreeFiles, TreeListing, git_stdout, merge_file_bytes,
    plan_squash_with, publish_commit_message, publishable, tree_files, update_ref_or_moved,
    write_tree_with_changes,
};
use crate::{GitBridgeError, ProjectionAttestation, is_reserved_path_component, plural};

/// Most a single file's pull-request diff shows.
const DIFF_FILE_CAP: usize = 32 * 1024;
/// Most all of a pull request's diffs show together.
const DIFF_TOTAL_CAP: usize = 256 * 1024;
/// Most canonical commits one sync-out walks.
const MAX_SYNC_OUT_COMMITS: usize = 2000;
/// Most upstream commits one sync-in imports.
const MAX_SYNC_IN_COMMITS: usize = 500;
/// How far back along upstream's first-parent chain a sync-in looks for its base.
const MAX_SYNC_IN_SCAN: usize = 5000;
/// Maximum canonical-to-upstream OID pairs retained in a sync cursor before trimming.
const MAX_MAPPING_ENTRIES: usize = 2000;
/// How many canonical first-parent commits sync-in checks when re-anchoring after reconnect.
const MAX_RECONNECT_ANCESTORS: usize = 64;

// ---------------------------------------------------------------------------------------------
// A. Exportability & inbound write guards
// ---------------------------------------------------------------------------------------------

fn is_control_plane_component(name: &str) -> bool {
    let base = crate::fold_path_component(name);
    if matches!(base.as_str(), ".access.toml" | ".env.schema") {
        return true;
    }
    if let Some((stem_tilde, ext)) = base.rsplit_once('.')
        && let Some((stem, digits)) = stem_tilde.split_once('~')
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
    {
        let is_hash_stem = |prefix: &str| {
            stem.len() == 6
                && stem.starts_with(prefix)
                && stem.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit())
        };
        return matches!(
            (stem, ext),
            ("acce" | "acces" | "access" | ".acces", "tom" | "toml")
                | (
                    "env" | "envs" | "envsch" | ".envsc",
                    "sch" | "schem" | "schema"
                )
        ) || (is_hash_stem("ac") && matches!(ext, "tom" | "toml"))
            || (is_hash_stem("en") && matches!(ext, "sch" | "schem" | "schema"));
    }
    false
}

/// Whether `path` contains one of the server's control-plane configuration files (`.access.toml`,
/// `.env.schema`), at any depth, including case, NTFS stream/dot/8.3, and HFS-ignorable aliases.
pub fn is_control_plane_config_path(path: &str) -> bool {
    path.trim_start_matches("./")
        .split('/')
        .any(is_control_plane_component)
}

/// Why a path stays off GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportHoldbackReason {
    ReservedPath,
    ControlPlaneConfig,
    OverlayExcluded,
    OutsideZone(String),
    NotPublicReadable,
}

impl ExportHoldbackReason {
    pub fn describe(&self) -> String {
        match self {
            Self::ReservedPath => "a reserved server path".to_owned(),
            Self::ControlPlaneConfig => {
                "control-plane configuration (.access.toml / .env.schema) is never exported to GitHub"
                    .to_owned()
            }
            Self::OverlayExcluded => "excluded by team/personal overlay guard".to_owned(),
            Self::OutsideZone(zone) => format!("outside bound zone '{zone}'"),
            Self::NotPublicReadable => "not readable by anonymous visitors".to_owned(),
        }
    }
}

/// A zone name without its optional `zone:` prefix.
fn zone_label(zone: &str) -> &str {
    let zone = zone.trim();
    zone.strip_prefix("zone:").unwrap_or(zone)
}

/// Whether the file at `path` on `ref_name` may be exported to GitHub: not reserved, not
/// control-plane configuration, a canonical repository path, not an overlay file, readable by
/// anonymous visitors, and, when a zone is bound, inside it (an unknown zone holds nothing).
pub fn check_github_exportable(
    policy: &CompiledPolicy,
    overlay_guard: Option<&OverlayGuard>,
    zone: Option<&str>,
    ref_name: &str,
    path: &str,
) -> Result<(), ExportHoldbackReason> {
    if path.split('/').any(is_reserved_path_component) {
        return Err(ExportHoldbackReason::ReservedPath);
    }
    if is_control_plane_config_path(path) {
        return Err(ExportHoldbackReason::ControlPlaneConfig);
    }
    let Some(repo_path) = RepoPath::new(path).ok().filter(|rp| rp.as_str() == path) else {
        return Err(ExportHoldbackReason::ReservedPath);
    };
    if overlay_guard.is_some_and(|g| g.is_overlay_path(&repo_path)) {
        return Err(ExportHoldbackReason::OverlayExcluded);
    }
    if !publishable(policy, ref_name, path) {
        return Err(ExportHoldbackReason::NotPublicReadable);
    }
    if let Some(zone) = zone
        && !(policy.has_zone(zone) && policy.path_in_zone(zone, &repo_path))
    {
        return Err(ExportHoldbackReason::OutsideZone(
            zone_label(zone).to_owned(),
        ));
    }
    Ok(())
}

/// Whether an inbound GitHub change may write (or delete) `path` on the canonical `ref_name`:
/// only a path that would be exported back ([`check_github_exportable`]), that policy lets the
/// sync write ([`CompiledPolicy::allows_inbound_write`]), and that does not collide, ignoring
/// ASCII case, with a file GitHub does not see (`existing_hidden_lower`: lowercased hidden file
/// paths). The `Err` says why, without naming any hidden path.
pub fn check_github_inbound_write(
    policy: &CompiledPolicy,
    overlay_guard: Option<&OverlayGuard>,
    zone: Option<&str>,
    ref_name: &str,
    path: &str,
    existing_hidden_lower: &HashSet<String>,
) -> Result<(), String> {
    let Some(repo_path) = RepoPath::new(path).ok().filter(|rp| rp.as_str() == path) else {
        return Err("not a valid repository path".to_owned());
    };
    if path.split('/').any(is_reserved_path_component) {
        return Err(ExportHoldbackReason::ReservedPath.describe());
    }
    if is_control_plane_config_path(path) {
        return Err(
            "control-plane configuration (.access.toml / .env.schema) is never imported from GitHub"
                .to_owned(),
        );
    }
    if overlay_guard.is_some_and(|g| g.is_overlay_path(&repo_path)) {
        return Err(ExportHoldbackReason::OverlayExcluded.describe());
    }
    check_github_exportable(policy, overlay_guard, zone, ref_name, path)
        .map_err(|reason| reason.describe())?;
    if !policy.allows_inbound_write(&repo_path, ref_name) {
        return Err("policy denies inbound GitHub sync writes to this path".to_owned());
    }
    if collides_with_hidden(&path.to_ascii_lowercase(), existing_hidden_lower) {
        return Err("collides (ignoring case) with a file GitHub does not see".to_owned());
    }
    Ok(())
}

/// Whether the lowercased path `lower` is, lies under, or contains a hidden path.
fn collides_with_hidden(lower: &str, hidden_lower: &HashSet<String>) -> bool {
    hidden_lower.contains(lower)
        || lower
            .match_indices('/')
            .any(|(end, _)| hidden_lower.contains(&lower[..end]))
        || hidden_lower.iter().any(|hidden| {
            hidden.starts_with(lower) && hidden.as_bytes().get(lower.len()) == Some(&b'/')
        })
}

/// [`check_github_exportable`] for one export, answered once per path.
struct Exporter<'a> {
    policy: &'a CompiledPolicy,
    overlay_guard: Option<&'a OverlayGuard>,
    zone: Option<&'a str>,
    ref_name: &'a str,
    memo: RefCell<HashMap<String, bool>>,
}

impl<'a> Exporter<'a> {
    fn new(
        policy: &'a CompiledPolicy,
        overlay_guard: Option<&'a OverlayGuard>,
        zone: Option<&'a str>,
        ref_name: &'a str,
    ) -> Self {
        Self {
            policy,
            overlay_guard,
            zone,
            ref_name,
            memo: RefCell::new(HashMap::new()),
        }
    }

    fn check(&self, path: &str) -> Result<(), ExportHoldbackReason> {
        check_github_exportable(
            self.policy,
            self.overlay_guard,
            self.zone,
            self.ref_name,
            path,
        )
    }

    fn ok(&self, path: &str) -> bool {
        if let Some(&known) = self.memo.borrow().get(path) {
            return known;
        }
        let ok = self.check(path).is_ok();
        self.memo.borrow_mut().insert(path.to_owned(), ok);
        ok
    }

    /// The files of `listing` GitHub may see.
    fn public_files(&self, listing: &TreeListing) -> TreeFiles {
        listing
            .files
            .iter()
            .filter(|(path, _)| self.ok(path))
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect()
    }
}

fn require_known_zone(policy: &CompiledPolicy, zone: Option<&str>) -> Result<(), GitBridgeError> {
    match zone {
        Some(zone) if !policy.has_zone(zone) => Err(GitBridgeError::Rejected(format!(
            "unknown zone '{}'",
            zone_label(zone)
        ))),
        _ => Ok(()),
    }
}

fn require_oid(oid: &str) -> Result<(), GitBridgeError> {
    if is_hex_oid(oid) {
        Ok(())
    } else {
        Err(GitBridgeError::Rejected(format!(
            "`{oid}` is not a full commit id"
        )))
    }
}

/// `git check-ref-format` on `refs/heads/<name>`.
fn valid_branch_name(root: &Path, name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && git_command(root)
            .args(["check-ref-format", &format!("refs/heads/{name}")])
            .output()
            .is_ok_and(|out| out.status.success())
}

fn require_branch_name(root: &Path, name: &str) -> Result<(), GitBridgeError> {
    if valid_branch_name(root, name) {
        Ok(())
    } else {
        Err(GitBridgeError::Rejected(format!(
            "`{name}` is not a valid branch name"
        )))
    }
}

fn is_regular_file_mode(mode: &str) -> bool {
    matches!(mode, "100644" | "100755")
}

/// Paths whose entry differs between `from` and `to`, with their entry in `to` (`None`: gone).
fn diff_files(from: &TreeFiles, to: &TreeFiles) -> Vec<(String, Option<(String, String)>)> {
    let paths: BTreeSet<&String> = from.keys().chain(to.keys()).collect();
    paths
        .into_iter()
        .filter(|path| from.get(*path) != to.get(*path))
        .map(|path| (path.clone(), to.get(path).cloned()))
        .collect()
}

/// The oid of the tree holding exactly `files`, computed in memory (nothing is written).
fn files_tree_oid(files: &TreeFiles) -> Result<String, GitBridgeError> {
    #[derive(Default)]
    struct Dir<'a> {
        entries: Vec<TreeEntry>,
        dirs: BTreeMap<&'a str, Dir<'a>>,
    }
    fn hash(dir: Dir<'_>) -> Result<String, GitBridgeError> {
        let mut entries = dir.entries;
        for (name, sub) in dir.dirs {
            entries.push(TreeEntry {
                mode: "40000".to_owned(),
                name: name.to_owned(),
                oid_hex: hash(sub)?,
            });
        }
        Ok(hash_git_object(GitObjectKind::Tree, &encode_tree(entries)?))
    }
    let mut root = Dir::default();
    for (path, (mode, oid)) in files {
        let mut dir = &mut root;
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_some() {
                dir = dir.dirs.entry(part).or_default();
            } else {
                dir.entries.push(TreeEntry {
                    mode: mode.clone(),
                    name: part.to_owned(),
                    oid_hex: oid.clone(),
                });
            }
        }
    }
    hash(root)
}

/// Write the tree holding exactly `files` into the repository at `root` (its blobs must be there).
fn write_files_tree(root: &Path, files: &TreeFiles) -> Result<String, GitBridgeError> {
    let mut changes: Vec<_> = files
        .iter()
        .map(|(path, entry)| (path.clone(), Some(entry.clone())))
        .collect();
    write_tree_with_changes(root, None, &mut changes)
}

/// Copy the blobs `oids` that `to` lacks from `from`, and nothing else.
fn copy_missing_blobs<'o>(
    from: &CanonicalGitRepo,
    to: &CanonicalGitRepo,
    oids: impl IntoIterator<Item = &'o str>,
) -> Result<(), GitBridgeError> {
    let query: String = oids.into_iter().map(|oid| format!("{oid}\n")).collect();
    if query.is_empty() {
        return Ok(());
    }
    let present = git_stdout(
        to.root(),
        None,
        &["cat-file", "--batch-check=%(objectname)"],
        query.as_bytes(),
    )?;
    let mut reader = from.reader()?;
    let mut objects = Vec::new();
    for oid in present
        .lines()
        .filter_map(|line| line.strip_suffix(" missing"))
    {
        let object = reader.read(oid)?;
        if object.kind != GitObjectKind::Blob {
            return Err(GitBridgeError::GitObject(format!("{oid} is not a blob")));
        }
        objects.push(object);
    }
    to.write_objects(&objects.iter().collect::<Vec<_>>())
}

fn write_commit(
    repo: &CanonicalGitRepo,
    tree: String,
    parent: Option<&str>,
    author: String,
    committer: String,
    message: String,
) -> Result<String, GitBridgeError> {
    let commit = CommitObj {
        tree,
        parents: parent.map(str::to_owned).into_iter().collect(),
        author,
        committer,
        message,
    };
    repo.write_object(GitObjectKind::Commit, &commit.encode())
}

fn fsck_strict(root: &Path) -> Result<(), GitBridgeError> {
    git_stdout(root, None, &["fsck", "--strict", "--full"], b"")
        .map(|_| ())
        .map_err(|_| GitBridgeError::GitObject("staging repository failed git fsck".to_owned()))
}

/// Commits from `base` (exclusive; `None`: the root) to `tip` along first parents, oldest first.
fn first_parent_commits(
    root: &Path,
    tip: &str,
    base: Option<&str>,
    max: usize,
) -> Result<Vec<String>, GitBridgeError> {
    let limit = format!("--max-count={}", max + 1);
    let exclude = base.map(|b| format!("^{b}"));
    let mut args = vec!["rev-list", "--first-parent", "--reverse", &limit, tip];
    args.extend(exclude.as_deref());
    let out = git_stdout(root, None, &args, b"")?;
    let commits: Vec<String> = out.lines().map(str::to_owned).collect();
    if commits.len() > max {
        return Err(GitBridgeError::Rejected(format!(
            "more than {max} commits to sync at once"
        )));
    }
    Ok(commits)
}

// ---------------------------------------------------------------------------------------------
// B. Squash-Declassify to a GitHub pull request
// ---------------------------------------------------------------------------------------------

/// One published file's change, as the pull request will show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectedFileDiff {
    pub path: String,
    /// `added`, `modified` or `deleted`.
    pub status: String,
    pub additions: usize,
    pub deletions: usize,
    pub binary: bool,
    pub truncated: bool,
    pub patch: String,
}

/// What the squash removed from what GitHub sees.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScrubbedMetadataSummary {
    pub commits_squashed: usize,
    pub private_ancestry_stripped: bool,
    pub canonical_oids_stripped: bool,
    pub copyfrom_history_stripped: bool,
    pub source_branch_name_redacted: bool,
    pub omitted_paths_count: usize,
}

/// A planned Squash-Declassify of a canonical branch into one GitHub pull request commit.
/// Owner-facing: it lists held-back paths, the pull request text never does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubPrSquashPlan {
    pub source_branch: String,
    pub base_branch: String,
    pub pr_branch: String,
    pub zone: Option<String>,
    pub gate_passed: bool,
    pub reason: Option<String>,
    pub published_paths: Vec<String>,
    pub scrubbed_paths: Vec<String>,
    pub held_back_reasons: BTreeMap<String, String>,
    pub conflicts: Vec<String>,
    pub blocked: Vec<String>,
    pub diffs: Vec<ProjectedFileDiff>,
    pub diff_truncated: bool,
    pub scrubbed_metadata: ScrubbedMetadataSummary,
    pub clean_commit_message: String,
    pub pr_title: String,
    pub pr_body: String,
    pub attestation: ProjectionAttestation,
    pub attestation_trailer: String,
    /// Paths to write onto the base, with their `(mode, oid)`; `None` deletes.
    #[serde(skip)]
    pub changes: Vec<(String, Option<(String, String)>)>,
    /// 3-way merged contents of changed paths the base changed too.
    #[serde(skip)]
    pub merged_blobs: BTreeMap<String, Vec<u8>>,
}

/// The pull request commit written into the staging repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializedGithubPr {
    pub public_commit_oid: String,
    pub pr_branch: String,
    pub base_branch: String,
    pub published_paths: Vec<String>,
    pub scrubbed_paths: Vec<String>,
    pub clean_commit_message: String,
    pub pr_title: String,
    pub pr_body: String,
    pub attestation: ProjectionAttestation,
}

/// `premier/declassify-<8 hex>`: names neither the source branch nor its commit.
fn default_pr_branch(source_oid: &str, source_branch: &str) -> String {
    let digest = hex::encode(Sha256::digest(format!("{source_oid}:{source_branch}")));
    format!("premier/declassify-{}", &digest[..8])
}

/// Plan a pull request publishing `source_oid`'s exportable changes onto the canonical base
/// branch (`base_branch` at `canonical_base_oid`): the source's changes since the merge base,
/// minus every path [`check_github_exportable`] holds back. Content at any held-back path (a
/// restricted file, a file outside the zone, `.access.toml`) counts as private, so copying or
/// moving it onto an exported path blocks the plan. Reads only.
#[allow(clippy::too_many_arguments)]
pub fn plan_github_pr_squash(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    overlay_guard: Option<&OverlayGuard>,
    zone: Option<&str>,
    source_branch: &str,
    source_oid: &str,
    base_branch: &str,
    canonical_base_oid: &str,
    pr_branch: Option<&str>,
    title: Option<&str>,
    body: Option<&str>,
) -> Result<GithubPrSquashPlan, GitBridgeError> {
    require_known_zone(policy, zone)?;
    require_oid(source_oid)?;
    require_oid(canonical_base_oid)?;
    let root = canonical.root();
    let pr_branch = match pr_branch.map(str::trim) {
        Some(name) if !name.is_empty() => name.to_owned(),
        _ => default_pr_branch(source_oid, source_branch),
    };
    require_branch_name(root, &pr_branch)?;

    let exporter = Exporter::new(policy, overlay_guard, zone, base_branch);
    let plan = plan_squash_with(
        canonical,
        &|path| exporter.ok(path),
        source_oid,
        Some(canonical_base_oid),
    )?;
    let held_back_reasons = plan
        .scrubbed_paths
        .iter()
        .map(|path| {
            let reason = exporter
                .check(path)
                .err()
                .map_or_else(|| "held back".to_owned(), |r| r.describe());
            (path.clone(), reason)
        })
        .collect();
    let base_files = tree_files(root, Some(canonical_base_oid))?.files;
    let (diffs, diff_truncated) =
        render_diffs(canonical, &base_files, &plan.changes, &plan.merged_blobs)?;

    let published_paths: Vec<String> = plan.changes.iter().map(|(p, _)| p.clone()).collect();
    let pr_title = match title.map(str::trim) {
        Some(title) if !title.is_empty() => title.to_owned(),
        _ => match zone {
            Some(zone) => format!("Update {}", zone_label(zone)),
            None => format!("Declassified changes for {base_branch}"),
        },
    };
    let attestation = ProjectionAttestation::build(source_oid, policy_fingerprint, false);
    let attestation_trailer = attestation.to_git_trailer();
    let summary = match body.map(str::trim) {
        Some(body) if !body.is_empty() => body.to_owned(),
        _ => format!(
            "Declassified update for `{base_branch}`, published from Premier.\n\n{} changed.",
            plural(published_paths.len(), "file")
        ),
    };
    let pr_body = format!("{summary}\n\n{attestation_trailer}\n");
    let clean_commit_message = publish_commit_message(
        &pr_title,
        &format!("refs/heads/{base_branch}"),
        &attestation,
    );

    let reason = if !plan.blocked.is_empty() {
        Some(format!(
            "publish would expose restricted content in {}",
            plural(plan.blocked.len(), "path")
        ))
    } else if !plan.conflicts.is_empty() {
        Some(format!(
            "conflicts with changes on `{base_branch}` in {}",
            plural(plan.conflicts.len(), "path")
        ))
    } else if plan.changes.is_empty() {
        Some("nothing to publish: no exportable change".to_owned())
    } else {
        None
    };

    Ok(GithubPrSquashPlan {
        source_branch: source_branch.to_owned(),
        base_branch: base_branch.to_owned(),
        pr_branch,
        zone: zone.map(|z| zone_label(z).to_owned()),
        gate_passed: reason.is_none(),
        reason,
        published_paths,
        scrubbed_metadata: ScrubbedMetadataSummary {
            commits_squashed: plan.source_commits,
            private_ancestry_stripped: true,
            canonical_oids_stripped: true,
            copyfrom_history_stripped: true,
            source_branch_name_redacted: true,
            omitted_paths_count: plan.scrubbed_paths.len(),
        },
        scrubbed_paths: plan.scrubbed_paths,
        held_back_reasons,
        conflicts: plan.conflicts,
        blocked: plan.blocked,
        diffs,
        diff_truncated,
        clean_commit_message,
        pr_title,
        pr_body,
        attestation,
        attestation_trailer,
        changes: plan.changes,
        merged_blobs: plan.merged_blobs,
    })
}

/// A side of a diff: the file's bytes (a gitlink shows as git shows it), `None` when absent.
fn read_side(
    reader: &mut ObjectReader,
    entry: Option<&(String, String)>,
) -> Result<Option<Vec<u8>>, GitBridgeError> {
    match entry {
        None => Ok(None),
        Some((mode, oid)) if mode == GITLINK_MODE => {
            Ok(Some(format!("Subproject commit {oid}\n").into_bytes()))
        }
        Some((_, oid)) => Ok(Some(reader.read(oid)?.data.to_vec())),
    }
}

/// One diff per change against the base, capped per file and in total.
fn render_diffs(
    canonical: &CanonicalGitRepo,
    base_files: &TreeFiles,
    changes: &[(String, Option<(String, String)>)],
    merged_blobs: &BTreeMap<String, Vec<u8>>,
) -> Result<(Vec<ProjectedFileDiff>, bool), GitBridgeError> {
    let mut reader = canonical.reader()?;
    let (mut diffs, mut total, mut truncated_any) = (Vec::new(), 0usize, false);
    for (path, new) in changes {
        let old = read_side(&mut reader, base_files.get(path))?;
        let new = match merged_blobs.get(path) {
            Some(bytes) => Some(bytes.clone()),
            None => read_side(&mut reader, new.as_ref())?,
        };
        let mut diff = file_diff(path, old.as_deref(), new.as_deref())?;
        let budget = DIFF_FILE_CAP.min(DIFF_TOTAL_CAP.saturating_sub(total));
        if diff.patch.len() > budget {
            let cut = diff.patch.as_bytes()[..budget]
                .iter()
                .rposition(|&b| b == b'\n')
                .map_or(0, |i| i + 1);
            diff.patch.truncate(cut);
            diff.truncated = true;
            truncated_any = true;
        }
        total += diff.patch.len();
        diffs.push(diff);
    }
    Ok((diffs, truncated_any))
}

/// A unified diff of one file, headed by its repository path only (no object ids).
fn file_diff(
    path: &str,
    old: Option<&[u8]>,
    new: Option<&[u8]>,
) -> Result<ProjectedFileDiff, GitBridgeError> {
    let status = match (old, new) {
        (None, _) => "added",
        (_, None) => "deleted",
        _ => "modified",
    };
    let is_binary = |bytes: &[u8]| bytes.contains(&0) || std::str::from_utf8(bytes).is_err();
    let mut diff = ProjectedFileDiff {
        path: path.to_owned(),
        status: status.to_owned(),
        additions: 0,
        deletions: 0,
        binary: old.is_some_and(is_binary) || new.is_some_and(is_binary),
        truncated: false,
        patch: String::new(),
    };
    if diff.binary {
        return Ok(diff);
    }
    let io = |e: std::io::Error| GitBridgeError::Io(format!("diff of {path}: {e}"));
    let tmp = tempfile::tempdir().map_err(io)?;
    std::fs::write(tmp.path().join("a"), old.unwrap_or_default()).map_err(io)?;
    std::fs::write(tmp.path().join("b"), new.unwrap_or_default()).map_err(io)?;
    let out = git_command(tmp.path())
        .args([
            "-c",
            "core.autocrlf=false",
            "diff",
            "--no-index",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "-U3",
            "--",
            "a",
            "b",
        ])
        .output()
        .map_err(io)?;
    // `git diff --no-index` exits 1 when the files differ.
    if !matches!(out.status.code(), Some(0 | 1)) {
        return Err(GitBridgeError::Io(format!("git diff of {path} failed")));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let hunks = if text.starts_with("@@") {
        &text[..]
    } else {
        text.find("\n@@").map_or("", |i| &text[i + 1..])
    };
    for line in hunks.lines() {
        if line.starts_with('+') {
            diff.additions += 1;
        } else if line.starts_with('-') {
            diff.deletions += 1;
        }
    }
    let from = old.map_or_else(|| "/dev/null".to_owned(), |_| format!("a/{path}"));
    let to = new.map_or_else(|| "/dev/null".to_owned(), |_| format!("b/{path}"));
    diff.patch = format!("--- {from}\n+++ {to}\n{hunks}");
    Ok(diff)
}

/// Plan ([`plan_github_pr_squash`]) and write the pull request commit into the staging bare
/// repository, on top of GitHub's base (`upstream_base_oid`, already fetched there; `None`
/// starts from an empty tree):
///
/// 1. Any blocked path, conflict, or empty plan refuses; nothing is written.
/// 2. A changed path GitHub's base changed too (against the exportable canonical base) is merged
///    three ways when both are regular text files; anything else refuses with
///    [`GitBridgeError::PublishConflict`].
/// 3. Only the vetted public blobs are copied into staging; the tree is built in a throwaway
///    index and every entry that differs from GitHub's base must pass [`check_github_exportable`].
/// 4. One commit, parented only on `upstream_base_oid`, moves `refs/heads/<pr branch>`, and the
///    staging repository must pass `git fsck --strict --full`.
#[allow(clippy::too_many_arguments)]
pub fn materialize_github_pr_in_staging(
    canonical: &CanonicalGitRepo,
    staging_bare_root: &Path,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    overlay_guard: Option<&OverlayGuard>,
    zone: Option<&str>,
    source_branch: &str,
    source_oid: &str,
    canonical_base_branch: &str,
    canonical_base_oid: &str,
    upstream_base_oid: Option<&str>,
    pr_head_branch: &str,
    title: Option<&str>,
    body: Option<&str>,
    author: &str,
) -> Result<MaterializedGithubPr, GitBridgeError> {
    if let Some(up) = upstream_base_oid {
        require_oid(up)?;
    }
    let plan = plan_github_pr_squash(
        canonical,
        policy,
        policy_fingerprint,
        overlay_guard,
        zone,
        source_branch,
        source_oid,
        canonical_base_branch,
        canonical_base_oid,
        Some(pr_head_branch),
        title,
        body,
    )?;
    if !plan.blocked.is_empty() {
        return Err(GitBridgeError::PublishBlocked(plan.blocked));
    }
    if !plan.conflicts.is_empty() {
        return Err(GitBridgeError::PublishConflict(plan.conflicts));
    }
    if let Some(reason) = plan.reason {
        return Err(GitBridgeError::Rejected(reason));
    }

    let staging = CanonicalGitRepo::open(staging_bare_root);
    let exporter = Exporter::new(policy, overlay_guard, zone, canonical_base_branch);
    let upstream = tree_files(staging_bare_root, upstream_base_oid)?.files;
    let published_base =
        exporter.public_files(&tree_files(canonical.root(), Some(canonical_base_oid))?);
    let mut canonical_reader = canonical.reader()?;
    let mut staging_reader = staging.reader()?;
    let mut extra_blobs: HashMap<String, Vec<u8>> = plan
        .merged_blobs
        .values()
        .map(|bytes| (hash_git_object(GitObjectKind::Blob, bytes), bytes.clone()))
        .collect();

    // Reconcile each change with what GitHub's base has at that path.
    let (mut changes, mut conflicts) = (Vec::new(), Vec::new());
    for (path, new) in &plan.changes {
        let (theirs, ours_base) = (upstream.get(path), published_base.get(path));
        if theirs == new.as_ref() {
            continue; // GitHub already has it (a deletion of a path it lacks included).
        }
        if theirs == ours_base {
            changes.push((path.clone(), new.clone()));
            continue;
        }
        let merged = match (ours_base, new, theirs) {
            (Some((base_mode, base_oid)), Some((new_mode, new_oid)), Some((up_mode, up_oid)))
                if is_regular_file_mode(base_mode)
                    && base_mode == new_mode
                    && base_mode == up_mode =>
            {
                let new_bytes = match extra_blobs.get(new_oid) {
                    Some(bytes) => bytes.clone(),
                    None => canonical_reader.read(new_oid)?.data.to_vec(),
                };
                merge_file_bytes(
                    canonical.root(),
                    &new_bytes,
                    &canonical_reader.read(base_oid)?.data,
                    &staging_reader.read(up_oid)?.data,
                )?
                .map(|bytes| (base_mode.clone(), bytes))
            }
            _ => None,
        };
        match merged {
            Some((mode, bytes)) => {
                let oid = hash_git_object(GitObjectKind::Blob, &bytes);
                extra_blobs.insert(oid.clone(), bytes);
                changes.push((path.clone(), Some((mode, oid))));
            }
            None => conflicts.push(path.clone()),
        }
    }
    if !conflicts.is_empty() {
        return Err(GitBridgeError::PublishConflict(conflicts));
    }

    // Copy only the vetted public blobs the commit names.
    let mut objects = Vec::new();
    for (mode, oid) in changes.iter().filter_map(|(_, entry)| entry.as_ref()) {
        if mode == GITLINK_MODE {
            continue;
        }
        let object = match extra_blobs.get(oid) {
            Some(bytes) => GitObject::new(GitObjectKind::Blob, bytes.clone()),
            None => canonical_reader.read(oid)?,
        };
        if object.kind != GitObjectKind::Blob || object.oid != *oid {
            return Err(GitBridgeError::GitObject(format!(
                "{oid} is not the blob it names"
            )));
        }
        objects.push(object);
    }
    staging.write_objects(&objects.iter().collect::<Vec<_>>())?;

    let tree = write_tree_with_changes(staging_bare_root, upstream_base_oid, &mut changes)?;
    // Defense in depth: every entry GitHub has not seen must be exportable.
    let result = tree_files(staging_bare_root, Some(&tree))?.files;
    if result == upstream {
        return Err(GitBridgeError::Rejected(
            "nothing to publish: GitHub already has these changes".to_owned(),
        ));
    }
    let leaked: Vec<String> = result
        .iter()
        .filter(|(path, entry)| upstream.get(*path) != Some(entry) && !exporter.ok(path))
        .map(|(path, _)| path.clone())
        .collect();
    if !leaked.is_empty() {
        return Err(GitBridgeError::PublishBlocked(leaked));
    }

    let public_commit_oid = write_commit(
        &staging,
        tree,
        upstream_base_oid,
        author.to_owned(),
        author.to_owned(),
        plan.clean_commit_message.clone(),
    )?;
    staging.update_ref(
        &format!("refs/heads/{}", plan.pr_branch),
        &public_commit_oid,
    )?;
    fsck_strict(staging_bare_root)?;

    Ok(MaterializedGithubPr {
        public_commit_oid,
        pr_branch: plan.pr_branch,
        base_branch: canonical_base_branch.to_owned(),
        published_paths: changes.into_iter().map(|(path, _)| path).collect(),
        scrubbed_paths: plan.scrubbed_paths,
        clean_commit_message: plan.clean_commit_message,
        pr_title: plan.pr_title,
        pr_body: plan.pr_body,
        attestation: plan.attestation,
    })
}

// ---------------------------------------------------------------------------------------------
// C. Bidirectional zone sync
// ---------------------------------------------------------------------------------------------

/// What the last sync of one canonical branch with one GitHub branch left behind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneSyncMappingState {
    #[serde(default)]
    pub last_canonical_oid: Option<String>,
    #[serde(default)]
    pub last_upstream_oid: Option<String>,
    #[serde(default)]
    pub canonical_to_upstream: BTreeMap<String, String>,
    #[serde(default)]
    pub upstream_to_canonical: BTreeMap<String, String>,
    #[serde(default)]
    pub last_policy_fingerprint: Option<String>,
}

/// One upstream change a sync-in refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundPolicyViolation {
    pub commit_oid: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneSyncOutResult {
    pub dry_run: bool,
    pub up_to_date: bool,
    pub zone: Option<String>,
    pub source_branch: String,
    pub target_branch: String,
    pub commits_projected: usize,
    pub commits_collapsed: usize,
    pub published_paths: Vec<String>,
    pub scrubbed_paths: Vec<String>,
    pub blocked: Vec<String>,
    pub canonical_tip: String,
    pub upstream_tip: Option<String>,
    pub attestation_trailer: String,
    pub updated_mapping: ZoneSyncMappingState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneSyncInResult {
    pub dry_run: bool,
    pub up_to_date: bool,
    pub zone: Option<String>,
    pub upstream_ref: String,
    pub target_branch: String,
    pub commits_imported: usize,
    pub imported_paths: Vec<String>,
    pub preserved_hidden_count: usize,
    pub policy_violations: Vec<InboundPolicyViolation>,
    pub conflicts: Vec<String>,
    pub upstream_tip: String,
    pub new_canonical_tip: Option<String>,
    pub updated_mapping: ZoneSyncMappingState,
}

fn trim_oid_map(map: &mut BTreeMap<String, String>, keep: Option<&str>) {
    if map.len() <= MAX_MAPPING_ENTRIES {
        return;
    }
    let excess = map.len() - MAX_MAPPING_ENTRIES;
    let drop_keys: Vec<String> = map
        .keys()
        .filter(|k| keep != Some(k.as_str()))
        .take(excess)
        .cloned()
        .collect();
    for k in drop_keys {
        map.remove(&k);
    }
}

fn prune_mapping(mapping: &mut ZoneSyncMappingState) {
    trim_oid_map(
        &mut mapping.canonical_to_upstream,
        mapping.last_canonical_oid.as_deref(),
    );
    trim_oid_map(
        &mut mapping.upstream_to_canonical,
        mapping.last_upstream_oid.as_deref(),
    );
}

fn contains_full_oid_after_commit_prefix(trimmed_lower: &str) -> bool {
    let Some(rest) = trimmed_lower.strip_prefix("commit ") else {
        return false;
    };
    let Some(token) = rest.split_whitespace().next() else {
        return false;
    };
    let token = token.trim_matches(|c: char| matches!(c, '.' | ':' | ')' | ']' | ','));
    (token.len() == 40 || token.len() == 64) && token.bytes().all(|b| b.is_ascii_hexdigit())
}

fn redact_hex_oids(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    let mut copy_from = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let len = i - start;
            if len == 40 || len == 64 {
                out.push_str(&line[copy_from..start]);
                out.push_str("[redacted-oid]");
                copy_from = i;
            }
        } else {
            i += 1;
        }
    }
    if copy_from == 0 {
        return line.to_owned();
    }
    out.push_str(&line[copy_from..]);
    out
}

/// Scrub canonical OIDs and cross-branch merge/revert/cherry-pick breadcrumbs from public
/// commit messages mirrored without squashing.
fn scrub_public_commit_message(raw: &str, parents: usize, target_branch: &str) -> String {
    if parents > 1 {
        return format!("Merge changes into {target_branch}\n");
    }
    let mut kept = Vec::new();
    let mut prev_blank = true;
    for line in raw.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("(cherry picked from commit ")
            || lower.starts_with("this reverts commit ")
            || lower.starts_with("squashed commit of the following:")
            || contains_full_oid_after_commit_prefix(&lower)
        {
            continue;
        }
        if trimmed.is_empty() {
            if !prev_blank {
                kept.push(String::new());
                prev_blank = true;
            }
        } else {
            kept.push(redact_hex_oids(line));
            prev_blank = false;
        }
    }
    while kept.last().is_some_and(|l| l.is_empty()) {
        kept.pop();
    }
    if kept.is_empty() {
        format!("Update {target_branch}\n")
    } else {
        let mut msg = kept.join("\n");
        msg.push('\n');
        msg
    }
}

/// Project the canonical branch `source_branch` (at `canonical_tip`) onto the GitHub branch
/// `target_branch` in the staging bare repository, whose GitHub tip is `upstream_remote_tip`
/// (fetched there; `None` when GitHub has no such branch).
///
/// - GitHub must still be where the last sync left it, else: run sync-in first.
/// - Every canonical commit since the last sync is checked: the exportable files of its tree are
///   its projection, and a private blob (any held-back path's content, in it or before it) found
///   at an exported path blocks the sync ([`GitBridgeError::PublishBlocked`]).
/// - A commit whose projection equals the one before it changed nothing GitHub sees: it collapses
///   and its author, date and message never leave.
/// - `squash` writes one commit with an attestation trailer instead of one per visible commit.
///
/// Unless `dry_run`, the commits are written into staging (only public blobs copied), the
/// staging ref moves, `git fsck --strict --full` must pass, and `updated_mapping` records it.
#[allow(clippy::too_many_arguments)]
pub fn project_zone_sync_out(
    canonical: &CanonicalGitRepo,
    staging_bare_root: &Path,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    overlay_guard: Option<&OverlayGuard>,
    zone: Option<&str>,
    source_branch: &str,
    canonical_tip: &str,
    target_branch: &str,
    upstream_remote_tip: Option<&str>,
    sync_state: &ZoneSyncMappingState,
    squash: bool,
    summary_message: Option<&str>,
    author: &str,
    dry_run: bool,
) -> Result<ZoneSyncOutResult, GitBridgeError> {
    require_known_zone(policy, zone)?;
    require_oid(canonical_tip)?;
    if let Some(tip) = upstream_remote_tip {
        require_oid(tip)?;
    }
    require_branch_name(staging_bare_root, target_branch)?;
    let root = canonical.root();
    let attestation = ProjectionAttestation::build(canonical_tip, policy_fingerprint, false);
    let mut result = ZoneSyncOutResult {
        dry_run,
        up_to_date: false,
        zone: zone.map(|z| zone_label(z).to_owned()),
        source_branch: source_branch.to_owned(),
        target_branch: target_branch.to_owned(),
        commits_projected: 0,
        commits_collapsed: 0,
        published_paths: Vec::new(),
        scrubbed_paths: Vec::new(),
        blocked: Vec::new(),
        canonical_tip: canonical_tip.to_owned(),
        upstream_tip: upstream_remote_tip.map(str::to_owned),
        attestation_trailer: attestation.to_git_trailer(),
        updated_mapping: sync_state.clone(),
    };

    // GitHub must still be where the last sync left it.
    let (prev_upstream, republish) =
        match (sync_state.last_upstream_oid.as_deref(), upstream_remote_tip) {
            (Some(expected), Some(remote)) if remote != expected => {
                return Err(GitBridgeError::Rejected(
                    "upstream branch diverged since last sync: run sync-in first".to_owned(),
                ));
            }
            (Some(expected), Some(_)) => (Some(expected.to_owned()), false),
            // GitHub lost the branch: re-project from scratch into the fresh staging repository.
            (Some(_), None) => (None, true),
            (None, Some(_)) => {
                return Err(GitBridgeError::Rejected(
                    "upstream branch has history this sync has not seen: run sync-in first"
                        .to_owned(),
                ));
            }
            (None, None) => (None, false),
        };

    let (base_canonical, commits) = if republish {
        (
            None,
            first_parent_commits(root, canonical_tip, None, MAX_SYNC_OUT_COMMITS)?,
        )
    } else {
        match sync_state.last_canonical_oid.as_deref() {
            Some(last) if last == canonical_tip => (Some(last.to_owned()), Vec::new()),
            Some(last) if canonical.is_ancestor(last, canonical_tip) => (
                Some(last.to_owned()),
                first_parent_commits(root, canonical_tip, Some(last), MAX_SYNC_OUT_COMMITS)?,
            ),
            Some(_) => {
                return Err(GitBridgeError::Rejected(
                    "the canonical branch was rewritten since the last sync".to_owned(),
                ));
            }
            None => (
                None,
                first_parent_commits(root, canonical_tip, None, MAX_SYNC_OUT_COMMITS)?,
            ),
        }
    };
    if commits.is_empty() && !republish {
        result.up_to_date = true;
        return Ok(result);
    }

    let exporter = Exporter::new(policy, overlay_guard, zone, source_branch);
    let is_public = |path: &str| exporter.ok(path);
    let prev_files = tree_files(staging_bare_root, prev_upstream.as_deref())?.files;
    let base_listing = tree_files(root, base_canonical.as_deref())?;
    let mut private = PrivateContent::default();
    private.add(&base_listing, &is_public);
    let mut already_public: HashSet<String> =
        prev_files.values().map(|(_, oid)| oid.clone()).collect();
    let mut current = prev_files.clone();
    let mut blocked = BTreeSet::new();
    // Each commit with its projection; `None`: it collapsed (nothing GitHub sees changed).
    let mut steps: Vec<(String, Option<TreeFiles>)> = Vec::new();
    let mut tip_files = base_listing.files.clone();
    for commit in &commits {
        let listing = tree_files(root, Some(commit))?;
        private.add(&listing, &is_public);
        let restricted = private.restricted_in(root, &listing, &is_public, &already_public)?;
        let projected = exporter.public_files(&listing);
        blocked.extend(
            projected
                .iter()
                .filter(|(path, (_, oid))| private.leaks(&listing, &restricted, path, oid))
                .map(|(path, _)| path.clone()),
        );
        if projected == current {
            result.commits_collapsed += 1;
            steps.push((commit.clone(), None));
        } else {
            already_public.extend(projected.values().map(|(_, oid)| oid.clone()));
            current = projected.clone();
            steps.push((commit.clone(), Some(projected)));
        }
        tip_files = listing.files;
    }

    result.scrubbed_paths = diff_files(&base_listing.files, &tip_files)
        .into_iter()
        .map(|(path, _)| path)
        .filter(|path| !is_public(path))
        .collect();
    result.published_paths = diff_files(&prev_files, &current)
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    result.blocked = blocked.into_iter().collect();
    result.commits_projected = if squash {
        usize::from(current != prev_files)
    } else {
        steps.iter().filter(|(_, p)| p.is_some()).count()
    };
    if !result.blocked.is_empty() && !dry_run {
        return Err(GitBridgeError::PublishBlocked(result.blocked));
    }
    if dry_run {
        result.up_to_date = result.commits_projected == 0 && !republish;
        return Ok(result);
    }

    // Copy only the public blobs the new commits name.
    let staging = CanonicalGitRepo::open(staging_bare_root);
    let written: Vec<&TreeFiles> = if squash {
        vec![&current]
    } else {
        steps.iter().filter_map(|(_, p)| p.as_ref()).collect()
    };
    let blobs: BTreeSet<&str> = written
        .iter()
        .flat_map(|files| files.values())
        .filter(|(mode, _)| mode != GITLINK_MODE)
        .map(|(_, oid)| oid.as_str())
        .collect();
    copy_missing_blobs(canonical, &staging, blobs)?;

    let mut mapping = sync_state.clone();
    let mut upstream_tip = prev_upstream;
    if squash {
        if current != prev_files {
            let title = match summary_message.map(str::trim) {
                Some(summary) if !summary.is_empty() => summary.to_owned(),
                _ => format!(
                    "Sync {} to {target_branch}",
                    zone.map_or("public files", zone_label)
                ),
            };
            let oid = write_commit(
                &staging,
                write_files_tree(staging_bare_root, &current)?,
                upstream_tip.as_deref(),
                author.to_owned(),
                author.to_owned(),
                publish_commit_message(&title, target_branch, &attestation),
            )?;
            mapping
                .upstream_to_canonical
                .insert(oid.clone(), canonical_tip.to_owned());
            upstream_tip = Some(oid);
        }
        if let Some(up) = &upstream_tip {
            for (commit, _) in &steps {
                mapping
                    .canonical_to_upstream
                    .insert(commit.clone(), up.clone());
            }
        }
    } else {
        let mut reader = canonical.reader()?;
        for (commit, projected) in &steps {
            if let Some(files) = projected {
                let parsed = CommitObj::parse(&reader.read(commit)?.data)?;
                let message = scrub_public_commit_message(
                    &parsed.message,
                    parsed.parents.len(),
                    target_branch,
                );
                let oid = write_commit(
                    &staging,
                    write_files_tree(staging_bare_root, files)?,
                    upstream_tip.as_deref(),
                    parsed.author,
                    parsed.committer,
                    message,
                )?;
                mapping
                    .upstream_to_canonical
                    .insert(oid.clone(), commit.clone());
                upstream_tip = Some(oid);
            }
            if let Some(up) = &upstream_tip {
                mapping
                    .canonical_to_upstream
                    .insert(commit.clone(), up.clone());
            }
        }
    }

    mapping.last_canonical_oid = Some(canonical_tip.to_owned());
    mapping.last_policy_fingerprint = Some(policy_fingerprint.to_owned());
    if let Some(tip) = &upstream_tip {
        staging.update_ref(&format!("refs/heads/{target_branch}"), tip)?;
        fsck_strict(staging_bare_root)?;
        mapping.last_upstream_oid = Some(tip.clone());
    }
    prune_mapping(&mut mapping);
    result.up_to_date = upstream_tip.as_deref() == upstream_remote_tip;
    result.upstream_tip = upstream_tip;
    result.updated_mapping = mapping;
    Ok(result)
}

/// Why an upstream entry of `mode` at `path` may not be imported, if it may not.
fn check_inbound_entry(
    reader: &mut ObjectReader,
    path: &str,
    mode: &str,
    oid: &str,
    hidden_lower: &HashSet<String>,
    is_public_target: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    match mode {
        "100644" | "100755" => Ok(()),
        "120000" => {
            let target = reader.read(oid).map_err(|e| e.to_string())?.data;
            match crate::resolve_safe_symlink_target(path, &target) {
                Ok(dest)
                    if !collides_with_hidden(&dest.to_ascii_lowercase(), hidden_lower)
                        && is_public_target(&dest) =>
                {
                    Ok(())
                }
                _ => Err("symbolic link points outside the public tree".to_owned()),
            }
        }
        GITLINK_MODE => Err("submodule (gitlink) entries are not imported from GitHub".to_owned()),
        other => Err(format!("unsupported file mode {other}")),
    }
}

fn collides_with_visible(lower: &str, path: &str, visible_case: &HashMap<String, String>) -> bool {
    if visible_case
        .get(lower)
        .is_some_and(|existing| existing != path)
    {
        return true;
    }
    if lower
        .match_indices('/')
        .any(|(end, _)| visible_case.contains_key(&lower[..end]))
    {
        return true;
    }
    visible_case.keys().any(|existing| {
        existing.starts_with(lower) && existing.as_bytes().get(lower.len()) == Some(&b'/')
    })
}

/// Import the GitHub branch `upstream_ref` (its tip `upstream_tip`, fetched into the staging
/// bare repository) into the canonical branch `target_branch` (at `canonical_tip`; `None` when
/// it does not exist yet).
///
/// The base is the newest commit on upstream's first-parent chain the last syncs recorded, or,
/// without a mapping, the one whose tree is the canonical tip's exportable projection. Every
/// incoming commit's changes are validated first ([`check_github_inbound_write`], symlink and
/// gitlink rules), and changed paths the canonical branch changed too since the base are merged
/// three ways or reported as conflicts. Any violation or conflict returns with
/// `new_canonical_tip: None` and nothing written.
///
/// Unless `dry_run`, each incoming commit is replayed onto the canonical branch with its own
/// author and message: only its validated public blobs are copied in, and every file GitHub does
/// not see (`.access.toml`, `.env.schema`, restricted paths, other zones) stays exactly as it
/// was. The ref then moves by compare-and-swap from `canonical_tip`.
#[allow(clippy::too_many_arguments)]
pub fn apply_zone_sync_in(
    canonical: &CanonicalGitRepo,
    staging_bare_root: &Path,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    overlay_guard: Option<&OverlayGuard>,
    zone: Option<&str>,
    upstream_ref: &str,
    upstream_tip: &str,
    target_branch: &str,
    canonical_tip: Option<&str>,
    sync_state: &ZoneSyncMappingState,
    dry_run: bool,
) -> Result<ZoneSyncInResult, GitBridgeError> {
    require_known_zone(policy, zone)?;
    require_oid(upstream_tip)?;
    if let Some(tip) = canonical_tip {
        require_oid(tip)?;
    }
    require_branch_name(canonical.root(), target_branch)?;
    let mut result = ZoneSyncInResult {
        dry_run,
        up_to_date: false,
        zone: zone.map(|z| zone_label(z).to_owned()),
        upstream_ref: upstream_ref.to_owned(),
        target_branch: target_branch.to_owned(),
        commits_imported: 0,
        imported_paths: Vec::new(),
        preserved_hidden_count: 0,
        policy_violations: Vec::new(),
        conflicts: Vec::new(),
        upstream_tip: upstream_tip.to_owned(),
        new_canonical_tip: None,
        updated_mapping: sync_state.clone(),
    };
    if sync_state.last_upstream_oid.as_deref() == Some(upstream_tip)
        || sync_state.upstream_to_canonical.contains_key(upstream_tip)
    {
        result.up_to_date = true;
        return Ok(result);
    }

    // Upstream's first-parent chain, newest first, with each commit's tree.
    let limit = format!("--max-count={MAX_SYNC_IN_SCAN}");
    let log = git_stdout(
        staging_bare_root,
        None,
        &[
            "log",
            "--first-parent",
            "--format=%H %T",
            &limit,
            upstream_tip,
        ],
        b"",
    )?;
    let chain: Vec<(&str, &str)> = log.lines().filter_map(|l| l.split_once(' ')).collect();
    let known = |oid: &str| {
        sync_state
            .upstream_to_canonical
            .get(oid)
            .cloned()
            .or_else(|| {
                (sync_state.last_upstream_oid.as_deref() == Some(oid))
                    .then(|| sync_state.last_canonical_oid.clone())
                    .flatten()
            })
    };

    let exporter = Exporter::new(policy, overlay_guard, zone, target_branch);
    let canonical_listing = tree_files(canonical.root(), canonical_tip)?;
    let no_base = || {
        GitBridgeError::Rejected(
            "no common sync base between upstream and canonical branch; run sync-out or verify target branch"
                .to_owned(),
        )
    };
    let (base_index, base_canonical) = if let Some(found) = chain
        .iter()
        .enumerate()
        .find_map(|(i, (oid, _))| known(oid).map(|c| (i, c)))
    {
        (Some(found.0), Some(found.1))
    } else if let Some(tip) = canonical_tip {
        let projected = files_tree_oid(&exporter.public_files(&canonical_listing))?;
        if let Some(index) = chain.iter().position(|(_, tree)| *tree == projected) {
            (Some(index), Some(tip.to_owned()))
        } else {
            let limit = format!("--max-count={}", MAX_RECONNECT_ANCESTORS + 1);
            let recent = git_stdout(
                canonical.root(),
                None,
                &["rev-list", "--first-parent", &limit, tip],
                b"",
            )?;
            let mut matched = None;
            for anc in recent.lines().skip(1) {
                let anc_listing = tree_files(canonical.root(), Some(anc))?;
                let anc_projected = files_tree_oid(&exporter.public_files(&anc_listing))?;
                if let Some(index) = chain.iter().position(|(_, tree)| *tree == anc_projected) {
                    matched = Some((Some(index), Some(anc.to_owned())));
                    break;
                }
            }
            matched.ok_or_else(no_base)?
        }
    } else if chain.len() >= MAX_SYNC_IN_SCAN {
        return Err(no_base());
    } else {
        (None, None)
    };
    if let Some(base) = &base_canonical {
        match canonical_tip {
            None => {
                return Err(GitBridgeError::Rejected(
                    "the canonical target branch no longer exists".to_owned(),
                ));
            }
            Some(tip) if !canonical.is_ancestor(base, tip) => {
                return Err(GitBridgeError::Rejected(
                    "the canonical branch was rewritten since the last sync".to_owned(),
                ));
            }
            Some(_) => {}
        }
    }
    let base_upstream = base_index.and_then(|i| chain.get(i)).map(|(oid, _)| *oid);
    let incoming: Vec<String> = chain[..base_index.unwrap_or(chain.len())]
        .iter()
        .rev()
        .map(|(oid, _)| (*oid).to_owned())
        .collect();
    if incoming.is_empty() {
        if sync_state.last_upstream_oid.as_deref() != Some(upstream_tip)
            || sync_state.last_canonical_oid != base_canonical
        {
            result.updated_mapping.last_upstream_oid = Some(upstream_tip.to_owned());
            if let Some(base_canon) = &base_canonical {
                result.updated_mapping.last_canonical_oid = Some(base_canon.clone());
                result
                    .updated_mapping
                    .upstream_to_canonical
                    .insert(upstream_tip.to_owned(), base_canon.clone());
                result
                    .updated_mapping
                    .canonical_to_upstream
                    .insert(base_canon.clone(), upstream_tip.to_owned());
            }
            result.updated_mapping.last_policy_fingerprint = Some(policy_fingerprint.to_owned());
            prune_mapping(&mut result.updated_mapping);
        }
        result.up_to_date = true;
        return Ok(result);
    }
    if incoming.len() > MAX_SYNC_IN_COMMITS {
        return Err(GitBridgeError::Rejected(format!(
            "more than {MAX_SYNC_IN_COMMITS} upstream commits to import at once"
        )));
    }

    let hidden: Vec<&String> = canonical_listing
        .files
        .keys()
        .filter(|path| !exporter.ok(path))
        .collect();
    let hidden_lower: HashSet<String> = hidden.iter().map(|p| p.to_ascii_lowercase()).collect();
    let mut visible_case: HashMap<String, String> = canonical_listing
        .files
        .keys()
        .filter(|path| exporter.ok(path))
        .map(|path| (path.to_ascii_lowercase(), (*path).clone()))
        .collect();
    result.preserved_hidden_count = hidden.len();

    // Validation pass: nothing is written until every incoming change is allowed.
    let staging = CanonicalGitRepo::open(staging_bare_root);
    let mut staging_reader = staging.reader()?;
    let base_upstream_files = tree_files(staging_bare_root, base_upstream)?.files;
    let mut prev = base_upstream_files.clone();
    let mut per_commit = Vec::new();
    let mut touched = BTreeSet::new();
    for commit in &incoming {
        let files = tree_files(staging_bare_root, Some(commit))?.files;
        let mut case_counts: HashMap<String, usize> = HashMap::new();
        for path in files.keys() {
            *case_counts.entry(path.to_ascii_lowercase()).or_insert(0) += 1;
        }
        let changes = diff_files(&prev, &files);
        // Apply deletions first so a same-commit case-only rename does not false-positive.
        for (path, entry) in &changes {
            if entry.is_some() {
                continue;
            }
            if let Err(reason) = check_github_inbound_write(
                policy,
                overlay_guard,
                zone,
                target_branch,
                path,
                &hidden_lower,
            ) {
                result.policy_violations.push(InboundPolicyViolation {
                    commit_oid: commit.clone(),
                    path: path.clone(),
                    reason,
                });
            } else {
                let lower = path.to_ascii_lowercase();
                if visible_case
                    .get(&lower)
                    .is_some_and(|existing| existing == path)
                {
                    visible_case.remove(&lower);
                }
            }
            touched.insert(path.clone());
        }
        for (path, entry) in &changes {
            let Some((mode, oid)) = entry else {
                continue;
            };
            let lower = path.to_ascii_lowercase();
            let verdict = check_github_inbound_write(
                policy,
                overlay_guard,
                zone,
                target_branch,
                path,
                &hidden_lower,
            )
            .and_then(|()| {
                check_inbound_entry(
                    &mut staging_reader,
                    path,
                    mode,
                    oid,
                    &hidden_lower,
                    &|dest| crate::projector::publishable(policy, target_branch, dest),
                )
            })
            .and_then(|()| {
                if case_counts.get(&lower).copied().unwrap_or(0) > 1
                    || collides_with_visible(&lower, path, &visible_case)
                {
                    Err("collides (ignoring case) with another path in the repository".to_owned())
                } else {
                    Ok(())
                }
            });
            if let Err(reason) = verdict {
                result.policy_violations.push(InboundPolicyViolation {
                    commit_oid: commit.clone(),
                    path: path.clone(),
                    reason,
                });
            } else {
                visible_case.insert(lower, path.clone());
            }
            touched.insert(path.clone());
        }
        per_commit.push((commit.clone(), changes));
        prev = files;
    }
    let upstream_tip_files = prev;
    result.imported_paths = touched.iter().cloned().collect();

    // Paths both sides changed since the base: `None` keeps canonical's version, `Some` is the
    // merged entry written by the last imported commit.
    let mut settled: BTreeMap<String, Option<(String, String)>> = BTreeMap::new();
    let mut merged_blobs = Vec::new();
    if let (Some(base), Some(tip)) = (&base_canonical, canonical_tip)
        && base != tip
    {
        let base_files = tree_files(canonical.root(), Some(base))?.files;
        let current = &canonical_listing.files;
        let mut canonical_reader = canonical.reader()?;
        for path in &touched {
            let (was, ours, theirs) = (
                base_files.get(path),
                current.get(path),
                upstream_tip_files.get(path),
            );
            if was == ours {
                continue; // Only upstream changed it.
            }
            if ours == theirs || theirs == was {
                settled.insert(path.clone(), None);
                continue;
            }
            let merged = match (was, ours, theirs) {
                (Some((was_mode, was_oid)), Some((our_mode, our_oid)), Some((up_mode, up_oid)))
                    if is_regular_file_mode(was_mode)
                        && was_mode == our_mode
                        && was_mode == up_mode =>
                {
                    merge_file_bytes(
                        canonical.root(),
                        &staging_reader.read(up_oid)?.data,
                        &canonical_reader.read(was_oid)?.data,
                        &canonical_reader.read(our_oid)?.data,
                    )?
                    .map(|bytes| (was_mode.clone(), bytes))
                }
                _ => None,
            };
            match merged {
                Some((mode, bytes)) => {
                    let object = GitObject::new(GitObjectKind::Blob, bytes);
                    settled.insert(path.clone(), Some((mode, object.oid.clone())));
                    merged_blobs.push(object);
                }
                None => result.conflicts.push(path.clone()),
            }
        }
    }
    if !result.policy_violations.is_empty() || !result.conflicts.is_empty() {
        return Ok(result);
    }
    if dry_run {
        result.commits_imported = incoming.len();
        return Ok(result);
    }

    // Materialization pass: only validated public blobs enter the canonical repository.
    let blobs: BTreeSet<&str> = per_commit
        .iter()
        .flat_map(|(_, changes)| changes.iter())
        .filter(|(path, _)| !settled.contains_key(path))
        .filter_map(|(_, entry)| entry.as_ref().map(|(_, oid)| oid.as_str()))
        .collect();
    copy_missing_blobs(&staging, canonical, blobs)?;
    canonical.write_objects(&merged_blobs.iter().collect::<Vec<_>>())?;

    let mut mapping = sync_state.clone();
    let mut parent = canonical_tip.map(str::to_owned);
    for (i, (upstream_commit, changes)) in per_commit.iter().enumerate() {
        let mut apply: Vec<_> = changes
            .iter()
            .filter(|(path, _)| !settled.contains_key(path))
            .cloned()
            .collect();
        if i + 1 == per_commit.len() {
            apply.extend(
                settled
                    .iter()
                    .filter_map(|(path, entry)| Some((path.clone(), Some(entry.clone()?)))),
            );
        }
        let tree = write_tree_with_changes(canonical.root(), parent.as_deref(), &mut apply)?;
        let parsed = CommitObj::parse(&staging_reader.read(upstream_commit)?.data)?;
        let oid = write_commit(
            canonical,
            tree,
            parent.as_deref(),
            parsed.author,
            parsed.committer,
            parsed.message,
        )?;
        mapping
            .upstream_to_canonical
            .insert(upstream_commit.clone(), oid.clone());
        mapping
            .canonical_to_upstream
            .insert(oid.clone(), upstream_commit.clone());
        parent = Some(oid);
    }
    let Some(new_tip) = parent else {
        return Err(GitBridgeError::GitObject(
            "sync-in wrote no commit".to_owned(),
        ));
    };

    // Defense in depth: every file GitHub does not see is exactly as it was.
    let final_files = tree_files(canonical.root(), Some(&new_tip))?.files;
    if hidden
        .iter()
        .any(|path| final_files.get(*path) != canonical_listing.files.get(*path))
    {
        return Err(GitBridgeError::Rejected(
            "sync-in would change files GitHub does not see".to_owned(),
        ));
    }
    update_ref_or_moved(
        canonical,
        &format!("refs/heads/{target_branch}"),
        &new_tip,
        canonical_tip,
    )?;

    mapping.last_canonical_oid = Some(new_tip.clone());
    mapping.last_upstream_oid = Some(upstream_tip.to_owned());
    mapping.last_policy_fingerprint = Some(policy_fingerprint.to_owned());
    prune_mapping(&mut mapping);
    result.commits_imported = per_commit.len();
    result.new_canonical_tip = Some(new_tip);
    result.updated_mapping = mapping;
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;

    use premier_overlay::OverlayManifest;
    use premier_policy::parse_policy_toml;

    use super::*;

    const AUTHOR: &str = "Premier Bot <bot@premier.test> 1732200000 +0000";
    const ZONE: Option<&str> = Some("zone:sdk");
    const POLICY: &str = r#"
version = 1
[defaults]
public = ["traverse", "list", "read"]

[zones.sdk]
paths = ["sdk/**", "README.md"]
exclude = ["sdk/internal/**"]

[[rules]]
id = "deny-billing"
effect = "deny"
principals = ["*"]
paths = ["billing/**"]
capabilities = ["traverse", "list", "read", "write", "use"]

[[rules]]
id = "deny-sync-locked"
effect = "deny"
principals = ["service:github-sync"]
paths = ["sdk/locked.txt"]
capabilities = ["write"]
"#;
    const LIB_RS: &str = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\n";

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "Alice")
            .env("GIT_AUTHOR_EMAIL", "alice@acme.test")
            .env("GIT_COMMITTER_NAME", "Alice")
            .env("GIT_COMMITTER_EMAIL", "alice@acme.test")
            .args(["-c", "core.autocrlf=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
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
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "--allow-empty", "-m", message]);
        git(dir, &["rev-parse", "HEAD"])
    }

    /// Stage `content` at exactly `path` with `mode`, whatever the filesystem would make of it.
    fn stage_entry(dir: &Path, scratch: &Path, path: &str, mode: &str, content: &str) {
        std::fs::write(scratch, content).unwrap();
        let blob = git(dir, &["hash-object", "-w", scratch.to_str().unwrap()]);
        git(
            dir,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("{mode},{blob},{path}"),
            ],
        );
    }

    fn blob_in(dir: &Path, oid: &str) -> bool {
        Command::new("git")
            .current_dir(dir)
            .args(["cat-file", "-e", oid])
            .status()
            .unwrap()
            .success()
    }

    struct Fixture {
        tmp: tempfile::TempDir,
        canonical_dir: PathBuf,
        staging: PathBuf,
        policy: CompiledPolicy,
    }

    impl Fixture {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let canonical_dir = tmp.path().join("canonical");
            std::fs::create_dir_all(&canonical_dir).unwrap();
            git(&canonical_dir, &["init", "-q", "-b", "main"]);
            git(&canonical_dir, &["config", "core.autocrlf", "false"]);
            commit(
                &canonical_dir,
                &[
                    ("README.md", "# SDK\n"),
                    ("sdk/lib.rs", LIB_RS),
                    (
                        "sdk/internal/keys.rs",
                        "pub const INTERNAL: &str = \"x\";\n",
                    ),
                    ("docs/guide.md", "Internal-facing public guide.\n"),
                    ("billing/key.txt", "TOP SECRET BILLING KEY\n"),
                    (".access.toml", "version = 1\n"),
                ],
                "initial",
            );
            let staging = tmp.path().join("staging.git");
            std::fs::create_dir_all(&staging).unwrap();
            git(&staging, &["init", "-q", "--bare", "-b", "main"]);
            git(&staging, &["config", "core.autocrlf", "false"]);
            let policy =
                CompiledPolicy::compile(None, &parse_policy_toml(POLICY).unwrap()).unwrap();
            Self {
                tmp,
                canonical_dir,
                staging,
                policy,
            }
        }

        fn canonical(&self) -> CanonicalGitRepo {
            CanonicalGitRepo::open(&self.canonical_dir)
        }

        fn head(&self) -> String {
            git(&self.canonical_dir, &["rev-parse", "HEAD"])
        }

        fn staging_tip(&self) -> String {
            git(&self.staging, &["rev-parse", "refs/heads/main"])
        }

        fn sync_out(
            &self,
            state: &ZoneSyncMappingState,
            squash: bool,
            dry_run: bool,
        ) -> Result<ZoneSyncOutResult, GitBridgeError> {
            let remote = git(
                &self.staging,
                &["for-each-ref", "--format=%(objectname)", "refs/heads/main"],
            );
            project_zone_sync_out(
                &self.canonical(),
                &self.staging,
                &self.policy,
                "fp-test",
                None,
                ZONE,
                "main",
                &self.head(),
                "main",
                (!remote.is_empty()).then_some(remote.as_str()),
                state,
                squash,
                None,
                AUTHOR,
                dry_run,
            )
        }

        fn sync_in(
            &self,
            state: &ZoneSyncMappingState,
            dry_run: bool,
        ) -> Result<ZoneSyncInResult, GitBridgeError> {
            apply_zone_sync_in(
                &self.canonical(),
                &self.staging,
                &self.policy,
                "fp-test",
                None,
                ZONE,
                "refs/heads/main",
                &self.staging_tip(),
                "main",
                Some(&self.head()),
                state,
                dry_run,
            )
        }

        /// A GitHub-side working clone of the staging repository.
        fn github_clone(&self, name: &str) -> PathBuf {
            let dir = self.tmp.path().join(name);
            git(
                self.tmp.path(),
                &["clone", "-q", self.staging.to_str().unwrap(), name],
            );
            git(&dir, &["config", "core.autocrlf", "false"]);
            dir
        }

        fn github_push(&self, clone: &Path) {
            git(clone, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        }

        fn files_at(dir: &Path, rev: &str) -> Vec<String> {
            git(dir, &["ls-tree", "-r", "--name-only", rev])
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    #[test]
    fn exportability_guards_fail_closed() {
        let policy = CompiledPolicy::compile(None, &parse_policy_toml(POLICY).unwrap()).unwrap();
        let guard = OverlayGuard::from_manifest(&OverlayManifest::default()).unwrap();
        let check = |zone, path| check_github_exportable(&policy, Some(&guard), zone, "main", path);

        assert!(is_control_plane_config_path(".access.toml"));
        assert!(is_control_plane_config_path("./.ENV.Schema"));
        assert!(is_control_plane_config_path("services/api/.access.toml"));
        assert!(!is_control_plane_config_path("access.toml"));

        use ExportHoldbackReason as R;
        assert_eq!(check(None, ".access.toml"), Err(R::ControlPlaneConfig));
        assert_eq!(check(None, ".env.schema"), Err(R::ControlPlaneConfig));
        assert_eq!(check(None, ".git/config"), Err(R::ReservedPath));
        assert_eq!(check(None, ".premier/state"), Err(R::ReservedPath));
        assert_eq!(check(None, "a//b"), Err(R::ReservedPath));
        assert_eq!(check(None, "AGENTS.local.md"), Err(R::OverlayExcluded));
        assert_eq!(check(None, "billing/key.txt"), Err(R::NotPublicReadable));
        assert_eq!(check(None, "docs/guide.md"), Ok(()));
        assert_eq!(check(ZONE, "sdk/lib.rs"), Ok(()));
        assert_eq!(check(ZONE, "README.md"), Ok(()));
        assert_eq!(
            check(ZONE, "docs/guide.md"),
            Err(R::OutsideZone("sdk".into()))
        );
        assert_eq!(
            check(ZONE, "sdk/internal/keys.rs"),
            Err(R::OutsideZone("sdk".into()))
        );
        // An unknown zone holds nothing.
        assert_eq!(
            check(Some("zone:nope"), "sdk/lib.rs"),
            Err(R::OutsideZone("nope".into()))
        );
        assert_eq!(
            R::OutsideZone("sdk".into()).describe(),
            "outside bound zone 'sdk'"
        );

        let hidden: HashSet<String> = ["billing/key.txt", "sdk/internal/keys.rs", ".access.toml"]
            .map(str::to_owned)
            .into();
        let inbound = |zone, path| {
            check_github_inbound_write(&policy, Some(&guard), zone, "main", path, &hidden)
        };
        assert_eq!(inbound(ZONE, "sdk/new.rs"), Ok(()));
        assert!(inbound(ZONE, ".access.toml").is_err());
        assert!(inbound(ZONE, "sdk/.env.schema").is_err());
        assert!(inbound(None, "billing/key.txt").is_err());
        assert!(inbound(ZONE, "docs/guide.md").is_err());
        // Write denied to the sync service by policy, although anonymous may read it.
        assert!(check(ZONE, "sdk/locked.txt").is_ok());
        assert!(
            inbound(ZONE, "sdk/locked.txt")
                .unwrap_err()
                .contains("policy")
        );
        // Case-insensitive collisions with hidden files: the file, a directory over it, a path
        // under it.
        for path in [
            "sdk/Internal/Keys.rs",
            "sdk/INTERNAL",
            "sdk/Internal/Keys.rs/x",
        ] {
            assert!(
                inbound(ZONE, path).unwrap_err().contains("collides"),
                "{path}"
            );
        }
        // `billing/**` deny rules also match case-insensitively at the policy layer.
        assert_eq!(check(None, "Billing/key.txt/x"), Err(R::NotPublicReadable));
        assert!(inbound(None, "Billing/key.txt/x").is_err());
    }

    #[test]
    fn github_pr_squashes_only_vetted_public_blobs_and_merges_with_upstream() {
        let fx = Fixture::new();
        let state = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap();
        let upstream_base = fx.staging_tip();
        let base_oid = fx.head();

        // Private feature work touching every kind of path.
        git(
            &fx.canonical_dir,
            &["checkout", "-q", "-b", "embargo-sdk-v2"],
        );
        let edited = LIB_RS.replace("line 1", "line 1 (feature)");
        let feature = commit(
            &fx.canonical_dir,
            &[
                ("sdk/lib.rs", &edited),
                ("sdk/new.rs", "pub fn added() {}\n"),
                (
                    "sdk/internal/keys.rs",
                    "pub const INTERNAL: &str = \"y\";\n",
                ),
                ("docs/guide.md", "Changed guide.\n"),
                ("billing/key.txt", "ROTATED BILLING KEY\n"),
                (".access.toml", "version = 1\n# changed\n"),
            ],
            "embargoed sdk v2 work",
        );
        git(&fx.canonical_dir, &["checkout", "-q", "main"]);

        let plan = plan_github_pr_squash(
            &fx.canonical(),
            &fx.policy,
            "fp-test",
            None,
            ZONE,
            "embargo-sdk-v2",
            &feature,
            "main",
            &base_oid,
            None,
            None,
            None,
        )
        .unwrap();
        assert!(plan.gate_passed, "{:?}", plan.reason);
        assert_eq!(plan.published_paths, ["sdk/lib.rs", "sdk/new.rs"]);
        assert_eq!(
            plan.scrubbed_paths,
            [
                ".access.toml",
                "billing/key.txt",
                "docs/guide.md",
                "sdk/internal/keys.rs"
            ]
        );
        assert_eq!(
            plan.held_back_reasons[".access.toml"],
            ExportHoldbackReason::ControlPlaneConfig.describe()
        );
        assert_eq!(
            plan.held_back_reasons["docs/guide.md"],
            "outside bound zone 'sdk'"
        );
        assert!(plan.pr_branch.starts_with("premier/declassify-"));
        assert_eq!(plan.pr_branch.len(), "premier/declassify-".len() + 8);
        assert_eq!(plan.pr_title, "Update sdk");
        assert_eq!(plan.scrubbed_metadata.omitted_paths_count, 4);
        assert_eq!(plan.scrubbed_metadata.commits_squashed, 1);
        for public_text in [&plan.pr_body, &plan.clean_commit_message, &plan.pr_branch] {
            assert!(!public_text.contains("embargo"), "{public_text}");
            assert!(!public_text.contains(&feature), "{public_text}");
            assert!(!public_text.contains("billing"), "{public_text}");
            assert!(!public_text.contains("access.toml"), "{public_text}");
        }
        assert!(plan.pr_body.contains(&plan.attestation_trailer));
        assert!(plan.attestation_trailer.contains("sig=unverified"));
        let added = plan.diffs.iter().find(|d| d.path == "sdk/new.rs").unwrap();
        assert_eq!((added.status.as_str(), added.additions), ("added", 1));
        assert!(
            added
                .patch
                .starts_with("--- /dev/null\n+++ b/sdk/new.rs\n@@")
        );
        let modified = plan.diffs.iter().find(|d| d.path == "sdk/lib.rs").unwrap();
        assert_eq!((modified.additions, modified.deletions), (1, 1));
        assert!(!plan.diff_truncated);

        // GitHub moved on meanwhile: a non-overlapping edit of the same file merges cleanly.
        let gh = fx.github_clone("gh");
        let theirs = LIB_RS.replace("line 7", "line 7 (github)");
        commit(
            &gh,
            &[("sdk/lib.rs", &theirs), ("CONTRIBUTING.md", "Be nice.\n")],
            "gh edit",
        );
        fx.github_push(&gh);
        let upstream_now = fx.staging_tip();
        assert_ne!(upstream_now, upstream_base);

        let pr = materialize_github_pr_in_staging(
            &fx.canonical(),
            &fx.staging,
            &fx.policy,
            "fp-test",
            None,
            ZONE,
            "embargo-sdk-v2",
            &feature,
            "main",
            &base_oid,
            Some(&upstream_now),
            "premier/sdk-v2",
            Some("SDK v2"),
            None,
            AUTHOR,
        )
        .unwrap();
        assert_eq!(pr.pr_branch, "premier/sdk-v2");
        assert_eq!(
            git(&fx.staging, &["rev-parse", "refs/heads/premier/sdk-v2"]),
            pr.public_commit_oid
        );
        // One commit, parented only on GitHub's tip.
        assert_eq!(
            git(
                &fx.staging,
                &["rev-list", "--parents", "-n", "1", &pr.public_commit_oid]
            ),
            format!("{} {upstream_now}", pr.public_commit_oid)
        );
        assert_eq!(
            Fixture::files_at(&fx.staging, &pr.public_commit_oid),
            ["CONTRIBUTING.md", "README.md", "sdk/lib.rs", "sdk/new.rs"]
        );
        let merged = git(
            &fx.staging,
            &["show", &format!("{}:sdk/lib.rs", pr.public_commit_oid)],
        );
        assert!(merged.contains("line 1 (feature)") && merged.contains("line 7 (github)"));
        let message = git(
            &fx.staging,
            &["log", "-1", "--format=%B", &pr.public_commit_oid],
        );
        assert!(message.starts_with("SDK v2\n"));
        assert!(message.contains("Premier-Projection-Attestation: v1:"));
        assert!(!message.contains(&feature) && !message.contains("embargo"));
        // No private object ever reached staging.
        for private in [
            "billing/key.txt",
            "docs/guide.md",
            "sdk/internal/keys.rs",
            ".access.toml",
        ] {
            for rev in [&feature, &base_oid] {
                let oid = git(
                    &fx.canonical_dir,
                    &["rev-parse", &format!("{rev}:{private}")],
                );
                assert!(!blob_in(&fx.staging, &oid), "{private} leaked into staging");
            }
        }
        assert!(!blob_in(&fx.staging, &feature));
        assert_eq!(
            state.updated_mapping.last_canonical_oid.as_deref(),
            Some(base_oid.as_str())
        );
    }

    #[test]
    fn github_pr_fails_closed_on_copies_and_overlapping_upstream_edits() {
        let fx = Fixture::new();
        fx.sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap();
        let base_oid = fx.head();
        let plan = |source: &str, oid: &str, zone| {
            plan_github_pr_squash(
                &fx.canonical(),
                &fx.policy,
                "fp",
                None,
                zone,
                source,
                oid,
                "main",
                &base_oid,
                None,
                None,
                None,
            )
        };
        let materialize = |source: &str, oid: &str, pr: &str| {
            materialize_github_pr_in_staging(
                &fx.canonical(),
                &fx.staging,
                &fx.policy,
                "fp",
                None,
                ZONE,
                source,
                oid,
                "main",
                &base_oid,
                Some(&fx.staging_tip()),
                pr,
                None,
                None,
                AUTHOR,
            )
        };

        // Copying held-back content (restricted, or merely outside the zone) into the zone.
        git(&fx.canonical_dir, &["checkout", "-q", "-b", "copy"]);
        let copy = commit(
            &fx.canonical_dir,
            &[
                ("sdk/leak.txt", "TOP SECRET BILLING KEY\n"),
                ("sdk/guide-copy.md", "Internal-facing public guide.\n"),
                ("sdk/ok.rs", "pub fn ok() {}\n"),
            ],
            "copy",
        );
        let copied = plan("copy", &copy, ZONE).unwrap();
        assert!(!copied.gate_passed);
        assert_eq!(copied.blocked, ["sdk/guide-copy.md", "sdk/leak.txt"]);
        assert!(matches!(
            materialize("copy", &copy, "pr-copy").unwrap_err(),
            GitBridgeError::PublishBlocked(_)
        ));

        // An unknown zone is refused outright.
        assert!(matches!(
            plan("copy", &copy, Some("zone:nope")),
            Err(GitBridgeError::Rejected(_))
        ));

        // GitHub edited the very line the feature edits.
        git(
            &fx.canonical_dir,
            &["checkout", "-q", "-b", "edit", &base_oid],
        );
        let edit = commit(
            &fx.canonical_dir,
            &[("sdk/lib.rs", &LIB_RS.replace("line 4", "line 4 (ours)"))],
            "edit",
        );
        let gh = fx.github_clone("gh");
        commit(
            &gh,
            &[("sdk/lib.rs", &LIB_RS.replace("line 4", "line 4 (theirs)"))],
            "gh",
        );
        fx.github_push(&gh);
        assert_eq!(
            materialize("edit", &edit, "pr-edit").unwrap_err(),
            GitBridgeError::PublishConflict(vec!["sdk/lib.rs".to_owned()])
        );
        assert!(git(&fx.staging, &["for-each-ref", "refs/heads/pr-edit"]).is_empty());
    }

    #[test]
    fn sync_out_collapses_private_only_commits_and_detects_divergence() {
        let fx = Fixture::new();
        let c1 = fx.head();
        let c2 = commit(
            &fx.canonical_dir,
            &[("billing/key.txt", "ROTATED\n")],
            "rotate billing key",
        );
        let c3 = commit(
            &fx.canonical_dir,
            &[("sdk/lib.rs", &LIB_RS.replace("line 2", "line 2!"))],
            "tweak sdk",
        );

        // A dry run writes nothing.
        let dry = fx
            .sync_out(&ZoneSyncMappingState::default(), false, true)
            .unwrap();
        assert_eq!((dry.commits_projected, dry.commits_collapsed), (2, 1));
        assert!(git(&fx.staging, &["for-each-ref", "refs/heads/main"]).is_empty());

        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), false, false)
            .unwrap();
        assert_eq!((out.commits_projected, out.commits_collapsed), (2, 1));
        assert_eq!(out.published_paths, ["README.md", "sdk/lib.rs"]);
        let tip = out.upstream_tip.clone().unwrap();
        assert_eq!(fx.staging_tip(), tip);
        assert_eq!(
            git(&fx.staging, &["log", "--format=%s|%an", &tip]),
            "tweak sdk|Alice\ninitial|Alice"
        );
        assert_eq!(
            Fixture::files_at(&fx.staging, &tip),
            ["README.md", "sdk/lib.rs"]
        );
        let mapping = &out.updated_mapping;
        assert_eq!(mapping.last_canonical_oid.as_deref(), Some(c3.as_str()));
        assert_eq!(mapping.last_upstream_oid.as_deref(), Some(tip.as_str()));
        assert_eq!(mapping.upstream_to_canonical[&tip], c3);
        // The private-only commit maps onto the projection of the one before it.
        let first_upstream = git(&fx.staging, &["rev-parse", &format!("{tip}^")]);
        assert_eq!(mapping.canonical_to_upstream[&c1], first_upstream);
        assert_eq!(mapping.canonical_to_upstream[&c2], first_upstream);

        // Nothing new: up to date. A private-only commit: still nothing to push.
        assert!(fx.sync_out(mapping, false, false).unwrap().up_to_date);
        let c4 = commit(
            &fx.canonical_dir,
            &[("billing/key.txt", "AGAIN\n")],
            "rotate again",
        );
        let quiet = fx.sync_out(mapping, false, false).unwrap();
        assert!(quiet.up_to_date);
        assert_eq!((quiet.commits_projected, quiet.commits_collapsed), (0, 1));
        assert_eq!(
            quiet.updated_mapping.last_canonical_oid.as_deref(),
            Some(c4.as_str())
        );
        assert_eq!(fx.staging_tip(), tip);

        // Copying private content onto a public path blocks the sync.
        commit(&fx.canonical_dir, &[("sdk/leak.txt", "AGAIN\n")], "leak");
        let state = quiet.updated_mapping;
        assert_eq!(
            fx.sync_out(&state, false, true).unwrap().blocked,
            ["sdk/leak.txt"]
        );
        assert_eq!(
            fx.sync_out(&state, false, false).unwrap_err(),
            GitBridgeError::PublishBlocked(vec!["sdk/leak.txt".to_owned()])
        );
        git(&fx.canonical_dir, &["reset", "-q", "--hard", "HEAD^"]);

        // GitHub moved since the last sync: sync-in first.
        let gh = fx.github_clone("gh");
        commit(&gh, &[("sdk/gh.rs", "// from github\n")], "gh");
        fx.github_push(&gh);
        let err = fx.sync_out(&state, false, false).unwrap_err();
        assert!(matches!(err, GitBridgeError::Rejected(m) if m.contains("diverged")));
    }

    #[test]
    fn squashed_sync_out_writes_one_attested_commit() {
        let fx = Fixture::new();
        commit(
            &fx.canonical_dir,
            &[("sdk/more.rs", "// more\n")],
            "more sdk",
        );
        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap();
        assert_eq!(out.commits_projected, 1);
        let tip = out.upstream_tip.unwrap();
        assert_eq!(git(&fx.staging, &["rev-list", "--count", &tip]), "1");
        let message = git(&fx.staging, &["log", "-1", "--format=%B", &tip]);
        assert!(message.starts_with("Sync sdk to main\n"));
        assert!(message.contains(&out.attestation_trailer));
        assert!(!message.contains(&fx.head()));
        assert_eq!(
            git(&fx.staging, &["log", "-1", "--format=%an <%ae>", &tip]),
            "Premier Bot <bot@premier.test>"
        );
        let unknown_zone = project_zone_sync_out(
            &fx.canonical(),
            &fx.staging,
            &fx.policy,
            "fp",
            None,
            Some("nope"),
            "main",
            &fx.head(),
            "main",
            None,
            &ZoneSyncMappingState::default(),
            true,
            None,
            AUTHOR,
            false,
        );
        assert!(matches!(unknown_zone, Err(GitBridgeError::Rejected(_))));
    }

    #[test]
    fn sync_in_imports_public_changes_and_preserves_hidden_files() {
        let fx = Fixture::new();
        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), false, false)
            .unwrap();
        let before = fx.head();
        let blob_at = |rev: &str, path: &str| {
            git(&fx.canonical_dir, &["rev-parse", &format!("{rev}:{path}")])
        };

        let gh = fx.github_clone("gh");
        git(&gh, &["config", "user.name", "Gina Hub"]);
        git(&gh, &["config", "user.email", "gina@github.test"]);
        let as_gina = |files: &[(&str, &str)], message: &str| {
            write(&gh, files);
            git(&gh, &["add", "-A"]);
            let out = Command::new("git")
                .current_dir(&gh)
                .args(["-c", "core.autocrlf=false", "commit", "-q", "-m", message])
                .status()
                .unwrap();
            assert!(out.success());
        };
        as_gina(&[("sdk/contrib.rs", "// contributed\n")], "add contrib");
        as_gina(
            &[("sdk/lib.rs", &LIB_RS.replace("line 3", "line 3 (gh)"))],
            "fix lib",
        );
        fx.github_push(&gh);

        // Without a mapping, the base is found by tree: same result.
        for state in [out.updated_mapping.clone(), ZoneSyncMappingState::default()] {
            let dry = fx.sync_in(&state, true).unwrap();
            assert_eq!(dry.commits_imported, 2);
            assert!(dry.new_canonical_tip.is_none());
            assert_eq!(fx.head(), before);
        }
        let res = fx.sync_in(&out.updated_mapping, false).unwrap();
        assert!(res.policy_violations.is_empty() && res.conflicts.is_empty());
        assert_eq!(res.commits_imported, 2);
        assert_eq!(res.imported_paths, ["sdk/contrib.rs", "sdk/lib.rs"]);
        assert_eq!(res.preserved_hidden_count, 4);
        let new_tip = res.new_canonical_tip.clone().unwrap();
        assert_eq!(
            git(&fx.canonical_dir, &["rev-parse", "refs/heads/main"]),
            new_tip
        );
        assert_eq!(
            git(
                &fx.canonical_dir,
                &["log", "-2", "--format=%s|%an", &new_tip]
            ),
            "fix lib|Gina Hub\nadd contrib|Gina Hub"
        );
        for path in [
            "billing/key.txt",
            ".access.toml",
            "docs/guide.md",
            "sdk/internal/keys.rs",
        ] {
            assert_eq!(blob_at(&new_tip, path), blob_at(&before, path));
        }
        assert!(
            git(
                &fx.canonical_dir,
                &["show", &format!("{new_tip}:sdk/lib.rs")]
            )
            .contains("line 3 (gh)")
        );

        // Round trip: GitHub already has all of it.
        let back = fx.sync_out(&res.updated_mapping, false, false).unwrap();
        assert!(back.up_to_date, "{back:?}");
        assert!(fx.sync_in(&res.updated_mapping, false).unwrap().up_to_date);
    }

    #[test]
    fn sync_in_refuses_policy_violations_atomically() {
        let fx = Fixture::new();
        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap();
        let before = fx.head();

        let gh = fx.github_clone("gh");
        commit(&gh, &[("sdk/fine.rs", "// fine\n")], "fine");
        write(
            &gh,
            &[
                (
                    ".access.toml",
                    "version = 1\n[defaults]\npublic = [\"*\"]\n",
                ),
                ("sdk/locked.txt", "overwrite\n"),
                ("sdk/internal/new.rs", "outside zone\n"),
            ],
        );
        git(
            &gh,
            &[
                "add",
                ".access.toml",
                "sdk/locked.txt",
                "sdk/internal/new.rs",
            ],
        );
        let scratch = fx.tmp.path().join("scratch-blob");
        // Exact spellings a case-insensitive filesystem would not keep, and a symbolic link
        // escaping the repository, staged without touching the filesystem.
        stage_entry(&gh, &scratch, "sdk/Internal/Keys.rs", "100644", "shadow\n");
        stage_entry(&gh, &scratch, "sdk/link", "120000", "../../../etc/passwd");
        git(&gh, &["commit", "-q", "-m", "sneaky"]);
        fx.github_push(&gh);

        let res = fx.sync_in(&out.updated_mapping, false).unwrap();
        assert!(res.new_canonical_tip.is_none());
        let mut refused: Vec<&str> = res
            .policy_violations
            .iter()
            .map(|v| v.path.as_str())
            .collect();
        refused.sort_unstable();
        assert_eq!(
            refused,
            [
                ".access.toml",
                "sdk/Internal/Keys.rs",
                "sdk/internal/new.rs",
                "sdk/link",
                "sdk/locked.txt"
            ]
        );
        // Atomic: not even the fine commit landed.
        assert_eq!(fx.head(), before);
        assert_eq!(res.updated_mapping, out.updated_mapping);
    }

    #[test]
    fn sync_in_merges_concurrent_canonical_edits_or_reports_conflicts() {
        let fx = Fixture::new();
        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), false, false)
            .unwrap();
        commit(
            &fx.canonical_dir,
            &[(
                "sdk/lib.rs",
                &LIB_RS.replace("line 1", "line 1 (canonical)"),
            )],
            "canonical edit",
        );
        let gh = fx.github_clone("gh");
        commit(
            &gh,
            &[("sdk/lib.rs", &LIB_RS.replace("line 7", "line 7 (gh)"))],
            "gh edit",
        );
        fx.github_push(&gh);

        let res = fx.sync_in(&out.updated_mapping, false).unwrap();
        let tip = res.new_canonical_tip.unwrap();
        let lib = git(&fx.canonical_dir, &["show", &format!("{tip}:sdk/lib.rs")]) + "\n";
        assert!(lib.contains("line 1 (canonical)") && lib.contains("line 7 (gh)"));

        // Both sides edit the same line next: a conflict, nothing written.
        let state = res.updated_mapping;
        let before = commit(
            &fx.canonical_dir,
            &[("sdk/lib.rs", &lib.replace("line 4", "line 4 (canonical)"))],
            "canonical again",
        );
        commit(
            &gh,
            &[(
                "sdk/lib.rs",
                &LIB_RS
                    .replace("line 7", "line 7 (gh)")
                    .replace("line 4", "line 4 (gh)"),
            )],
            "gh again",
        );
        fx.github_push(&gh);
        let res = fx.sync_in(&state, false).unwrap();
        assert_eq!(res.conflicts, ["sdk/lib.rs"]);
        assert!(res.new_canonical_tip.is_none());
        assert_eq!(fx.head(), before);
    }

    #[test]
    fn ntfs_hfs_control_plane_config_checks_and_oid_redaction() {
        for blocked in [
            ".access.toml::$DATA",
            ".ACCESS.TOML.",
            "sub/.Env.Schema   ",
            "ACCE~1.TOM",
            "ENVSCH~1.SCH",
            ".access.toml/nested.txt",
            ".\u{200c}access.toml",
        ] {
            assert!(is_control_plane_config_path(blocked), "{blocked}");
        }
        assert!(!is_control_plane_config_path("access.toml"));
        assert!(!is_control_plane_config_path("sdk/readme.md"));

        let oid1 = "0123456789abcdef0123456789abcdef01234567";
        let oid2 = "fedcba9876543210fedcba9876543210fedcba98";
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let scrubbed = scrub_public_commit_message(
            &format!(
                "Fix widget ({sha256})\n\nThis reverts commit {oid1}.\n(cherry picked from commit {oid2})\ncommit {oid1}\nSquashed commit of the following:\nKeep line\n"
            ),
            1,
            "main",
        );
        assert!(!scrubbed.contains(oid1));
        assert!(!scrubbed.contains(oid2));
        assert!(!scrubbed.contains(sha256));
        assert!(scrubbed.contains("Fix widget ([redacted-oid])"));
        assert!(scrubbed.contains("Keep line"));
        assert_eq!(
            scrub_public_commit_message("Merge branch 'embargo' into main", 2, "main"),
            "Merge changes into main\n"
        );
    }

    #[test]
    fn non_squash_sync_out_scrubs_oids_reverts_cherry_picks_and_merges() {
        let fx = Fixture::new();
        let leaked_oid = "0123456789abcdef0123456789abcdef01234567";
        let picked_oid = "fedcba9876543210fedcba9876543210fedcba98";
        commit(
            &fx.canonical_dir,
            &[("sdk/lib.rs", &LIB_RS.replace("line 1", "line 1!"))],
            &format!(
                "Update widget\n\nThis reverts commit {leaked_oid}.\n(cherry picked from commit {picked_oid})\nFollow-up to {leaked_oid}\n"
            ),
        );

        git(
            &fx.canonical_dir,
            &["checkout", "-q", "-b", "secret-embargo-branch"],
        );
        commit(
            &fx.canonical_dir,
            &[("README.md", "# Updated\n")],
            "prep embargo",
        );
        git(&fx.canonical_dir, &["checkout", "-q", "main"]);
        git(
            &fx.canonical_dir,
            &[
                "merge",
                "--no-ff",
                "-m",
                "Merge branch 'secret-embargo-branch' into main",
                "secret-embargo-branch",
            ],
        );

        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), false, false)
            .unwrap();
        let tip = out.upstream_tip.unwrap();
        let all_msgs = git(&fx.staging, &["log", "--format=%B", &tip]);
        assert!(!all_msgs.contains(leaked_oid), "{all_msgs}");
        assert!(!all_msgs.contains(picked_oid), "{all_msgs}");
        assert!(!all_msgs.contains("secret-embargo-branch"), "{all_msgs}");
        assert!(all_msgs.contains("Merge changes into main"), "{all_msgs}");
        assert!(
            all_msgs.contains("Follow-up to [redacted-oid]"),
            "{all_msgs}"
        );
    }

    #[test]
    fn sync_in_reconnect_reanchors_tree_matched_cursor_and_republishes_cleanly() {
        let fx = Fixture::new();
        let c1 = fx.head();
        let out1 = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap();
        let u1 = out1.upstream_tip.unwrap();

        // Simulate canonical advancing after disconnect with empty mapping state.
        let c2 = commit(
            &fx.canonical_dir,
            &[(
                "sdk/lib.rs",
                &LIB_RS.replace("line 2", "line 2 (post-disconnect)"),
            )],
            "canonical moved",
        );
        // Before re-anchoring, sync-out sees upstream history not in empty mapping.
        let err = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap_err();
        assert!(matches!(err, GitBridgeError::Rejected(m) if m.contains("sync-in first")));

        let reanchored = fx.sync_in(&ZoneSyncMappingState::default(), false).unwrap();
        assert!(reanchored.up_to_date);
        assert!(reanchored.new_canonical_tip.is_none());
        assert_eq!(
            reanchored.updated_mapping.last_upstream_oid.as_deref(),
            Some(u1.as_str())
        );
        assert_eq!(
            reanchored.updated_mapping.last_canonical_oid.as_deref(),
            Some(c1.as_str())
        );

        let out2 = fx
            .sync_out(&reanchored.updated_mapping, true, false)
            .unwrap();
        assert!(!out2.up_to_date);
        assert_eq!(
            out2.updated_mapping.last_canonical_oid.as_deref(),
            Some(c2.as_str())
        );

        // If GitHub loses the target branch, republish rebuilds cleanly from canonical.
        git(&fx.staging, &["update-ref", "-d", "refs/heads/main"]);
        let rebuilt = fx.sync_out(&out2.updated_mapping, true, false).unwrap();
        assert!(!rebuilt.up_to_date);
        assert_eq!(fx.staging_tip(), rebuilt.upstream_tip.unwrap());
    }

    #[test]
    fn squashed_first_sync_out_blocks_copyfrom_even_if_private_file_deleted() {
        let fx = Fixture::new();
        git(&fx.canonical_dir, &["rm", "-q", "billing/key.txt"]);
        git(&fx.canonical_dir, &["commit", "-q", "-m", "drop key"]);
        commit(
            &fx.canonical_dir,
            &[("sdk/leak.txt", "TOP SECRET BILLING KEY\n")],
            "re-introduce deleted secret",
        );
        let err = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap_err();
        assert_eq!(
            err,
            GitBridgeError::PublishBlocked(vec!["sdk/leak.txt".to_owned()])
        );
    }

    #[test]
    fn sync_in_refuses_public_case_collisions_atomically() {
        let fx = Fixture::new();
        let out = fx
            .sync_out(&ZoneSyncMappingState::default(), true, false)
            .unwrap();
        let before = fx.head();

        let gh = fx.github_clone("gh");
        let scratch = fx.tmp.path().join("scratch-case");
        stage_entry(&gh, &scratch, "sdk/Lib.rs", "100644", "case collision\n");
        git(&gh, &["commit", "-q", "-m", "colliding lib.rs"]);
        fx.github_push(&gh);

        let res = fx.sync_in(&out.updated_mapping, false).unwrap();
        assert!(res.new_canonical_tip.is_none());
        assert!(
            res.policy_violations
                .iter()
                .any(|v| v.path == "sdk/Lib.rs" && v.reason.contains("collides")),
            "{:?}",
            res.policy_violations
        );
        assert_eq!(fx.head(), before);
    }
}
