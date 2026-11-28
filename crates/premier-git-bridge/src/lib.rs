//! `premier-git-bridge` — Pure-Rust Reversible Projected Git Bridge, Smart HTTP v2 transport,
//! Anti-CFOR reachability isolation, Projection Attestations, and Squash-Declassify Gate.

pub mod companion;
pub mod http_v2;
pub mod lanes;
pub mod objects;
pub mod projector;
pub mod receive_pack;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod security_tests;

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use premier_core::Visibility;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use companion::{
    ExportHoldbackReason, GithubPrSquashPlan, InboundPolicyViolation, MaterializedGithubPr,
    ProjectedFileDiff, ScrubbedMetadataSummary, ZoneSyncInResult, ZoneSyncMappingState,
    ZoneSyncOutResult, apply_zone_sync_in, check_github_exportable, check_github_inbound_write,
    is_control_plane_config_path, materialize_github_pr_in_staging, plan_github_pr_squash,
    project_zone_sync_out,
};
pub use http_v2::{handle_upload_pack_v2, render_info_refs_v2};
pub use lanes::{
    CommitInterdiff, ConflictHunk, InterdiffEntry, LaneConflict, LaneFileChange, RebaseApplyResult,
    RebasePlan, compute_commit_interdiff, create_lane_snapshot_commit, diff_commits_to_changes,
    execute_three_way_rebase, merge_file_diff3, parse_diff3_conflicts, plan_three_way_rebase,
};
pub use objects::{
    CanonicalGitRepo, CommitObj, GitObject, GitObjectKind, InMemoryOdb, ObjectReader, TreeEntry,
    encode_packfile, encode_tree, git_command, hash_git_object, parse_tree, rewrite_commit,
};
pub use projector::{
    OWNERS_SELECTOR, ProjectedView, SquashDeclassifyResult, SquashFirewallInput, SquashPlan,
    can_see_ref, collect_reachable_objects, default_ref_visibility, execute_squash_declassify,
    execute_squash_declassify_with_firewall, exposes_hidden_files, new_branch_visibility,
    path_is_projected, plan_squash_declassify, project_commit_tree_for_workspace,
    project_repository, publish_commit_message, publishable, scan_squash_declassify, tip_is_served,
};
pub use receive_pack::{
    AcceptedRefUpdate, MAX_CONCURRENT_PUSHES, ProtectedFiles, REJECT_REF, ReceivePackFirewall,
    ReceivePackResult, handle_receive_pack, handle_receive_pack_with_firewall,
    render_receive_pack_refs, unpack_packfile,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GitBridgeError {
    /// Deliberately indistinguishable error returned for unauthorized or nonexistent OIDs
    /// to eliminate Git `have`/ACK and `allow*SHA1InWant` existence oracles.
    #[error("object not found in authorized scope")]
    ObjectNotVisible,

    #[error("cross-boundary declassification requires zone owner approval for path '{path}'")]
    DeclassificationApprovalRequired { path: String },

    #[error("overlay exclusion guard blocked public commit: {0}")]
    OverlayLeak(String),

    /// A publish would overwrite these paths, changed on the target since the branches forked.
    #[error("publish conflicts with changes on the target branch in {}", plural(.0.len(), "path"))]
    PublishConflict(Vec<String>),

    /// A publish would put the content of a file the public may not read on these public paths.
    #[error("publish would expose restricted content in {}", plural(.0.len(), "path"))]
    PublishBlocked(Vec<String>),

    /// The target branch was not where the publish expected it (lost compare-and-swap).
    #[error("the target branch moved while publishing: reload and try again")]
    RefMoved,

    /// The caller's check refused the commit before any ref moved.
    #[error("{0}")]
    Rejected(String),

    /// The declassification firewall refused a publish. The report is the full (owner) view:
    /// a caller answering a non-owner redacts it first.
    #[error("declassification firewall blocked operation ({} blocking finding(s))", .0.blocking_count)]
    FirewallBlocked(Box<premier_policy::DeclassificationReport>),

    #[error("git object error: {0}")]
    GitObject(String),

    #[error("git protocol error: {0}")]
    Protocol(String),

    #[error("I/O error: {0}")]
    Io(String),
}

/// A count for people to read: `1 path`, `2 paths`.
pub fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Unicode characters ignored by HFS+ / APFS or invisible in path components.
pub(crate) fn is_ignorable_path_char(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
    )
}

/// Normalize a single path component the way HFS+ and NTFS resolve it: strip ignorable characters,
/// lowercase, drop any NTFS Alternate Data Stream (`:stream`) suffix, and trim trailing dots/spaces.
pub(crate) fn fold_path_component(name: &str) -> String {
    let folded: String = name
        .chars()
        .filter(|c| !is_ignorable_path_char(*c))
        .flat_map(char::to_lowercase)
        .collect();
    folded
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches(['.', ' '])
        .to_owned()
}

fn is_ntfs_hash_stem(stem: &str, prefix: &str) -> bool {
    stem.len() == 6
        && stem.starts_with(prefix)
        && stem.as_bytes()[2..].iter().all(|b| b.is_ascii_hexdigit())
}

/// Whether a single path component (one tree entry name) may never be written by a push, a
/// publish or a server-made commit: the server's own state directories, `.git`, and every
/// spelling a case-insensitive, NTFS or HFS+ working tree resolves to one of them (the checks of
/// `git fsck`: case, trailing dots and spaces, 8.3 short names, `name:stream`, HFS-ignorable
/// code points). A name with a backslash, a NUL or another control character, or ending in a dot
/// or a space, is refused outright: Windows does not keep it as written.
pub fn is_reserved_path_component(name: &str) -> bool {
    if name.is_empty()
        || name.ends_with(['.', ' '])
        || name.chars().any(|c| c == '\\' || c.is_control())
    {
        return true;
    }
    let base = fold_path_component(name);
    if base.is_empty() {
        return true;
    }
    matches!(base.as_str(), ".git" | ".premier" | ".premier-local")
        // 8.3 short names of the above (`GIT~1`, `GI7EBA~1`, `PREMIE~1`, `PREMIE~1.LOC`).
        || base.split_once('~').is_some_and(|(stem, suffix)| {
            let digits = suffix.split('.').next().unwrap_or("");
            let short_alias = matches!(stem, "git" | "premie")
                || is_ntfs_hash_stem(stem, "gi")
                || is_ntfs_hash_stem(stem, "pr");
            short_alias && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Whether a path component resolves to a control-plane or Git configuration file
/// (`.access.toml`, `.env.schema`, `.gitmodules`), including case, NTFS `:stream`, trailing
/// dots/spaces, HFS+ ignorable characters, and Windows 8.3 short names.
pub(crate) fn is_config_or_gitmodules_component(name: &str) -> bool {
    let base = fold_path_component(name);
    if matches!(
        base.as_str(),
        ".access.toml" | ".env.schema" | ".gitmodules"
    ) {
        return true;
    }
    if let Some((stem_tilde, ext)) = base.rsplit_once('.')
        && let Some((stem, digits)) = stem_tilde.split_once('~')
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
    {
        return matches!(
            (stem, ext),
            ("acce" | "acces" | "access" | ".acces", "tom" | "toml")
                | (
                    "env" | "envs" | "envsch" | ".envsc",
                    "sch" | "schem" | "schema"
                )
        ) || (is_ntfs_hash_stem(stem, "ac") && matches!(ext, "tom" | "toml"))
            || (is_ntfs_hash_stem(stem, "en") && matches!(ext, "sch" | "schem" | "schema"));
    }
    if let Some((stem, suffix)) = base.split_once('~') {
        let digits = suffix.split('.').next().unwrap_or("");
        if !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (matches!(stem, "gitmod" | ".gitmo") || is_ntfs_hash_stem(stem, "gi"))
        {
            return true;
        }
    }
    false
}

/// Strictly validate and resolve a Git symbolic link (`120000`) at `link_path` pointing to `target`.
///
/// Rejects non-UTF-8/empty targets, control characters, Unix absolute paths (`/`), Windows drive /
/// UNC / ADS paths (`\`, `:`), `..` escaping the repository root, targets resolving to the
/// repository root, and any component matching reserved or configuration names (`.git`, `.premier`,
/// `.premier-local`, `.access.toml`, `.env.schema`, `.gitmodules` and their filesystem aliases).
pub fn resolve_safe_symlink_target(link_path: &str, target: &[u8]) -> Result<String, &'static str> {
    let target = std::str::from_utf8(target).map_err(|_| "symlink target is not valid UTF-8")?;
    if target.is_empty() {
        return Err("symlink target must not be empty");
    }
    if target.starts_with('/') {
        return Err("absolute symlink targets are not allowed");
    }
    if target.ends_with('/')
        || target == "."
        || target.ends_with("/.")
        || target == ".."
        || target.ends_with("/..")
    {
        return Err("symlink target must name a leaf entry, not a directory alias");
    }
    if target
        .chars()
        .any(|c| c == '\\' || c == ':' || c.is_control())
    {
        return Err("symlink target contains forbidden path characters");
    }
    let mut parts: Vec<&str> = link_path.split('/').collect();
    parts.pop();
    for seg in target.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err("symlink target escapes repository root");
                }
            }
            name => {
                if is_reserved_path_component(name) || is_config_or_gitmodules_component(name) {
                    return Err("symlink target references a reserved or protected path");
                }
                parts.push(name);
            }
        }
    }
    if parts.is_empty() {
        return Err("symlink target resolves to repository root");
    }
    if parts
        .iter()
        .any(|name| is_reserved_path_component(name) || is_config_or_gitmodules_component(name))
    {
        return Err("symlink target references a reserved or protected path");
    }
    Ok(parts.join("/"))
}

/// Namespace of branches that are not public (the on-disk ref format).
pub const PRIVATE_REF_PREFIX: &str = "refs/premier-private/";

/// Namespace of agent lane snapshots: server-internal, never listed by
/// [`CanonicalGitRepo::list_refs`], so never advertised over Git or projected into a view.
pub const LANE_REF_PREFIX: &str = "refs/premier-lanes/";

/// Domain-separation tag of [`ProjectionAttestation`] commitments.
const ATTESTATION_TAG: &[u8] = b"premier-projection-attestation-v1:";

/// Isolated visibility scope identifier (prevents Cross-Fork Object Reference / CFOR leaks).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ScopeId(pub String);

/// Statement tying a projected commit to its canonical one. Served out-of-band
/// ([`ProjectedView::attestation`]), never written into a projected commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionAttestation {
    pub version: u8,
    pub canonical_commit_commitment: String,
    pub policy_fingerprint: String,
    pub original_signature_verified: bool,
    pub issued_at: DateTime<Utc>,
}

impl ProjectionAttestation {
    /// Deterministic commitment tying projected commit back to canonical commit without leaking raw OIDs.
    pub fn build(
        canonical_oid: &str,
        policy_fingerprint: &str,
        original_signature_verified: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ATTESTATION_TAG);
        hasher.update(canonical_oid.as_bytes());
        hasher.update(b":");
        hasher.update(policy_fingerprint.as_bytes());
        Self {
            version: 1,
            canonical_commit_commitment: hex::encode(hasher.finalize()),
            policy_fingerprint: policy_fingerprint.to_owned(),
            original_signature_verified,
            issued_at: Utc::now(),
        }
    }

    pub fn to_git_trailer(&self) -> String {
        format!(
            "Premier-Projection-Attestation: v1:{}:{}:sig={}",
            self.canonical_commit_commitment,
            self.policy_fingerprint,
            if self.original_signature_verified {
                "verified"
            } else {
                "unverified"
            }
        )
    }
}

/// Per-scope OID reachability ledger enforcing strict anti-CFOR isolation.
///
/// Guarantees that a caller in `scope_a` can never probe (`have`/ACK) or fetch (`want`)
/// an object reachable only from `scope_b` (such as a private branch on a public repo).
#[derive(Debug, Default, Clone)]
pub struct ScopeReachabilityLedger {
    scopes: HashMap<ScopeId, HashSet<String>>,
    ref_visibility: HashMap<String, Visibility>,
}

impl ScopeReachabilityLedger {
    fn retained_bytes(&self) -> usize {
        projector::hash_table_bytes::<ScopeId, HashSet<String>>(self.scopes.capacity())
            + self
                .scopes
                .iter()
                .map(|(scope, oids)| {
                    scope.0.capacity()
                        + projector::hash_table_bytes::<String, ()>(oids.capacity())
                        + oids.iter().map(String::capacity).sum::<usize>()
                })
                .sum::<usize>()
            + projector::hash_table_bytes::<String, Visibility>(self.ref_visibility.capacity())
            + self
                .ref_visibility
                .iter()
                .map(|(name, visibility)| name.capacity() + projector::visibility_bytes(visibility))
                .sum::<usize>()
    }

    pub fn register_oid(&mut self, scope: ScopeId, oid: impl Into<String>) {
        self.scopes.entry(scope).or_default().insert(oid.into());
    }

    pub fn set_ref_visibility(&mut self, ref_name: impl Into<String>, visibility: Visibility) {
        self.ref_visibility.insert(ref_name.into(), visibility);
    }

    /// Strict anti-oracle check: returns `Err(ObjectNotVisible)` identically whether
    /// `oid` does not exist OR exists only in another scope.
    pub fn require_oid_in_scope(&self, scope: &ScopeId, oid: &str) -> Result<(), GitBridgeError> {
        let visible = self
            .scopes
            .get(scope)
            .is_some_and(|oids| oids.contains(oid));
        if visible {
            Ok(())
        } else {
            Err(GitBridgeError::ObjectNotVisible)
        }
    }

    /// Neutral `have` negotiation filter: only acknowledges OIDs strictly inside the caller's scope.
    pub fn filter_negotiated_haves<'a>(
        &self,
        scope: &ScopeId,
        client_haves: &'a [String],
    ) -> Vec<&'a str> {
        let Some(allowed) = self.scopes.get(scope) else {
            return Vec::new();
        };
        client_haves
            .iter()
            .filter(|oid| allowed.contains(oid.as_str()))
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use premier_core::{DelegatedIdentity, Principal};
    use premier_overlay::{OverlayGuard, OverlayManifest};
    use premier_policy::{CompiledPolicy, parse_policy_toml};

    use super::*;

    #[test]
    fn git_never_answers_for_an_enclosing_repository() {
        let tmp = tempfile::tempdir().unwrap();
        run_git(tmp.path(), &["init", "-q"]);
        let inner = tmp.path().join("lost-its-git");
        std::fs::create_dir(&inner).unwrap();
        let found = |dir: &Path| {
            let out = git_command(dir)
                .args(["rev-parse", "--git-dir"])
                .output()
                .unwrap();
            out.status.success()
        };
        assert!(found(tmp.path()));
        assert!(!found(&inner));
    }

    fn run_git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(dir)
            .env("GIT_AUTHOR_NAME", "Alice")
            .env("GIT_AUTHOR_EMAIL", "alice@acme.test")
            .env("GIT_COMMITTER_NAME", "Alice")
            .env("GIT_COMMITTER_EMAIL", "alice@acme.test")
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    fn multiple_refs_keep_single_ref_oids_and_share_history() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        run_git(dir, &["init", "-q", "-b", "main"]);
        std::fs::write(dir.join("one.txt"), "shared blob").unwrap();
        run_git(dir, &["add", "."]);
        run_git(dir, &["commit", "-qm", "shared"]);
        run_git(dir, &["branch", "second"]);
        std::fs::write(dir.join("two.txt"), "shared blob").unwrap();
        run_git(dir, &["add", "."]);
        run_git(dir, &["commit", "-qm", "main tip"]);
        let repo = CanonicalGitRepo::open(dir);
        let policy = CompiledPolicy::compile(
            None,
            &parse_policy_toml("version = 1\n[defaults]\npublic = ['read', 'list', 'traverse']")
                .unwrap(),
        )
        .unwrap();
        let identity = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let shared =
            project_repository(&repo, &policy, "test", &identity, &HashMap::new()).unwrap();
        for (name, hidden) in [("main", "second"), ("second", "main")] {
            let visibility = HashMap::from([(hidden.to_owned(), Visibility::Org)]);
            let standalone =
                project_repository(&repo, &policy, "test", &identity, &visibility).unwrap();
            let name = format!("refs/heads/{name}");
            assert_eq!(standalone.refs[&name], shared.refs[&name]);
            let wants = [shared.refs[&name].clone()];
            let single = collect_reachable_objects(&standalone, &wants, &[]).unwrap();
            let combined = collect_reachable_objects(&shared, &wants, &[]).unwrap();
            assert_eq!(
                encode_packfile(&single).unwrap(),
                encode_packfile(&combined).unwrap()
            );
        }
        assert_eq!(
            shared
                .odb
                .iter()
                .filter(|obj| obj.kind == GitObjectKind::Blob)
                .count(),
            1
        );
        assert_eq!(
            shared
                .odb
                .iter()
                .filter(|obj| obj.kind == GitObjectKind::Commit)
                .count(),
            2
        );
        assert_eq!(shared.projected_commit_count, 2);
    }

    #[test]
    fn two_repositories_with_the_same_commits_do_not_share_a_projection() {
        let tmp = tempfile::tempdir().unwrap();
        // Same content, author and dates: the same commit id, so the same refs, in both.
        let repo = |name: &str| {
            let dir = tmp.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            run_git(&dir, &["init", "-q", "-b", "main"]);
            std::fs::write(dir.join("README.md"), "# Same\n").unwrap();
            run_git(&dir, &["add", "."]);
            let date = "1732200000 +0000";
            let done = Command::new("git")
                .current_dir(&dir)
                .args([
                    "-c",
                    "user.name=A",
                    "-c",
                    "user.email=a@acme.test",
                    "commit",
                    "-q",
                    "-m",
                    "same",
                ])
                .env("GIT_AUTHOR_DATE", date)
                .env("GIT_COMMITTER_DATE", date)
                .status()
                .unwrap();
            assert!(done.success());
            CanonicalGitRepo::open(&dir)
        };
        let (one, two) = (repo("one"), repo("two"));
        assert_eq!(one.list_refs().unwrap(), two.list_refs().unwrap());

        let file = parse_policy_toml(
            "version = 1\n[defaults]\npublic = [\"traverse\", \"list\", \"read\"]\n",
        );
        let policy = CompiledPolicy::compile(None, &file.unwrap()).unwrap();
        let anon = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let view = |repo: &CanonicalGitRepo| {
            project_repository(repo, &policy, "fp", &anon, &HashMap::new()).unwrap()
        };
        let (first, second) = (view(&one), view(&two));
        assert!(first.refs.contains_key("refs/heads/main"));
        // Everything but the repository is equal: the cache must still tell them apart.
        assert!(!std::sync::Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn anti_cfor_and_have_oracle_isolation() {
        let mut ledger = ScopeReachabilityLedger::default();
        let public_scope = ScopeId("public".to_owned());
        let private_scope = ScopeId("branch:launch-v3".to_owned());

        ledger.register_oid(public_scope.clone(), "aaa111");
        ledger.register_oid(private_scope.clone(), "bbb222");

        let err_private = ledger
            .require_oid_in_scope(&public_scope, "bbb222")
            .unwrap_err();
        let err_missing = ledger
            .require_oid_in_scope(&public_scope, "zzz999")
            .unwrap_err();
        assert_eq!(err_private, err_missing);

        let haves = [
            "aaa111".to_owned(),
            "bbb222".to_owned(),
            "zzz999".to_owned(),
        ];
        let acks = ledger.filter_negotiated_haves(&public_scope, &haves);
        assert_eq!(acks, vec!["aaa111"]);
    }

    #[test]
    fn projected_repo_and_squash_declassify_eliminate_restricted_paths_and_pass_fsck() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("canonical");
        std::fs::create_dir_all(repo_dir.join("billing/ledger")).unwrap();
        std::fs::create_dir_all(repo_dir.join("apps/web")).unwrap();

        run_git(&repo_dir, &["init", "-b", "main"]);
        std::fs::write(repo_dir.join("README.md"), "# Public Readme\n").unwrap();
        std::fs::write(repo_dir.join("apps/web/app.ts"), "export const v = 1;\n").unwrap();
        std::fs::write(
            repo_dir.join("billing/ledger/tx.rs"),
            "pub fn charge() { /* billing secret logic */ }\n",
        )
        .unwrap();
        std::fs::write(
            repo_dir.join("billing/ledger/master.key"),
            "TOP_SECRET_MASTER_KEY\n",
        )
        .unwrap();

        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "initial canonical commit"]);
        let main_oid = run_git(&repo_dir, &["rev-parse", "HEAD"]);

        // Create an embargoed private branch with both public & private changes.
        run_git(&repo_dir, &["checkout", "-b", "launch-v3-embargo"]);
        std::fs::write(repo_dir.join("apps/web/app.ts"), "export const v = 3;\n").unwrap();
        std::fs::write(
            repo_dir.join("billing/ledger/tx.rs"),
            "pub fn charge() { /* v3 embargoed */ }\n",
        )
        .unwrap();
        run_git(&repo_dir, &["add", "."]);
        run_git(&repo_dir, &["commit", "-m", "embargoed v3 launch work"]);
        let embargo_oid = run_git(&repo_dir, &["rev-parse", "HEAD"]);
        run_git(&repo_dir, &["checkout", "main"]);

        let repo_policy = parse_policy_toml(
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
        let server_policy = parse_policy_toml(
            r#"
version = 1
[[rules]]
id = "server-allow-billing-ledger"
effect = "allow"
principals = ["group:billing"]
paths = ["billing/ledger/**"]
capabilities = ["traverse", "list", "read", "write"]
[[rules]]
id = "server-hard-deny-master-key"
effect = "deny"
principals = ["*"]
paths = ["billing/ledger/master.key"]
capabilities = ["traverse", "list", "read", "write", "use"]
"#,
        )
        .unwrap();
        let compiled = CompiledPolicy::compile(Some(&server_policy), &repo_policy).unwrap();

        let mut vis_map = HashMap::new();
        vis_map.insert("main".to_owned(), Visibility::Public);
        vis_map.insert(
            "launch-v3-embargo".to_owned(),
            Visibility::Restricted(vec!["@alice".to_owned()]),
        );

        let canonical = CanonicalGitRepo::open(&repo_dir);

        // 1. Project for anonymous external caller.
        let anon_id = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let anon_view =
            project_repository(&canonical, &compiled, "fp123456", &anon_id, &vis_map).unwrap();

        // Anonymous MUST NOT see private branch!
        assert!(anon_view.refs.contains_key("refs/heads/main"));
        assert!(!anon_view.refs.contains_key("refs/heads/launch-v3-embargo"));

        // Inspect projected root tree for anonymous: ZERO `billing` entry!
        let anon_main_oid = &anon_view.refs["refs/heads/main"];
        let anon_commit =
            CommitObj::parse(&anon_view.odb.get(anon_main_oid).unwrap().data).unwrap();
        // The projection adds nothing to a commit; its attestation is out-of-band.
        assert_eq!(anon_commit.message.trim(), "initial canonical commit");
        assert!(anon_view.attestation(anon_main_oid).is_some());
        let root_entries = parse_tree(&anon_view.odb.get(&anon_commit.tree).unwrap().data).unwrap();
        assert!(!root_entries.iter().any(|e| e.name == "billing"));
        assert!(root_entries.iter().any(|e| e.name == "README.md"));
        assert!(root_entries.iter().any(|e| e.name == "apps"));

        // 2. Project for @alice (group:billing).
        let alice_id = DelegatedIdentity::human_only(
            Principal::User("alice".to_owned()),
            vec!["billing".to_owned()],
        );
        let alice_view =
            project_repository(&canonical, &compiled, "fp123456", &alice_id, &vis_map).unwrap();
        assert!(alice_view.refs.contains_key("refs/heads/launch-v3-embargo"));

        // Anti-oracle test: anonymous requesting Alice's private branch OID gets ObjectNotVisible!
        let alice_embargo_oid = &alice_view.refs["refs/heads/launch-v3-embargo"];
        let mut bad_fetch = Vec::new();
        bad_fetch.extend_from_slice(&http_v2::encode_pkt_line(b"command=fetch\n"));
        bad_fetch.extend_from_slice(b"0001");
        bad_fetch.extend_from_slice(&http_v2::encode_pkt_line(
            format!("want {alice_embargo_oid}\n").as_bytes(),
        ));
        bad_fetch.extend_from_slice(&http_v2::encode_pkt_line(b"done\n"));
        bad_fetch.extend_from_slice(b"0000");
        assert_eq!(
            handle_upload_pack_v2(&anon_view, None, &bad_fetch).unwrap_err(),
            GitBridgeError::ObjectNotVisible
        );

        // 3. Real Squash-Declassify landing commit onto `refs/heads/public-release`!
        run_git(&repo_dir, &["branch", "public-release", "main"]);
        let guard = OverlayGuard::from_manifest(&OverlayManifest::default()).unwrap();
        let res = execute_squash_declassify(
            &canonical,
            &compiled,
            "fp123456",
            Some(&guard),
            "launch-v3-embargo",
            &embargo_oid,
            "refs/heads/public-release",
            Some(&main_oid),
            "release: publish launch-v3 publicly",
            "Alice <alice@acme.test> 1732200000 +0000",
            None,
        )
        .unwrap();

        // Only the change the public may read lands; the target keeps its own restricted files.
        assert_eq!(res.published_paths, ["apps/web/app.ts"]);
        assert_eq!(res.scrubbed_paths, ["billing/ledger/tx.rs"]);
        // Verify real git fsck passes on the repository with our written commit & trees!
        run_git(&repo_dir, &["fsck", "--strict", "--full"]);
        let release_files = run_git(
            &repo_dir,
            &["ls-tree", "-r", "--name-only", &res.new_commit_oid],
        );
        assert_eq!(
            release_files,
            run_git(&repo_dir, &["ls-tree", "-r", "--name-only", "main"])
        );
        let blob =
            |rev: &str, path: &str| run_git(&repo_dir, &["rev-parse", &format!("{rev}:{path}")]);
        let (new, tx) = (res.new_commit_oid.as_str(), "billing/ledger/tx.rs");
        assert_eq!(
            blob(new, "apps/web/app.ts"),
            blob(&embargo_oid, "apps/web/app.ts")
        );
        assert_eq!(blob(new, tx), blob("main", tx));
        assert_eq!(
            run_git(&repo_dir, &["rev-parse", &format!("{new}^")]),
            main_oid
        );
    }

    #[test]
    fn reserved_control_plane_symlink_and_gpgsig_hardening() {
        // Expanded HFS+ ignorable characters, NTFS ADS, trailing dots/spaces, 8.3 dotgit forms.
        for bad in [
            ".g\u{00AD}it",
            ".g\u{180E}it",
            ".g\u{200B}it",
            ".g\u{2060}it",
            ".g\u{FEFF}it",
            ".git::$DATA",
            "GI7EBA~1",
            "gi7eba~2",
            "PREMIE~1.LOC",
        ] {
            assert!(
                is_reserved_path_component(bad),
                "expected reserved: {bad:?}"
            );
        }
        for bad_cp in [
            ".acc\u{00AD}ess.toml",
            ".acc\u{180E}ess.toml",
            ".acc\u{200B}ess.toml",
            ".acc\u{2060}ess.toml",
            ".env.schema::$DATA",
            ".ACCESS.TOML.",
            "AC1A2B~1.TOM",
        ] {
            assert!(
                is_control_plane_config_path(bad_cp),
                "expected control plane: {bad_cp:?}"
            );
        }

        // Strict symlink target validator.
        assert_eq!(
            resolve_safe_symlink_target("docs/link", b"guide.md"),
            Ok("docs/guide.md".to_owned())
        );
        assert_eq!(
            resolve_safe_symlink_target("docs/sub/link", b"../guide.md"),
            Ok("docs/guide.md".to_owned())
        );
        for bad_target in [
            b"" as &[u8],
            b"/etc/passwd",
            b"C:\\Windows\\win.ini",
            b"C:secret",
            b"\\\\server\\share\\file",
            b"../../outside",
            b"..",
            b".",
            b"../.git/config",
            b"../GI7EBA~1/HEAD",
            b"../.premier/age.key",
            b"../.premier-local/state",
            b"../.access.toml",
            b"../.ENV.SCHEMA",
            b"../.gitmodules",
            b"sub\nline",
        ] {
            assert!(
                resolve_safe_symlink_target("docs/link", bad_target).is_err(),
                "expected symlink target rejected: {:?}",
                String::from_utf8_lossy(bad_target)
            );
        }

        // `commit_has_gpgsig` checks headers only, never commit message body.
        let unsigned = b"tree 0000000000000000000000000000000000000000\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\n\ngpgsig fake-in-body\n";
        assert!(!objects::commit_has_gpgsig(unsigned));
        let signed = b"tree 0000000000000000000000000000000000000000\nauthor A <a@b> 1 +0000\ncommitter A <a@b> 1 +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n -----END PGP SIGNATURE-----\n\nmsg\n";
        assert!(objects::commit_has_gpgsig(signed));
    }
}
