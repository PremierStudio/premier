//! Pure-Rust Git Packfile v2 unpacker and Reversible `git-receive-pack` Smart HTTP handler.
//!
//! Enables standard `git push` from a dynamically projected clone back into canonical history:
//! 1. Unpacks pushed Git Packfile v2 objects (`commit`, `tree`, `blob`, `ofs-delta`, `ref-delta`).
//! 2. Accepts only objects the pusher sent or can already see, on a ref they can see, against
//!    the tip the server projected for them (compare-and-swap).
//! 3. Enforces `CompiledPolicy` `WRITE` on every modified, added, or deleted path.
//! 4. Enforces `OverlayGuard` to structurally reject team/personal overlay files.
//! 5. Maps every pushed commit to one canonical commit whose tree adds back the files the
//!    pusher cannot see, so the projection of the result is the pushed history, hash for hash.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use flate2::{Decompress, FlushDecompress, Status};
use premier_core::{Capability, DelegatedIdentity, RepoPath, Visibility};
use premier_overlay::OverlayGuard;
use premier_policy::{
    CompiledPolicy, DeclassificationReport, FirewallScanInput, GENERIC_FIREWALL_REJECT,
    PrivateBlobEntry, PrivateCorpus, ScanTargetFile, VaultSecretIndex,
    run_declassification_firewall,
};
use sha1::{Digest, Sha1};

use crate::http_v2::encode_pkt_line;
use crate::objects::{
    CanonicalGitRepo, CommitObj, GitObject, GitObjectKind, InMemoryOdb, ObjectReader, TreeEntry,
    ZERO_OID, encode_tree, is_canonical_tree, is_hex_oid, parse_tree, rewrite_commit,
    rewrite_tag_object,
};
use crate::projector::{
    MAX_CORPUS_BLOB_BYTES, ProjectedView, default_ref_visibility, exposes_hidden_files,
    is_ancestor, new_branch_visibility, path_is_projected,
};
use crate::{GitBridgeError, PRIVATE_REF_PREFIX, is_reserved_path_component};

const PKT_FLUSH: &[u8] = b"0000";

/// Largest inflated size of one pushed object (zip-bomb guard).
const MAX_OBJECT_BYTES: usize = 100 * 1024 * 1024;
/// Largest total inflated size of one pushed pack. With the request body the server accepts
/// (512 MiB) and [`MAX_CONCURRENT_PUSHES`], this bounds what pushes hold in memory at once.
const MAX_PACK_BYTES: usize = 768 * 1024 * 1024;
/// Pushes unpacked and validated at the same time; the rest wait their turn for up to
/// [`PUSH_QUEUE_WAIT`] and are then refused with [`REJECT_BUSY`]. A server should admit no more
/// than this many push requests before reading their bodies.
pub const MAX_CONCURRENT_PUSHES: usize = 2;
const PUSH_QUEUE_WAIT: Duration = Duration::from_secs(30);
/// Most objects one pushed pack may declare.
const MAX_PACK_OBJECTS: usize = 200_000;
/// Deepest directory nesting and most files accepted in one pushed tree (a tree may reference
/// the same subtree many times, so the flattened size is not bounded by the pack size).
const MAX_TREE_DEPTH: usize = 256;
const MAX_TREE_FILES: usize = 2_000_000;
/// Most commits one ref update may add (each is validated against its parent's whole tree).
const MAX_PUSH_COMMITS: usize = 10_000;

/// One answer for every ref update refused for a reason that depends on state the pusher may not
/// be able to see (hidden ref, stale old-oid, lost race), so it reveals none of it.
pub const REJECT_REF: &str =
    "ref update rejected: fetch and retry, or check the branch and your access";
/// One answer for every object reference the pusher is not entitled to make.
const REJECT_OBJECT: &str =
    "push references an object that is neither in the pack nor in your view";
const REJECT_BUSY: &str = "server busy: retry the push in a moment";
const REJECT_TREE: &str = "pushed tree is malformed or uses an unsupported entry type";
/// A force-push that would drop commits the pusher is not shown. Names none of them.
pub(crate) const REJECT_HIDDEN_HISTORY: &str =
    "force-push refused: the branch has changes you cannot see; ask an owner";
pub(crate) const REJECT_TAG_CREATE: &str =
    "creating a tag needs WRITE on a branch that contains its commit, or the owner role";

/// Admission control for pushes: at most [`MAX_CONCURRENT_PUSHES`] hold a permit at once.
pub(crate) struct PushGate {
    active: Mutex<usize>,
    freed: Condvar,
}

pub(crate) struct PushPermit<'a>(&'a PushGate);

static PUSH_GATE: PushGate = PushGate::new();

impl PushGate {
    pub(crate) const fn new() -> Self {
        Self {
            active: Mutex::new(0),
            freed: Condvar::new(),
        }
    }

    /// A permit, waiting up to `wait` for one to be free.
    pub(crate) fn enter(&self, wait: Duration) -> Option<PushPermit<'_>> {
        let active = self.active.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut active, _) = self
            .freed
            .wait_timeout_while(active, wait, |n| *n >= MAX_CONCURRENT_PUSHES)
            .unwrap_or_else(PoisonError::into_inner);
        if *active >= MAX_CONCURRENT_PUSHES {
            return None;
        }
        *active += 1;
        Some(PushPermit(self))
    }
}

impl Drop for PushPermit<'_> {
    fn drop(&mut self) {
        *self.0.active.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
        self.0.freed.notify_one();
    }
}

struct ReceiveCommand {
    old_oid: String,
    new_oid: String,
    ref_name: String,
}

struct ParsedReceive {
    commands: Vec<ReceiveCommand>,
    caps: Vec<String>,
    pack_offset: usize,
}

/// One accepted ref update, for the audit trail. The author and committer of the commits are
/// whatever the pusher wrote (as in any Git server); `pusher` is who actually authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRefUpdate {
    /// The ref as the pusher named it.
    pub ref_name: String,
    pub canonical_ref: String,
    pub canonical_old: String,
    pub canonical_new: String,
    pub pusher: String,
    /// How many pushed commits the update added.
    pub commits: usize,
    /// Set when the push created the branch: the visibility the server must record for
    /// `canonical_ref`.
    pub created_visibility: Option<Visibility>,
}

/// Result of processing one `git-receive-pack` push request.
#[derive(Debug, Clone)]
pub struct ReceivePackResult {
    pub response_bytes: Vec<u8>,
    pub updated_refs: Vec<(String, String)>,
    pub rejected_refs: Vec<(String, String)>,
    pub accepted: Vec<AcceptedRefUpdate>,
}

/// Root-level files of one branch that configure the server itself (`.access.toml`,
/// `.env.schema`): the server, not path policy, decides whether a push may change them.
pub struct ProtectedFiles<'a> {
    /// Canonical ref whose tip the server reads them from.
    pub full_ref: &'a str,
    pub names: &'a [&'a str],
    /// Called for each of `names` the update changes at the tip, with its new bytes (`None`:
    /// deleted). `Err(Some(reason))` refuses the update with that reason, `Err(None)` with the
    /// generic [`REJECT_REF`].
    #[allow(clippy::type_complexity)]
    pub check: &'a dyn Fn(&str, Option<&[u8]>) -> Result<(), Option<String>>,
}

/// What the server gives the declassification firewall of a push beyond the policy.
pub struct ReceivePackFirewall<'a> {
    /// Keyed digests of the vault's secret values (secret push protection).
    pub vault: Option<&'a VaultSecretIndex>,
    /// Owner-approved instruction file path -> SHA-256 hex.
    pub approved_instructions: &'a BTreeMap<String, String>,
    /// Called with the pushed ref and the full (owner) report of every update the firewall
    /// refuses, e.g. for the audit log; the pusher only gets the rejection text.
    #[allow(clippy::type_complexity)]
    pub on_blocked: Option<&'a dyn Fn(&str, &DeclassificationReport)>,
}

/// Render `GET /info/refs?service=git-receive-pack` capability & ref advertisement
/// strictly scoped to the caller's `ProjectedView`.
pub fn render_receive_pack_refs(view: &ProjectedView) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&encode_pkt_line(b"# service=git-receive-pack\n"));
    out.extend_from_slice(PKT_FLUSH);

    let caps = "report-status side-band-64k atomic ofs-delta delete-refs agent=premier/0.1";
    if view.refs.is_empty() {
        let line = format!("{ZERO_OID} capabilities^{{}}\0{caps}\n");
        out.extend_from_slice(&encode_pkt_line(line.as_bytes()));
    } else {
        for (idx, (ref_name, oid)) in view.refs.iter().enumerate() {
            let line = if idx == 0 {
                format!("{oid} {ref_name}\0{caps}\n")
            } else {
                format!("{oid} {ref_name}\n")
            };
            out.extend_from_slice(&encode_pkt_line(line.as_bytes()));
        }
    }

    out.extend_from_slice(PKT_FLUSH);
    out
}

/// Handle `POST /git-receive-pack`: every pushed commit becomes one canonical commit (same
/// author, committer, message and signature; the files the pusher cannot see carried over), so
/// the pusher's next fetch finds exactly the commits they pushed.
///
/// Every command is validated before anything is written. With the `atomic` capability one
/// refused command refuses them all, and the ref updates are a single transaction.
/// `pusher_is_owner` only decides the visibility of a branch the push creates.
#[allow(clippy::too_many_arguments)]
pub fn handle_receive_pack(
    canonical: &CanonicalGitRepo,
    view: &ProjectedView,
    policy: &CompiledPolicy,
    overlay_guard: &OverlayGuard,
    identity: &DelegatedIdentity,
    pusher_is_owner: bool,
    protected: Option<&ProtectedFiles<'_>>,
    request_body: &[u8],
) -> Result<ReceivePackResult, GitBridgeError> {
    handle_receive_pack_with_firewall(
        canonical,
        view,
        policy,
        overlay_guard,
        identity,
        pusher_is_owner,
        protected,
        None,
        request_body,
    )
}

/// [`handle_receive_pack`] with the server's inputs to the declassification firewall and the
/// instruction quarantine. Both run on every branch update whatever `firewall` is; `None` only
/// means no vault index, no approved instruction files and no callback.
#[allow(clippy::too_many_arguments)]
pub fn handle_receive_pack_with_firewall(
    canonical: &CanonicalGitRepo,
    view: &ProjectedView,
    policy: &CompiledPolicy,
    overlay_guard: &OverlayGuard,
    identity: &DelegatedIdentity,
    pusher_is_owner: bool,
    protected: Option<&ProtectedFiles<'_>>,
    firewall: Option<&ReceivePackFirewall<'_>>,
    request_body: &[u8],
) -> Result<ReceivePackResult, GitBridgeError> {
    let no_approvals = BTreeMap::new();
    let no_firewall = ReceivePackFirewall {
        vault: None,
        approved_instructions: &no_approvals,
        on_blocked: None,
    };
    let firewall = firewall.unwrap_or(&no_firewall);
    // Parse pkt-line ref update commands until `0000` flush; remaining bytes are the raw PACK.
    let parsed = parse_receive_commands(request_body)?;
    let use_sideband = parsed.caps.iter().any(|c| c == "side-band-64k");
    let atomic = parsed.caps.iter().any(|c| c == "atomic");

    // Unpacking is where a push costs memory: only so many at a time.
    let Some(_permit) = PUSH_GATE.enter(PUSH_QUEUE_WAIT) else {
        let rejected_refs: Vec<(String, String)> = parsed
            .commands
            .iter()
            .map(|c| (c.ref_name.clone(), REJECT_BUSY.to_owned()))
            .collect();
        return Ok(ReceivePackResult {
            response_bytes: render_report(use_sideband, &[], &[], &rejected_refs),
            updated_refs: Vec::new(),
            rejected_refs,
            accepted: Vec::new(),
        });
    };

    let mut unpacked = InMemoryOdb::default();
    if parsed.pack_offset < request_body.len()
        && request_body[parsed.pack_offset..].starts_with(b"PACK")
    {
        unpack_packfile(
            &request_body[parsed.pack_offset..],
            &view.odb,
            &mut unpacked,
        )?;
    }

    let canonical_refs: HashSet<String> =
        canonical.list_refs()?.into_iter().map(|(r, _)| r).collect();
    let mut push = Push {
        canonical,
        reader: canonical.reader()?,
        view,
        unpacked: &unpacked,
        policy,
        overlay_guard,
        identity,
        pusher_is_owner,
        protected,
        firewall,
        canonical_refs: &canonical_refs,
        staged: InMemoryOdb::default(),
        staged_blobs: HashMap::new(),
        pushed_commits: HashMap::new(),
        pending_pushed_commits: HashMap::new(),
    };

    // 1. Validate everything; nothing is written yet. Plan branch updates before tag updates so a
    //    tag pushed alongside a branch commit can resolve that commit, while preserving the
    //    caller's command order in the report.
    let mut order_indices: Vec<usize> = (0..parsed.commands.len()).collect();
    order_indices.sort_by_key(|&i| parsed.commands[i].ref_name.starts_with("refs/tags/"));
    let mut plans_by_idx: Vec<Option<(String, Result<AcceptedPush, String>)>> =
        (0..parsed.commands.len()).map(|_| None).collect();
    for idx in order_indices {
        let c = &parsed.commands[idx];
        // A refused update leaves none of its objects behind.
        let kept = (
            std::mem::take(&mut push.staged),
            std::mem::take(&mut push.staged_blobs),
            std::mem::take(&mut push.pending_pushed_commits),
        );
        let plan = push.plan_ref_update(&c.ref_name, &c.old_oid, &c.new_oid);
        let staged = std::mem::replace(&mut push.staged, kept.0);
        let staged_blobs = std::mem::replace(&mut push.staged_blobs, kept.1);
        let pending_commits = std::mem::replace(&mut push.pending_pushed_commits, kept.2);
        if plan.is_ok() {
            for obj in staged.iter() {
                push.staged.insert(obj.clone());
            }
            push.staged_blobs.extend(staged_blobs);
            push.pushed_commits.extend(pending_commits);
        }
        plans_by_idx[idx] = Some((c.ref_name.clone(), plan));
    }
    let mut plans: Vec<(String, Result<AcceptedPush, String>)> =
        plans_by_idx.into_iter().flatten().collect();
    let refuse_all = |plans: &mut Vec<(String, Result<AcceptedPush, String>)>, why: &str| {
        for (_, plan) in plans.iter_mut().filter(|(_, p)| p.is_ok()) {
            *plan = Err(why.to_owned());
        }
    };
    if atomic && plans.iter().any(|(_, p)| p.is_err()) {
        refuse_all(&mut plans, "atomic push: another ref update was rejected");
    }

    // 2. Apply: objects first (unreferenced until a ref moves), then the compare-and-swap that
    //    makes the old-oid check real: it fails if the canonical ref moved since this caller's
    //    view was projected.
    let cas = |a: &AcceptedPush| {
        (
            a.canonical_ref.clone(),
            a.canonical_oid.clone(),
            a.canonical_old.clone(),
        )
    };
    if plans.iter().any(|(_, p)| p.is_ok()) {
        let objects: Vec<&GitObject> = push
            .staged
            .iter()
            .chain(push.staged_blobs.values().copied())
            .collect();
        canonical.write_objects(&objects)?;
    }
    if atomic {
        let all: Vec<_> = plans
            .iter()
            .filter_map(|(_, p)| p.as_ref().ok().map(cas))
            .collect();
        if !all.is_empty() && canonical.update_refs_cas(&all).is_err() {
            refuse_all(&mut plans, REJECT_REF);
        }
    } else {
        for (_, plan) in &mut plans {
            if let Ok(accepted) = plan
                && canonical.update_refs_cas(&[cas(accepted)]).is_err()
            {
                *plan = Err(REJECT_REF.to_owned());
            }
        }
    }

    let mut updated_refs = Vec::new();
    let mut rejected_refs = Vec::new();
    let mut accepted = Vec::new();
    let mut notes = Vec::new();
    for (ref_name, plan) in plans {
        match plan {
            Ok(a) => {
                // Not what `git push origin x:new` reads like: say so.
                if let (Some(Visibility::Personal(_)), Some(name)) =
                    (&a.created_visibility, ref_name.strip_prefix("refs/heads/"))
                {
                    notes.push(format!(
                        "created '{name}' as a personal branch (visible to you and owners)"
                    ));
                }
                updated_refs.push((ref_name.clone(), a.canonical_oid.clone()));
                accepted.push(AcceptedRefUpdate {
                    ref_name,
                    canonical_ref: a.canonical_ref,
                    canonical_old: a.canonical_old,
                    canonical_new: a.canonical_oid,
                    pusher: identity.principal.canonical_id(),
                    commits: a.commits,
                    created_visibility: a.created_visibility,
                });
            }
            Err(reason) => rejected_refs.push((ref_name, reason)),
        }
    }

    let response_bytes = render_report(use_sideband, &notes, &updated_refs, &rejected_refs);

    Ok(ReceivePackResult {
        response_bytes,
        updated_refs,
        rejected_refs,
        accepted,
    })
}

/// The `report-status` answer to a push. `notes` are progress lines for the pusher (git prints
/// each after `remote: `); they need the side band.
fn render_report(
    use_sideband: bool,
    notes: &[String],
    updated_refs: &[(String, String)],
    rejected_refs: &[(String, String)],
) -> Vec<u8> {
    let mut status_payload = Vec::new();
    status_payload.extend_from_slice(&encode_pkt_line(b"unpack ok\n"));
    for (ref_name, _) in updated_refs {
        status_payload.extend_from_slice(&encode_pkt_line(format!("ok {ref_name}\n").as_bytes()));
    }
    for (ref_name, reason) in rejected_refs {
        let clean_reason = reason.replace(['\r', '\n'], " ");
        status_payload.extend_from_slice(&encode_pkt_line(
            format!("ng {ref_name} {clean_reason}\n").as_bytes(),
        ));
    }
    status_payload.extend_from_slice(PKT_FLUSH);

    if !use_sideband {
        return status_payload;
    }
    let mut sb = Vec::new();
    for note in notes {
        sb.extend_from_slice(&encode_pkt_line(format!("\u{2}{note}\n").as_bytes()));
    }
    for chunk in status_payload.chunks(65_000) {
        let mut frame = Vec::with_capacity(chunk.len() + 1);
        frame.push(1u8);
        frame.extend_from_slice(chunk);
        sb.extend_from_slice(&encode_pkt_line(&frame));
    }
    sb.extend_from_slice(PKT_FLUSH);
    sb
}

/// A fully validated ref update, ready for the canonical compare-and-swap.
struct AcceptedPush {
    canonical_ref: String,
    canonical_oid: String,
    /// What the canonical ref must still point at (zero OID: must not exist).
    canonical_old: String,
    commits: usize,
    created_visibility: Option<Visibility>,
}

type FileMap = BTreeMap<String, (String, String)>;

/// `git check-ref-format --branch` rules for the part after `refs/heads/` or `refs/tags/`.
fn valid_branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "HEAD"
        && name != "@"
        && !name.starts_with('-')
        && !name.starts_with("refs/")
        && !name.ends_with('.')
        && !name.contains("..")
        && !name.contains("@{")
        && name
            .split('/')
            .all(|c| !c.is_empty() && !c.starts_with('.') && !c.ends_with(".lock"))
        && name
            .chars()
            .all(|ch| !ch.is_control() && !" ~^:?*[\\\u{fffd}".contains(ch))
}

/// Validate a Git `ident` line (`Name <email> <unix-ts> <+/-HHMM>`) so `git fsck --strict`
/// always accepts rewritten annotated tag objects.
fn is_valid_git_ident(ident: &str) -> bool {
    let Some((name_part, rest)) = ident.split_once('<') else {
        return false;
    };
    let Some((email_part, time_part)) = rest.split_once('>') else {
        return false;
    };
    if name_part.trim().is_empty()
        || !name_part.ends_with(' ')
        || email_part.contains(['<', '>', '\n', '\r'])
    {
        return false;
    }
    let Some(time_part) = time_part.strip_prefix(' ') else {
        return false;
    };
    let mut parts = time_part.split(' ');
    let (Some(ts), Some(tz), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !ts.is_empty()
        && ts.bytes().all(|b| b.is_ascii_digit())
        && tz.len() == 5
        && matches!(tz.as_bytes()[0], b'+' | b'-')
        && tz.as_bytes()[1..].iter().all(u8::is_ascii_digit)
}

/// Every proper directory prefix of `path` (`a/b/c` -> `a`, `a/b`).
fn dir_prefixes(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/').map(move |(i, _)| &path[..i])
}

/// Whether `path` collides (ignoring ASCII case) with a hidden file or directory:
/// exact match, a hidden file as a parent directory of `path`, or a hidden file
/// underneath `path`. Mirrors `companion::collides_with_hidden` so macOS/Windows
/// case-folding cannot bypass hidden-path protection.
fn collides_with_hidden(path: &str, hidden_lower: &BTreeSet<String>) -> bool {
    if hidden_lower.is_empty() {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    if hidden_lower.contains(&lower) || dir_prefixes(&lower).any(|d| hidden_lower.contains(d)) {
        return true;
    }
    let prefix = format!("{lower}/");
    hidden_lower
        .range(prefix.clone()..)
        .next()
        .is_some_and(|h| h.starts_with(&prefix))
}

/// Find any path in `files` that collides (ignoring ASCII case) with another file or directory
/// in the same tree (e.g. `.access.toml` vs `.ACCESS.TOML`, or `dir` file vs `DIR/child`).
fn find_visible_case_collision(files: &FileMap) -> Option<&str> {
    let mut seen_files: HashSet<String> = HashSet::with_capacity(files.len());
    let mut seen_dirs: HashSet<String> = HashSet::new();
    for path in files.keys() {
        let lower = path.to_ascii_lowercase();
        if !seen_files.insert(lower.clone()) || seen_dirs.contains(&lower) {
            return Some(path.as_str());
        }
        for dir in dir_prefixes(&lower) {
            if seen_files.contains(dir) {
                return Some(path.as_str());
            }
            seen_dirs.insert(dir.to_owned());
        }
    }
    None
}

/// One push request: what it may read from, and the canonical objects staged for it so far.
struct Push<'a> {
    canonical: &'a CanonicalGitRepo,
    reader: ObjectReader,
    view: &'a ProjectedView,
    unpacked: &'a InMemoryOdb,
    policy: &'a CompiledPolicy,
    overlay_guard: &'a OverlayGuard,
    identity: &'a DelegatedIdentity,
    pusher_is_owner: bool,
    protected: Option<&'a ProtectedFiles<'a>>,
    firewall: &'a ReceivePackFirewall<'a>,
    canonical_refs: &'a HashSet<String>,
    /// New canonical trees, commits, and rewritten tags.
    staged: InMemoryOdb,
    /// Pushed blobs an accepted tree names.
    staged_blobs: HashMap<&'a str, &'a GitObject>,
    /// Projected commit -> (canonical commit, branch it was pushed to) from accepted branch
    /// commands in this push.
    pushed_commits: HashMap<String, (String, String)>,
    /// The same, staged for the command currently being planned.
    pending_pushed_commits: HashMap<String, (String, String)>,
}

impl<'a> Push<'a> {
    /// The pusher may only name objects they sent or already see; never the canonical store.
    /// The kind must match too: an entry's mode decides how its object is used.
    fn lookup(&self, oid: &str, kind: GitObjectKind) -> Result<&'a GitObject, String> {
        self.unpacked
            .get(oid)
            .or_else(|| self.view.odb.get(oid))
            .filter(|o| o.kind == kind)
            .ok_or_else(|| REJECT_OBJECT.to_owned())
    }

    /// `path -> (mode, oid)` of a pushed or projected tree, exactly as the projection encodes it.
    fn files_of(&self, tree_oid: &str) -> Result<FileMap, String> {
        let mut files = FileMap::new();
        flatten_tree(
            &|oid| {
                self.lookup(oid, GitObjectKind::Tree)
                    .map(|o| o.data.as_ref())
            },
            tree_oid,
            "",
            0,
            &mut files,
        )?;
        if files
            .keys()
            .any(|p| dir_prefixes(p).any(|d| files.contains_key(d)))
        {
            return Err(REJECT_TREE.to_owned());
        }
        Ok(files)
    }

    /// The files of `canonical_commit` missing from `visible`, the pusher's view of it. Path
    /// rules may differ by branch name, so on a `new_branch` none of them may become readable to
    /// its creator.
    fn hidden_files(
        &mut self,
        canonical_commit: &str,
        visible: &FileMap,
        new_branch: Option<&str>,
    ) -> Result<FileMap, String> {
        let internal = |_: GitBridgeError| REJECT_REF.to_owned();
        let data = self.reader.read(canonical_commit).map_err(internal)?.data;
        let tree = CommitObj::parse(&data).map_err(internal)?.tree;
        let mut hidden = FileMap::new();
        flatten_canonical_tree(&mut self.reader, &tree, "", &mut hidden).map_err(internal)?;
        hidden.retain(|path, _| !visible.contains_key(path));
        if let Some(branch) = new_branch
            && exposes_hidden_files(
                self.policy,
                self.identity,
                branch,
                hidden.keys().map(String::as_str),
            )
        {
            return Err(REJECT_REF.to_owned());
        }
        Ok(hidden)
    }

    /// Bytes of a canonical object: staged for this push, sent with it, or already stored.
    fn canonical_bytes(&mut self, oid: &str) -> Result<Vec<u8>, String> {
        if let Some(obj) = self.staged.get(oid).or_else(|| self.unpacked.get(oid)) {
            return Ok(obj.data.to_vec());
        }
        self.reader
            .read(oid)
            .map(|o| o.data.to_vec())
            .map_err(|_| REJECT_REF.to_owned())
    }

    /// Every file of canonical commit `commit` (stored, or staged for this push).
    fn canonical_files(&mut self, commit: &str) -> Result<FileMap, String> {
        let bad = |_: GitBridgeError| REJECT_REF.to_owned();
        let tree = CommitObj::parse(&self.canonical_bytes(commit)?)
            .map_err(bad)?
            .tree;
        let mut files = FileMap::new();
        let mut trees = vec![(String::new(), tree)];
        while let Some((prefix, tree)) = trees.pop() {
            for entry in parse_tree(&self.canonical_bytes(&tree)?).map_err(bad)? {
                let rel = format!("{prefix}{}", entry.name);
                if entry.is_dir() {
                    trees.push((format!("{rel}/"), entry.oid_hex));
                } else {
                    files.insert(rel, (entry.mode, entry.oid_hex));
                }
            }
        }
        Ok(files)
    }

    /// All root-level entries matching `name` (ASCII case-insensitively) in canonical commit
    /// `commit`, as `(actual_name, mode, oid)` sorted by name.
    fn root_entries_ci(
        &mut self,
        commit: &str,
        name: &str,
    ) -> Result<Vec<(String, String, String)>, String> {
        let bad = |_: GitBridgeError| REJECT_REF.to_owned();
        let tree = CommitObj::parse(&self.canonical_bytes(commit)?)
            .map_err(bad)?
            .tree;
        let entries = parse_tree(&self.canonical_bytes(&tree)?).map_err(bad)?;
        let mut matched: Vec<(String, String, String)> = entries
            .into_iter()
            .filter(|e| e.name.eq_ignore_ascii_case(name))
            .map(|e| (e.name, e.mode, e.oid_hex))
            .collect();
        matched.sort();
        Ok(matched)
    }

    /// Ask the server about every protected file `accepted` would change at the branch tip.
    fn check_protected(&mut self, accepted: &AcceptedPush) -> Result<(), String> {
        // No default ref the server could name (detached HEAD), or one that does not exist:
        // the files are protected on every ref rather than on none.
        let Some(protected) = self.protected.filter(|p| {
            p.full_ref == accepted.canonical_ref || !self.canonical_refs.contains(p.full_ref)
        }) else {
            return Ok(());
        };
        for name in protected.names {
            let before = match accepted.canonical_old.as_str() {
                ZERO_OID => Vec::new(),
                old => self.root_entries_ci(old, name)?,
            };
            let after = self.root_entries_ci(&accepted.canonical_oid, name)?;
            if before == after {
                continue;
            }
            if after.len() > 1 {
                return Err(format!(
                    "case-folded collision on protected config file {name}"
                ));
            }
            let after_entry = after.into_iter().next();
            // A symlink's blob is a path, not the file's content: never a server config file.
            if after_entry
                .as_ref()
                .is_some_and(|(_, mode, _)| !matches!(mode.as_str(), "100644" | "100755"))
            {
                return Err(format!(
                    "{name} must be a regular file, not a symlink or a directory"
                ));
            }
            let content = after_entry
                .as_ref()
                .map(|(_, _, oid)| self.canonical_bytes(oid))
                .transpose()?;
            (protected.check)(name, content.as_deref())
                .map_err(|why| why.unwrap_or_else(|| REJECT_REF.to_owned()))?;
            if let Some((actual_name, _, _)) = after_entry
                && actual_name != *name
            {
                return Err(format!(
                    "protected config file '{actual_name}' must use canonical casing '{name}'"
                ));
            }
        }
        // Always protect `.gitmodules` on the protected ref even if the caller did not include it
        // in `protected.names` (owner-only, regular file, canonical casing).
        if !protected
            .names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(".gitmodules"))
        {
            let before = match accepted.canonical_old.as_str() {
                ZERO_OID => Vec::new(),
                old => self.root_entries_ci(old, ".gitmodules")?,
            };
            let after = self.root_entries_ci(&accepted.canonical_oid, ".gitmodules")?;
            if before != after {
                if after.len() > 1 {
                    return Err(
                        "case-folded collision on protected config file .gitmodules".to_owned()
                    );
                }
                let after_entry = after.into_iter().next();
                if after_entry
                    .as_ref()
                    .is_some_and(|(_, mode, _)| !matches!(mode.as_str(), "100644" | "100755"))
                {
                    return Err(
                        ".gitmodules must be a regular file, not a symlink or a directory"
                            .to_owned(),
                    );
                }
                if !self.pusher_is_owner {
                    return Err(REJECT_REF.to_owned());
                }
                if let Some((actual_name, _, _)) = after_entry
                    && actual_name != ".gitmodules"
                {
                    return Err(format!(
                        "protected config file '{actual_name}' must use canonical casing '.gitmodules'"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Resolve a tag target OID (either a lightweight commit or an annotated tag object) into
    /// the canonical OID to store under `refs/tags/<name>`, and the projected commit it tags.
    /// Stages rewritten annotated tags.
    fn resolve_tag_target(
        &mut self,
        new_projected_oid: &str,
        expected_tag_name: &str,
    ) -> Result<(String, String), String> {
        let obj = self
            .unpacked
            .get(new_projected_oid)
            .or_else(|| self.view.odb.get(new_projected_oid))
            .ok_or_else(|| REJECT_OBJECT.to_owned())?;
        let resolve_commit = |projected_commit_oid: &str| -> Result<String, String> {
            self.pushed_commits
                .get(projected_commit_oid)
                .map(|(c, _)| c)
                .or_else(|| self.view.projected_to_canonical.get(projected_commit_oid))
                .cloned()
                .ok_or_else(|| REJECT_OBJECT.to_owned())
        };
        match obj.kind {
            GitObjectKind::Commit => Ok((
                resolve_commit(new_projected_oid)?,
                new_projected_oid.to_owned(),
            )),
            GitObjectKind::Tag => {
                // Strictly validate the annotated tag format so `git fsck --strict` always passes:
                //   object <40-lowercase-hex>\n
                //   type commit\n
                //   tag <exact_tag_name>\n
                //   tagger <valid ident>\n
                //   \n
                //   <message...>
                if obj.data.contains(&0) {
                    return Err("invalid tag object".to_owned());
                }
                let Some(sep) = obj.data.windows(2).position(|w| w == b"\n\n") else {
                    return Err("invalid tag object".to_owned());
                };
                let headers =
                    std::str::from_utf8(&obj.data[..sep]).map_err(|_| "invalid tag object")?;
                let lines: Vec<&str> = headers.split('\n').collect();
                if lines.len() != 4 {
                    return Err("invalid tag object".to_owned());
                }
                let Some(target_oid) = lines[0].strip_prefix("object ") else {
                    return Err("invalid tag object".to_owned());
                };
                if target_oid.len() != 40
                    || !target_oid
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                {
                    return Err("invalid tag object".to_owned());
                }
                if lines[1] != "type commit" {
                    return Err("tags must point to a commit".to_owned());
                }
                let Some(tag_header_name) = lines[2].strip_prefix("tag ") else {
                    return Err("invalid tag object".to_owned());
                };
                if tag_header_name != expected_tag_name {
                    return Err("tag object name does not match ref name".to_owned());
                }
                let Some(tagger) = lines[3].strip_prefix("tagger ") else {
                    return Err("invalid tag object".to_owned());
                };
                if !is_valid_git_ident(tagger) {
                    return Err("invalid tag object".to_owned());
                }

                let canonical_commit = resolve_commit(target_oid)?;
                let rewritten = rewrite_tag_object(&obj.data, &canonical_commit)
                    .map_err(|_| "invalid tag object".to_owned())?;
                let tag = self
                    .staged
                    .insert(GitObject::new(GitObjectKind::Tag, rewritten));
                Ok((tag, target_oid.to_owned()))
            }
            GitObjectKind::Tree | GitObjectKind::Blob => Err(REJECT_OBJECT.to_owned()),
        }
    }

    /// The tag rule: creating a tag needs the owner role, or WRITE on at least one file of the
    /// tagged commit on a branch of the pusher's view (or of this push) that contains it.
    fn may_tag(&self, commit: &str) -> Result<bool, String> {
        let mut branches: Vec<&str> = self
            .view
            .refs
            .iter()
            .filter(|(r, tip)| {
                r.starts_with("refs/heads/") && is_ancestor(&self.view.odb, commit, tip)
            })
            .filter_map(|(r, _)| r.strip_prefix("refs/heads/"))
            .collect();
        branches.extend(self.pushed_commits.get(commit).map(|(_, b)| b.as_str()));
        if branches.is_empty() {
            return Ok(false);
        }
        let tree = CommitObj::parse(&self.lookup(commit, GitObjectKind::Commit)?.data)
            .map_err(|_| REJECT_REF)?
            .tree;
        let files = self.files_of(&tree)?;
        Ok(branches.iter().any(|branch| {
            files.keys().any(|path| {
                RepoPath::new(path).is_ok_and(|rp| {
                    self.policy
                        .explain(self.identity, &rp, branch)
                        .allows(Capability::WRITE)
                })
            })
        }))
    }

    /// Whether every canonical commit `old` reaches and `new` does not is one the pusher is
    /// shown on `advertised_ref` (none collapsed in their projection), so a force-push from
    /// `old` to `new` erases only history they can see.
    // shortcut: walks all of `new`'s history per force-push; stop at the merge base if that
    // gets slow on large repositories.
    fn drops_only_visible(
        &mut self,
        advertised_ref: &str,
        old: &str,
        new: &str,
    ) -> Result<bool, String> {
        let shown = self.view.commits_on(advertised_ref);
        let mut parents = |oid: &str| -> Result<Vec<String>, String> {
            Ok(CommitObj::parse(&self.canonical_bytes(oid)?)
                .map_err(|_| REJECT_REF)?
                .parents)
        };
        let mut kept = HashSet::new();
        let mut stack = vec![new.to_owned()];
        while let Some(oid) = stack.pop() {
            if kept.insert(oid.clone()) {
                stack.extend(parents(&oid)?);
            }
        }
        let mut stack = vec![old.to_owned()];
        while let Some(oid) = stack.pop() {
            if !kept.insert(oid.clone()) {
                continue;
            }
            if !shown.contains_key(&oid) {
                return Ok(false);
            }
            stack.extend(parents(&oid)?);
        }
        Ok(true)
    }

    /// Validate a tag ref create, update, or delete (`refs/tags/<valid tag name>`).
    fn plan_tag_update(
        &mut self,
        ref_name: &str,
        tag_name: &str,
        old_projected_oid: &str,
        new_projected_oid: &str,
    ) -> Result<AcceptedPush, String> {
        if !valid_branch_name(tag_name) {
            return Err(
                "only refs/heads/<valid branch name> or refs/tags/<valid tag name> can be pushed"
                    .to_owned(),
            );
        }
        if !is_hex_oid(old_projected_oid) || !is_hex_oid(new_projected_oid) {
            return Err(REJECT_REF.to_owned());
        }
        if !self.identity.principal.is_authenticated() {
            return Err(REJECT_REF.to_owned());
        }

        let existing = self
            .view
            .refs
            .get(ref_name)
            .zip(self.view.ref_sources.get(ref_name));

        if new_projected_oid == ZERO_OID {
            let Some((projected_tip, (full_ref, canonical_tip))) = existing else {
                return Err(REJECT_REF.to_owned());
            };
            if old_projected_oid != projected_tip {
                return Err(REJECT_REF.to_owned());
            }
            if !self.pusher_is_owner {
                return Err("only repository owners may delete tags".to_owned());
            }
            return Ok(AcceptedPush {
                canonical_ref: full_ref.clone(),
                canonical_oid: ZERO_OID.to_owned(),
                canonical_old: canonical_tip.clone(),
                commits: 0,
                created_visibility: None,
            });
        }

        if old_projected_oid == ZERO_OID {
            // Restrict global tag creation to repository owners before checking canonical refs
            // so non-owners can neither squat global tags nor probe hidden tag names.
            if !self.pusher_is_owner {
                return Err("only repository owners may create tags".to_owned());
            }
            if existing.is_some() || self.canonical_refs.contains(ref_name) {
                return Err(REJECT_REF.to_owned());
            }
            let (canonical_oid, commit) = self.resolve_tag_target(new_projected_oid, tag_name)?;
            // Defense in depth behind the owner-only gate above: if that gate is ever relaxed,
            // a non-owner still needs WRITE on a branch holding the tagged commit.
            if !self.pusher_is_owner && !self.may_tag(&commit)? {
                return Err(REJECT_TAG_CREATE.to_owned());
            }
            return Ok(AcceptedPush {
                canonical_ref: ref_name.to_owned(),
                canonical_oid,
                canonical_old: ZERO_OID.to_owned(),
                commits: 0,
                created_visibility: None,
            });
        }

        // Updating an existing tag: owner-only with strict CAS against the caller's projected tip.
        let Some((projected_tip, (full_ref, canonical_tip))) = existing else {
            return Err(REJECT_REF.to_owned());
        };
        if old_projected_oid != projected_tip {
            return Err(REJECT_REF.to_owned());
        }
        if !self.pusher_is_owner {
            return Err("only repository owners may update existing tags".to_owned());
        }
        let (canonical_oid, _) = self.resolve_tag_target(new_projected_oid, tag_name)?;
        Ok(AcceptedPush {
            canonical_ref: full_ref.clone(),
            canonical_oid,
            canonical_old: canonical_tip.clone(),
            commits: 0,
            created_visibility: None,
        })
    }

    /// Validate one ref update completely and stage its canonical objects. Nothing reaches the
    /// canonical repository here, and no rejection names a path or OID the pusher did not send
    /// or cannot see.
    fn plan_ref_update(
        &mut self,
        ref_name: &str,
        old_projected_oid: &str,
        new_projected_oid: &str,
    ) -> Result<AcceptedPush, String> {
        if let Some(tag_name) = ref_name.strip_prefix("refs/tags/") {
            return self.plan_tag_update(ref_name, tag_name, old_projected_oid, new_projected_oid);
        }

        let (view, policy, identity) = (self.view, self.policy, self.identity);
        let short_ref = ref_name
            .strip_prefix("refs/heads/")
            .filter(|n| valid_branch_name(n))
            .ok_or(
                "only refs/heads/<valid branch name> or refs/tags/<valid tag name> can be pushed",
            )?;
        if !is_hex_oid(old_projected_oid) || !is_hex_oid(new_projected_oid) {
            return Err(REJECT_REF.to_owned());
        }

        // Branch deletion (`git push --delete`): strict CAS, never the default branch,
        // allowed only for repository owners or the branch's own personal owner.
        if new_projected_oid == ZERO_OID {
            let Some((projected_tip, (full_ref, canonical_tip))) =
                view.refs.get(ref_name).zip(view.ref_sources.get(ref_name))
            else {
                return Err(REJECT_REF.to_owned());
            };
            if old_projected_oid != projected_tip || !identity.principal.is_authenticated() {
                return Err(REJECT_REF.to_owned());
            }
            if self.protected.is_some_and(|p| {
                p.full_ref.is_empty()
                    || !self.canonical_refs.contains(p.full_ref)
                    || p.full_ref == full_ref.as_str()
            }) {
                return Err("cannot delete the default branch".to_owned());
            }
            let is_own_personal = matches!(
                view.ref_visibilities.get(ref_name),
                Some(Visibility::Personal(owner)) if identity.matches_selector(owner)
            );
            if !self.pusher_is_owner && !is_own_personal {
                return Err(
                    "only repository owners or the branch's personal owner may delete this branch"
                        .to_owned(),
                );
            }
            return Ok(AcceptedPush {
                canonical_ref: full_ref.clone(),
                canonical_oid: ZERO_OID.to_owned(),
                canonical_old: canonical_tip.clone(),
                commits: 0,
                created_visibility: None,
            });
        }

        // The existing branch this push moves: its canonical ref and tip, and the server's own
        // projection of that tip. Client-supplied state is only ever compared, never used.
        let existing = match view.refs.get(ref_name).zip(view.ref_sources.get(ref_name)) {
            Some((projected_tip, (full_ref, canonical_tip))) => {
                if old_projected_oid != projected_tip {
                    return Err(REJECT_REF.to_owned());
                }
                Some((projected_tip.as_str(), full_ref, canonical_tip))
            }
            None => {
                // A new branch: the name must be free canonically (a hidden branch answers like
                // any other refused update), and only a signed-in caller may create one.
                let taken = self.canonical_refs.contains(ref_name)
                    || self
                        .canonical_refs
                        .contains(&format!("{PRIVATE_REF_PREFIX}{short_ref}"));
                if taken || old_projected_oid != ZERO_OID || !identity.principal.is_authenticated()
                {
                    return Err(REJECT_REF.to_owned());
                }
                None
            }
        };

        // The canonical commit behind a commit of the pusher's view. A tip stands for its
        // branch's canonical tip, which may carry commits the pusher cannot see on top of it:
        // building on the tip must not drop them.
        let canonical_of_visible = |projected: &str| -> Option<String> {
            if let Some((tip, _, canonical_tip)) = existing
                && tip == projected
            {
                return Some(canonical_tip.clone());
            }
            view.refs
                .iter()
                .filter(|(advertised, _)| advertised.starts_with("refs/heads/"))
                .find(|(_, tip)| tip.as_str() == projected)
                .and_then(|(advertised, _)| view.ref_sources.get(advertised))
                .map(|(_, canonical_tip)| canonical_tip)
                .or_else(|| view.projected_to_canonical.get(projected))
                .cloned()
        };

        // Pushed commits, parents first, and the commits of the pusher's view they grow from.
        let mut pushed: HashMap<String, (&'a GitObject, CommitObj)> = HashMap::new();
        let mut order: Vec<String> = Vec::new();
        let mut done: HashSet<String> = HashSet::new();
        let mut bases: Vec<String> = Vec::new();
        let mut stack = vec![new_projected_oid.to_owned()];
        while let Some(oid) = stack.last().cloned() {
            if view.projected_to_canonical.contains_key(&oid) {
                if !bases.contains(&oid) {
                    bases.push(oid);
                }
                stack.pop();
                continue;
            }
            if done.contains(&oid) {
                stack.pop();
                continue;
            }
            if !pushed.contains_key(&oid) {
                if pushed.len() >= MAX_PUSH_COMMITS {
                    return Err(format!(
                        "more than {MAX_PUSH_COMMITS} commits in one push; push in smaller steps"
                    ));
                }
                let obj = self.lookup(&oid, GitObjectKind::Commit)?;
                let commit = CommitObj::parse(&obj.data).map_err(|_| "invalid commit")?;
                let mut distinct = HashSet::new();
                // Only a commit that survives the trip to canonical and back byte for byte.
                if commit.author.is_empty()
                    || commit.committer.is_empty()
                    || !commit
                        .parents
                        .iter()
                        .all(|p| is_hex_oid(p) && distinct.insert(p))
                    || rewrite_commit(&obj.data, &commit.tree, &commit.parents)
                        .ok()
                        .as_deref()
                        != Some(obj.data.as_ref())
                {
                    return Err("invalid commit".to_owned());
                }
                pushed.insert(oid.clone(), (obj, commit));
            }
            let mut pending = Vec::new();
            for parent in &pushed[&oid].1.parents {
                if view.projected_to_canonical.contains_key(parent) {
                    if !bases.contains(parent) {
                        bases.push(parent.clone());
                    }
                } else if !done.contains(parent) {
                    pending.push(parent.clone());
                }
            }
            if pending.is_empty() {
                stack.pop();
                done.insert(oid.clone());
                order.push(oid);
            } else {
                stack.extend(pending);
            }
        }

        // Determine whether an update to an existing branch is a canonical fast-forward.
        // Non-fast-forward updates (force-push / `--force-with-lease`) are permitted ONLY for
        // repository owners or on the pusher's own `Visibility::Personal` branch, MUST NOT drop
        // unseen canonical commits sitting above `projected_tip`, and MUST carry over the hidden
        // files of the branch's current `canonical_tip` untouched.
        let (force_push_hidden, mut descends_from_tip): (Option<Rc<FileMap>>, HashSet<String>) =
            if let Some((tip, _, canonical_tip)) = existing {
                let tip_bases: HashSet<String> = bases
                    .iter()
                    .filter(|b| {
                        b.as_str() == tip
                            || canonical_of_visible(b)
                                .is_some_and(|c| self.canonical.is_ancestor(canonical_tip, &c))
                    })
                    .cloned()
                    .collect();
                let is_fast_forward = !tip_bases.is_empty();
                if !is_fast_forward {
                    let is_own_personal = identity.principal.is_authenticated()
                        && matches!(
                            view.ref_visibilities.get(ref_name),
                            Some(Visibility::Personal(owner)) if identity.matches_selector(owner)
                        );
                    if !self.pusher_is_owner && !is_own_personal {
                        return Err(
                            "not a fast-forward of the server's branch: force-push is only allowed for owners or on your personal branch"
                                .to_owned(),
                        );
                    }
                    // The lease matched the projected tip, but the canonical branch holds commits
                    // above it that the pusher cannot see: a rewrite would erase them.
                    if view.projected_to_canonical.get(tip) != Some(canonical_tip) {
                        return Err(REJECT_HIDDEN_HISTORY.to_owned());
                    }
                    let tip_tree = CommitObj::parse(&self.lookup(tip, GitObjectKind::Commit)?.data)
                        .map_err(|_| REJECT_REF)?
                        .tree;
                    let tip_visible = self.files_of(&tip_tree)?;
                    (
                        Some(Rc::new(self.hidden_files(
                            canonical_tip,
                            &tip_visible,
                            None,
                        )?)),
                        HashSet::new(),
                    )
                } else {
                    (None, tip_bases)
                }
            } else {
                (None, HashSet::new())
            };

        let denied =
            |path: &str| format!("policy denied WRITE on '{path}' for {}", identity.principal);
        let may_write = |path: &str| {
            RepoPath::new(path).is_ok_and(|rp| {
                rp.as_str() == path
                    && policy
                        .explain(identity, &rp, short_ref)
                        .allows(Capability::WRITE)
            })
        };

        // Pushed commit -> its canonical commit; canonical commit -> the files hidden from the
        // pusher in it; and the last tree flattened (a chain's next parent).
        let mut canonical_of_pushed: HashMap<String, String> = HashMap::new();
        let mut hidden_of: HashMap<String, Rc<FileMap>> = HashMap::new();
        let mut last_files: Option<(String, Rc<FileMap>)> = None;

        for oid in &order {
            let (raw, commit) = &pushed[oid];
            let canonical_parents = commit
                .parents
                .iter()
                .map(|p| {
                    canonical_of_pushed
                        .get(p)
                        .cloned()
                        .or_else(|| canonical_of_visible(p))
                        .ok_or_else(|| REJECT_OBJECT.to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;

            // What the pusher saw in the base parent (the parent descending from `canonical_tip`
            // on a fast-forward merge, e.g. `parent[1]` after `git merge main`, or otherwise the
            // first parent), and what they could not see there: carried over untouched. On a
            // force-push, every rewritten commit preserves the hidden files of the branch's
            // current `canonical_tip` so hidden files are never dropped or reverted.
            let ff_parent_idx = commit
                .parents
                .iter()
                .position(|p| descends_from_tip.contains(p));
            if ff_parent_idx.is_some() {
                descends_from_tip.insert(oid.clone());
            }
            let chosen_parent = ff_parent_idx
                .and_then(|i| commit.parents.get(i).zip(canonical_parents.get(i)))
                .or_else(|| commit.parents.first().zip(canonical_parents.first()));
            let (parent_files, hidden) = match chosen_parent {
                None => (
                    Rc::new(FileMap::new()),
                    force_push_hidden
                        .as_ref()
                        .map_or_else(|| Rc::new(FileMap::new()), Rc::clone),
                ),
                Some((parent, canonical_parent)) => {
                    let parent_tree = match pushed.get(parent) {
                        Some((_, c)) => c.tree.clone(),
                        None => {
                            let obj = self.lookup(parent, GitObjectKind::Commit)?;
                            CommitObj::parse(&obj.data).map_err(|_| REJECT_REF)?.tree
                        }
                    };
                    let parent_files = match &last_files {
                        Some((tree, files)) if *tree == parent_tree => Rc::clone(files),
                        _ => Rc::new(self.files_of(&parent_tree)?),
                    };
                    let hidden = if let Some(ref branch_hidden) = force_push_hidden {
                        Rc::clone(branch_hidden)
                    } else {
                        match hidden_of.get(canonical_parent) {
                            Some(hidden) => Rc::clone(hidden),
                            None => Rc::new(self.hidden_files(
                                canonical_parent,
                                &parent_files,
                                existing.is_none().then_some(short_ref),
                            )?),
                        }
                    };
                    (parent_files, hidden)
                }
            };

            let files = Rc::new(self.files_of(&commit.tree)?);
            if files.is_empty() && commit.parents.is_empty() {
                // The projection never starts a history with a commit that shows no file.
                return Err("a history cannot start with an empty commit".to_owned());
            }

            // Every entry this commit added or modified must be a real file the pusher sent or
            // can see, on a path they may WRITE and will be served back (or the commit would not
            // project to what they pushed). An entry identical to the parent's is untouched.
            let on_new_base = existing.is_none()
                && !commit
                    .parents
                    .first()
                    .is_some_and(|p| pushed.contains_key(p));
            let mut changed_paths = Vec::new();
            if let Some(colliding) = find_visible_case_collision(&files) {
                return Err(format!(
                    "'{colliding}' collides (ignoring case) with another path in the repository"
                ));
            }
            let hidden_lower: BTreeSet<String> =
                hidden.keys().map(|h| h.to_ascii_lowercase()).collect();
            for (path, entry) in files.iter() {
                let unchanged = parent_files.get(path) == Some(entry);
                if unchanged && !on_new_base {
                    continue;
                }
                if !path_is_projected(policy, identity, short_ref, path) {
                    return Err(format!(
                        "'{path}' cannot be pushed: it would not be readable by you on this branch"
                    ));
                }
                if unchanged {
                    continue;
                }
                if path.split('/').any(|seg| {
                    crate::is_config_or_gitmodules_component(seg)
                        && !matches!(
                            seg.to_ascii_lowercase().as_str(),
                            ".access.toml" | ".env.schema" | ".gitmodules"
                        )
                }) {
                    return Err(REJECT_TREE.to_owned());
                }
                let (mode, blob_oid) = entry;
                if !matches!(mode.as_str(), "100644" | "100755" | "120000") {
                    return Err(REJECT_TREE.to_owned());
                }
                let blob = self.lookup(blob_oid, GitObjectKind::Blob)?;
                if mode == "120000" {
                    let dest = crate::resolve_safe_symlink_target(path, &blob.data)
                        .map_err(|_| denied(path))?;
                    if collides_with_hidden(&dest, &hidden_lower)
                        || !path_is_projected(policy, identity, short_ref, &dest)
                    {
                        return Err(denied(path));
                    }
                }
                // A pushed path colliding (ignoring ASCII case) with a hidden file or directory
                // answers exactly like a policy denial.
                if collides_with_hidden(path, &hidden_lower) || !may_write(path) {
                    return Err(denied(path));
                }
                if self.unpacked.get(blob_oid).is_some() {
                    self.staged_blobs.insert(blob.oid.as_str(), blob);
                }
                changed_paths.extend(RepoPath::new(path).ok());
            }
            // Every file of the parent missing from the commit is a delete.
            for old_path in parent_files.keys() {
                if !files.contains_key(old_path) && !may_write(old_path) {
                    return Err(denied(old_path));
                }
            }
            // Structural OverlayGuard check: every path a commit introduces, and the whole tree
            // the branch ends up with.
            let guarded = if oid == new_projected_oid {
                files.keys().filter_map(|p| RepoPath::new(p).ok()).collect()
            } else {
                changed_paths
            };
            self.overlay_guard
                .validate_public_paths(&guarded)
                .map_err(|e| format!("overlay guard blocked push: {e}"))?;

            // The canonical commit: the pushed bytes with the canonical parents and a tree that
            // adds the hidden files back. Author, committer, dates, encoding, message and any
            // `gpgsig` are the pusher's, verbatim, so the projection of this commit is the
            // pushed commit again, bit for bit. A signature was made over the pushed bytes: it
            // verifies in the pusher's view, and not on the canonical commit whenever hidden
            // files or parents make that one differ. That is expected.
            let io = |e: GitBridgeError| e.to_string();
            let merged = hidden.iter().chain(files.iter());
            let tree = stage_tree(merged, &mut self.staged).map_err(io)?;
            let canonical_commit = GitObject::new(
                GitObjectKind::Commit,
                rewrite_commit(&raw.data, &tree, &canonical_parents).map_err(io)?,
            );
            hidden_of.insert(canonical_commit.oid.clone(), hidden);
            canonical_of_pushed.insert(oid.clone(), self.staged.insert(canonical_commit));
            last_files = Some((commit.tree.clone(), files));
        }

        // A ref pointed at a commit the pusher already sees needs no new commit at all —
        // except on a force-push whose target canonical commit has different hidden files from
        // the branch's current `canonical_tip`, in which case we stage a canonical commit that
        // carries over the branch's hidden files untouched.
        let canonical_oid = match canonical_of_pushed.get(new_projected_oid) {
            Some(canonical_oid) => canonical_oid.clone(),
            None => {
                let base_canonical = canonical_of_visible(new_projected_oid)
                    .ok_or_else(|| REJECT_OBJECT.to_owned())?;
                if existing.is_none() {
                    let commit = self.lookup(new_projected_oid, GitObjectKind::Commit)?;
                    let tree = CommitObj::parse(&commit.data).map_err(|_| REJECT_REF)?.tree;
                    let visible = self.files_of(&tree)?;
                    self.hidden_files(&base_canonical, &visible, Some(short_ref))?;
                    base_canonical
                } else if let Some(ref hidden) = force_push_hidden {
                    let raw_commit = self.lookup(new_projected_oid, GitObjectKind::Commit)?;
                    let parsed = CommitObj::parse(&raw_commit.data).map_err(|_| REJECT_REF)?;
                    let visible = self.files_of(&parsed.tree)?;
                    if let Some(colliding) = find_visible_case_collision(&visible) {
                        return Err(format!(
                            "'{colliding}' collides (ignoring case) with another path in the repository"
                        ));
                    }
                    let mut expected = (**hidden).clone();
                    let hidden_lower: BTreeSet<String> =
                        hidden.keys().map(|h| h.to_ascii_lowercase()).collect();
                    for (path, entry) in &visible {
                        if collides_with_hidden(path, &hidden_lower) {
                            return Err(denied(path));
                        }
                        if entry.0 == "120000" {
                            let blob = self.lookup(&entry.1, GitObjectKind::Blob)?;
                            let dest = crate::resolve_safe_symlink_target(path, &blob.data)
                                .map_err(|_| denied(path))?;
                            if collides_with_hidden(&dest, &hidden_lower)
                                || !path_is_projected(policy, identity, short_ref, &dest)
                            {
                                return Err(denied(path));
                            }
                        }
                        expected.insert(path.clone(), entry.clone());
                    }
                    if self.canonical_files(&base_canonical)? == expected {
                        base_canonical
                    } else {
                        // The replaced canonical commit's own parents, not the canonical commits
                        // the pusher's projected parents stand for: those would skip history that
                        // collapsed in their view and so erase it.
                        let canonical_parents =
                            CommitObj::parse(&self.canonical_bytes(&base_canonical)?)
                                .map_err(|_| REJECT_REF)?
                                .parents;
                        let io = |e: GitBridgeError| e.to_string();
                        let merged = hidden.iter().chain(visible.iter());
                        let tree = stage_tree(merged, &mut self.staged).map_err(io)?;
                        let rewritten = GitObject::new(
                            GitObjectKind::Commit,
                            rewrite_commit(&raw_commit.data, &tree, &canonical_parents)
                                .map_err(io)?,
                        );
                        self.staged.insert(rewritten)
                    }
                } else {
                    base_canonical
                }
            }
        };

        // Unconditionally enforce OverlayGuard on the final visible tree of `new_projected_oid`
        // for every non-delete branch push, including empty-pack FF and branch creation at an
        // existing visible commit.
        let final_visible = match &last_files {
            Some((_, files)) if canonical_of_pushed.contains_key(new_projected_oid) => {
                Rc::clone(files)
            }
            _ => {
                let raw = self.lookup(new_projected_oid, GitObjectKind::Commit)?;
                let tree = CommitObj::parse(&raw.data).map_err(|_| REJECT_REF)?.tree;
                Rc::new(self.files_of(&tree)?)
            }
        };
        let guarded: Vec<RepoPath> = final_visible
            .keys()
            .filter_map(|p| RepoPath::new(p).ok())
            .collect();
        self.overlay_guard
            .validate_public_paths(&guarded)
            .map_err(|e| format!("overlay guard blocked push: {e}"))?;

        // On an existing branch, WRITE is a property of the move itself (this branch, its tip ->
        // the new tip), whatever the pack carried and whichever branch the commits were first
        // pushed to: every path that differs between what the pusher sees of the two needs
        // WRITE here, and everything they cannot see must be this branch's own, untouched.
        if let Some((tip, _, canonical_tip)) = existing {
            let tree_of = |this: &Self, oid: &str| -> Result<String, String> {
                let commit = this.lookup(oid, GitObjectKind::Commit)?;
                Ok(CommitObj::parse(&commit.data).map_err(|_| REJECT_REF)?.tree)
            };
            let was = self.files_of(&tree_of(self, tip)?)?;
            let now = final_visible.as_ref();
            for (path, entry) in now {
                if was.get(path) != Some(entry)
                    && !(path_is_projected(policy, identity, short_ref, path) && may_write(path))
                {
                    return Err(denied(path));
                }
            }
            if let Some(deleted) = was.keys().find(|p| !now.contains_key(*p) && !may_write(p)) {
                return Err(denied(deleted));
            }
            let mut expected = self.canonical_files(canonical_tip)?;
            expected.retain(|path, _| !was.contains_key(path));
            expected.extend(now.iter().map(|(k, v)| (k.clone(), v.clone())));
            if self.canonical_files(&canonical_oid)? != expected {
                return Err(REJECT_REF.to_owned());
            }
            // The lease compares projected tips, which hide commits that changed only what the
            // pusher cannot see: a rewrite may only drop history they are shown in full.
            if force_push_hidden.is_some()
                && !self.drops_only_visible(ref_name, canonical_tip, &canonical_oid)?
            {
                return Err(REJECT_HIDDEN_HISTORY.to_owned());
            }
        }

        // Who may read the branch once it moves decides what the firewall checks.
        let target_visibility = match existing {
            Some((_, full_ref, _)) => view
                .ref_visibilities
                .get(ref_name)
                .cloned()
                .unwrap_or_else(|| default_ref_visibility(full_ref)),
            None => new_branch_visibility(
                self.pusher_is_owner,
                &identity.principal,
                &fork_sources(view, &bases),
            ),
        };
        self.check_firewall(
            ref_name,
            short_ref,
            &target_visibility,
            existing.map(|(tip, _, canonical_tip)| (tip, canonical_tip.as_str())),
            &order,
            &bases,
            &canonical_of_pushed,
        )?;

        let on_branch = |c: String| (c, short_ref.to_owned());
        self.pending_pushed_commits.extend(
            canonical_of_pushed
                .into_iter()
                .map(|(p, c)| (p, on_branch(c))),
        );
        self.pending_pushed_commits.insert(
            new_projected_oid.to_owned(),
            on_branch(canonical_oid.clone()),
        );

        let accepted = match existing {
            Some((_, full_ref, canonical_tip)) => AcceptedPush {
                canonical_ref: full_ref.clone(),
                canonical_oid,
                canonical_old: canonical_tip.clone(),
                commits: order.len(),
                created_visibility: None,
            },
            None => {
                let visibility = new_branch_visibility(
                    self.pusher_is_owner,
                    &identity.principal,
                    &fork_sources(view, &bases),
                );
                // Like every other branch: only a public one lives under `refs/heads/`.
                let namespace = if visibility == Visibility::Public {
                    "refs/heads/"
                } else {
                    PRIVATE_REF_PREFIX
                };
                AcceptedPush {
                    canonical_ref: format!("{namespace}{short_ref}"),
                    canonical_oid,
                    canonical_old: ZERO_OID.to_owned(),
                    commits: order.len(),
                    created_visibility: Some(visibility),
                }
            }
        };
        self.check_protected(&accepted)?;
        Ok(accepted)
    }

    /// Run the declassification firewall and the instruction quarantine over every commit this
    /// update brings to `ref_name`, one commit at a time (a secret added in one commit and
    /// deleted in the next is still refused). Every update checks its pushed commits (`order`);
    /// one that lands on a branch anonymous or signed-in readers see (`target_visibility`
    /// public or org) also checks the commits of the pusher's view it brings across that
    /// boundary (a fast-forward to a commit first pushed to a personal branch), against the
    /// restricted files of the canonical trees on both sides. The corpus never comes from what
    /// the pusher cannot see: an owner sees everything, and their leak is refused too.
    #[allow(clippy::too_many_arguments)]
    fn check_firewall(
        &mut self,
        ref_name: &str,
        short_ref: &str,
        target_visibility: &Visibility,
        existing: Option<(&str, &str)>,
        order: &[String],
        bases: &[String],
        canonical_of_pushed: &HashMap<String, String>,
    ) -> Result<(), String> {
        let (view, policy) = (self.view, self.policy);
        if !policy.firewall_enabled() && !policy.quarantine_enforced() {
            return Ok(());
        }
        let check_cross_boundary =
            matches!(target_visibility, Visibility::Public | Visibility::Org);
        let parse = |this: &Self, oid: &str| -> Result<CommitObj, String> {
            CommitObj::parse(&this.lookup(oid, GitObjectKind::Commit)?.data)
                .map_err(|_| REJECT_REF.to_owned())
        };

        // `(commit of the pusher's view or push, its canonical commit)`, and the canonical
        // commits already across the boundary that they grow from.
        let mut scan: Vec<(CommitObj, String)> = Vec::new();
        for oid in order {
            let canonical = canonical_of_pushed
                .get(oid)
                .cloned()
                .ok_or_else(|| REJECT_REF.to_owned())?;
            scan.push((parse(self, oid)?, canonical));
        }
        let mut crossed_bases: Vec<String> = existing
            .map(|(_, canonical_tip)| canonical_tip.to_owned())
            .into_iter()
            .collect();
        if check_cross_boundary {
            let at_least_as_open = |v: &Visibility| {
                *v == Visibility::Public
                    || (*target_visibility == Visibility::Org && *v == Visibility::Org)
            };
            let mut crossed_tips: Vec<String> = view
                .refs
                .iter()
                .filter(|(advertised, _)| advertised.starts_with("refs/heads/"))
                .filter(|(advertised, _)| {
                    let visibility =
                        view.ref_visibilities.get(*advertised).cloned().or_else(|| {
                            view.ref_sources
                                .get(*advertised)
                                .map(|(full_ref, _)| default_ref_visibility(full_ref))
                        });
                    visibility.is_some_and(|v| at_least_as_open(&v))
                })
                .map(|(_, tip)| tip.clone())
                .collect();
            crossed_tips.extend(existing.map(|(tip, _)| tip.to_owned()));
            let crossed = view_ancestors(view, crossed_tips);
            let mut stack: Vec<String> = bases
                .iter()
                .filter(|b| !crossed.contains(*b))
                .cloned()
                .collect();
            let mut seen = HashSet::new();
            while let Some(oid) = stack.pop() {
                if !seen.insert(oid.clone()) {
                    continue;
                }
                if seen.len() > MAX_PUSH_COMMITS {
                    return Err(format!(
                        "more than {MAX_PUSH_COMMITS} commits would reach this branch at once; move it in smaller steps"
                    ));
                }
                let commit = parse(self, &oid)?;
                let canonical = view
                    .projected_to_canonical
                    .get(&oid)
                    .cloned()
                    .ok_or_else(|| REJECT_OBJECT.to_owned())?;
                stack.extend(
                    commit
                        .parents
                        .iter()
                        .filter(|p| !crossed.contains(*p))
                        .cloned(),
                );
                scan.push((commit, canonical));
            }
            for (commit, _) in &scan {
                crossed_bases.extend(
                    commit
                        .parents
                        .iter()
                        .filter(|p| crossed.contains(*p))
                        .filter_map(|p| view.projected_to_canonical.get(p).cloned()),
                );
            }
        }

        let corpus = if policy.firewall_enabled() && check_cross_boundary {
            let mut public_of: HashMap<String, bool> = HashMap::new();
            let mut is_public = |path: &str| {
                *public_of.entry(path.to_owned()).or_insert_with(|| {
                    RepoPath::new(path).is_ok_and(|rp| policy.is_path_public(&rp, short_ref))
                })
            };
            let mut seen: HashSet<(String, String)> = HashSet::new();
            let (mut private, mut already_public) = (Vec::new(), Vec::new());
            crossed_bases.sort();
            crossed_bases.dedup();
            // Restricted files of the scanned commits too: one introduced by the first commit of
            // a push and copied to a public file by the second is caught.
            let scanned: Vec<String> = scan
                .iter()
                .map(|(_, canonical)| canonical.clone())
                .collect();
            for (commit, on_boundary) in crossed_bases
                .iter()
                .map(|c| (c, true))
                .chain(scanned.iter().map(|c| (c, false)))
            {
                for (path, (mode, oid)) in self.canonical_files(commit)? {
                    if mode == "160000" {
                        continue;
                    }
                    let public = is_public(&path);
                    if (public && !on_boundary) || !seen.insert((path.clone(), oid.clone())) {
                        continue;
                    }
                    let mut content = self.canonical_bytes(&oid)?;
                    content.truncate(MAX_CORPUS_BLOB_BYTES);
                    let entry = PrivateBlobEntry { path, content };
                    if public {
                        already_public.push(entry);
                    } else {
                        private.push(entry);
                    }
                }
            }
            Some(PrivateCorpus::build(
                &private,
                &already_public,
                policy.firewall_min_snippet_bytes(),
                policy.firewall_min_shingle_matches(),
            ))
        } else {
            None
        };

        for (commit, _) in &scan {
            let now = self.files_of(&commit.tree)?;
            let before = match commit.parents.first() {
                Some(parent) => {
                    let tree = parse(self, parent)?.tree;
                    self.files_of(&tree)?
                }
                None => FileMap::new(),
            };
            let mut files = Vec::new();
            for (path, entry @ (mode, oid)) in &now {
                // Symlinks too: their target is a path. Never a gitlink's commit.
                if before.get(path) == Some(entry)
                    || !matches!(mode.as_str(), "100644" | "100755" | "120000")
                {
                    continue;
                }
                files.push(ScanTargetFile {
                    path: path.clone(),
                    content: self.lookup(oid, GitObjectKind::Blob)?.data.to_vec(),
                    deleted: false,
                });
            }
            files.extend(
                before
                    .keys()
                    .filter(|path| !now.contains_key(*path))
                    .map(|path| ScanTargetFile {
                        path: path.clone(),
                        content: Vec::new(),
                        deleted: true,
                    }),
            );
            let report = run_declassification_firewall(&FirewallScanInput {
                policy,
                ref_name: short_ref,
                commit_messages: std::slice::from_ref(&commit.message),
                files: &files,
                corpus: corpus.as_ref(),
                vault: self.firewall.vault,
                check_cross_boundary,
                actor_is_owner: self.pusher_is_owner,
                actor_is_agent: self.identity.agent_task.is_some(),
                approved_instructions: self.firewall.approved_instructions,
            });
            if !report.passed {
                if let Some(on_blocked) = self.firewall.on_blocked {
                    on_blocked(ref_name, &report);
                }
                return Err(report
                    .push_rejection_message(self.pusher_is_owner)
                    .unwrap_or_else(|| GENERIC_FIREWALL_REJECT.to_owned()));
            }
        }
        Ok(())
    }
}

/// Every commit of `view` reachable from `tips`.
fn view_ancestors(view: &ProjectedView, tips: Vec<String>) -> HashSet<String> {
    let mut seen = HashSet::new();
    let mut stack = tips;
    while let Some(oid) = stack.pop() {
        if !seen.insert(oid.clone()) {
            continue;
        }
        if let Some(obj) = view.odb.get(&oid)
            && obj.kind == GitObjectKind::Commit
            && let Ok(commit) = CommitObj::parse(&obj.data)
        {
            stack.extend(commit.parents);
        }
    }
    seen
}

/// For each commit a new branch grows from, how visible that commit already is: public if a
/// public branch holds it, else the one visibility of the branches that do. Commits held only by
/// branches of differing visibility yield two entries, which no single visibility satisfies.
fn fork_sources(view: &ProjectedView, bases: &[String]) -> Vec<Visibility> {
    let mut sources = Vec::new();
    for base in bases {
        let mut holders: Vec<&Visibility> = view
            .refs
            .iter()
            .filter(|(advertised, tip)| {
                advertised.starts_with("refs/heads/") && is_ancestor(&view.odb, base, tip)
            })
            .filter_map(|(advertised, _)| view.ref_visibilities.get(advertised))
            .collect();
        if holders.contains(&&Visibility::Public) {
            holders = vec![&Visibility::Public];
        }
        holders.dedup();
        sources.extend(holders.into_iter().cloned());
    }
    sources
}

fn parse_receive_commands(body: &[u8]) -> Result<ParsedReceive, GitBridgeError> {
    let mut i = 0usize;
    let mut commands = Vec::new();
    let mut caps = Vec::new();

    while i + 4 <= body.len() {
        let len_bytes = &body[i..i + 4];
        if !len_bytes.iter().all(u8::is_ascii_hexdigit) {
            return Err(GitBridgeError::Protocol(format!(
                "invalid pkt-line hex '{}'",
                String::from_utf8_lossy(len_bytes)
            )));
        }
        let len_str = std::str::from_utf8(len_bytes)
            .map_err(|_| GitBridgeError::Protocol("non-ASCII receive-pack pkt-line".to_owned()))?;
        let len = usize::from_str_radix(len_str, 16)
            .map_err(|_| GitBridgeError::Protocol(format!("invalid pkt-line hex '{len_str}'")))?;
        i += 4;
        if len == 0 {
            break;
        }
        if len < 4 || i + (len - 4) > body.len() {
            return Err(GitBridgeError::Protocol(
                "truncated receive-pack command".to_owned(),
            ));
        }
        let payload = &body[i..i + (len - 4)];
        i += len - 4;

        let (cmd_bytes, cap_bytes) = match payload.iter().position(|&b| b == 0) {
            Some(nul) => (&payload[..nul], Some(&payload[nul + 1..])),
            None => (payload, None),
        };
        if let Some(cb) = cap_bytes {
            let cap_str = String::from_utf8_lossy(cb);
            for tok in cap_str.split_whitespace() {
                caps.push(tok.to_owned());
            }
        }
        let cmd_str = String::from_utf8_lossy(cmd_bytes);
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        if parts.len() >= 3 {
            commands.push(ReceiveCommand {
                old_oid: parts[0].to_owned(),
                new_oid: parts[1].to_owned(),
                ref_name: parts[2].to_owned(),
            });
        }
    }

    Ok(ParsedReceive {
        commands,
        caps,
        pack_offset: i,
    })
}

fn pack_err(msg: &str) -> GitBridgeError {
    GitBridgeError::GitObject(msg.to_owned())
}

/// Unpack a raw Git Packfile v2 stream into `out` (supports non-delta, `OFS_DELTA`, and `REF_DELTA`).
///
/// A delta may only build on an object of the same pack or of the pusher's own projected view:
/// resolving a base from the canonical store would let a pusher reconstruct any object whose OID
/// they can guess.
pub fn unpack_packfile(
    pack: &[u8],
    projected_odb: &InMemoryOdb,
    out: &mut InMemoryOdb,
) -> Result<(), GitBridgeError> {
    unpack_with_limits(pack, projected_odb, out, MAX_OBJECT_BYTES)
}

pub(crate) fn unpack_with_limits(
    pack: &[u8],
    projected_odb: &InMemoryOdb,
    out: &mut InMemoryOdb,
    max_object_bytes: usize,
) -> Result<(), GitBridgeError> {
    if pack.len() < 32 || &pack[0..4] != b"PACK" {
        return Err(pack_err("invalid packfile header"));
    }
    let version = u32::from_be_bytes([pack[4], pack[5], pack[6], pack[7]]);
    if version != 2 {
        return Err(GitBridgeError::GitObject(format!(
            "unsupported packfile version {version}"
        )));
    }
    let expected_checksum = &pack[pack.len() - 20..];
    let mut hasher = Sha1::new();
    hasher.update(&pack[..pack.len() - 20]);
    if hasher.finalize().as_slice() != expected_checksum {
        return Err(pack_err("packfile SHA-1 checksum mismatch"));
    }

    let num_objects = u32::from_be_bytes([pack[8], pack[9], pack[10], pack[11]]) as usize;
    if num_objects > MAX_PACK_OBJECTS {
        return Err(pack_err("packfile declares too many objects"));
    }
    let payload_end = pack.len() - 20;
    let mut pos = 12usize;
    let mut by_offset: HashMap<usize, String> = HashMap::new();
    let mut total_bytes = 0usize;
    let next_byte = |pos: &mut usize| -> Result<u8, GitBridgeError> {
        let b = *pack[..payload_end]
            .get(*pos)
            .ok_or_else(|| pack_err("unexpected EOF while unpacking packfile"))?;
        *pos += 1;
        Ok(b)
    };

    for _ in 0..num_objects {
        let entry_start = pos;
        let b0 = next_byte(&mut pos)?;
        let obj_type = (b0 >> 4) & 0x07;
        // The declared size is not trusted; only the continuation bytes are skipped.
        let mut cont = (b0 & 0x80) != 0;
        while cont {
            cont = (next_byte(&mut pos)? & 0x80) != 0;
        }

        let obj = match obj_type {
            1..=4 => {
                let kind = match obj_type {
                    1 => GitObjectKind::Commit,
                    2 => GitObjectKind::Tree,
                    3 => GitObjectKind::Blob,
                    _ => GitObjectKind::Tag,
                };
                let (data, consumed) = inflate_zlib(&pack[pos..payload_end], max_object_bytes)?;
                pos += consumed;
                GitObject::new(kind, data)
            }
            6 => {
                // OBJ_OFS_DELTA
                let mut b = next_byte(&mut pos)?;
                let mut rel_offset = (b & 0x7f) as usize;
                while (b & 0x80) != 0 {
                    if rel_offset > pack.len() {
                        return Err(pack_err("invalid OFS_DELTA offset"));
                    }
                    b = next_byte(&mut pos)?;
                    rel_offset = ((rel_offset + 1) << 7) | ((b & 0x7f) as usize);
                }
                let base = entry_start
                    .checked_sub(rel_offset)
                    .and_then(|base_offset| by_offset.get(&base_offset))
                    .and_then(|oid| out.get(oid))
                    .ok_or_else(|| pack_err("OFS_DELTA base missing"))?;
                let (delta, consumed) = inflate_zlib(&pack[pos..payload_end], max_object_bytes)?;
                pos += consumed;
                let reconstructed = apply_git_delta(&base.data, &delta, max_object_bytes)?;
                GitObject::new(base.kind, reconstructed)
            }
            7 => {
                // OBJ_REF_DELTA
                if pos + 20 > payload_end {
                    return Err(pack_err("truncated REF_DELTA base OID"));
                }
                let base_oid = hex::encode(&pack[pos..pos + 20]);
                pos += 20;
                let base = out
                    .get(&base_oid)
                    .or_else(|| projected_odb.get(&base_oid))
                    .ok_or_else(|| pack_err("REF_DELTA base is not in the pack or your view"))?;
                let (delta, consumed) = inflate_zlib(&pack[pos..payload_end], max_object_bytes)?;
                pos += consumed;
                let reconstructed = apply_git_delta(&base.data, &delta, max_object_bytes)?;
                GitObject::new(base.kind, reconstructed)
            }
            other => {
                return Err(GitBridgeError::GitObject(format!(
                    "unsupported pack object type {other}"
                )));
            }
        };

        total_bytes += obj.data.len();
        if total_bytes > MAX_PACK_BYTES {
            return Err(pack_err("packfile inflates beyond the size limit"));
        }
        by_offset.insert(entry_start, obj.oid.clone());
        out.insert(obj);
    }

    Ok(())
}

fn inflate_zlib(input: &[u8], max_bytes: usize) -> Result<(Vec<u8>, usize), GitBridgeError> {
    let mut decomp = Decompress::new(true);
    let mut output = Vec::new();
    let mut buf = [0u8; 8192];

    loop {
        let in_pos = decomp.total_in() as usize;
        let before_out = decomp.total_out();
        let status = decomp
            .decompress(&input[in_pos..], &mut buf, FlushDecompress::None)
            .map_err(|e| GitBridgeError::GitObject(format!("zlib inflate error: {e}")))?;
        let produced = (decomp.total_out() - before_out) as usize;
        if output.len() + produced > max_bytes {
            return Err(pack_err("pack object inflates beyond the size limit"));
        }
        output.extend_from_slice(&buf[..produced]);
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if produced == 0 && (decomp.total_in() as usize) == in_pos {
                    return Err(pack_err("truncated zlib stream in packfile"));
                }
            }
        }
    }

    Ok((output, decomp.total_in() as usize))
}

fn delta_byte(data: &[u8], pos: &mut usize) -> Result<usize, GitBridgeError> {
    let b = *data.get(*pos).ok_or_else(|| pack_err("truncated delta"))?;
    *pos += 1;
    Ok(b as usize)
}

fn read_delta_varint(data: &[u8], pos: &mut usize) -> Result<usize, GitBridgeError> {
    let mut result = 0usize;
    let mut shift = 0usize;
    loop {
        let b = delta_byte(data, pos)?;
        if shift > 56 {
            return Err(pack_err("delta size out of range"));
        }
        result |= (b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
}

fn apply_git_delta(base: &[u8], delta: &[u8], max_bytes: usize) -> Result<Vec<u8>, GitBridgeError> {
    let mut pos = 0usize;
    let src_len = read_delta_varint(delta, &mut pos)?;
    if src_len != base.len() {
        return Err(pack_err("delta source length mismatch"));
    }
    let dst_len = read_delta_varint(delta, &mut pos)?;
    if dst_len > max_bytes {
        return Err(pack_err("pack object inflates beyond the size limit"));
    }
    let mut out = Vec::with_capacity(dst_len);

    while pos < delta.len() {
        let cmd = delta_byte(delta, &mut pos)?;
        if (cmd & 0x80) != 0 {
            let mut cp_off = 0usize;
            let mut cp_size = 0usize;
            for (bit, shift) in [(0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)] {
                if (cmd & bit) != 0 {
                    cp_off |= delta_byte(delta, &mut pos)? << shift;
                }
            }
            for (bit, shift) in [(0x10, 0), (0x20, 8), (0x40, 16)] {
                if (cmd & bit) != 0 {
                    cp_size |= delta_byte(delta, &mut pos)? << shift;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            if cp_off + cp_size > base.len() {
                return Err(pack_err("delta copy out of bounds"));
            }
            out.extend_from_slice(&base[cp_off..cp_off + cp_size]);
        } else if cmd > 0 {
            if pos + cmd > delta.len() {
                return Err(pack_err("delta insert out of bounds"));
            }
            out.extend_from_slice(&delta[pos..pos + cmd]);
            pos += cmd;
        } else {
            return Err(pack_err("invalid zero delta opcode"));
        }
        if out.len() > dst_len {
            return Err(pack_err("delta result length mismatch"));
        }
    }
    if out.len() != dst_len {
        return Err(pack_err("delta result length mismatch"));
    }

    Ok(out)
}

/// Flatten a pushed or projected tree into `path -> (mode, oid)`. Subtrees resolve only through
/// `tree_data`; leaf entries are recorded as sent and judged by the caller.
fn flatten_tree<'a>(
    tree_data: &dyn Fn(&str) -> Result<&'a [u8], String>,
    tree_oid: &str,
    prefix: &str,
    depth: usize,
    out: &mut FileMap,
) -> Result<(), String> {
    let raw = tree_data(tree_oid)?;
    // Only trees the projection itself would write (and never an empty directory): anything
    // else could not project back to the pushed commit.
    if depth > MAX_TREE_DEPTH || !is_canonical_tree(raw) || (raw.is_empty() && depth > 0) {
        return Err(REJECT_TREE.to_owned());
    }
    for entry in parse_tree(raw).map_err(|_| REJECT_TREE.to_owned())? {
        if entry.name.contains('/') || is_reserved_path_component(&entry.name) {
            return Err(REJECT_TREE.to_owned());
        }
        let rel = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        if entry.is_dir() {
            flatten_tree(tree_data, &entry.oid_hex, &rel, depth + 1, out)?;
        } else {
            if out.len() >= MAX_TREE_FILES {
                return Err(REJECT_TREE.to_owned());
            }
            out.insert(rel, (entry.mode, entry.oid_hex));
        }
    }
    Ok(())
}

fn flatten_canonical_tree(
    reader: &mut ObjectReader,
    tree_oid: &str,
    prefix: &str,
    out: &mut FileMap,
) -> Result<(), GitBridgeError> {
    let obj = reader.read(tree_oid)?;
    for entry in parse_tree(&obj.data)? {
        let rel = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        if entry.is_dir() {
            flatten_canonical_tree(reader, &entry.oid_hex, &rel, out)?;
        } else {
            out.insert(rel, (entry.mode, entry.oid_hex));
        }
    }
    Ok(())
}

#[derive(Default)]
struct DirBuilder {
    files: Vec<TreeEntry>,
    dirs: BTreeMap<String, DirBuilder>,
}

impl DirBuilder {
    fn insert(&mut self, segments: &[&str], mode: String, oid_hex: String) {
        if segments.len() == 1 {
            self.files.push(TreeEntry {
                mode,
                name: segments[0].to_owned(),
                oid_hex,
            });
            return;
        }
        let child = self.dirs.entry(segments[0].to_owned()).or_default();
        child.insert(&segments[1..], mode, oid_hex);
    }

    fn stage(self, out: &mut InMemoryOdb) -> Result<String, GitBridgeError> {
        let mut entries = self.files;
        for (dir_name, child) in self.dirs {
            let child_oid = child.stage(out)?;
            entries.push(TreeEntry {
                mode: "40000".to_owned(),
                name: dir_name,
                oid_hex: child_oid,
            });
        }
        Ok(out.insert(GitObject::new(GitObjectKind::Tree, encode_tree(entries)?)))
    }
}

/// Build the tree holding `files` into `out` and return its OID.
fn stage_tree<'f>(
    files: impl Iterator<Item = (&'f String, &'f (String, String))>,
    out: &mut InMemoryOdb,
) -> Result<String, GitBridgeError> {
    let mut root = DirBuilder::default();
    for (path, (mode, oid)) in files {
        let segs: Vec<&str> = path.split('/').collect();
        root.insert(&segs, mode.clone(), oid.clone());
    }
    root.stage(out)
}
