//! Reversible Algebraic Zone Projector (Josh-inspired) & Squash-Declassify Gate.
//!
//! Dynamically projects a canonical Git DAG into an isolated, `git fsck --strict`-clean
//! projected object database where unauthorized files, filenames, and blob hashes never exist.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use premier_core::{Capability, DelegatedIdentity, RepoPath, Visibility};
use premier_overlay::OverlayGuard;
use premier_policy::{
    CompiledPolicy, DeclassificationReport, FirewallScanInput, PrivateBlobEntry, PrivateCorpus,
    ScanTargetFile, VaultSecretIndex, run_declassification_firewall,
};
use sha2::{Digest, Sha256};

use crate::objects::{
    CanonicalGitRepo, CommitObj, GitObject, GitObjectKind, InMemoryOdb, ObjectReader, TreeEntry,
    commit_has_gpgsig, encode_tree, git_command, hash_git_object, parse_tag_object, parse_tree,
    rewrite_commit, rewrite_tag_object,
};
use crate::{
    GitBridgeError, PRIVATE_REF_PREFIX, ProjectionAttestation, ScopeId, ScopeReachabilityLedger,
    is_reserved_path_component, resolve_safe_symlink_target,
};

/// Result of projecting a canonical repository for one caller identity & policy.
#[derive(Debug, Clone)]
pub struct ProjectedView {
    pub scope: ScopeId,
    pub refs: BTreeMap<String, String>,
    pub odb: InMemoryOdb,
    pub ledger: ScopeReachabilityLedger,
    pub canonical_to_projected: HashMap<String, String>,
    /// Projected commit -> the canonical commit it was rewritten from (never a collapsed one).
    pub projected_to_canonical: HashMap<String, String>,
    /// Advertised ref -> `(canonical full ref, canonical tip when this view was projected)`.
    pub ref_sources: HashMap<String, (String, String)>,
    /// Advertised ref -> the visibility it was admitted under.
    pub ref_visibility: HashMap<String, Visibility>,
    /// Advertised visible branch ref (`refs/heads/<name>`) -> its `Visibility`.
    pub ref_visibilities: HashMap<String, Visibility>,
    pub policy_fingerprint: String,
    #[cfg(test)]
    pub(crate) projected_commit_count: usize,
}

impl ProjectedView {
    /// The attestation tying a projected commit to its canonical one. It lives outside the commit
    /// object: anything written into the commit would change its hash, and a pushed commit must
    /// project back to exactly the bytes its author pushed.
    pub fn attestation(&self, projected_oid: &str) -> Option<ProjectionAttestation> {
        let canonical = self.projected_to_canonical.get(projected_oid)?;
        // Nothing here verifies signatures, so it does not claim to.
        Some(ProjectionAttestation::build(
            canonical,
            &self.policy_fingerprint,
            false,
        ))
    }

    /// The canonical commit behind a commit id of this view, given whole or abbreviated (an
    /// ambiguous abbreviation names nothing). A canonical id that is not one of the view's own
    /// commits answers like an unknown one.
    pub fn canonical_commit(&self, projected: &str) -> Option<&str> {
        if let Some(canonical) = self.projected_to_canonical.get(projected) {
            return Some(canonical);
        }
        let mut found = self
            .projected_to_canonical
            .iter()
            .filter(|(p, _)| p.starts_with(projected));
        let first = found.next()?;
        found.next().is_none().then_some(first.1.as_str())
    }

    /// Canonical commit -> the commit a clone of `advertised_ref` has for it. A commit that
    /// collapsed onto its parent (it changed nothing the caller sees) is in no clone and not here.
    // shortcut: walks the ref's projected history per call, and two canonical commits with one
    // projection (the same commit pushed onto two hidden states) share one entry; keep a per-ref
    // map in the view if either shows up.
    pub fn commits_on(&self, advertised_ref: &str) -> HashMap<String, String> {
        let mut out = HashMap::new();
        let mut stack: Vec<&str> = self
            .refs
            .get(advertised_ref)
            .map(String::as_str)
            .into_iter()
            .collect();
        let mut seen = HashSet::new();
        while let Some(oid) = stack.pop() {
            if !seen.insert(oid) {
                continue;
            }
            let Some((projected, canonical)) = self.projected_to_canonical.get_key_value(oid)
            else {
                continue;
            };
            out.insert(canonical.clone(), projected.clone());
            if let Some(obj) = self.odb.get(oid)
                && let Ok(commit) = CommitObj::parse(&obj.data)
            {
                for parent in &commit.parents {
                    if let Some((parent, _)) =
                        self.projected_to_canonical.get_key_value(parent.as_str())
                    {
                        stack.push(parent);
                    }
                }
            }
        }
        out
    }
}

/// The one rule for a branch nobody chose a visibility for. `sources` are the visibilities of
/// what it forks from. An owner's branch is as visible as its single source (public without
/// one); anyone else's, and any ambiguous case, is the creator's alone: the most restrictive
/// choice that still shows it to them, so creating a branch can never publish anything.
pub fn new_branch_visibility(
    creator_is_owner: bool,
    creator: &premier_core::Principal,
    sources: &[Visibility],
) -> Visibility {
    match sources {
        [] if creator_is_owner => Visibility::Public,
        [first, rest @ ..] if creator_is_owner && rest.iter().all(|v| v == first) => first.clone(),
        _ => Visibility::Personal(creator.canonical_id()),
    }
}

/// Whether `project_tree` keeps the file at `path` for `identity` on `ref_name`.
pub fn path_is_projected(
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    ref_name: &str,
    path: &str,
) -> bool {
    let caps = |p: &str| {
        RepoPath::new(p)
            .ok()
            .filter(|rp| rp.as_str() == p)
            .map(|rp| policy.explain(identity, &rp, ref_name).effective)
    };
    caps(path).is_some_and(|c| c.contains(Capability::READ))
        && path.match_indices('/').all(|(i, _)| {
            caps(&path[..i]).is_some_and(|c| {
                c.intersects(Capability::TRAVERSE | Capability::LIST | Capability::READ)
            })
        })
}

/// Whether a ref named `to_ref`, pointed at a tree holding `hidden` (the files `identity` cannot
/// read under the ref(s) that tree comes from), would let them read any of them: path rules are
/// ref-scoped, so naming a branch can unlock files. The one check for every path that creates or
/// moves a ref onto an existing commit on a caller's behalf (Git push, the API).
pub fn exposes_hidden_files<'p>(
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    to_ref: &str,
    hidden: impl IntoIterator<Item = &'p str>,
) -> bool {
    // READ on the file itself, a superset of what the projection serves: the file API answers on it.
    hidden.into_iter().any(|p| {
        RepoPath::new(p).is_ok_and(|rp| {
            policy
                .explain(identity, &rp, to_ref)
                .allows(Capability::READ)
        })
    })
}

pub(crate) const EMPTY_TREE_OID: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";
pub(crate) const GITLINK_MODE: &str = "160000";
const MAX_TAG_PEEL_DEPTH: usize = 8;

/// Process-wide weak interner for immutable projected blob payloads, deduplicating identical
/// `Arc<[u8]>` buffers across refs and cached `ProjectedView` entries without pinning evicted RAM.
static BLOB_INTERNER: OnceLock<Mutex<HashMap<String, Weak<[u8]>>>> = OnceLock::new();

fn intern_blob_bytes(oid: &str, data: Arc<[u8]>) -> Arc<[u8]> {
    let table = BLOB_INTERNER.get_or_init(|| Mutex::new(HashMap::new()));
    let Ok(mut map) = table.lock() else {
        return data;
    };
    if let Some(existing) = map.get(oid).and_then(Weak::upgrade)
        && existing.as_ref() == data.as_ref()
    {
        return existing;
    }
    if map.len() >= 4096 {
        map.retain(|_, weak| weak.strong_count() > 0);
    }
    map.insert(oid.to_owned(), Arc::downgrade(&data));
    data
}

/// Finished projections, most recent last. The key covers everything a projection depends on
/// (repository, identity, compiled policy, ref visibility, canonical ref tips), so a push or a
/// policy change misses by construction.
const PROJECTION_CACHE_BUDGET: usize = 128 * 1024 * 1024;
const PROJECTION_CACHE_MAX_ENTRIES: usize = 64;
static PROJECTION_CACHE: Mutex<ProjectionCache> =
    Mutex::new(ProjectionCache::new(PROJECTION_CACHE_BUDGET));

struct CachedProjection {
    key: [u8; 32],
    view: Arc<ProjectedView>,
    bytes: usize,
}

struct ProjectionCache {
    entries: VecDeque<CachedProjection>,
    bytes: usize,
    budget: usize,
}

impl ProjectionCache {
    const fn new(budget: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            bytes: 0,
            budget,
        }
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<Arc<ProjectedView>> {
        let index = self.entries.iter().position(|entry| &entry.key == key)?;
        let entry = self.entries.remove(index)?;
        let view = Arc::clone(&entry.view);
        self.entries.push_back(entry);
        Some(view)
    }

    fn insert(&mut self, key: [u8; 32], view: Arc<ProjectedView>, bytes: usize) {
        if bytes > self.budget || self.get(&key).is_some() {
            return;
        }
        while bytes > self.budget - self.bytes || self.entries.len() == PROJECTION_CACHE_MAX_ENTRIES
        {
            let Some(evicted) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= evicted.bytes;
        }
        self.bytes += bytes;
        self.entries
            .push_back(CachedProjection { key, view, bytes });
    }
}

pub(crate) fn hash_table_bytes<K, V>(capacity: usize) -> usize {
    // Account for the control bytes and slack of the hash table's buckets.
    if capacity == 0 {
        return 0;
    }
    let buckets = (capacity + capacity.div_ceil(7)).next_power_of_two().max(4);
    16 + buckets * (size_of::<(K, V)>() + 1)
}

pub(crate) fn visibility_bytes(visibility: &Visibility) -> usize {
    match visibility {
        Visibility::Personal(owner) => owner.capacity(),
        Visibility::Restricted(selectors) => {
            selectors.capacity() * size_of::<String>()
                + selectors.iter().map(String::capacity).sum::<usize>()
        }
        Visibility::Org | Visibility::Public => 0,
    }
}

impl ProjectedView {
    fn cache_bytes(&self) -> usize {
        let string_map_bytes = |map: &HashMap<String, String>| {
            hash_table_bytes::<String, String>(map.capacity())
                + map
                    .iter()
                    .map(|(key, value)| key.capacity() + value.capacity())
                    .sum::<usize>()
        };
        let visibility_map_bytes = |map: &HashMap<String, Visibility>| {
            hash_table_bytes::<String, Visibility>(map.capacity())
                + map
                    .iter()
                    .map(|(key, value)| key.capacity() + visibility_bytes(value))
                    .sum::<usize>()
        };
        // The ODB only grows during construction. Its cloned keys have the length of each OID.
        let object_bytes = self
            .odb
            .iter()
            .map(|obj| obj.oid.len() + obj.oid.capacity() + obj.data.len())
            .sum::<usize>();
        size_of::<CachedProjection>() + size_of::<Self>() + 2 * size_of::<usize>()
            + self.scope.0.capacity()
            + self.policy_fingerprint.capacity()
            + hash_table_bytes::<String, GitObject>(self.odb.len())
            + object_bytes
            + self.ledger.retained_bytes()
            // Conservative allowance for B-tree nodes, including unoccupied slots.
            + self.refs.iter().map(|(key, value)| {
                12 * size_of::<(String, String)>() + key.capacity() + value.capacity()
            }).sum::<usize>()
            + string_map_bytes(&self.canonical_to_projected)
            + string_map_bytes(&self.projected_to_canonical)
            + hash_table_bytes::<String, (String, String)>(self.ref_sources.capacity())
            + self.ref_sources.iter().map(|(key, (source, tip))| {
                key.capacity() + source.capacity() + tip.capacity()
            }).sum::<usize>()
            + visibility_map_bytes(&self.ref_visibility)
            + visibility_map_bytes(&self.ref_visibilities)
    }
}

/// Result of executing a real Squash-Declassify landing commit onto a target branch.
#[derive(Debug, Clone)]
pub struct SquashDeclassifyResult {
    pub new_commit_oid: String,
    pub target_ref: String,
    /// Paths the commit added, changed or deleted on the target.
    pub published_paths: Vec<String>,
    /// Paths the source changed that were left out (the target keeps its own version).
    pub scrubbed_paths: Vec<String>,
    pub attestation: ProjectionAttestation,
    /// The full message of the new commit, attestation trailer included.
    pub commit_message: String,
}

/// A caller's last word on a squash commit (given its oid) before the target ref moves to it.
pub type RefUpdateCheck<'a> = &'a dyn Fn(&str) -> Result<(), String>;

/// Selector of the implicit owners group (the server's principal directory puts every owner in it).
pub const OWNERS_SELECTOR: &str = "group:owners";

/// The one rule for a ref nobody declared a visibility for, shared by the API and the Git
/// projection: branches are public, the private namespace is the owners'.
pub fn default_ref_visibility(full_ref: &str) -> Visibility {
    if full_ref.starts_with(PRIVATE_REF_PREFIX) {
        Visibility::Restricted(vec![OWNERS_SELECTOR.to_owned()])
    } else {
        Visibility::Public
    }
}

/// Evaluate whether `identity` may see a Git ref with the given `Visibility`. An owner sees every
/// ref of the workspace, another user's personal branch included: the one rule for API and Git.
pub fn can_see_ref(identity: &DelegatedIdentity, visibility: &Visibility) -> bool {
    if identity.matches_selector(OWNERS_SELECTOR) {
        return true;
    }
    match visibility {
        Visibility::Public => true,
        Visibility::Org => identity.principal.is_authenticated(),
        Visibility::Restricted(allow) => allow.iter().any(|sel| identity.matches_selector(sel)),
        Visibility::Personal(owner) => identity.matches_selector(owner),
    }
}

/// Project all authorized refs and commit graphs of `canonical` for `identity` under `policy`.
///
/// Guarantees:
/// - Unauthorized refs (private branches) are completely omitted.
/// - Unauthorized blobs and empty denied subtrees are completely omitted (zero filename/hash leaks).
/// - A rewritten commit differs from its canonical one only in `tree` and `parent` headers; its
///   attestation is out-of-band ([`ProjectedView::attestation`]).
/// - All reachable projected OIDs are registered in an isolated per-scope `ScopeReachabilityLedger` (anti-CFOR).
pub fn project_repository(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    identity: &DelegatedIdentity,
    ref_visibility: &HashMap<String, Visibility>,
) -> Result<Arc<ProjectedView>, GitBridgeError> {
    let canonical_refs = canonical.list_refs()?;

    let mut visibility: Vec<_> = ref_visibility.iter().collect();
    visibility.sort_by(|a, b| a.0.cmp(b.0));
    let key: [u8; 32] = Sha256::digest(format!(
        "{:?}\0{identity:?}\0{policy:?}\0{policy_fingerprint}\0{visibility:?}\0{canonical_refs:?}",
        canonical.root()
    ))
    .into();
    if let Ok(mut cache) = PROJECTION_CACHE.lock()
        && let Some(hit) = cache.get(&key)
    {
        return Ok(hit);
    }

    let view = Arc::new(project_uncached(
        canonical,
        policy,
        policy_fingerprint,
        identity,
        ref_visibility,
        canonical_refs,
    )?);
    let bytes = view.cache_bytes();
    if let Ok(mut cache) = PROJECTION_CACHE.lock() {
        cache.insert(key, Arc::clone(&view), bytes);
    }
    Ok(view)
}

#[cfg(test)]
mod cache_tests {
    use super::*;

    fn view(payload: usize) -> Arc<ProjectedView> {
        let mut odb = InMemoryOdb::default();
        odb.insert(GitObject::new(GitObjectKind::Blob, vec![0; payload]));
        Arc::new(ProjectedView {
            scope: ScopeId("test".into()),
            refs: BTreeMap::new(),
            odb,
            ledger: ScopeReachabilityLedger::default(),
            canonical_to_projected: HashMap::new(),
            projected_to_canonical: HashMap::new(),
            ref_sources: HashMap::new(),
            ref_visibility: HashMap::new(),
            ref_visibilities: HashMap::new(),
            policy_fingerprint: "test".into(),
            projected_commit_count: 0,
        })
    }

    #[test]
    fn cache_evicts_lru_under_byte_pressure_and_skips_oversized_views() {
        let one = view(1024);
        let two = view(1024);
        let three = view(1024);
        let bytes = one.cache_bytes();
        let mut cache = ProjectionCache::new(2 * bytes);
        cache.insert([1; 32], Arc::clone(&one), bytes);
        cache.insert([2; 32], two, bytes);
        assert!(cache.get(&[1; 32]).is_some());
        cache.insert([3; 32], three, bytes);
        assert!(cache.get(&[2; 32]).is_none());
        assert!(cache.get(&[1; 32]).is_some());
        assert!(cache.get(&[3; 32]).is_some());
        let oversized = view(4 * bytes);
        cache.insert([4; 32], Arc::clone(&oversized), oversized.cache_bytes());
        assert!(cache.get(&[4; 32]).is_none());
        assert_eq!(cache.bytes, 2 * bytes);
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn blob_interner_deduplicates_shared_arc_payloads_across_views() {
        let payload = b"shared-projected-blob-payload-wave3".to_vec();
        let oid = hash_git_object(GitObjectKind::Blob, &payload);
        let first = intern_blob_bytes(&oid, Arc::from(payload.clone()));
        let second = intern_blob_bytes(&oid, Arc::from(payload));
        assert!(
            Arc::ptr_eq(&first, &second),
            "identical blob OIDs across views must share one Arc<[u8]> allocation"
        );
    }
}

/// Mutable state of one projection run.
struct Projection {
    scope: ScopeId,
    odb: InMemoryOdb,
    ledger: ScopeReachabilityLedger,
    /// Canonical commit -> projected commit, for refs that agree on the memo's path decisions.
    commits: HashMap<String, Option<String>>,
    trees: TreeMemo,
    canonical_to_projected: HashMap<String, String>,
    /// Canonical commit -> its canonical tree.
    canonical_trees: HashMap<String, String>,
    /// Projected commit -> its tree.
    projected_trees: HashMap<String, String>,
    projected_to_canonical: HashMap<String, String>,
    reverse_mapping_collision: bool,
    #[cfg(test)]
    projected_commit_count: usize,
}

impl Projection {
    fn reset_history(&mut self) {
        self.commits.clear();
        self.trees.clear();
    }

    fn memoize_commit(&mut self, canonical: String, projected: Option<String>, branch: bool) {
        if branch && let Some(oid) = &projected {
            self.canonical_to_projected
                .insert(canonical.clone(), oid.clone());
        }
        self.commits.insert(canonical, projected);
        #[cfg(test)]
        {
            self.projected_commit_count += 1;
        }
    }
}

#[derive(Default)]
struct TreeMemo {
    trees: HashMap<(String, String), Option<String>>,
    /// The effective decisions the cached trees actually depended upon, including denials and
    /// directory traversal. Reusing history requires checking them under the incoming ref.
    decisions: HashMap<(RepoPath, bool), bool>,
}

impl TreeMemo {
    fn clear(&mut self) {
        self.trees.clear();
        self.decisions.clear();
    }

    fn compatible(
        &self,
        policy: &CompiledPolicy,
        identity: &DelegatedIdentity,
        ref_name: &str,
    ) -> bool {
        self.decisions.iter().all(|((path, is_dir), allowed)| {
            *allowed == Self::permits(policy, identity, ref_name, path, *is_dir)
        })
    }

    fn permits(
        policy: &CompiledPolicy,
        identity: &DelegatedIdentity,
        ref_name: &str,
        path: &RepoPath,
        is_dir: bool,
    ) -> bool {
        let effective = policy.explain(identity, path, ref_name).effective;
        let required = if is_dir {
            Capability::TRAVERSE | Capability::LIST | Capability::READ
        } else {
            Capability::READ
        };
        effective.intersects(required)
    }

    fn permits_and_remember(
        &mut self,
        policy: &CompiledPolicy,
        identity: &DelegatedIdentity,
        ref_name: &str,
        path: RepoPath,
        is_dir: bool,
    ) -> bool {
        *self
            .decisions
            .entry((path, is_dir))
            .or_insert_with_key(|(path, is_dir)| {
                Self::permits(policy, identity, ref_name, path, *is_dir)
            })
    }
}

fn project_uncached(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    identity: &DelegatedIdentity,
    ref_visibility: &HashMap<String, Visibility>,
    canonical_refs: Vec<(String, String)>,
) -> Result<ProjectedView, GitBridgeError> {
    let (view, collision) = project_pass(
        canonical,
        policy,
        policy_fingerprint,
        identity,
        ref_visibility,
        &canonical_refs,
        true,
    )?;
    if collision {
        // Multiple canonical commits can rewrite to the same projected OID. In this unusual
        // case, preserve the per-ref traversal's last-writer attestation and tag semantics.
        drop(view);
        return project_pass(
            canonical,
            policy,
            policy_fingerprint,
            identity,
            ref_visibility,
            &canonical_refs,
            false,
        )
        .map(|(view, _)| view);
    }
    Ok(view)
}

fn project_pass(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    identity: &DelegatedIdentity,
    ref_visibility: &HashMap<String, Visibility>,
    canonical_refs: &[(String, String)],
    reuse_history: bool,
) -> Result<(ProjectedView, bool), GitBridgeError> {
    let mut reader = canonical.reader()?;
    let mut st = Projection {
        scope: ScopeId(format!(
            "{}:{}",
            identity.principal.canonical_id(),
            &policy_fingerprint[..policy_fingerprint.len().min(12)]
        )),
        odb: InMemoryOdb::default(),
        ledger: ScopeReachabilityLedger::default(),
        commits: HashMap::new(),
        trees: TreeMemo::default(),
        canonical_to_projected: HashMap::new(),
        canonical_trees: HashMap::new(),
        projected_trees: HashMap::new(),
        projected_to_canonical: HashMap::new(),
        reverse_mapping_collision: false,
        #[cfg(test)]
        projected_commit_count: 0,
    };
    let mut projected_refs = BTreeMap::new();
    let mut ref_sources = HashMap::new();
    let mut admitted = HashMap::new();

    let mut branch_refs = Vec::new();
    let mut tag_refs = Vec::new();
    for (full_ref, oid) in canonical_refs.iter().cloned() {
        if full_ref.starts_with("refs/tags/") {
            tag_refs.push((full_ref, oid));
        } else {
            branch_refs.push((full_ref, oid));
        }
    }

    for (full_ref, canonical_tip) in branch_refs {
        let short_name = full_ref
            .strip_prefix("refs/heads/")
            .or_else(|| full_ref.strip_prefix(PRIVATE_REF_PREFIX))
            .unwrap_or(&full_ref);

        let vis = ref_visibility
            .get(&full_ref)
            .or_else(|| ref_visibility.get(short_name))
            .cloned()
            .unwrap_or_else(|| default_ref_visibility(&full_ref));

        if !can_see_ref(identity, &vis) {
            continue;
        }
        // A ref whose tip shows the caller no file is not advertised at all: the branch name and
        // its commits' authors, dates and messages are private too. Checked before projecting so
        // none of its objects ever enter the caller's scope ledger (anti-CFOR).
        let tip = CommitObj::parse(&reader.read(&canonical_tip)?.data)?;
        if !tree_has_readable_file(&mut reader, policy, identity, short_name, &tip.tree, "")? {
            continue;
        }
        if !reuse_history || !st.trees.compatible(policy, identity, short_name) {
            st.reset_history();
        }

        let projected_tip = project_commit(
            &mut reader,
            policy,
            identity,
            short_name,
            &canonical_tip,
            &mut st,
            true,
        )?;
        let Some(projected_tip) = projected_tip else {
            continue;
        };

        // Expose authorized private branches cleanly under `refs/heads/<name>` for the allowed caller.
        let advertised_ref = format!("refs/heads/{short_name}");
        ref_sources.insert(advertised_ref.clone(), (full_ref.clone(), canonical_tip));
        admitted.insert(advertised_ref.clone(), vis);
        projected_refs.insert(advertised_ref, projected_tip);
    }

    // Project `refs/tags/*` strictly against already-projected visible commits (anti-CFOR: tags
    // pointing to commits outside `canonical_to_projected`, or to collapsed secret-only commits
    // whose projected commit belongs to an earlier canonical commit, are completely invisible).
    // Nested annotated tags (tag -> tag -> ... -> commit) are peeled up to `MAX_TAG_PEEL_DEPTH`.
    let is_owner = identity.matches_selector(OWNERS_SELECTOR);
    for (full_ref, canonical_oid) in tag_refs {
        let short_tag = full_ref.strip_prefix("refs/tags/").unwrap_or(&full_ref);
        let explicit_tag_vis = ref_visibility
            .get(&full_ref)
            .or_else(|| ref_visibility.get(&format!("tags/{short_tag}")));
        if let Some(vis) = explicit_tag_vis
            && !can_see_ref(identity, vis)
        {
            continue;
        }
        let mut tag_chain: Vec<Vec<u8>> = Vec::new();
        let mut seen_tags: HashSet<String> = HashSet::new();
        let mut cur_oid = canonical_oid.clone();
        let target_commit_oid = loop {
            let Ok(obj) = reader.read(&cur_oid) else {
                break None;
            };
            match obj.kind {
                GitObjectKind::Commit => break Some(cur_oid),
                GitObjectKind::Tag => {
                    if tag_chain.len() >= MAX_TAG_PEEL_DEPTH || !seen_tags.insert(cur_oid.clone()) {
                        break None;
                    }
                    let Ok(next_oid) = parse_tag_object(&obj.data) else {
                        break None;
                    };
                    tag_chain.push(obj.data.to_vec());
                    cur_oid = next_oid;
                }
                GitObjectKind::Tree | GitObjectKind::Blob => break None,
            }
        };

        let Some(target_commit_oid) = target_commit_oid else {
            continue;
        };
        // An owner sees every ref, so also a tag no branch holds any more: its history is
        // projected on its own, under the tag's full name (no branch-scoped rule matches it),
        // so they can fetch it and delete it.
        if is_owner && !st.canonical_to_projected.contains_key(&target_commit_oid) {
            st.reset_history();
            if let Ok(Some(projected)) = project_commit(
                &mut reader,
                policy,
                identity,
                &full_ref,
                &target_commit_oid,
                &mut st,
                false,
            ) {
                st.canonical_to_projected
                    .insert(target_commit_oid.clone(), projected);
            }
        }
        let Some(projected_c) = st.canonical_to_projected.get(&target_commit_oid) else {
            continue;
        };
        if st.projected_to_canonical.get(projected_c) != Some(&target_commit_oid) {
            continue;
        }

        if tag_chain.is_empty() {
            ref_sources.insert(full_ref.clone(), (full_ref.clone(), canonical_oid));
            projected_refs.insert(full_ref, projected_c.clone());
        } else {
            let mut rewritten_tags: Vec<GitObject> = Vec::with_capacity(tag_chain.len());
            let mut next_target = projected_c.clone();
            let mut ok = true;
            for raw_tag in tag_chain.iter().rev() {
                let Ok(rewritten) = rewrite_tag_object(raw_tag, &next_target) else {
                    ok = false;
                    break;
                };
                let tag_obj = GitObject::new(GitObjectKind::Tag, rewritten);
                next_target = tag_obj.oid.clone();
                rewritten_tags.push(tag_obj);
            }
            if ok {
                for tag_obj in rewritten_tags {
                    let oid = st.odb.insert(tag_obj);
                    st.ledger.register_oid(st.scope.clone(), oid);
                }
                ref_sources.insert(full_ref.clone(), (full_ref.clone(), canonical_oid));
                projected_refs.insert(full_ref, next_target);
            }
        }
    }

    Ok((
        ProjectedView {
            scope: st.scope,
            refs: projected_refs,
            odb: st.odb,
            ledger: st.ledger,
            canonical_to_projected: st.canonical_to_projected,
            projected_to_canonical: st.projected_to_canonical,
            ref_sources,
            ref_visibility: admitted.clone(),
            ref_visibilities: admitted,
            policy_fingerprint: policy_fingerprint.to_owned(),
            #[cfg(test)]
            projected_commit_count: st.projected_commit_count,
        },
        st.reverse_mapping_collision,
    ))
}

/// Whether a clone by `identity` would be served the branch `short_name` whose tip is the
/// canonical commit `tip`, visibility aside: the rule [`project_repository`] advertises refs by.
pub fn tip_is_served(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    short_name: &str,
    tip: &str,
) -> Result<bool, GitBridgeError> {
    let mut reader = canonical.reader()?;
    let tip = CommitObj::parse(&reader.read(tip)?.data)?;
    tree_has_readable_file(&mut reader, policy, identity, short_name, &tip.tree, "")
}

/// Project one canonical commit's tree for `identity` (the same rules as a clone of
/// `policy_ref_name`) into a fresh, isolated object store: the tree a workspace for that caller
/// is hydrated from. `None` when the caller may read no file of it. Restricted files, their
/// names and their blob oids never enter the returned store.
pub fn project_commit_tree_for_workspace(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    policy_ref_name: &str,
    canonical_commit_oid: &str,
) -> Result<Option<(String, InMemoryOdb)>, GitBridgeError> {
    let mut reader = canonical.reader()?;
    let commit = CommitObj::parse(&reader.read(canonical_commit_oid)?.data)?;
    if !tree_has_readable_file(
        &mut reader,
        policy,
        identity,
        policy_ref_name,
        &commit.tree,
        "",
    )? {
        return Ok(None);
    }
    let scope = ScopeId(format!(
        "workspace:{}:{canonical_commit_oid}",
        identity.principal.canonical_id()
    ));
    let mut odb = InMemoryOdb::default();
    let tree = project_tree(
        &mut reader,
        policy,
        identity,
        policy_ref_name,
        &commit.tree,
        "",
        &scope,
        &mut odb,
        &mut ScopeReachabilityLedger::default(),
        &mut Vec::new(),
        &mut TreeMemo::default(),
    )?;
    Ok(tree.map(|oid| (oid, odb)))
}

/// Whether `identity` may read at least one file under the tree, by the same rules as
/// `project_tree`. An empty root tree counts as readable (its history may still show files).
fn tree_has_readable_file(
    reader: &mut ObjectReader,
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    ref_name: &str,
    tree_oid: &str,
    prefix: &str,
) -> Result<bool, GitBridgeError> {
    let entries = parse_tree(&reader.read(tree_oid)?.data)?;
    if entries.is_empty() {
        return Ok(prefix.is_empty());
    }
    for entry in entries {
        let rel_path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        let Ok(repo_path) = RepoPath::new(&rel_path) else {
            continue;
        };
        let dec = policy.explain(identity, &repo_path, ref_name);
        let readable = if entry.is_dir() {
            dec.effective
                .intersects(Capability::TRAVERSE | Capability::LIST | Capability::READ)
                && tree_has_readable_file(
                    reader,
                    policy,
                    identity,
                    ref_name,
                    &entry.oid_hex,
                    &rel_path,
                )?
        } else {
            dec.allows(Capability::READ)
        };
        if readable {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Project `tip` and its whole ancestry (iteratively: history depth never touches the stack).
///
/// A commit that changed only paths the caller cannot see is not rewritten at all: it collapses
/// onto its first projected parent, so its message, author and date never reach the caller.
///
/// A projected commit is the canonical one with only its `tree` and `parent` headers replaced.
/// Signatures (`gpgsig`) are kept verbatim: one made over a pushed commit verifies for whoever is
/// served the same bytes, one made over different canonical bytes does not verify here.
fn project_commit(
    reader: &mut ObjectReader,
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    ref_name: &str,
    tip: &str,
    st: &mut Projection,
    branch: bool,
) -> Result<Option<String>, GitBridgeError> {
    let mut stack = vec![tip.to_owned()];
    while let Some(canonical_oid) = stack.last().cloned() {
        if st.commits.contains_key(&canonical_oid) {
            stack.pop();
            continue;
        }
        let raw = reader.read(&canonical_oid)?.data;
        let parsed = CommitObj::parse(&raw)?;
        let pending: Vec<String> = parsed
            .parents
            .iter()
            .filter(|p| !st.commits.contains_key(*p))
            .cloned()
            .collect();
        if !pending.is_empty() {
            stack.extend(pending);
            continue;
        }
        stack.pop();

        let projected_tree = project_tree(
            reader,
            policy,
            identity,
            ref_name,
            &parsed.tree,
            "",
            &st.scope,
            &mut st.odb,
            &mut st.ledger,
            &mut Vec::new(),
            &mut st.trees,
        )?;
        // Ensure root tree always exists (even if empty tree for fully restricted caller).
        let root_tree_oid = match projected_tree {
            Some(oid) => oid,
            None => {
                let oid = st
                    .odb
                    .insert(GitObject::new(GitObjectKind::Tree, Vec::new()));
                st.ledger.register_oid(st.scope.clone(), oid.clone());
                oid
            }
        };

        let mut projected_parents: Vec<String> = Vec::new();
        for p in &parsed.parents {
            if let Some(Some(pp)) = st.commits.get(p)
                && !projected_parents.contains(pp)
            {
                projected_parents.push(pp.clone());
            }
        }

        // Did this commit change anything canonically? (An intentionally empty commit touches no
        // restricted path and stays visible.)
        let parent_canonical_tree = parsed
            .parents
            .first()
            .and_then(|p| st.canonical_trees.get(p))
            .map_or(EMPTY_TREE_OID, String::as_str);
        let changed_canonically = parsed.tree != parent_canonical_tree;
        st.canonical_trees
            .insert(canonical_oid.clone(), parsed.tree.clone());

        let collapsed = match projected_parents.split_first() {
            // Nothing visible here or anywhere before it, whether or not the commit changed
            // anything canonically: a history never starts with a commit that shows no file.
            None => (root_tree_oid == EMPTY_TREE_OID).then_some(None),
            // Nothing visible changed against the first parent, and every other parent's
            // visible history is already part of it: nothing to show for this commit.
            Some((first, rest)) => (changed_canonically
                && st.projected_trees.get(first) == Some(&root_tree_oid)
                && rest.iter().all(|o| is_ancestor(&st.odb, o, first)))
            .then(|| Some(first.clone())),
        };
        if let Some(onto) = collapsed {
            st.memoize_commit(canonical_oid, onto, branch);
            continue;
        }

        let projected_oid = st.odb.insert(GitObject::new(
            GitObjectKind::Commit,
            rewrite_commit(&raw, &root_tree_oid, &projected_parents)?,
        ));
        st.ledger
            .register_oid(st.scope.clone(), projected_oid.clone());
        st.projected_trees
            .insert(projected_oid.clone(), root_tree_oid);
        if let Some(prior) = st
            .projected_to_canonical
            .insert(projected_oid.clone(), canonical_oid.clone())
        {
            st.reverse_mapping_collision |= prior != canonical_oid;
        }
        st.memoize_commit(canonical_oid, Some(projected_oid), branch);
    }

    Ok(st.commits.get(tip).cloned().flatten())
}

/// Whether projected commit `ancestor` is `of` or reachable from it.
pub(crate) fn is_ancestor(odb: &InMemoryOdb, ancestor: &str, of: &str) -> bool {
    let mut seen = HashSet::new();
    let mut stack = vec![of.to_owned()];
    while let Some(oid) = stack.pop() {
        if oid == ancestor {
            return true;
        }
        if !seen.insert(oid.clone()) {
            continue;
        }
        if let Some(obj) = odb.get(&oid)
            && let Ok(c) = CommitObj::parse(&obj.data)
        {
            stack.extend(c.parents);
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn project_tree(
    reader: &mut ObjectReader,
    policy: &CompiledPolicy,
    identity: &DelegatedIdentity,
    ref_name: &str,
    canonical_tree_oid: &str,
    prefix: &str,
    scope: &ScopeId,
    odb: &mut InMemoryOdb,
    ledger: &mut ScopeReachabilityLedger,
    scrubbed_paths: &mut Vec<String>,
    // Subtrees already projected at the same path (so `scrubbed_paths` lists them once).
    memo: &mut TreeMemo,
) -> Result<Option<String>, GitBridgeError> {
    let memo_key = (canonical_tree_oid.to_owned(), prefix.to_owned());
    if let Some(done) = memo.trees.get(&memo_key) {
        return Ok(done.clone());
    }
    let raw_tree = reader.read(canonical_tree_oid)?;
    let entries = parse_tree(&raw_tree.data)?;
    let mut kept_entries = Vec::new();

    for entry in entries {
        let rel_path = if prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{prefix}/{}", entry.name)
        };
        let Ok(repo_path) = RepoPath::new(&rel_path) else {
            continue;
        };

        let is_dir = entry.is_dir();
        if !memo.permits_and_remember(policy, identity, ref_name, repo_path, is_dir) {
            scrubbed_paths.push(if is_dir {
                format!("{rel_path}/")
            } else {
                rel_path
            });
            continue;
        }
        if is_dir {
            if let Some(child_tree_oid) = project_tree(
                reader,
                policy,
                identity,
                ref_name,
                &entry.oid_hex,
                &rel_path,
                scope,
                odb,
                ledger,
                scrubbed_paths,
                memo,
            )? {
                kept_entries.push(TreeEntry {
                    mode: "40000".to_owned(),
                    name: entry.name,
                    oid_hex: child_tree_oid,
                });
            }
        } else {
            // A gitlink names a commit of another repository: keep the entry, there is no
            // object of ours behind it.
            let blob_oid = if entry.mode == GITLINK_MODE || odb.get(&entry.oid_hex).is_some() {
                entry.oid_hex
            } else {
                let mut blob = reader.read(&entry.oid_hex)?;
                blob.data = intern_blob_bytes(&blob.oid, blob.data);
                let blob_oid = odb.insert(blob);
                ledger.register_oid(scope.clone(), blob_oid.clone());
                blob_oid
            };
            kept_entries.push(TreeEntry {
                mode: entry.mode,
                name: entry.name,
                oid_hex: blob_oid,
            });
        }
    }

    if kept_entries.is_empty() && !prefix.is_empty() {
        // Prune empty denied subtrees completely (zero directory-name leakage!).
        memo.trees.insert(memo_key, None);
        return Ok(None);
    }

    let encoded = encode_tree(kept_entries)?;
    let tree_obj = GitObject::new(GitObjectKind::Tree, encoded);
    let tree_oid = odb.insert(tree_obj);
    ledger.register_oid(scope.clone(), tree_oid.clone());
    memo.trees.insert(memo_key, Some(tree_oid.clone()));
    Ok(Some(tree_oid))
}

/// Collect all reachable objects from `wants` inside the isolated `ProjectedView` ODB,
/// stopping at `haves` strictly inside the caller's authorized scope.
pub fn collect_reachable_objects<'a>(
    view: &'a ProjectedView,
    wants: &[String],
    haves: &[String],
) -> Result<Vec<&'a GitObject>, GitBridgeError> {
    // Anti-oracle validation: EVERY requested `want` must exist in the caller's scope!
    for w in wants {
        view.ledger.require_oid_in_scope(&view.scope, w)?;
    }
    // Neutral `have` filter: ignore any OID outside the caller's scope.
    let valid_haves: HashSet<&str> = view
        .ledger
        .filter_negotiated_haves(&view.scope, haves)
        .into_iter()
        .collect();

    // Mark ancestors of valid `haves` as already possessed by client.
    let mut stop_set: HashSet<String> = HashSet::new();
    let mut have_stack: Vec<String> = valid_haves.into_iter().map(str::to_owned).collect();
    while let Some(oid) = have_stack.pop() {
        if !stop_set.insert(oid.clone()) {
            continue;
        }
        if let Some(obj) = view.odb.get(&oid) {
            match obj.kind {
                GitObjectKind::Commit => {
                    if let Ok(c) = CommitObj::parse(&obj.data) {
                        for p in c.parents {
                            have_stack.push(p);
                        }
                    }
                }
                GitObjectKind::Tag => {
                    if let Ok(target) = parse_tag_object(&obj.data) {
                        have_stack.push(target);
                    }
                }
                GitObjectKind::Tree | GitObjectKind::Blob => {}
            }
        }
    }

    let mut visited = HashSet::new();
    let mut stack: Vec<String> = wants.to_vec();
    let mut out = Vec::new();

    while let Some(oid) = stack.pop() {
        if stop_set.contains(&oid) || !visited.insert(oid.clone()) {
            continue;
        }
        let Some(obj) = view.odb.get(&oid) else {
            return Err(GitBridgeError::ObjectNotVisible);
        };
        match obj.kind {
            GitObjectKind::Commit => {
                let c = CommitObj::parse(&obj.data)?;
                stack.push(c.tree);
                for p in c.parents {
                    stack.push(p);
                }
            }
            GitObjectKind::Tree => {
                for entry in parse_tree(&obj.data)? {
                    if entry.mode != GITLINK_MODE {
                        stack.push(entry.oid_hex);
                    }
                }
            }
            GitObjectKind::Tag => {
                if let Ok(target) = parse_tag_object(&obj.data) {
                    stack.push(target);
                }
            }
            GitObjectKind::Blob => {}
        }
        out.push(obj);
    }

    Ok(out)
}

/// What a Squash-Declassify publish of one source commit onto one target tip would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SquashPlan {
    /// Paths to write on the target, with their `(mode, oid)` on the source; `None` deletes.
    pub changes: Vec<(String, Option<(String, String)>)>,
    /// Paths the source changed that are not published (see [`publishable`]).
    pub scrubbed_paths: Vec<String>,
    /// Published paths the target changed too since the merge base: the publish is refused.
    pub conflicts: Vec<String>,
    /// Published paths whose new content is that of a file the public may not read (a private
    /// file copied or moved to a public path): the publish is refused.
    pub blocked: Vec<String>,
    /// Line-level 3-way merged blob payloads for paths changed cleanly on both source and target.
    pub merged_blobs: BTreeMap<String, Vec<u8>>,
    /// Commits of the source the target does not have. Their number says how much hidden work
    /// there is: only for a caller who may see all of the source.
    pub source_commits: usize,
    /// Those of them that changed at least one publishable path: what the public could count.
    pub source_commits_public: usize,
    /// For each path in `changes` the target already has: its `(mode, oid)` there.
    pub target_before: BTreeMap<String, (String, String)>,
}

/// Every file of a tree: path -> `(mode, oid)`.
pub(crate) type TreeFiles = BTreeMap<String, (String, String)>;

/// A tree, flattened: its files and its directories (path -> tree oid).
#[derive(Default)]
pub(crate) struct TreeListing {
    pub(crate) files: TreeFiles,
    pub(crate) dirs: BTreeMap<String, String>,
}

/// The message of a publish commit (public on the target): `summary` when the owner gave one,
/// else `Publish to <target>`, then the attestation trailer. It names neither the source branch
/// nor anything about what was held back. A publish preview proposes exactly this.
pub fn publish_commit_message(
    summary: &str,
    target_ref: &str,
    attestation: &ProjectionAttestation,
) -> String {
    let target = target_ref.strip_prefix("refs/heads/").unwrap_or(target_ref);
    let title = match summary.trim() {
        "" => format!("Publish to {target}"),
        summary => summary.to_owned(),
    };
    format!("{title}\n\n{}\n", attestation.to_git_trailer())
}

/// Copy detection is a best-effort exact-content check, not an access boundary (path rules are):
/// any non-empty private blob found at a public path blocks the publish, however short. Only the
/// empty blob (`.gitkeep`) is exempt, since it carries nothing and is everywhere.
pub(crate) const MIN_BLOCKED_BLOB_BYTES: u64 = 1;

pub(crate) fn git_stdout(
    root: &Path,
    index: Option<&Path>,
    args: &[&str],
    stdin: &[u8],
) -> Result<String, GitBridgeError> {
    use std::io::Write as _;
    use std::process::Stdio;
    let io = |e: std::io::Error| GitBridgeError::Io(format!("git {}: {e}", args[0]));
    let mut cmd = git_command(root);
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(io)?;
    let written = child
        .stdin
        .take()
        .map_or(Ok(()), |mut pipe| pipe.write_all(stdin));
    let out = child.wait_with_output().map_err(io)?;
    written.map_err(io)?;
    if !out.status.success() {
        return Err(GitBridgeError::Io(format!("git {} failed", args[0])));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub(crate) fn tree_files(root: &Path, rev: Option<&str>) -> Result<TreeListing, GitBridgeError> {
    let mut listing = TreeListing::default();
    let Some(rev) = rev else {
        return Ok(listing);
    };
    // `<mode> <type> <oid>\t<path>` per entry (a gitlink is listed as one file).
    let out = git_stdout(
        root,
        None,
        &["ls-tree", "-r", "-t", "-z", "--end-of-options", rev],
        b"",
    )?;
    for line in out.split('\0').filter(|line| !line.is_empty()) {
        let entry = line.split_once('\t').and_then(|(meta, path)| {
            let mut meta = meta.split(' ');
            Some((meta.next()?, meta.next()?, meta.next()?, path))
        });
        let Some((mode, kind, oid, path)) = entry else {
            return Err(GitBridgeError::GitObject(
                "unreadable git ls-tree output".to_owned(),
            ));
        };
        if kind == "tree" {
            listing.dirs.insert(path.to_owned(), oid.to_owned());
        } else {
            listing
                .files
                .insert(path.to_owned(), (mode.to_owned(), oid.to_owned()));
        }
    }
    Ok(listing)
}

/// The scrub rule, the one [`project_tree`] applies for the anonymous public: a path is published
/// only if anonymous may `read` it, and enter (`traverse`, `list` or `read`) every directory
/// above it, on the target branch. A reserved path ([`is_reserved_path_component`]) never is.
pub fn publishable(policy: &CompiledPolicy, ref_name: &str, path: &str) -> bool {
    if path.split('/').any(is_reserved_path_component) {
        return false;
    }
    let public = DelegatedIdentity::human_only(premier_core::Principal::Anonymous, vec![]);
    let may = |path: &str, any_of: Capability| {
        RepoPath::new(path).is_ok_and(|rp| {
            policy
                .explain(&public, &rp, ref_name)
                .effective
                .intersects(any_of)
        })
    };
    let enter = Capability::TRAVERSE | Capability::LIST | Capability::READ;
    may(path, Capability::READ)
        && path
            .match_indices('/')
            .all(|(end, _)| may(&path[..end], enter))
}

/// Attempt a clean 3-way line-level merge via `git merge-file -p <source> <base> <target>`.
/// Returns `Ok(Some(bytes))` only when `git merge-file` exits 0 (no conflicts, non-binary).
pub(crate) fn try_three_way_merge(
    canonical: &CanonicalGitRepo,
    source_oid: &str,
    base_oid: &str,
    target_oid: &str,
) -> Result<Option<Vec<u8>>, GitBridgeError> {
    merge_file_bytes(
        canonical.root(),
        &canonical.read_object(source_oid)?.data,
        &canonical.read_object(base_oid)?.data,
        &canonical.read_object(target_oid)?.data,
    )
}

/// [`try_three_way_merge`] over blob contents, wherever they were read from.
pub(crate) fn merge_file_bytes(
    root: &Path,
    source: &[u8],
    base: &[u8],
    target: &[u8],
) -> Result<Option<Vec<u8>>, GitBridgeError> {
    let tmp = tempfile::tempdir()
        .map_err(|e| GitBridgeError::Io(format!("tempdir for 3-way merge failed: {e}")))?;
    let source_path = tmp.path().join("source");
    let base_path = tmp.path().join("base");
    let target_path = tmp.path().join("target");
    std::fs::write(&source_path, source)
        .map_err(|e| GitBridgeError::Io(format!("write source blob failed: {e}")))?;
    std::fs::write(&base_path, base)
        .map_err(|e| GitBridgeError::Io(format!("write base blob failed: {e}")))?;
    std::fs::write(&target_path, target)
        .map_err(|e| GitBridgeError::Io(format!("write target blob failed: {e}")))?;

    let out = git_command(root)
        .args(["merge-file", "-p", "--"])
        .arg(&source_path)
        .arg(&base_path)
        .arg(&target_path)
        .output()
        .map_err(|e| GitBridgeError::Io(format!("git merge-file failed: {e}")))?;

    if out.status.success() {
        Ok(Some(out.stdout))
    } else {
        Ok(None)
    }
}

/// Content the public may not read, gathered from tree listings: every blob at an unpublishable
/// path, and every directory with no publishable file in it. Path rules alone would publish a
/// private file copied (or a private directory moved) to a public path.
#[derive(Default)]
pub(crate) struct PrivateContent {
    pub(crate) blobs: HashSet<String>,
    trees: HashSet<String>,
}

impl PrivateContent {
    pub(crate) fn add(&mut self, listing: &TreeListing, is_public: &dyn Fn(&str) -> bool) {
        let mut public_dirs: HashSet<&str> = HashSet::new();
        for (path, (mode, oid)) in &listing.files {
            if is_public(path) {
                public_dirs.extend(path.match_indices('/').map(|(end, _)| &path[..end]));
            } else if mode != GITLINK_MODE {
                self.blobs.insert(oid.clone());
            }
        }
        let private = listing
            .dirs
            .iter()
            .filter(|(dir, _)| !public_dirs.contains(dir.as_str()));
        self.trees.extend(private.map(|(_, oid)| oid.clone()));
    }

    /// The private blobs `source` shows at public paths, minus content the target already shows
    /// the public (`already_public`) and the empty blob ([`MIN_BLOCKED_BLOB_BYTES`]).
    pub(crate) fn restricted_in(
        &self,
        root: &Path,
        source: &TreeListing,
        is_public: &dyn Fn(&str) -> bool,
        already_public: &HashSet<String>,
    ) -> Result<HashSet<String>, GitBridgeError> {
        let suspects: HashSet<&str> = source
            .files
            .iter()
            .filter(|(path, (_, oid))| {
                is_public(path) && self.blobs.contains(oid) && !already_public.contains(oid)
            })
            .map(|(_, (_, oid))| oid.as_str())
            .collect();
        let mut restricted = HashSet::new();
        if suspects.is_empty() {
            return Ok(restricted);
        }
        let oids: String = suspects.iter().map(|oid| format!("{oid}\n")).collect();
        let sizes = git_stdout(
            root,
            None,
            &["cat-file", "--batch-check=%(objectname) %(objectsize)"],
            oids.as_bytes(),
        )?;
        for line in sizes.lines() {
            match line
                .split_once(' ')
                .map(|(oid, size)| (oid, size.parse::<u64>()))
            {
                Some((oid, Ok(size))) if size >= MIN_BLOCKED_BLOB_BYTES => {
                    restricted.insert(oid.to_owned());
                }
                Some((_, Ok(_))) => {}
                _ => {
                    return Err(GitBridgeError::GitObject(
                        "unreadable git cat-file output".to_owned(),
                    ));
                }
            }
        }
        Ok(restricted)
    }

    /// Whether the public file `path` of `source`, holding blob `oid`, carries private content:
    /// the blob is `restricted`, or a private directory moved wholesale took it along.
    pub(crate) fn leaks(
        &self,
        source: &TreeListing,
        restricted: &HashSet<String>,
        path: &str,
        oid: &str,
    ) -> bool {
        restricted.contains(oid)
            || path
                .match_indices('/')
                .map(|(end, _)| &path[..end])
                .any(|dir| {
                    let inside = format!("{dir}/");
                    source
                        .dirs
                        .get(dir)
                        .is_some_and(|tree| self.trees.contains(tree))
                        && source
                            .files
                            .range(inside.clone()..)
                            .take_while(|(p, _)| p.starts_with(&inside))
                            .any(|(_, (_, oid))| restricted.contains(oid))
                })
    }
}

/// Plan a publish of `source_oid` onto `target_tip` (the tip of `target_ref`, `None` when the
/// branch does not exist yet): the source's changes since the merge base, minus the scrubbed
/// ones, merged three ways per file. Reads only; [`execute_squash_declassify`] applies exactly this.
pub fn plan_squash_declassify(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    source_oid: &str,
    target_ref: &str,
    target_tip: Option<&str>,
) -> Result<SquashPlan, GitBridgeError> {
    let ref_name = target_ref.strip_prefix("refs/heads/").unwrap_or(target_ref);
    plan_squash_with(
        canonical,
        &|path| publishable(policy, ref_name, path),
        source_oid,
        target_tip,
    )
}

/// [`plan_squash_declassify`] with the scrub rule given: a path is published only when
/// `is_publishable` says so, and the content of every other path counts as private.
pub(crate) fn plan_squash_with(
    canonical: &CanonicalGitRepo,
    is_publishable: &dyn Fn(&str) -> bool,
    source_oid: &str,
    target_tip: Option<&str>,
) -> Result<SquashPlan, GitBridgeError> {
    let root = canonical.root();
    // Unrelated histories (or no target yet): everything on the source is a change.
    let base = target_tip.and_then(|tip| {
        let found = git_stdout(
            root,
            None,
            &["merge-base", "--end-of-options", source_oid, tip],
            b"",
        );
        found.ok().map(|oid| oid.trim().to_owned())
    });
    let base = tree_files(root, base.as_deref())?;
    let source = tree_files(root, Some(source_oid))?;
    let target = tree_files(root, target_tip)?;
    let listings = [&base, &source, &target];

    let mut public: HashMap<&str, bool> = HashMap::new();
    for path in listings.iter().flat_map(|l| l.files.keys()) {
        public.entry(path).or_insert_with(|| is_publishable(path));
    }
    let is_public = |path: &str| public.get(path).copied().unwrap_or(false);

    // Private content on the source, the merge base or the target.
    let mut private = PrivateContent::default();
    for listing in listings {
        private.add(listing, &is_public);
    }
    // Not content the target already shows the public.
    let already_public: HashSet<String> = target
        .files
        .iter()
        .filter(|(path, _)| is_public(path))
        .map(|(_, (_, oid))| oid.clone())
        .collect();
    let restricted = private.restricted_in(root, &source, &is_public, &already_public)?;
    let hidden_lower: HashSet<String> = listings
        .iter()
        .flat_map(|l| l.files.keys())
        .filter(|p| !is_public(p))
        .map(|p| p.to_ascii_lowercase())
        .collect();
    let symlink_is_blocked = |path: &str, mode: &str, oid: &str| -> Result<bool, GitBridgeError> {
        if mode != "120000" {
            return Ok(false);
        }
        let target_bytes = canonical.read_object(oid)?.data;
        let Ok(dest) = resolve_safe_symlink_target(path, &target_bytes) else {
            return Ok(true);
        };
        let dest_lower = dest.to_ascii_lowercase();
        let collides_hidden = hidden_lower.contains(&dest_lower)
            || dest_lower
                .match_indices('/')
                .any(|(end, _)| hidden_lower.contains(&dest_lower[..end]))
            || hidden_lower.iter().any(|h| {
                h.starts_with(&dest_lower) && h.as_bytes().get(dest_lower.len()) == Some(&b'/')
            });
        Ok(collides_hidden || !is_publishable(&dest))
    };

    let mut plan = SquashPlan::default();
    let paths: std::collections::BTreeSet<&String> =
        base.files.keys().chain(source.files.keys()).collect();
    for path in paths {
        let (was, new, there) = (
            base.files.get(path),
            source.files.get(path),
            target.files.get(path),
        );
        if was == new {
            continue;
        }
        if !is_public(path) {
            plan.scrubbed_paths.push(path.clone());
        } else if new.is_some_and(|(_, oid)| private.leaks(&source, &restricted, path, oid))
            || match new {
                Some((mode, oid)) => symlink_is_blocked(path, mode, oid)?,
                None => false,
            }
        {
            plan.blocked.push(path.clone());
        } else if there == new {
            // The target already has this change.
        } else if there != was {
            let merged = if let (
                Some((was_mode, was_oid)),
                Some((new_mode, new_oid)),
                Some((there_mode, there_oid)),
            ) = (was, new, there)
                && matches!(was_mode.as_str(), "100644" | "100755")
                && was_mode == new_mode
                && was_mode == there_mode
            {
                try_three_way_merge(canonical, new_oid, was_oid, there_oid)?
                    .map(|merged_bytes| (was_mode.clone(), merged_bytes))
            } else {
                None
            };
            if let Some((mode, merged_bytes)) = merged {
                let merged_oid = hash_git_object(GitObjectKind::Blob, &merged_bytes);
                let merged_is_restricted = restricted.contains(&merged_oid)
                    || (merged_bytes.len() as u64 >= MIN_BLOCKED_BLOB_BYTES
                        && private.blobs.contains(merged_oid.as_str())
                        && !already_public.contains(merged_oid.as_str()));
                if merged_is_restricted {
                    plan.blocked.push(path.clone());
                } else {
                    plan.merged_blobs.insert(path.clone(), merged_bytes);
                    plan.changes.push((path.clone(), Some((mode, merged_oid))));
                    if let Some(before) = there {
                        plan.target_before.insert(path.clone(), before.clone());
                    }
                }
            } else {
                plan.conflicts.push(path.clone());
            }
        } else {
            plan.changes.push((path.clone(), new.cloned()));
            if let Some(before) = there {
                plan.target_before.insert(path.clone(), before.clone());
            }
        }
    }

    // Detect file/directory (D/F) collisions between planned additions and the target tree
    // remaining after planned deletions, so preview and execute agree 100%.
    let mut resulting_files: std::collections::BTreeSet<String> =
        target.files.keys().cloned().collect();
    for (path, entry) in &plan.changes {
        if entry.is_none() {
            resulting_files.remove(path);
        }
    }
    let mut kept_changes = Vec::with_capacity(plan.changes.len());
    let mut df_conflicts = false;
    for (path, entry) in plan.changes {
        if entry.is_some() {
            let ancestor_is_file = path
                .match_indices('/')
                .any(|(i, _)| resulting_files.contains(&path[..i]));
            let dir_prefix = format!("{path}/");
            let has_descendant_file = resulting_files
                .range(dir_prefix.clone()..)
                .next()
                .is_some_and(|p| p.starts_with(&dir_prefix));
            if ancestor_is_file || has_descendant_file {
                plan.merged_blobs.remove(&path);
                plan.conflicts.push(path);
                df_conflicts = true;
                continue;
            }
        }
        kept_changes.push((path, entry));
    }
    plan.changes = kept_changes;
    if df_conflicts {
        plan.conflicts.sort();
        plan.conflicts.dedup();
    }

    // One `\x01` per commit, then the paths it changed (none listed for a merge).
    let range = match target_tip {
        Some(tip) => format!("{tip}..{source_oid}"),
        None => source_oid.to_owned(),
    };
    let log = git_stdout(
        root,
        None,
        &[
            "log",
            "--no-renames",
            "--format=%x01",
            "--name-only",
            "-z",
            "--end-of-options",
            &range,
        ],
        b"",
    )?;
    for commit in log.split('\u{1}').skip(1) {
        plan.source_commits += 1;
        let mut changed = commit.split(['\0', '\n']).filter(|path| !path.is_empty());
        if changed.any(is_publishable) {
            plan.source_commits_public += 1;
        }
    }
    Ok(plan)
}

/// The tree of `base` (a commit or tree of the repository at `root`; `None` starts empty) with
/// `changes` applied, built in a throwaway index: no checkout. A `None` entry deletes the path.
/// Every object named must already be in the repository.
pub(crate) fn write_tree_with_changes(
    root: &Path,
    base: Option<&str>,
    changes: &mut [(String, Option<(String, String)>)],
) -> Result<String, GitBridgeError> {
    let index = std::env::temp_dir().join(format!(
        "premier-publish-index-{}-{}",
        std::process::id(),
        PUBLISH_INDEX_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&index);
    let tree = (|| {
        if let Some(base) = base {
            git_stdout(root, Some(&index), &["read-tree", base], b"")?;
        }
        // Deletions first, so a file that became a directory (or the reverse) can be written.
        changes.sort_by_key(|(_, entry)| entry.is_some());
        let zero = "0".repeat(40);
        let input: String = changes
            .iter()
            .map(|(path, entry)| match entry {
                Some((mode, oid)) => format!("{mode} {oid}\t{path}\0"),
                None => format!("0 {zero}\t{path}\0"),
            })
            .collect();
        // Refused by git when a path is, or runs through, something that is not a directory.
        git_stdout(
            root,
            Some(&index),
            &["update-index", "-z", "--index-info"],
            input.as_bytes(),
        )
        .map_err(|_| {
            GitBridgeError::Rejected(
                "a published path collides with a file or directory on the target".to_owned(),
            )
        })?;
        Ok(git_stdout(root, Some(&index), &["write-tree"], b"")?
            .trim()
            .to_owned())
    })();
    let _ = std::fs::remove_file(&index);
    tree
}

static PUBLISH_INDEX_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Compare-and-swap `target_ref` from `expected_old` (`None`: it must not exist yet) to
/// `new_oid`. [`GitBridgeError::RefMoved`] only when the ref really is elsewhere now; any other
/// failure of git is reported as itself.
pub(crate) fn update_ref_or_moved(
    repo: &CanonicalGitRepo,
    target_ref: &str,
    new_oid: &str,
    expected_old: Option<&str>,
) -> Result<(), GitBridgeError> {
    let expected = expected_old.map_or_else(|| "0".repeat(40), str::to_owned);
    if let Err(failed) = repo.update_ref_cas(target_ref, new_oid, &expected) {
        let now = repo
            .list_refs()?
            .into_iter()
            .find(|(name, _)| name == target_ref);
        return Err(
            if now.as_ref().map(|(_, oid)| oid.as_str()) == expected_old {
                failed
            } else {
                GitBridgeError::RefMoved
            },
        );
    }
    Ok(())
}

/// Execute a real **Squash-Declassify** landing commit on `canonical`:
///
/// 1. Plans it ([`plan_squash_declassify`]): the source's changes since the merge base, without
///    the paths the public may not read. Any conflict, and any restricted content on a public
///    path, refuses the publish; nothing is written.
/// 2. Validates every published path against `overlay_guard` (zero `AGENTS.local.md`/`.run/**` leak).
/// 3. Applies the changes onto the tree of `target_parent_oid` (the target's tip): every other
///    path of the target stays exactly as it is, whoever may read it.
/// 4. Writes one squashed commit (parented ONLY on `target_parent_oid`, discarding the private
///    branch ancestry) with a `Premier-Projection-Attestation` trailer.
/// 5. Compare-and-swaps `target_ref` from `target_parent_oid` to it, unless `before_ref_update`
///    (given the new commit's oid) refuses: then nothing has moved.
#[allow(clippy::too_many_arguments)]
pub fn execute_squash_declassify(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    overlay_guard: Option<&OverlayGuard>,
    source_branch: &str,
    source_oid: &str,
    target_ref: &str,
    target_parent_oid: Option<&str>,
    landing_message: &str,
    author: &str,
    before_ref_update: Option<RefUpdateCheck<'_>>,
) -> Result<SquashDeclassifyResult, GitBridgeError> {
    let firewall = SquashFirewallInput {
        actor_is_owner: true,
        ..SquashFirewallInput::default()
    };
    execute_squash_declassify_with_firewall(
        canonical,
        policy,
        policy_fingerprint,
        overlay_guard,
        source_branch,
        source_oid,
        target_ref,
        target_parent_oid,
        landing_message,
        author,
        &firewall,
        before_ref_update,
    )
}

/// Who publishes, and what the declassification firewall checks a publish against.
#[derive(Default)]
pub struct SquashFirewallInput<'a> {
    pub vault: Option<&'a VaultSecretIndex>,
    /// Owner-approved instruction file path -> SHA-256 hex (`None`: none approved).
    pub approved_instructions: Option<&'a BTreeMap<String, String>>,
    pub actor_is_owner: bool,
    pub actor_is_agent: bool,
    /// The `report_digest` of the blocking report an owner reviewed and chose to override.
    pub owner_override_digest: Option<&'a str>,
}

/// Largest prefix of one blob the firewall's restricted corpus reads.
pub(crate) const MAX_CORPUS_BLOB_BYTES: usize = 4 * 1024 * 1024;

/// Run the declassification firewall over what `plan` would publish on `target_ref`: the
/// published files and the landing message, against every file the public may not read on the
/// source, the merge base and the target. Reads only.
#[allow(clippy::too_many_arguments)]
pub fn scan_squash_declassify(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    plan: &SquashPlan,
    source_oid: &str,
    target_ref: &str,
    target_parent_oid: Option<&str>,
    landing_message: &str,
    fw: &SquashFirewallInput<'_>,
) -> Result<DeclassificationReport, GitBridgeError> {
    let root = canonical.root();
    let ref_name = target_ref.strip_prefix("refs/heads/").unwrap_or(target_ref);
    let base = target_parent_oid.and_then(|tip| {
        git_stdout(
            root,
            None,
            &["merge-base", "--end-of-options", source_oid, tip],
            b"",
        )
        .ok()
        .map(|oid| oid.trim().to_owned())
    });
    let target = tree_files(root, target_parent_oid)?;
    let source = tree_files(root, Some(source_oid))?;
    let base = tree_files(root, base.as_deref())?;

    let read_capped = |oid: &str| -> Result<Vec<u8>, GitBridgeError> {
        let mut data = canonical.read_object(oid)?.data.to_vec();
        data.truncate(MAX_CORPUS_BLOB_BYTES);
        Ok(data)
    };
    let mut already_public = Vec::new();
    for (path, (mode, oid)) in &target.files {
        if mode != GITLINK_MODE && publishable(policy, ref_name, path) {
            already_public.push(PrivateBlobEntry {
                path: path.clone(),
                content: read_capped(oid)?,
            });
        }
    }
    let mut private = Vec::new();
    let mut seen: HashSet<(&str, &str)> = HashSet::new();
    for listing in [&source, &base, &target] {
        for (path, (mode, oid)) in &listing.files {
            if mode != GITLINK_MODE
                && seen.insert((path.as_str(), oid.as_str()))
                && !publishable(policy, ref_name, path)
            {
                private.push(PrivateBlobEntry {
                    path: path.clone(),
                    content: read_capped(oid)?,
                });
            }
        }
    }
    let corpus = PrivateCorpus::build(
        &private,
        &already_public,
        policy.firewall_min_snippet_bytes(),
        policy.firewall_min_shingle_matches(),
    );

    let mut files = Vec::new();
    for (path, entry) in &plan.changes {
        match entry {
            Some((mode, _)) if mode == GITLINK_MODE => {}
            Some((_, oid)) => files.push(ScanTargetFile {
                path: path.clone(),
                // A merged blob reaches the object store only when the publish executes.
                content: match plan.merged_blobs.get(path) {
                    Some(bytes) => bytes.clone(),
                    None => canonical.read_object(oid)?.data.to_vec(),
                },
                deleted: false,
            }),
            None => files.push(ScanTargetFile {
                path: path.clone(),
                content: Vec::new(),
                deleted: true,
            }),
        }
    }
    let commit_messages: Vec<String> = if landing_message.trim().is_empty() {
        Vec::new()
    } else {
        vec![landing_message.to_owned()]
    };
    let no_approvals = BTreeMap::new();
    Ok(run_declassification_firewall(&FirewallScanInput {
        policy,
        ref_name,
        commit_messages: &commit_messages,
        files: &files,
        corpus: Some(&corpus),
        vault: fw.vault,
        check_cross_boundary: true,
        actor_is_owner: fw.actor_is_owner,
        actor_is_agent: fw.actor_is_agent,
        approved_instructions: fw.approved_instructions.unwrap_or(&no_approvals),
    }))
}

/// [`execute_squash_declassify`] with the declassification firewall run as `firewall` says
/// ([`scan_squash_declassify`]) after the plan's own checks: a blocking report refuses the
/// publish ([`GitBridgeError::FirewallBlocked`]) unless a human owner overrides exactly that
/// report (its digest) and the policy allows owner overrides.
#[allow(clippy::too_many_arguments)]
pub fn execute_squash_declassify_with_firewall(
    canonical: &CanonicalGitRepo,
    policy: &CompiledPolicy,
    policy_fingerprint: &str,
    overlay_guard: Option<&OverlayGuard>,
    source_branch: &str,
    source_oid: &str,
    target_ref: &str,
    target_parent_oid: Option<&str>,
    landing_message: &str,
    author: &str,
    firewall: &SquashFirewallInput<'_>,
    before_ref_update: Option<RefUpdateCheck<'_>>,
) -> Result<SquashDeclassifyResult, GitBridgeError> {
    let plan =
        plan_squash_declassify(canonical, policy, source_oid, target_ref, target_parent_oid)?;
    if !plan.blocked.is_empty() {
        return Err(GitBridgeError::PublishBlocked(plan.blocked));
    }
    if !plan.conflicts.is_empty() {
        return Err(GitBridgeError::PublishConflict(plan.conflicts));
    }
    if plan.changes.is_empty() {
        return Err(GitBridgeError::Rejected(format!(
            "nothing to publish from `{source_branch}` ({} scrubbed)",
            crate::plural(plan.scrubbed_paths.len(), "restricted path")
        )));
    }
    if let Some(guard) = overlay_guard {
        let written: Vec<RepoPath> = plan
            .changes
            .iter()
            .filter(|(_, entry)| entry.is_some())
            .filter_map(|(path, _)| RepoPath::new(path).ok())
            .collect();
        guard
            .validate_public_paths(&written)
            .map_err(|e| GitBridgeError::OverlayLeak(e.to_string()))?;
    }
    let report = scan_squash_declassify(
        canonical,
        policy,
        &plan,
        source_oid,
        target_ref,
        target_parent_oid,
        landing_message,
        firewall,
    )?;
    let overridden = firewall.actor_is_owner
        && !firewall.actor_is_agent
        && policy.firewall_allow_owner_override()
        && firewall.owner_override_digest == Some(report.report_digest.as_str());
    if !report.passed && !overridden {
        return Err(GitBridgeError::FirewallBlocked(Box::new(report)));
    }
    let SquashPlan {
        mut changes,
        scrubbed_paths,
        merged_blobs,
        ..
    } = plan;
    let published_paths: Vec<String> = changes.iter().map(|(path, _)| path.clone()).collect();

    // Write any 3-way merged blobs before updating the throwaway index.
    for bytes in merged_blobs.values() {
        canonical.write_object(GitObjectKind::Blob, bytes)?;
    }

    // The target's tree with the changes applied.
    let final_tree_oid =
        write_tree_with_changes(canonical.root(), target_parent_oid, &mut changes)?;

    let source_signed = canonical
        .read_object(source_oid)
        .ok()
        .is_some_and(|obj| obj.kind == GitObjectKind::Commit && commit_has_gpgsig(&obj.data));
    let attestation = ProjectionAttestation::build(source_oid, policy_fingerprint, source_signed);
    let full_msg = publish_commit_message(landing_message, target_ref, &attestation);

    let new_commit = CommitObj {
        tree: final_tree_oid,
        parents: target_parent_oid
            .map(|p| vec![p.to_owned()])
            .unwrap_or_default(),
        author: author.to_owned(),
        committer: author.to_owned(),
        message: full_msg.clone(),
    };
    let new_commit_oid = canonical.write_object(GitObjectKind::Commit, &new_commit.encode())?;
    if let Some(check) = before_ref_update {
        check(&new_commit_oid).map_err(GitBridgeError::Rejected)?;
    }
    update_ref_or_moved(canonical, target_ref, &new_commit_oid, target_parent_oid)?;

    Ok(SquashDeclassifyResult {
        new_commit_oid,
        target_ref: target_ref.to_owned(),
        published_paths,
        scrubbed_paths,
        attestation,
        commit_message: full_msg,
    })
}
