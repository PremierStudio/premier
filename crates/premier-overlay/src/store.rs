//! Durable per-user and per-team overlay store.
//!
//! Everything lives under `<state_dir>/overlays/` (never the canonical working tree):
//! `index.json` (records), `blobs/<id>.bin` (payloads) and `.key` (the 32-byte AES-256-GCM
//! master key, `0o600` on Unix). An encrypted payload is a JSON envelope around ciphertext whose
//! AAD binds repository, overlay id, kind, owner/team and path, so a blob moved to another
//! record or tampered with fails to decrypt.

use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use premier_core::{OverlayKind, RepoPath};
use rand::RngCore as _;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{OverlayEntry, OverlayError, OverlayGuard, OverlayManifest};

const ENVELOPE_VERSION: u32 = 1;
const ALG: &str = "AES-256-GCM";
/// Path components an overlay may never name: Git internals and Premier's own state.
const RESERVED: [&str; 4] = [".git", "git~1", ".premier", ".premier-local"];

// shortcut: one process-wide lock serialises index read-modify-write; two processes (server and
// CLI) mounting at the same instant can still drop an entry. Upgrade to a file lock if that bites.
static INDEX_LOCK: Mutex<()> = Mutex::new(());

/// One stored overlay. Identity is `(kind, owner-or-team, path)`, so two principals can each
/// keep a personal overlay at the same path without ever seeing or clobbering the other's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayRecord {
    pub id: String,
    pub kind: OverlayKind,
    pub path: String,
    #[serde(default)]
    pub owner_principal: Option<String>,
    #[serde(default)]
    pub team_group: Option<String>,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub has_payload: bool,
}

/// What the API lists: a record, never its payload.
pub type OverlaySummary = OverlayRecord;

impl OverlayRecord {
    /// A metadata-only summary of a manifest entry that has no stored record.
    pub fn from_legacy(entry: &OverlayEntry) -> Self {
        Self {
            id: String::new(),
            team_group: match &entry.kind {
                OverlayKind::Team(t) => Some(t.clone()),
                OverlayKind::Personal => None,
            },
            kind: entry.kind.clone(),
            path: entry.path.clone(),
            owner_principal: None,
            encrypted: entry.encrypted,
            has_payload: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayListResponse {
    pub version: u32,
    pub entries: Vec<OverlaySummary>,
}

impl OverlayListResponse {
    pub fn new(entries: Vec<OverlaySummary>) -> Self {
        Self {
            version: 1,
            entries,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MountOverlayInput {
    pub kind: OverlayKind,
    pub path: String,
    pub owner_principal: Option<String>,
    pub team_group: Option<String>,
    pub encrypted: bool,
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct IndexFile {
    #[serde(default = "one")]
    version: u32,
    /// Pinned at first write so a renamed checkout keeps decrypting its payloads.
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    records: Vec<OverlayRecord>,
}

fn one() -> u32 {
    1
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    v: u32,
    alg: String,
    nonce: String,
    ct: String,
}

/// `@alice`, `alice` and `user:Alice` are the same owner: `alice`.
pub fn normalize_principal(raw: &str) -> String {
    let t = raw.trim();
    let t = t.strip_prefix("user:").unwrap_or(t);
    t.strip_prefix('@').unwrap_or(t).trim().to_ascii_lowercase()
}

/// `group:core`, `team:core` and `core` are the same team: `core`.
pub fn normalize_group(raw: &str) -> String {
    let t = raw.trim();
    let t = t
        .strip_prefix("group:")
        .or_else(|| t.strip_prefix("team:"))
        .unwrap_or(t);
    t.trim().to_ascii_lowercase()
}

fn is_glob(path: &str) -> bool {
    path.contains(['*', '?', '[', ']', '{', '}'])
}

fn invalid(path: &str, reason: impl Into<String>) -> OverlayError {
    OverlayError::InvalidPath {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> OverlayError {
    let context = context.into();
    move |source| OverlayError::Io { context, source }
}

/// A repository-relative overlay path that never names `.git` or Premier state.
fn checked_path(raw: &str) -> Result<String, OverlayError> {
    let raw = raw.trim();
    let rp = RepoPath::new(raw).map_err(|e| invalid(raw, e.to_string()))?;
    if rp.is_root() {
        return Err(invalid(raw, "the repository root is not an overlay"));
    }
    for seg in rp.as_str().split('/') {
        if RESERVED.iter().any(|r| seg.eq_ignore_ascii_case(r)) {
            return Err(invalid(raw, format!("'{seg}' is reserved")));
        }
    }
    Ok(rp.as_str().to_owned())
}

fn kind_tag(kind: &OverlayKind) -> String {
    match kind {
        OverlayKind::Personal => "personal".to_owned(),
        OverlayKind::Team(t) => format!("team:{t}"),
    }
}

/// The normalised owner (personal) or team (team) a record belongs to.
fn holder(r: &OverlayRecord) -> String {
    match &r.kind {
        OverlayKind::Personal => r
            .owner_principal
            .as_deref()
            .map(normalize_principal)
            .unwrap_or_default(),
        OverlayKind::Team(t) => normalize_group(t),
    }
}

fn record_id(kind: &OverlayKind, holder: &str, path: &str) -> String {
    let digest = Sha256::digest(
        format!("{}|{holder}|{}", kind_tag(kind), path.to_ascii_lowercase()).as_bytes(),
    );
    hex::encode(&digest[..16])
}

fn same_path(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Write `bytes` to `path` through a sibling temp file and a rename, `0o600` on Unix.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), OverlayError> {
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{file_name}.tmp-{}", hex::encode(suffix)));
    let result = (|| {
        let mut f = private_create(&tmp, false)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result.map_err(io(format!("writing {}", path.display())))
}

fn private_create(path: &Path, create_new: bool) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn lock() -> Result<std::sync::MutexGuard<'static, ()>, OverlayError> {
    INDEX_LOCK
        .lock()
        .map_err(|_| OverlayError::Corrupt("overlay index lock poisoned".to_owned()))
}

/// Encrypted per-user and per-team overlay storage for one repository.
pub struct OverlayStore {
    root: PathBuf,
    repo_id: String,
    key: Option<Zeroizing<[u8; 32]>>,
}

impl std::fmt::Debug for OverlayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlayStore")
            .field("root", &self.root)
            .field("repo_id", &self.repo_id)
            .finish_non_exhaustive()
    }
}

impl OverlayStore {
    /// Open the store under `<state_dir>/overlays/`. Nothing is written until the first mount;
    /// the master key is read (or generated) only when a payload is encrypted or decrypted.
    pub fn open(
        state_dir: impl AsRef<Path>,
        repo_id: impl Into<String>,
    ) -> Result<Self, OverlayError> {
        let mut store = Self {
            root: state_dir.as_ref().join("overlays"),
            repo_id: repo_id.into(),
            key: None,
        };
        if let Some(pinned) = store.load_index()?.repo_id {
            store.repo_id = pinned;
        }
        Ok(store)
    }

    /// [`Self::open`] with a caller-supplied master key (tests, external KMS unwrapping).
    pub fn open_with_key(
        state_dir: impl AsRef<Path>,
        repo_id: impl Into<String>,
        key: [u8; 32],
    ) -> Result<Self, OverlayError> {
        let mut store = Self::open(state_dir, repo_id)?;
        store.key = Some(Zeroizing::new(key));
        Ok(store)
    }

    /// `<state_dir>/overlays`.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.root.join("blobs").join(format!("{id}.bin"))
    }

    fn load_index(&self) -> Result<IndexFile, OverlayError> {
        let path = self.root.join("index.json");
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| OverlayError::Corrupt(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(IndexFile::default()),
            Err(e) => Err(io(format!("reading {}", path.display()))(e)),
        }
    }

    fn save_index(&self, mut index: IndexFile) -> Result<(), OverlayError> {
        std::fs::create_dir_all(&self.root).map_err(io("creating the overlay directory"))?;
        index.version = 1;
        index.repo_id = Some(self.repo_id.clone());
        index
            .records
            .sort_by(|a, b| (&a.path, &a.id).cmp(&(&b.path, &b.id)));
        let bytes =
            serde_json::to_vec_pretty(&index).map_err(|e| OverlayError::Corrupt(e.to_string()))?;
        write_atomic(&self.root.join("index.json"), &bytes)
    }

    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, OverlayError> {
        if let Some(k) = &self.key {
            return Ok(k.clone());
        }
        let path = self.root.join(".key");
        let read = |path: &Path| -> Result<Zeroizing<[u8; 32]>, OverlayError> {
            let bytes = Zeroizing::new(std::fs::read(path).map_err(io("reading the overlay key"))?);
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                OverlayError::Corrupt(format!("{} is not a 32-byte key", path.display()))
            })?;
            Ok(Zeroizing::new(arr))
        };
        if path.exists() {
            return read(&path);
        }
        std::fs::create_dir_all(&self.root).map_err(io("creating the overlay directory"))?;
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        match private_create(&path, true) {
            Ok(mut f) => {
                f.write_all(key.as_ref())
                    .and_then(|()| f.sync_all())
                    .map_err(io("writing the overlay key"))?;
                Ok(key)
            }
            // Another writer won the race: use theirs.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read(&path),
            Err(e) => Err(io("creating the overlay key")(e)),
        }
    }

    fn aad(&self, r: &OverlayRecord) -> String {
        format!(
            "premier-overlay-v1|repo={}|id={}|kind={}|owner={}|path={}",
            self.repo_id,
            r.id,
            kind_tag(&r.kind),
            holder(r),
            r.path
        )
    }

    fn seal(&self, r: &OverlayRecord, plaintext: &[u8]) -> Result<Vec<u8>, OverlayError> {
        let key = self.master_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let aad = self.aad(r);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| OverlayError::Crypto {
                path: r.path.clone(),
            })?;
        serde_json::to_vec(&Envelope {
            v: ENVELOPE_VERSION,
            alg: ALG.to_owned(),
            nonce: B64.encode(nonce),
            ct: B64.encode(ct),
        })
        .map_err(|e| OverlayError::Corrupt(e.to_string()))
    }

    fn open_envelope(&self, r: &OverlayRecord, bytes: &[u8]) -> Result<Vec<u8>, OverlayError> {
        let crypto = || OverlayError::Crypto {
            path: r.path.clone(),
        };
        let env: Envelope = serde_json::from_slice(bytes).map_err(|_| crypto())?;
        if env.v != ENVELOPE_VERSION || env.alg != ALG {
            return Err(crypto());
        }
        let nonce = B64.decode(env.nonce).map_err(|_| crypto())?;
        let ct = B64.decode(env.ct).map_err(|_| crypto())?;
        if nonce.len() != 12 {
            return Err(crypto());
        }
        let key = self.master_key()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
        let aad = self.aad(r);
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| crypto())
    }

    fn write_payload(&self, r: &OverlayRecord, payload: &[u8]) -> Result<(), OverlayError> {
        std::fs::create_dir_all(self.root.join("blobs"))
            .map_err(io("creating the overlay blob directory"))?;
        let bytes = if r.encrypted {
            self.seal(r, payload)?
        } else {
            payload.to_vec()
        };
        write_atomic(&self.blob_path(&r.id), &bytes)
    }

    fn read_payload(&self, r: &OverlayRecord) -> Result<Option<Vec<u8>>, OverlayError> {
        if !r.has_payload {
            return Ok(None);
        }
        let path = self.blob_path(&r.id);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(format!("reading {}", path.display()))(e)),
        };
        if r.encrypted {
            self.open_envelope(r, &bytes).map(Some)
        } else {
            Ok(Some(bytes))
        }
    }

    fn remove_blob(&self, id: &str) -> Result<(), OverlayError> {
        match std::fs::remove_file(self.blob_path(id)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(io("deleting an overlay blob")(e))
            }
            _ => Ok(()),
        }
    }

    /// Mount (or re-mount) an overlay. A personal overlay belongs to `owner_principal`; a team
    /// overlay to the team named by its kind (or `team_group`). Re-mounting without a payload
    /// keeps the stored one, re-encoded if `encrypted` changed.
    pub fn mount(&self, input: MountOverlayInput) -> Result<OverlayRecord, OverlayError> {
        let path = checked_path(&input.path)?;
        OverlayGuard::from_manifest(&OverlayManifest {
            version: 1,
            entries: vec![OverlayEntry {
                kind: OverlayKind::Personal,
                path: path.clone(),
                encrypted: false,
            }],
        })?;
        if is_glob(&path) && input.payload.is_some() {
            return Err(OverlayError::InvalidInput(
                "a glob overlay cannot carry file content".to_owned(),
            ));
        }
        let (kind, owner_principal, team_group) = match input.kind {
            OverlayKind::Personal => {
                let raw = input.owner_principal.unwrap_or_default();
                let owner = normalize_principal(&raw);
                if owner.is_empty() || owner == "anonymous" || owner == "*" || owner.contains(':') {
                    return Err(OverlayError::InvalidInput(format!(
                        "a personal overlay needs a signed-in owner, not '{raw}'"
                    )));
                }
                (OverlayKind::Personal, Some(format!("@{owner}")), None)
            }
            OverlayKind::Team(name) => {
                let mut team = normalize_group(&name);
                if team.is_empty() {
                    team = input
                        .team_group
                        .as_deref()
                        .map(normalize_group)
                        .unwrap_or_default();
                }
                if team.is_empty() {
                    return Err(OverlayError::InvalidInput(
                        "a team overlay needs a team name".to_owned(),
                    ));
                }
                (OverlayKind::Team(team.clone()), None, Some(team))
            }
        };
        let mut record = OverlayRecord {
            id: String::new(),
            kind,
            path,
            owner_principal,
            team_group,
            encrypted: input.encrypted,
            has_payload: false,
        };
        record.id = record_id(&record.kind, &holder(&record), &record.path);

        let _guard = lock()?;
        let mut index = self.load_index()?;
        let existing = index.records.iter().position(|r| r.id == record.id);
        let payload = match (input.payload, existing) {
            (Some(p), _) => Some(Zeroizing::new(p)),
            (None, Some(i)) => self.read_payload(&index.records[i])?.map(Zeroizing::new),
            (None, None) => None,
        };
        match &payload {
            Some(p) => {
                self.write_payload(&record, p)?;
                record.has_payload = true;
            }
            None => self.remove_blob(&record.id)?,
        }
        match existing {
            Some(i) => index.records[i] = record.clone(),
            None => index.records.push(record.clone()),
        }
        self.save_index(index)?;
        Ok(record)
    }

    /// Unmount `path` for `actor_principal`: their own personal overlay there, else the team
    /// overlays there. A path held only by someone else's personal overlay is refused.
    pub fn unmount(&self, path: &str, actor_principal: &str) -> Result<bool, OverlayError> {
        let path = checked_path(path)?;
        let actor = normalize_principal(actor_principal);
        let _guard = lock()?;
        let mut index = self.load_index()?;
        let at_path = |r: &OverlayRecord| same_path(&r.path, &path);
        let own = |r: &OverlayRecord| {
            at_path(r) && r.kind == OverlayKind::Personal && !actor.is_empty() && holder(r) == actor
        };
        let team = |r: &OverlayRecord| at_path(r) && matches!(r.kind, OverlayKind::Team(_));
        let doomed: Vec<String> = if index.records.iter().any(own) {
            index
                .records
                .iter()
                .filter(|r| own(r))
                .map(|r| r.id.clone())
                .collect()
        } else {
            index
                .records
                .iter()
                .filter(|r| team(r))
                .map(|r| r.id.clone())
                .collect()
        };
        if doomed.is_empty() {
            if index.records.iter().any(at_path) {
                return Err(OverlayError::AccessDenied { path });
            }
            return Ok(false);
        }
        index.records.retain(|r| !doomed.contains(&r.id));
        self.save_index(index)?;
        for id in &doomed {
            self.remove_blob(id)?;
        }
        Ok(true)
    }

    fn visible(r: &OverlayRecord, principal: &str, groups: &HashSet<String>) -> bool {
        match &r.kind {
            OverlayKind::Personal => !principal.is_empty() && holder(r) == principal,
            OverlayKind::Team(t) => groups.contains(&normalize_group(t)),
        }
    }

    /// The caller's own personal overlays plus the team overlays of their `groups`.
    pub fn list_for_principal(
        &self,
        principal: &str,
        groups: &[String],
    ) -> Result<Vec<OverlayRecord>, OverlayError> {
        let principal = normalize_principal(principal);
        let groups: HashSet<String> = groups.iter().map(|g| normalize_group(g)).collect();
        Ok(self
            .load_index()?
            .records
            .into_iter()
            .filter(|r| Self::visible(r, &principal, &groups))
            .collect())
    }

    /// The caller's own personal overlays plus every team overlay (an administrator's view):
    /// never another principal's personal overlay.
    pub fn list_for_owner(&self, principal: &str) -> Result<Vec<OverlayRecord>, OverlayError> {
        let principal = normalize_principal(principal);
        Ok(self
            .load_index()?
            .records
            .into_iter()
            .filter(|r| match r.kind {
                OverlayKind::Personal => !principal.is_empty() && holder(r) == principal,
                OverlayKind::Team(_) => true,
            })
            .collect())
    }

    /// The decrypted content of the overlay at `path` that `principal` may read: their own
    /// personal one first, else a team one of their `groups`. `Ok(None)` when nothing is stored;
    /// `AccessDenied` when the path is held only by overlays they may not read.
    pub fn read_payload_for_principal(
        &self,
        path: &str,
        principal: &str,
        groups: &[String],
    ) -> Result<Option<Vec<u8>>, OverlayError> {
        let path = checked_path(path)?;
        let principal = normalize_principal(principal);
        let groups: HashSet<String> = groups.iter().map(|g| normalize_group(g)).collect();
        let records: Vec<OverlayRecord> = self
            .load_index()?
            .records
            .into_iter()
            .filter(|r| same_path(&r.path, &path))
            .collect();
        let pick = records
            .iter()
            .filter(|r| Self::visible(r, &principal, &groups))
            .min_by_key(|r| matches!(r.kind, OverlayKind::Team(_)));
        match pick {
            Some(r) => self.read_payload(r),
            None if records.is_empty() => Ok(None),
            None => Err(OverlayError::AccessDenied { path }),
        }
    }

    /// Write every non-glob overlay `(principal, groups)` may read that has content into
    /// `target_dir` (personal wins over team at the same path). Refuses `..`, absolute paths,
    /// `.git`, Premier state and any symlink (or junction) on the way. Returns the paths written.
    pub fn materialize_into_dir(
        &self,
        target_dir: &Path,
        principal: &str,
        groups: &[String],
    ) -> Result<Vec<String>, OverlayError> {
        let target = std::fs::canonicalize(target_dir)
            .map_err(io(format!("resolving {}", target_dir.display())))?;
        let mut records = self.list_for_principal(principal, groups)?;
        records.retain(|r| r.has_payload && !is_glob(&r.path));
        records.sort_by_key(|r| matches!(r.kind, OverlayKind::Team(_)));
        // Validate every path before writing any file.
        for r in &records {
            checked_path(&r.path)?;
        }
        let mut written: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for r in &records {
            if !seen.insert(r.path.to_ascii_lowercase()) {
                continue;
            }
            let Some(bytes) = self.read_payload(r)?.map(Zeroizing::new) else {
                continue;
            };
            write_confined(&target, &r.path, &bytes)?;
            written.push(r.path.clone());
        }
        Ok(written)
    }

    /// Every stored overlay, across all principals, for push exclusion.
    pub fn to_manifest(&self) -> Result<OverlayManifest, OverlayError> {
        let mut entries: Vec<OverlayEntry> = Vec::new();
        for r in self.load_index()?.records {
            let entry = OverlayEntry {
                kind: r.kind,
                path: r.path,
                encrypted: r.encrypted,
            };
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
        Ok(OverlayManifest {
            version: 1,
            entries,
        })
    }
}

/// Write `rel` under the canonical `root`, creating directories one by one and refusing any
/// component that is a symlink (or resolves outside `root`).
fn write_confined(root: &Path, rel: &str, bytes: &[u8]) -> Result<(), OverlayError> {
    let escape = || {
        invalid(
            rel,
            "goes through a symbolic link or leaves the target directory",
        )
    };
    let segments: Vec<&str> = rel.split('/').collect();
    let Some((file, dirs)) = segments.split_last() else {
        return Err(invalid(rel, "empty path"));
    };
    let mut cur = root.to_path_buf();
    for seg in dirs {
        cur.push(seg);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() || !m.is_dir() => return Err(escape()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&cur).map_err(io(format!("creating {}", cur.display())))?;
            }
            Err(e) => return Err(io(format!("inspecting {}", cur.display()))(e)),
        }
    }
    // Catches junctions and anything else `is_symlink` does not report.
    let parent = std::fs::canonicalize(&cur).map_err(io(format!("resolving {}", cur.display())))?;
    if !parent.starts_with(root) {
        return Err(escape());
    }
    let dest = parent.join(file);
    if let Ok(m) = std::fs::symlink_metadata(&dest)
        && (m.file_type().is_symlink() || m.is_dir())
    {
        return Err(escape());
    }
    write_atomic(&dest, bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
