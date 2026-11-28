//! Pure-Rust Git object codec, Packfile v2 encoder, and canonical repository reader.
//!
//! Zero C dependencies (`flate2` with `rust_backend` + `sha1`).

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use flate2::Compression;
use flate2::write::ZlibEncoder;
use sha1::{Digest, Sha1};

use crate::{GitBridgeError, PRIVATE_REF_PREFIX};

/// All-zero SHA-1 OID used by Git ref transactions to represent a nonexistent or deleted ref.
pub(crate) const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// The one way Premier runs git against a repository directory: never prompting, and never
/// discovering a repository above `dir` (a repository directory that lost its `.git` must fail,
/// not answer for whatever repository encloses it).
pub fn git_command(dir: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir).env("GIT_TERMINAL_PROMPT", "0");
    if let Some(parent) = std::path::absolute(dir)
        .ok()
        .as_deref()
        .and_then(Path::parent)
    {
        cmd.env("GIT_CEILING_DIRECTORIES", parent);
    }
    cmd
}

/// Canonical Git object type tag (matching Git packfile v2 type numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitObjectKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
}

impl GitObjectKind {
    pub fn header_name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    pub fn parse_name(name: &str) -> Result<Self, GitBridgeError> {
        match name {
            "commit" => Ok(Self::Commit),
            "tree" => Ok(Self::Tree),
            "blob" => Ok(Self::Blob),
            "tag" => Ok(Self::Tag),
            other => Err(GitBridgeError::GitObject(format!(
                "unsupported git object kind '{other}'"
            ))),
        }
    }
}

/// A raw Git object with its canonical SHA-1 hex OID.
#[derive(Debug, Clone)]
pub struct GitObject {
    pub oid: String,
    pub kind: GitObjectKind,
    pub data: Arc<[u8]>,
}

impl GitObject {
    /// Hash and construct a Git object (`"<type> <len>\0<data>"`).
    pub fn new(kind: GitObjectKind, data: impl Into<Arc<[u8]>>) -> Self {
        let data: Arc<[u8]> = data.into();
        let oid = hash_git_object(kind, &data);
        Self { oid, kind, data }
    }
}

/// Compute the canonical Git SHA-1 hex OID for `(kind, data)`.
pub fn hash_git_object(kind: GitObjectKind, data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    let header = format!("{} {}\0", kind.header_name(), data.len());
    hasher.update(header.as_bytes());
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// One parsed entry in a Git tree object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub oid_hex: String,
}

impl TreeEntry {
    pub fn is_dir(&self) -> bool {
        self.mode == "40000" || self.mode == "040000"
    }

    /// Git canonical tree sort key (directories sort as if suffixed with `/`).
    fn sort_key(&self) -> Vec<u8> {
        let mut key = self.name.as_bytes().to_vec();
        if self.is_dir() {
            key.push(b'/');
        }
        key
    }
}

/// Parse raw Git binary tree bytes into `TreeEntry` items.
pub fn parse_tree(raw: &[u8]) -> Result<Vec<TreeEntry>, GitBridgeError> {
    let mut entries = Vec::new();
    let mut i = 0usize;
    while i < raw.len() {
        let Some(sp_rel) = raw[i..].iter().position(|&b| b == b' ') else {
            return Err(GitBridgeError::GitObject(
                "malformed tree: missing space".to_owned(),
            ));
        };
        let mode = String::from_utf8_lossy(&raw[i..i + sp_rel]).into_owned();
        i += sp_rel + 1;

        let Some(nul_rel) = raw[i..].iter().position(|&b| b == 0) else {
            return Err(GitBridgeError::GitObject(
                "malformed tree: missing NUL".to_owned(),
            ));
        };
        let name = String::from_utf8_lossy(&raw[i..i + nul_rel]).into_owned();
        i += nul_rel + 1;

        if i + 20 > raw.len() {
            return Err(GitBridgeError::GitObject(
                "malformed tree: truncated 20-byte OID".to_owned(),
            ));
        }
        let oid_hex = hex::encode(&raw[i..i + 20]);
        i += 20;

        entries.push(TreeEntry {
            mode,
            name,
            oid_hex,
        });
    }
    Ok(entries)
}

/// Serialize `TreeEntry` items into strictly sorted, `git fsck`-valid raw Git tree bytes.
pub fn encode_tree(mut entries: Vec<TreeEntry>) -> Result<Vec<u8>, GitBridgeError> {
    entries.sort_by_key(|a| a.sort_key());
    let mut out = Vec::new();
    for e in entries {
        // Git fsck requires canonical mode `"40000"` (no leading zero) for trees.
        let mode = if e.is_dir() { "40000" } else { e.mode.as_str() };
        out.extend_from_slice(mode.as_bytes());
        out.push(b' ');
        out.extend_from_slice(e.name.as_bytes());
        out.push(0);
        let oid_bytes = hex::decode(&e.oid_hex)
            .map_err(|err| GitBridgeError::GitObject(format!("invalid entry OID: {err}")))?;
        if oid_bytes.len() != 20 {
            return Err(GitBridgeError::GitObject(
                "tree entry OID must be 20 bytes".to_owned(),
            ));
        }
        out.extend_from_slice(&oid_bytes);
    }
    Ok(out)
}

/// Parsed Git commit object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitObj {
    pub tree: String,
    pub parents: Vec<String>,
    pub author: String,
    pub committer: String,
    pub message: String,
}

impl CommitObj {
    pub fn parse(raw: &[u8]) -> Result<Self, GitBridgeError> {
        let text = String::from_utf8_lossy(raw);
        let (headers_part, msg_part) = text.split_once("\n\n").unwrap_or((&text, ""));
        let mut tree = String::new();
        let mut parents = Vec::new();
        let mut author = String::new();
        let mut committer = String::new();

        for line in headers_part.lines() {
            if let Some(t) = line.strip_prefix("tree ") {
                tree = t.trim().to_owned();
            } else if let Some(p) = line.strip_prefix("parent ") {
                parents.push(p.trim().to_owned());
            } else if let Some(a) = line.strip_prefix("author ") {
                author = a.trim().to_owned();
            } else if let Some(c) = line.strip_prefix("committer ") {
                committer = c.trim().to_owned();
            }
        }
        if tree.is_empty() {
            return Err(GitBridgeError::GitObject(
                "commit missing tree header".to_owned(),
            ));
        }
        Ok(Self {
            tree,
            parents,
            author,
            committer,
            message: msg_part.to_owned(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push_str(&format!("tree {}\n", self.tree));
        for p in &self.parents {
            out.push_str(&format!("parent {p}\n"));
        }
        out.push_str(&format!("author {}\n", self.author));
        out.push_str(&format!("committer {}\n", self.committer));
        out.push('\n');
        out.push_str(&self.message);
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.into_bytes()
    }
}

/// Whether a raw Git commit object carries a `gpgsig` header (inspected strictly in the header
/// block before the first blank line, never in the commit message body).
pub fn commit_has_gpgsig(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let headers = text.split_once("\n\n").map_or(text.as_ref(), |(h, _)| h);
    headers
        .lines()
        .any(|line| line.starts_with("gpgsig ") || line.starts_with("gpgsig-sha256 "))
}

/// Replace a raw commit's `tree` and `parent` headers and keep every other byte (author,
/// committer, `encoding`, `gpgsig`, `mergetag`, message) exactly as it was, so a commit rewritten
/// to a view and back hashes to what it was before.
pub fn rewrite_commit(
    raw: &[u8],
    tree: &str,
    parents: &[String],
) -> Result<Vec<u8>, GitBridgeError> {
    let bad = || GitBridgeError::GitObject("commit does not start with a tree header".to_owned());
    let line_end = |from: usize| {
        raw[from..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| from + i + 1)
    };
    if !raw.starts_with(b"tree ") {
        return Err(bad());
    }
    let mut rest = line_end(0).ok_or_else(bad)?;
    while raw[rest..].starts_with(b"parent ") {
        rest = line_end(rest).ok_or_else(bad)?;
    }
    let mut out = format!("tree {tree}\n").into_bytes();
    for p in parents {
        out.extend_from_slice(format!("parent {p}\n").as_bytes());
    }
    out.extend_from_slice(&raw[rest..]);
    Ok(out)
}

/// Parse the target OID from the leading `object <oid>\n` header of a raw Git annotated tag.
pub fn parse_tag_object(raw: &[u8]) -> Result<String, GitBridgeError> {
    let bad = || GitBridgeError::GitObject("tag does not start with an object header".to_owned());
    let first_end = raw.iter().position(|&b| b == b'\n').ok_or_else(bad)?;
    let line = std::str::from_utf8(&raw[..first_end]).map_err(|_| bad())?;
    let target = line.strip_prefix("object ").ok_or_else(bad)?.trim();
    if !is_hex_oid(target) {
        return Err(bad());
    }
    Ok(target.to_owned())
}

/// Replace the leading `object <oid>\n` header of a raw Git annotated tag, preserving all
/// remaining bytes (`type`, `tag`, `tagger`, message, signature) verbatim.
pub fn rewrite_tag_object(raw: &[u8], new_target_oid: &str) -> Result<Vec<u8>, GitBridgeError> {
    let bad = || GitBridgeError::GitObject("tag does not start with an object header".to_owned());
    if !raw.starts_with(b"object ") || !is_hex_oid(new_target_oid) {
        return Err(bad());
    }
    let first_end = raw.iter().position(|&b| b == b'\n').ok_or_else(bad)?;
    let mut out = format!("object {new_target_oid}\n").into_bytes();
    out.extend_from_slice(&raw[first_end + 1..]);
    Ok(out)
}

/// Whether raw tree bytes are exactly what [`encode_tree`] writes: canonical modes, strictly
/// sorted, no duplicate names.
pub(crate) fn is_canonical_tree(raw: &[u8]) -> bool {
    parse_tree(raw).is_ok_and(|entries| {
        entries
            .windows(2)
            .all(|w| w[0].sort_key() < w[1].sort_key())
            && encode_tree(entries).is_ok_and(|encoded| encoded == raw)
    })
}

/// Isolated in-memory Git object database (anti-CFOR: one store per projected scope).
#[derive(Debug, Default, Clone)]
pub struct InMemoryOdb {
    objects: HashMap<String, GitObject>,
}

impl InMemoryOdb {
    pub fn insert(&mut self, obj: GitObject) -> String {
        let oid = obj.oid.clone();
        self.objects.insert(oid.clone(), obj);
        oid
    }

    pub fn get(&self, oid: &str) -> Option<&GitObject> {
        self.objects.get(oid)
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &GitObject> {
        self.objects.values()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

/// Encode a set of Git objects into a valid Git Packfile v2 (`PACK` + SHA-1 trailer).
pub fn encode_packfile(objects: &[&GitObject]) -> Result<Vec<u8>, GitBridgeError> {
    let mut pack = Vec::new();
    pack.extend_from_slice(b"PACK");
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());

    for obj in objects {
        let kind_num = obj.kind as u8;
        let mut size = obj.data.len();
        let mut first = (kind_num << 4) | ((size & 0x0f) as u8);
        size >>= 4;
        if size > 0 {
            first |= 0x80;
        }
        pack.push(first);
        while size > 0 {
            let mut byte = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                byte |= 0x80;
            }
            pack.push(byte);
        }

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&obj.data)
            .map_err(|e| GitBridgeError::GitObject(format!("zlib pack encode failed: {e}")))?;
        let compressed = encoder
            .finish()
            .map_err(|e| GitBridgeError::GitObject(format!("zlib finish failed: {e}")))?;
        pack.extend_from_slice(&compressed);
    }

    let mut hasher = Sha1::new();
    hasher.update(&pack);
    pack.extend_from_slice(&hasher.finalize());
    Ok(pack)
}

/// Read-only handle onto a canonical local Git repository (supports both loose & packed objects).
#[derive(Debug, Clone)]
pub struct CanonicalGitRepo {
    root: std::path::PathBuf,
}

impl CanonicalGitRepo {
    pub fn open(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// List all refs under `refs/heads/`, `refs/premier-private/`, and `refs/tags/` as
    /// `(full_ref_name, oid_hex)`.
    pub fn list_refs(&self) -> Result<Vec<(String, String)>, GitBridgeError> {
        let out = git_command(&self.root)
            .args([
                "for-each-ref",
                "--format=%(refname) %(objectname)",
                "refs/heads",
                PRIVATE_REF_PREFIX,
                "refs/tags",
            ])
            .output()
            .map_err(|e| GitBridgeError::Io(format!("git for-each-ref failed: {e}")))?;
        if !out.status.success() {
            return Err(GitBridgeError::Io(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        let mut refs = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some((r, oid)) = line.split_once(' ') {
                refs.push((r.trim().to_owned(), oid.trim().to_owned()));
            }
        }
        Ok(refs)
    }

    /// Read a Git object by hex OID from the canonical repo.
    pub fn read_object(&self, oid: &str) -> Result<GitObject, GitBridgeError> {
        let kind_out = git_command(&self.root)
            .args(["cat-file", "-t", oid])
            .output()
            .map_err(|e| GitBridgeError::Io(format!("git cat-file -t failed: {e}")))?;
        if !kind_out.status.success() {
            return Err(GitBridgeError::ObjectNotVisible);
        }
        let kind_str = String::from_utf8_lossy(&kind_out.stdout).trim().to_owned();
        let kind = GitObjectKind::parse_name(&kind_str)?;

        let data_out = git_command(&self.root)
            .args(["cat-file", &kind_str, oid])
            .output()
            .map_err(|e| GitBridgeError::Io(format!("git cat-file payload failed: {e}")))?;
        if !data_out.status.success() {
            return Err(GitBridgeError::ObjectNotVisible);
        }

        Ok(GitObject {
            oid: oid.to_owned(),
            kind,
            data: Arc::from(data_out.stdout),
        })
    }

    /// Start one long-lived `git cat-file --batch` process for many object reads.
    pub fn reader(&self) -> Result<ObjectReader, GitBridgeError> {
        use std::process::Stdio;
        let mut child = git_command(&self.root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| GitBridgeError::Io(format!("git cat-file --batch spawn failed: {e}")))?;
        let pipes = child.stdin.take().zip(child.stdout.take());
        let Some((stdin, stdout)) = pipes else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(GitBridgeError::Io(
                "git cat-file --batch has no pipes".to_owned(),
            ));
        };
        Ok(ObjectReader {
            child,
            stdin,
            stdout: std::io::BufReader::new(stdout),
        })
    }

    /// Write a Git object into the canonical repo's object store and return its hex OID.
    pub fn write_object(&self, kind: GitObjectKind, data: &[u8]) -> Result<String, GitBridgeError> {
        use std::process::Stdio;
        let mut child = git_command(&self.root)
            .args(["hash-object", "-w", "-t", kind.header_name(), "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| GitBridgeError::Io(format!("git hash-object spawn failed: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(data)
                .map_err(|e| GitBridgeError::Io(format!("git hash-object write failed: {e}")))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| GitBridgeError::Io(format!("git hash-object wait failed: {e}")))?;
        if !out.status.success() {
            return Err(GitBridgeError::Io(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    /// Update a Git ref atomically via `git update-ref`.
    pub fn update_ref(&self, full_ref: &str, new_oid: &str) -> Result<(), GitBridgeError> {
        self.run_update_ref(&[full_ref, new_oid])
    }

    /// Compare-and-swap a ref: fails unless it still points at `old_oid` (the zero OID means
    /// "must not exist yet").
    pub fn update_ref_cas(
        &self,
        full_ref: &str,
        new_oid: &str,
        old_oid: &str,
    ) -> Result<(), GitBridgeError> {
        self.run_update_ref(&[full_ref, new_oid, old_oid])
    }

    /// Apply every `(ref, new, old)` compare-and-swap in one ref transaction: all or none.
    /// When `new` is the all-zero OID, emits `delete <ref> <old>` for atomic CAS deletion.
    pub fn update_refs_cas(
        &self,
        updates: &[(String, String, String)],
    ) -> Result<(), GitBridgeError> {
        let input: String = updates
            .iter()
            .map(|(full_ref, new, old)| {
                if new == ZERO_OID {
                    format!("delete {full_ref} {old}\n")
                } else {
                    format!("update {full_ref} {new} {old}\n")
                }
            })
            .collect();
        self.run_with_stdin(&["update-ref", "--stdin"], input.as_bytes())
    }

    /// Store many objects with one `git unpack-objects`.
    pub fn write_objects(&self, objects: &[&GitObject]) -> Result<(), GitBridgeError> {
        if objects.is_empty() {
            return Ok(());
        }
        self.run_with_stdin(&["unpack-objects", "-q"], &encode_packfile(objects)?)
    }

    fn run_with_stdin(&self, args: &[&str], input: &[u8]) -> Result<(), GitBridgeError> {
        use std::process::Stdio;
        let io = |e: std::io::Error| GitBridgeError::Io(format!("git {}: {e}", args[0]));
        // stderr is dropped so a failing git can never block on a full pipe while we still write.
        let mut child = git_command(&self.root)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(io)?;
        let written = child
            .stdin
            .take()
            .map_or(Ok(()), |mut stdin| stdin.write_all(input));
        let status = child.wait().map_err(io)?;
        written.map_err(io)?;
        if !status.success() {
            return Err(GitBridgeError::Io(format!("git {} failed", args[0])));
        }
        Ok(())
    }

    /// Whether canonical commit `ancestor` is `of` or reachable from it.
    pub fn is_ancestor(&self, ancestor: &str, of: &str) -> bool {
        is_hex_oid(ancestor)
            && is_hex_oid(of)
            && git_command(&self.root)
                .args(["merge-base", "--is-ancestor", ancestor, of])
                .output()
                .is_ok_and(|o| o.status.success())
    }

    fn run_update_ref(&self, args: &[&str]) -> Result<(), GitBridgeError> {
        let out = git_command(&self.root)
            .arg("update-ref")
            .args(args)
            .output()
            .map_err(|e| GitBridgeError::Io(format!("git update-ref failed: {e}")))?;
        if !out.status.success() {
            return Err(GitBridgeError::Io(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(())
    }
}

/// True for a full lowercase-or-uppercase 40-hex SHA-1 object id.
pub fn is_hex_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A long-lived `git cat-file --batch` process: one spawn for a whole projection instead of two
/// per object.
#[derive(Debug)]
pub struct ObjectReader {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
}

impl ObjectReader {
    /// Read one object by full hex OID. Missing objects answer `ObjectNotVisible`.
    pub fn read(&mut self, oid: &str) -> Result<GitObject, GitBridgeError> {
        use std::io::{BufRead, Read};
        // `cat-file --batch` resolves any revision expression; only ever hand it a full OID.
        if !is_hex_oid(oid) {
            return Err(GitBridgeError::ObjectNotVisible);
        }
        let io = |e: std::io::Error| GitBridgeError::Io(format!("git cat-file --batch: {e}"));
        self.stdin
            .write_all(
                format!(
                    "{oid}
"
                )
                .as_bytes(),
            )
            .map_err(io)?;
        self.stdin.flush().map_err(io)?;

        let mut header = String::new();
        self.stdout.read_line(&mut header).map_err(io)?;
        let mut parts = header.split_whitespace().skip(1);
        let (Some(kind), Some(size)) = (parts.next(), parts.next()) else {
            // "<oid> missing"
            return Err(GitBridgeError::ObjectNotVisible);
        };
        let kind = GitObjectKind::parse_name(kind)?;
        let size: usize = size
            .parse()
            .map_err(|_| GitBridgeError::Io("git cat-file --batch: bad size".to_owned()))?;
        let mut data = vec![0u8; size + 1];
        self.stdout.read_exact(&mut data).map_err(io)?;
        data.pop(); // trailing newline after the payload
        Ok(GitObject {
            oid: oid.to_ascii_lowercase(),
            kind,
            data: Arc::from(data),
        })
    }
}

impl Drop for ObjectReader {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
