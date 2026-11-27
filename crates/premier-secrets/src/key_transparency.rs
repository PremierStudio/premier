//! Append-only, SHA-256 hash-chained Key Transparency (KT) log of vault public-key bindings.
//!
//! Every Sovereign `age` / Envelope vault binds its recipient public keys (or KMS key id) into
//! this log. A vault whose recipients differ from the latest binding for its repo — a silent
//! public-key swap — or a log whose chain no longer verifies fails closed with
//! [`SecretError::Crypto`]. Entries hold public material only, never keys or secrets.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::SecretError;
use crate::backend::create_state_dir;

fn normalize_lock_path(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
        && let Ok(canon_parent) = std::fs::canonicalize(parent)
    {
        return canon_parent.join(name);
    }
    path.to_path_buf()
}

/// Process-wide per-path mutex used to serialize concurrent vault and KT log operations.
pub(crate) fn acquire_path_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let table = LOCKS.get_or_init(Default::default);
    let key = normalize_lock_path(path);
    let mut map = table.lock().unwrap_or_else(PoisonError::into_inner);
    Arc::clone(map.entry(key).or_insert_with(|| Arc::new(Mutex::new(()))))
}

/// `prev_hash` of the first entry.
const GENESIS_PREV_HASH: &str = "genesis";

/// One public-key binding in the KT log (JSON Lines on disk).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyTransparencyEntry {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub repo_id: String,
    pub vault_path: String,
    pub recipients: Vec<String>,
    pub recipients_fingerprint: String,
    pub actor: String,
    pub event: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

/// Outcome of a successful chain verification (failures are `Err`, never `valid: false`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KtVerificationReport {
    pub valid: bool,
    pub entry_count: usize,
    pub latest_hash: Option<String>,
    pub latest_recipients: Vec<String>,
}

/// File-backed append-only KT log.
#[derive(Debug, Clone)]
pub struct KeyTransparencyLog {
    path: PathBuf,
}

/// Trimmed, lowercased, sorted and deduplicated recipients.
pub(crate) fn normalize_recipients(recipients: &[String]) -> Vec<String> {
    let mut out: Vec<String> = recipients
        .iter()
        .map(|r| r.trim().to_ascii_lowercase())
        .filter(|r| !r.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Deterministic SHA-256 fingerprint of a recipient set.
pub fn recipients_fingerprint(recipients: &[String]) -> String {
    let mut h = Sha256::new();
    h.update(b"premier-kt-recipients-v1");
    for r in normalize_recipients(recipients) {
        h.update((r.len() as u64).to_be_bytes());
        h.update(r.as_bytes());
    }
    hex::encode(h.finalize())
}

fn compute_entry_hash(e: &KeyTransparencyEntry) -> String {
    let ts = e.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let seq = e.seq.to_string();
    let mut h = Sha256::new();
    h.update(b"premier-kt-entry-v1");
    // Length-prefixed fields so no two field tuples hash alike.
    for field in [
        seq.as_str(),
        ts.as_str(),
        e.repo_id.as_str(),
        e.vault_path.as_str(),
        e.recipients_fingerprint.as_str(),
        e.actor.as_str(),
        e.event.as_str(),
        e.prev_hash.as_str(),
    ] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    hex::encode(h.finalize())
}

fn tampered(msg: String) -> SecretError {
    SecretError::Crypto(format!("key transparency log verification failed: {msg}"))
}

impl KeyTransparencyLog {
    pub fn open(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// All entries in file order (empty when the log does not exist yet).
    pub fn entries(&self) -> Result<Vec<KeyTransparencyEntry>, SecretError> {
        let lock = acquire_path_lock(&self.path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        self.entries_unlocked()
    }

    fn entries_unlocked(&self) -> Result<Vec<KeyTransparencyEntry>, SecretError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(SecretError::Io(format!("read KT log failed: {e}"))),
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, line)| {
                serde_json::from_str(line)
                    .map_err(|e| tampered(format!("line {} is not a valid entry: {e}", i + 1)))
            })
            .collect()
    }

    /// Append a binding of `recipients` for `repo_id`, after verifying the existing chain.
    pub fn append_binding(
        &self,
        repo_id: &str,
        vault_path: &str,
        recipients: &[String],
        actor: &str,
        event: &str,
    ) -> Result<KeyTransparencyEntry, SecretError> {
        let lock = acquire_path_lock(&self.path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let existing = self.entries_unlocked()?;
        Self::verify_entries(&existing)?;
        let recipients = normalize_recipients(recipients);
        let mut entry = KeyTransparencyEntry {
            seq: existing.last().map_or(1, |e| e.seq + 1),
            timestamp: Utc::now(),
            repo_id: repo_id.to_owned(),
            vault_path: vault_path.to_owned(),
            recipients_fingerprint: recipients_fingerprint(&recipients),
            recipients,
            actor: actor.to_owned(),
            event: event.to_owned(),
            prev_hash: existing
                .last()
                .map_or_else(|| GENESIS_PREV_HASH.to_owned(), |e| e.entry_hash.clone()),
            entry_hash: String::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry);

        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_state_dir(parent)
                .map_err(|e| SecretError::Io(format!("create KT log dir failed: {e}")))?;
        }
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| SecretError::Io(format!("serialize KT entry failed: {e}")))?;
        line.push('\n');
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| SecretError::Io(format!("open KT log failed: {e}")))?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| SecretError::Io(format!("append KT log failed: {e}")))?;
        Ok(entry)
    }

    fn verify_entries(entries: &[KeyTransparencyEntry]) -> Result<(), SecretError> {
        let mut prev = GENESIS_PREV_HASH.to_owned();
        for (i, e) in entries.iter().enumerate() {
            let expected_seq = i as u64 + 1;
            if e.seq != expected_seq {
                return Err(tampered(format!(
                    "expected seq {expected_seq}, found {}",
                    e.seq
                )));
            }
            if e.prev_hash != prev {
                return Err(tampered(format!(
                    "seq {} prev_hash breaks the chain",
                    e.seq
                )));
            }
            if e.recipients != normalize_recipients(&e.recipients)
                || e.recipients_fingerprint != recipients_fingerprint(&e.recipients)
            {
                return Err(tampered(format!(
                    "seq {} recipients do not match their fingerprint",
                    e.seq
                )));
            }
            if e.entry_hash != compute_entry_hash(e) {
                return Err(tampered(format!("seq {} entry_hash was altered", e.seq)));
            }
            prev.clone_from(&e.entry_hash);
        }
        Ok(())
    }

    /// Verify the whole hash chain.
    pub fn verify_chain(&self) -> Result<KtVerificationReport, SecretError> {
        let lock = acquire_path_lock(&self.path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let entries = self.entries_unlocked()?;
        Self::verify_entries(&entries)?;
        let last = entries.last();
        Ok(KtVerificationReport {
            valid: true,
            entry_count: entries.len(),
            latest_hash: last.map(|e| e.entry_hash.clone()),
            latest_recipients: last.map(|e| e.recipients.clone()).unwrap_or_default(),
        })
    }

    /// Verify the chain, then that `recipients` equal the latest binding for `repo_id` (if the
    /// log has one). `latest_hash` is `None` when `repo_id` has never been bound.
    pub fn verify_vault_recipients(
        &self,
        repo_id: &str,
        recipients: &[String],
    ) -> Result<KtVerificationReport, SecretError> {
        let lock = acquire_path_lock(&self.path);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        let entries = self.entries_unlocked()?;
        Self::verify_entries(&entries)?;
        let Some(latest) = entries.iter().rev().find(|e| e.repo_id == repo_id) else {
            return Ok(KtVerificationReport {
                valid: true,
                entry_count: entries.len(),
                latest_hash: None,
                latest_recipients: Vec::new(),
            });
        };
        if normalize_recipients(recipients) != latest.recipients {
            return Err(SecretError::Crypto(format!(
                "key transparency mismatch for repo '{repo_id}': vault recipients differ from the latest KT binding (seq {}); possible silent public-key swap",
                latest.seq
            )));
        }
        Ok(KtVerificationReport {
            valid: true,
            entry_count: entries.len(),
            latest_hash: Some(latest.entry_hash.clone()),
            latest_recipients: latest.recipients.clone(),
        })
    }
}
