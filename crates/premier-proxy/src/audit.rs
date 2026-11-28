//! Structured per-capability audit log sink (JSONL file + in-memory ring buffer + live broadcast).

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use premier_core::AuditEvent;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

const MAX_IN_MEMORY_EVENTS: usize = 2048;
const BROADCAST_CAPACITY: usize = 256;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static AUDIT_TMP_SEQ: AtomicU64 = AtomicU64::new(0);
// Independent sinks in the same process can open one log. Serialize checkpoint changes
// with appends and retention rewrites so they observe one ordered chain.
static AUDIT_IO: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AuditHead {
    event_hash: String,
    bytes: u64,
    entries: usize,
}

impl Default for AuditHead {
    fn default() -> Self {
        Self {
            event_hash: GENESIS.to_owned(),
            bytes: 0,
            entries: 0,
        }
    }
}

#[derive(Debug, Default)]
struct AuditState {
    events: VecDeque<AuditEvent>,
    head: AuditHead,
    writable: bool,
}

/// Thread-safe audit sink recording proxy decisions without storing raw secrets.
#[derive(Debug)]
pub struct AuditSink {
    file_path: Option<PathBuf>,
    state: Mutex<AuditState>,
    tx: broadcast::Sender<AuditEvent>,
}

impl Default for AuditSink {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Verify the log and its persisted head checkpoint. Returns the number of chained events.
/// Preserve the adjacent audit.jsonl.head checkpoint with the log when copying it.
/// A legacy log has zero chained events until the first chained append.
pub fn verify_audit_chain(path: &Path) -> io::Result<usize> {
    let _io = lock_audit_io()?;
    Ok(scan_log(path, |_| Ok(()))?.entries)
}

fn lock_audit_io() -> io::Result<std::sync::MutexGuard<'static, ()>> {
    AUDIT_IO
        .lock()
        .map_err(|_| io::Error::other("audit I/O lock poisoned"))
}

fn head_path(path: &Path) -> PathBuf {
    with_suffix(path, ".head")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn open_private(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn read_head(path: &Path) -> io::Result<Option<AuditHead>> {
    match open_private(OpenOptions::new().read(true), &head_path(path)) {
        Ok(file) => Ok(Some(serde_json::from_reader(BufReader::new(file))?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn event_hash(
    prev_hash: &str,
    fields: &serde_json::Map<String, serde_json::Value>,
) -> io::Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"premier-audit-v1\0");
    hash.update(prev_hash.as_bytes());
    hash.update(serde_json::to_vec(fields)?);
    Ok(hex::encode(hash.finalize()))
}

fn scan_log(
    path: &Path,
    mut visit: impl FnMut(AuditEvent) -> io::Result<()>,
) -> io::Result<AuditHead> {
    let checkpoint = read_head(path)?;
    let file = match open_private(OpenOptions::new().read(true), path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound && checkpoint.is_none() => {
            return Ok(AuditHead::default());
        }
        Err(e) => return Err(e),
    };
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut head = AuditHead::default();
    let mut line_no = 0;
    loop {
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        line_no += 1;
        if !line.ends_with('\n') {
            return Err(invalid(format!("incomplete audit line {line_no}")));
        }
        let mut fields: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&line)?;
        let recorded = fields.remove("event_hash");
        let digest = event_hash(&head.event_hash, &fields)?;
        match (fields.remove("prev_hash"), recorded) {
            (None, None) if head.entries == 0 => {}
            (Some(prev), Some(event))
                if prev.as_str() == Some(head.event_hash.as_str())
                    && event.as_str() == Some(digest.as_str()) =>
            {
                head.entries += 1;
            }
            _ => return Err(invalid(format!("audit chain mismatch at line {line_no}"))),
        }
        head.event_hash = digest;
        head.bytes += bytes as u64;
        visit(serde_json::from_value(serde_json::Value::Object(fields))?)?;
    }
    match checkpoint {
        Some(expected) if expected != head => Err(invalid("audit head checkpoint mismatch")),
        None if head.entries > 0 => Err(invalid("audit head checkpoint missing")),
        _ => Ok(head),
    }
}

fn encode_event(head: &mut AuditHead, event: &AuditEvent) -> io::Result<Vec<u8>> {
    let mut fields: serde_json::Map<String, serde_json::Value> =
        serde_json::from_value(serde_json::to_value(event)?)?;
    fields.insert("prev_hash".to_owned(), head.event_hash.clone().into());
    let digest = event_hash(&head.event_hash, &fields)?;
    fields.insert("event_hash".to_owned(), digest.clone().into());
    let mut line = serde_json::to_vec(&fields)?;
    line.push(b'\n');
    head.event_hash = digest;
    head.bytes += line.len() as u64;
    head.entries += 1;
    Ok(line)
}

fn write_atomic(path: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let seq = AUDIT_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = with_suffix(path, &format!(".tmp.{}.{seq}", std::process::id()));
    let mut file = open_private(OpenOptions::new().write(true).create_new(true), &tmp)?;
    let result = write(&mut file).and_then(|()| file.sync_all());
    drop(file);
    let result = result.and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

fn persist_head(path: &Path, head: &AuditHead) -> io::Result<()> {
    write_atomic(&head_path(path), |file| {
        serde_json::to_writer(file, head)?;
        Ok(())
    })
}

fn push_event(events: &mut VecDeque<AuditEvent>, event: AuditEvent) {
    if events.len() == MAX_IN_MEMORY_EVENTS {
        events.pop_front();
    }
    events.push_back(event);
}

impl AuditSink {
    pub fn new(file_path: Option<PathBuf>) -> Self {
        let mut state = AuditState::default();
        if let Some(path) = &file_path {
            let mut initial = VecDeque::new();
            match lock_audit_io().and_then(|_io| {
                scan_log(path, |event| {
                    push_event(&mut initial, event);
                    Ok(())
                })
            }) {
                Ok(head) => {
                    state.events = initial;
                    state.head = head;
                    state.writable = true;
                }
                Err(error) => {
                    tracing::error!(%error, path = %path.display(), "could not verify audit log")
                }
            }
        }
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            file_path,
            state: Mutex::new(state),
            tx,
        }
    }

    pub fn record(&self, event: AuditEvent) {
        if let Ok(mut state) = self.state.lock() {
            if let Some(path) = &self.file_path
                && let Err(error) = Self::append(path, &mut state, &event)
            {
                tracing::error!(%error, path = %path.display(), "could not persist audit event");
            }
            push_event(&mut state.events, event.clone());
            let _ = self.tx.send(event);
        } else {
            tracing::error!("could not record audit event: audit lock poisoned");
        }
    }

    fn append(path: &Path, state: &mut AuditState, event: &AuditEvent) -> io::Result<()> {
        if !state.writable {
            return Err(invalid("audit log requires recovery before appending"));
        }
        let _io = lock_audit_io()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            premier_secrets::create_state_dir(parent)?;
        }
        let mut file = open_private(OpenOptions::new().create(true).append(true), path)?;
        let checkpoint = read_head(path)?;
        if file.metadata()?.len() != state.head.bytes
            || checkpoint.as_ref().is_some_and(|head| *head != state.head)
            || (checkpoint.is_none() && state.head.entries > 0)
        {
            let refreshed = scan_log(path, |_| Ok(()))?;
            if checkpoint.is_none() && state.head.entries > 0 {
                return Err(invalid("audit head checkpoint disappeared"));
            }
            state.head = refreshed;
        }
        let mut next = state.head.clone();
        let line = encode_event(&mut next, event)?;
        if let Err(error) = file
            .write_all(&line)
            .and_then(|()| file.sync_all())
            .and_then(|()| persist_head(path, &next))
        {
            drop(file);
            if let Err(rollback) =
                open_private(OpenOptions::new().write(true), path).and_then(|file| {
                    file.set_len(state.head.bytes)?;
                    file.sync_all()
                })
            {
                state.writable = false;
                tracing::error!(%rollback, path = %path.display(), "could not roll back failed audit append");
            }
            return Err(error);
        }
        state.head = next;
        Ok(())
    }

    /// On-disk JSONL log, when this sink has one.
    pub fn file_path(&self) -> Option<&Path> {
        self.file_path.as_deref()
    }

    /// Drop events older than cutoff and rebuild the on-disk chain for the retained events.
    pub fn prune_older_than(&self, cutoff: DateTime<Utc>) -> io::Result<usize> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("audit lock poisoned"))?;
        let mut dropped = 0;
        if let Some(path) = &self.file_path {
            let _io = lock_audit_io()?;
            if !state.writable {
                return Err(invalid("audit log requires recovery before pruning"));
            }
            let original = scan_log(path, |event| {
                dropped += usize::from(event.timestamp < cutoff);
                Ok(())
            })?;
            if dropped > 0 {
                let mut next = AuditHead::default();
                write_atomic(path, |file| {
                    let scanned = scan_log(path, |event| {
                        if event.timestamp >= cutoff {
                            file.write_all(&encode_event(&mut next, &event)?)?;
                        }
                        Ok(())
                    })?;
                    if scanned != original {
                        return Err(invalid("audit log changed during pruning"));
                    }
                    Ok(())
                })?;
                if let Err(error) = persist_head(path, &next) {
                    state.writable = false;
                    return Err(error);
                }
                state.head = next;
            }
        }
        state.events.retain(|ev| ev.timestamp >= cutoff);
        Ok(dropped)
    }

    pub fn snapshot(&self) -> Vec<AuditEvent> {
        self.state
            .lock()
            .map(|state| state.events.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Subscribe to live audit events used by the server SSE stream.
    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use premier_core::{AuditDecision, DelegatedIdentity, Principal};

    use super::*;

    #[test]
    fn audit_chain_detects_edits_gaps_reordering_and_tail_removal() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let id = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        for action in ["first", "second", "third"] {
            let sink = AuditSink::new(Some(path.clone()));
            sink.record(AuditEvent::now(
                &id,
                "t",
                action,
                AuditDecision::Allowed,
                "reason",
            ));
        }
        assert_eq!(verify_audit_chain(&path).unwrap(), 3);
        let original = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = original.lines().collect();
        for altered in [
            original.replace("second", "edited"),
            format!("{}\n{}\n", lines[0], lines[2]),
            format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]),
            format!("{}\n{}\n", lines[0], lines[1]),
            format!("{original}{{"),
        ] {
            std::fs::write(&path, altered).unwrap();
            assert!(verify_audit_chain(&path).is_err());
        }
    }

    #[test]
    fn audit_sinks_opened_together_continue_one_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let id = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let first = AuditSink::new(Some(path.clone()));
        let second = AuditSink::new(Some(path.clone()));
        for (sink, action) in [(&first, "first"), (&second, "second"), (&first, "third")] {
            sink.record(AuditEvent::now(
                &id,
                "t",
                action,
                AuditDecision::Allowed,
                "reason",
            ));
        }
        assert_eq!(verify_audit_chain(&path).unwrap(), 3);
    }

    #[test]
    fn prune_drops_old_events_on_disk_and_in_memory() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let sink = AuditSink::new(Some(path.clone()));
        let id = DelegatedIdentity::human_only(Principal::Anonymous, vec![]);
        let mut old = AuditEvent::now(&id, "t", "old", AuditDecision::Allowed, "old");
        old.timestamp = Utc::now() - chrono::Duration::days(10);
        sink.record(old);
        sink.record(AuditEvent::now(
            &id,
            "t",
            "new",
            AuditDecision::Allowed,
            "new",
        ));

        let cutoff = Utc::now() - chrono::Duration::days(5);
        assert_eq!(sink.prune_older_than(cutoff).unwrap(), 1);
        assert_eq!(sink.snapshot().len(), 1);
        assert_eq!(verify_audit_chain(&path).unwrap(), 1);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"new\""));
    }
}
