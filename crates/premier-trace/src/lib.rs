mod crypto;
mod integrity;
mod output;
mod utf8;

pub use crypto::{EncryptionKey, KEY_FILE_ENV};
pub use integrity::{IntegrityReport, IntegrityStatus, assess_integrity};
pub use output::prepare_trace_output;
pub use utf8::{decode_utf8_chunk, finish_utf8};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use prost::Message;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, SystemTime};
use uuid::Uuid;

pub const FORMAT_VERSION: u32 = 1;
pub const LOCAL_TENANT: &str = "local";
pub const RECORDER_LEASE: &str = "recorder.lease";
/// Append-in-progress journal file name inside a trace's `events/` directory.
pub const ACTIVE_JOURNAL: &str = "active.events.pb";
/// Finalized compressed journal file name inside a trace's `events/` directory.
pub const FINAL_JOURNAL: &str = "000001.events.pb.zst";
/// Hard cap on one journal frame, enforced identically by writers and readers.
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, PartialEq, Message, Serialize, Deserialize)]
pub struct TraceEvent {
    #[prost(string, tag = "1")]
    pub event_id: String,
    #[prost(string, tag = "2")]
    pub trace_id: String,
    #[prost(uint64, tag = "3")]
    pub sequence: u64,
    #[prost(string, tag = "4")]
    pub timestamp: String,
    #[prost(string, tag = "5")]
    pub kind: String,
    #[prost(string, tag = "6")]
    pub source: String,
    #[prost(string, tag = "7")]
    pub payload_json: String,
    #[prost(string, tag = "8")]
    pub actor_id: String,
    #[prost(string, tag = "9")]
    pub actor_type: String,
    #[prost(string, tag = "10")]
    pub parent_event_id: String,
    #[prost(string, tag = "11")]
    pub span_id: String,
    #[prost(string, tag = "12")]
    pub parent_span_id: String,
    #[prost(string, tag = "13")]
    pub correlation_id: String,
    #[prost(string, tag = "14")]
    pub status: String,
    #[prost(uint64, tag = "15")]
    pub duration_ms: u64,
    #[prost(string, repeated, tag = "16")]
    pub links: Vec<String>,
}

impl TraceEvent {
    pub fn payload(&self) -> serde_json::Value {
        serde_json::from_str(&self.payload_json).unwrap_or(serde_json::Value::Null)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventInput {
    pub kind: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub actor_id: String,
    #[serde(default)]
    pub actor_type: String,
    #[serde(default)]
    pub parent_event_id: String,
    #[serde(default)]
    pub span_id: String,
    #[serde(default)]
    pub parent_span_id: String,
    #[serde(default)]
    pub correlation_id: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub payload: serde_json::Value,
    /// Optional producer timestamp (RFC 3339). When omitted, receipt time is used.
    #[serde(default)]
    pub timestamp: Option<String>,
}

fn default_source() -> String {
    "sdk".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalFile {
    pub path: String,
    pub sha256: String,
    pub event_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceDiagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}

/// How the recorded root process stopped. `TraceManifest::exit_code` remains the
/// shell-compatible code for older readers; this structure preserves the exact
/// distinction between a normal exit, a signal, and an interrupted recorder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationKind {
    Exit,
    Signal,
    Interrupted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessTermination {
    pub kind: TerminationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_name: Option<String>,
}

impl ProcessTermination {
    pub fn exited(exit_code: i32) -> Self {
        Self {
            kind: TerminationKind::Exit,
            exit_code: Some(exit_code),
            signal: None,
            signal_name: None,
        }
    }

    pub fn signaled(signal: i32, signal_name: Option<String>) -> Self {
        Self {
            kind: TerminationKind::Signal,
            exit_code: None,
            signal: Some(signal),
            signal_name,
        }
    }

    pub fn interrupted() -> Self {
        Self {
            kind: TerminationKind::Interrupted,
            exit_code: None,
            signal: None,
            signal_name: None,
        }
    }

    pub fn shell_exit_code(&self) -> i32 {
        self.exit_code
            .or_else(|| self.signal.map(|signal| 128_i32.saturating_add(signal)))
            .unwrap_or(130)
    }
}

#[derive(Clone, Debug)]
pub struct RecoveryOptions {
    /// Refuse to recover a journal modified more recently than this duration.
    pub minimum_idle: StdDuration,
    /// Override the idle guard. This never permits rewriting a finalized trace.
    pub force: bool,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            minimum_idle: StdDuration::from_secs(300),
            force: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceManifest {
    pub format_version: u32,
    pub trace_id: String,
    /// Immutable ownership boundary used by the viewer API. Old manifests default
    /// to the local-only tenant so they remain readable without becoming remotely
    /// visible to newly configured tenants.
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub command: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination: Option<ProcessTermination>,
    pub journal: Option<JournalFile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<TraceDiagnostic>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<RedactionProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterProvenance>,
    /// Public encryption envelope. When present, sensitive manifest fields and
    /// every event frame are XChaCha20-Poly1305 ciphertext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    pub algorithm: String,
    pub key_id: String,
    pub private_manifest: String,
}

/// Sensitive manifest fields stored only as authenticated ciphertext. The
/// journal digest and event count live here so that an attacker without the
/// key cannot truncate trailing frames and rewrite the expected digest/count.
#[derive(Serialize, Deserialize)]
struct PrivateManifest {
    name: Option<String>,
    command: Vec<String>,
    ended_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    termination: Option<ProcessTermination>,
    journal: Option<JournalFile>,
    diagnostics: Vec<TraceDiagnostic>,
    capabilities: Vec<String>,
    redaction: Option<RedactionProvenance>,
    adapter: Option<AdapterProvenance>,
}

fn default_tenant_id() -> String {
    LOCAL_TENANT.to_owned()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterProvenance {
    pub provider: String,
    pub schema_version: u32,
    pub transport: String,
    pub completeness: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionProvenance {
    /// Safe defaults are always active for object-shaped event payloads.
    pub structured_defaults: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_fields: Vec<String>,
    #[serde(default)]
    pub terminal_literal_count: usize,
    #[serde(default)]
    pub terminal_regex_count: usize,
}

#[derive(Clone, Debug)]
pub struct RedactionConfig {
    fields: HashSet<String>,
    custom_fields: Vec<String>,
    terminal_literals: Vec<String>,
    terminal_regexes: Vec<regex::Regex>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self::new(
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .expect("empty redaction patterns are valid")
    }
}

impl RedactionConfig {
    pub fn new(
        custom_fields: impl IntoIterator<Item = impl Into<String>>,
        terminal_literals: impl IntoIterator<Item = impl Into<String>>,
        terminal_regexes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self> {
        let mut fields: HashSet<String> = [
            "password",
            "passwd",
            "secret",
            "clientsecret",
            "apikey",
            "accesstoken",
            "refreshtoken",
            "token",
            "authorization",
            "proxyauthorization",
            "cookie",
            "setcookie",
            "secretaccesskey",
            "privatekey",
        ]
        .into_iter()
        .map(normalize_redaction_field)
        .collect();
        let mut custom_fields: Vec<String> = custom_fields
            .into_iter()
            .map(Into::into)
            .filter(|field| !field.trim().is_empty())
            .collect();
        custom_fields.sort();
        custom_fields.dedup();
        fields.extend(custom_fields.iter().map(normalize_redaction_field));
        let terminal_literals = terminal_literals
            .into_iter()
            .map(Into::into)
            .filter(|literal| !literal.is_empty())
            .collect();
        let terminal_regexes = terminal_regexes
            .into_iter()
            .map(Into::into)
            .map(|pattern: String| {
                regex::Regex::new(&pattern)
                    .with_context(|| format!("invalid terminal redaction regex: {pattern}"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            fields,
            custom_fields,
            terminal_literals,
            terminal_regexes,
        })
    }

    fn provenance(&self) -> RedactionProvenance {
        RedactionProvenance {
            structured_defaults: true,
            custom_fields: self.custom_fields.clone(),
            terminal_literal_count: self.terminal_literals.len(),
            terminal_regex_count: self.terminal_regexes.len(),
        }
    }

    fn redact_event(&self, kind: &str, payload: &mut serde_json::Value) {
        redact_structured_fields(payload, &self.fields);
        if matches!(
            kind,
            "process.stdout" | "process.stderr" | "process.terminal"
        ) && let Some(text) = payload.get("text").and_then(serde_json::Value::as_str)
        {
            let mut redacted = text.to_owned();
            for literal in &self.terminal_literals {
                redacted = redacted.replace(literal, "[REDACTED]");
            }
            for pattern in &self.terminal_regexes {
                redacted = pattern.replace_all(&redacted, "[REDACTED]").into_owned();
            }
            payload["text"] = serde_json::Value::String(redacted);
        }
    }
}

fn normalize_redaction_field(field: impl AsRef<str>) -> String {
    field
        .as_ref()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn redact_structured_fields(value: &mut serde_json::Value, fields: &HashSet<String>) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, child) in object {
                let normalized = normalize_redaction_field(key);
                if fields
                    .iter()
                    .any(|sensitive| normalized == *sensitive || normalized.ends_with(sensitive))
                {
                    *child = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_structured_fields(child, fields);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_structured_fields(item, fields);
            }
        }
        _ => {}
    }
}

pub struct TraceWriter {
    root: PathBuf,
    manifest: TraceManifest,
    journal: BufWriter<File>,
    sequence: u64,
    redaction: RedactionConfig,
    encryption_key: Option<EncryptionKey>,
}

impl TraceWriter {
    pub fn create(root: impl AsRef<Path>, command: Vec<String>) -> Result<Self> {
        Self::create_named(root, command, None)
    }

    pub fn create_named(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
    ) -> Result<Self> {
        Self::create_named_with_redaction(root, command, name, RedactionConfig::default())
    }

    pub fn create_named_with_redaction(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        redaction: RedactionConfig,
    ) -> Result<Self> {
        Self::create_named_for_tenant_with_redaction(root, command, name, LOCAL_TENANT, redaction)
    }

    pub fn create_named_for_tenant_with_redaction(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        tenant_id: &str,
        redaction: RedactionConfig,
    ) -> Result<Self> {
        let master_key = crypto::key_from_environment()?;
        Self::create_with_master_key(root, command, name, tenant_id, redaction, master_key)
    }

    pub fn create_named_for_tenant_with_redaction_and_key(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        tenant_id: &str,
        redaction: RedactionConfig,
        master_key: EncryptionKey,
    ) -> Result<Self> {
        Self::create_with_master_key(root, command, name, tenant_id, redaction, Some(master_key))
    }

    fn create_with_master_key(
        root: impl AsRef<Path>,
        command: Vec<String>,
        name: Option<String>,
        tenant_id: &str,
        redaction: RedactionConfig,
        master_key: Option<EncryptionKey>,
    ) -> Result<Self> {
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty()
            || tenant_id.len() > 128
            || !tenant_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            bail!("tenant id must be 1-128 ASCII letters, digits, '.', '_' or '-'")
        }
        let root = root.as_ref().to_path_buf();
        if root.exists() {
            bail!("trace path already exists: {}", root.display());
        }
        create_private_dir(&root)?;
        create_private_dir(&root.join("events"))?;
        create_private_dir(&root.join("blobs"))?;
        create_private_dir(&root.join("blobs/sha256"))?;
        create_private_dir(&root.join("indexes"))?;

        let mut capabilities = vec![
            "process".into(),
            "terminal".into(),
            "agent-events".into(),
            "causal-links".into(),
            "structured-redaction".into(),
        ];
        if !redaction.terminal_literals.is_empty() || !redaction.terminal_regexes.is_empty() {
            capabilities.push("terminal-redaction".into());
        }
        let trace_id = Uuid::now_v7().to_string();
        let encryption_key = master_key
            .as_ref()
            .map(|key| key.for_trace(&trace_id))
            .transpose()?;
        if encryption_key.is_some() {
            capabilities.push("encrypted-at-rest.xchacha20poly1305".into());
        }
        let manifest = TraceManifest {
            format_version: FORMAT_VERSION,
            trace_id,
            tenant_id: tenant_id.to_owned(),
            name: name.filter(|value| !value.trim().is_empty()),
            command,
            started_at: Utc::now(),
            ended_at: None,
            exit_code: None,
            termination: None,
            journal: None,
            diagnostics: Vec::new(),
            capabilities,
            redaction: Some(redaction.provenance()),
            adapter: None,
            encryption: encryption_key.as_ref().map(|_| EncryptionMetadata {
                algorithm: "XChaCha20-Poly1305".into(),
                key_id: master_key.as_ref().expect("master key exists").key_id(),
                private_manifest: String::new(),
            }),
        };
        write_manifest(&root, &manifest, encryption_key.as_ref())?;
        let journal = private_new_file(&root.join("events").join(ACTIVE_JOURNAL))?;
        Ok(Self {
            root,
            manifest,
            journal: BufWriter::new(journal),
            sequence: 0,
            redaction,
            encryption_key,
        })
    }

    pub fn trace_id(&self) -> &str {
        &self.manifest.trace_id
    }

    /// Advertise an optional recorder feature in the portable manifest.
    /// Duplicate values are ignored so callers can compose capture modes.
    pub fn add_capability(&mut self, capability: impl Into<String>) -> Result<()> {
        let capability = capability.into();
        if !self.manifest.capabilities.contains(&capability) {
            self.manifest.capabilities.push(capability);
            write_manifest(&self.root, &self.manifest, self.encryption_key.as_ref())?;
        }
        Ok(())
    }

    /// Record which native structured stream contributed normalized evidence.
    pub fn set_adapter(&mut self, adapter: AdapterProvenance) -> Result<()> {
        let capability = format!("adapter.{}.v{}", adapter.provider, adapter.schema_version);
        if !self.manifest.capabilities.contains(&capability) {
            self.manifest.capabilities.push(capability);
        }
        self.manifest.adapter = Some(adapter);
        write_manifest(&self.root, &self.manifest, self.encryption_key.as_ref())
    }

    pub fn append(
        &mut self,
        kind: &str,
        source: &str,
        payload: serde_json::Value,
    ) -> Result<TraceEvent> {
        self.append_input(EventInput {
            kind: kind.to_owned(),
            source: source.to_owned(),
            payload,
            ..EventInput::default()
        })
    }

    pub fn append_input(&mut self, mut input: EventInput) -> Result<TraceEvent> {
        if input.kind.trim().is_empty() {
            bail!("event kind cannot be empty")
        }
        self.redaction.redact_event(&input.kind, &mut input.payload);
        let timestamp = input
            .timestamp
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| Utc::now().to_rfc3339());
        let event = TraceEvent {
            event_id: Uuid::now_v7().to_string(),
            trace_id: self.manifest.trace_id.clone(),
            sequence: self.sequence + 1,
            timestamp,
            kind: input.kind,
            source: input.source,
            payload_json: serde_json::to_string(&input.payload)?,
            actor_id: input.actor_id,
            actor_type: input.actor_type,
            parent_event_id: input.parent_event_id,
            span_id: input.span_id,
            parent_span_id: input.parent_span_id,
            correlation_id: input.correlation_id,
            status: input.status,
            duration_ms: input.duration_ms,
            links: input.links,
        };
        write_frame(
            &mut self.journal,
            &event,
            self.encryption_key.as_ref(),
            &self.manifest.trace_id,
        )?;
        self.journal.flush()?;
        self.sequence = event.sequence;
        Ok(event)
    }

    pub fn finish(self, exit_code: i32) -> Result<TraceManifest> {
        self.finish_termination(ProcessTermination::exited(exit_code))
    }

    pub fn finish_termination(mut self, termination: ProcessTermination) -> Result<TraceManifest> {
        self.journal.flush()?;
        self.journal.get_ref().sync_all()?;
        drop(self.journal);
        finalize_active_journal(
            &self.root,
            self.manifest,
            self.sequence,
            termination,
            self.encryption_key.as_ref(),
        )
    }
}

/// Finalize an abandoned active trace while preserving every complete frame.
/// A torn trailing frame is discarded and represented by a terminal recovery
/// event. Fresh traces are guarded by default so operators cannot accidentally
/// recover a recording that is still receiving events.
pub fn recover_interrupted_trace(
    root: impl AsRef<Path>,
    options: RecoveryOptions,
) -> Result<TraceManifest> {
    let root = root.as_ref();
    let mut manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    if manifest.journal.is_some() {
        bail!("trace is already finalized")
    }
    let active = root.join("events").join(ACTIVE_JOURNAL);
    if !active.is_file() {
        bail!("trace has no active journal to recover")
    }
    if !options.force {
        let mut modified = fs::metadata(&active)?.modified()?;
        let lease = root.join(RECORDER_LEASE);
        if let Ok(lease_modified) = fs::metadata(lease).and_then(|metadata| metadata.modified()) {
            modified = modified.max(lease_modified);
        }
        let idle = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(StdDuration::ZERO);
        if idle < options.minimum_idle {
            bail!(
                "trace appears active (journal idle for {}s; require {}s or pass --force)",
                idle.as_secs(),
                options.minimum_idle.as_secs()
            )
        }
    }
    let bytes = fs::read(&active)?;
    let (mut events, valid_bytes) =
        read_complete_frames(&bytes, encryption_key.as_ref(), &manifest.trace_id)?;
    if events
        .iter()
        .any(|event| event.trace_id != manifest.trace_id)
    {
        bail!("active journal contains an event from a different trace")
    }
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1 {
            bail!("active journal event sequence is not contiguous")
        }
    }
    let discarded_bytes = bytes.len().saturating_sub(valid_bytes);
    let recovery_event = TraceEvent {
        event_id: Uuid::now_v7().to_string(),
        trace_id: manifest.trace_id.clone(),
        sequence: events.len() as u64 + 1,
        timestamp: Utc::now().to_rfc3339(),
        kind: "session.interrupted".into(),
        source: "premier-recovery".into(),
        payload_json: serde_json::to_string(&serde_json::json!({
            "reason": "recorder_interrupted",
            "recovered_event_count": events.len(),
            "discarded_trailing_bytes": discarded_bytes,
        }))?,
        actor_id: "root".into(),
        actor_type: "process".into(),
        parent_event_id: String::new(),
        span_id: "session".into(),
        parent_span_id: String::new(),
        correlation_id: String::new(),
        status: "error".into(),
        duration_ms: 0,
        links: Vec::new(),
    };
    events.push(recovery_event);

    // A prior finalization may have crashed after publishing the compressed
    // journal but before committing the manifest. Do not remove that orphan
    // until the authoritative active journal has passed validation.
    let orphaned_final = root.join("events").join(FINAL_JOURNAL);
    if orphaned_final.exists() {
        fs::remove_file(orphaned_final)?;
    }

    let replacement = active.with_extension("pb.recovery.tmp");
    {
        let file = private_truncate_file(&replacement)?;
        let mut writer = BufWriter::new(file);
        for event in &events {
            write_frame(
                &mut writer,
                event,
                encryption_key.as_ref(),
                &manifest.trace_id,
            )?;
        }
        writer.flush()?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(&replacement, &active)?;
    manifest.termination = None;
    finalize_active_journal(
        root,
        manifest,
        events.len() as u64,
        ProcessTermination::interrupted(),
        encryption_key.as_ref(),
    )
}

fn finalize_active_journal(
    root: &Path,
    mut manifest: TraceManifest,
    event_count: u64,
    termination: ProcessTermination,
    encryption_key: Option<&EncryptionKey>,
) -> Result<TraceManifest> {
    let active = root.join("events").join(ACTIVE_JOURNAL);
    let final_path = root.join("events").join(FINAL_JOURNAL);
    let temporary_final = root.join("events").join(format!("{FINAL_JOURNAL}.tmp"));
    let mut input = BufReader::new(File::open(&active)?);
    let output = BufWriter::new(private_truncate_file(&temporary_final)?);
    let mut encoder = zstd::stream::write::Encoder::new(output, 3)?;
    std::io::copy(&mut input, &mut encoder)?;
    encoder.finish()?.into_inner()?.sync_all()?;
    fs::rename(&temporary_final, &final_path)?;

    manifest.diagnostics = validate_events(&read_frames(
        BufReader::new(File::open(&active)?),
        encryption_key,
        &manifest.trace_id,
    )?);
    manifest.ended_at = Some(Utc::now());
    manifest.exit_code = Some(termination.shell_exit_code());
    manifest.termination = Some(termination);
    manifest.journal = Some(JournalFile {
        path: format!("events/{FINAL_JOURNAL}"),
        sha256: sha256_file(&final_path)?,
        event_count,
    });
    write_manifest(root, &manifest, encryption_key)?;
    fs::remove_file(active)?;
    let lease = root.join(RECORDER_LEASE);
    if lease.exists() {
        fs::remove_file(lease)?;
    }
    Ok(manifest)
}

pub fn validate_events(events: &[TraceEvent]) -> Vec<TraceDiagnostic> {
    const KNOWN: [&str; 10] = [
        "agent.spawn",
        "agent.result",
        "agent.delegation",
        "agent.join",
        "model.request",
        "model.response",
        "tool.invocation",
        "tool.result",
        "approval.request",
        "approval.decision",
    ];
    const STATUSES: [&str; 14] = [
        "running",
        "ok",
        "error",
        "failed",
        "denied",
        "blocked",
        "pending",
        "approved",
        "rejected",
        "cancelled",
        "completed",
        "success",
        "warning",
        "skipped",
    ];
    let mut diagnostics = Vec::new();
    let mut seen_event_ids = HashSet::new();
    for event in events {
        if !event.parent_event_id.is_empty()
            && !seen_event_ids.contains(event.parent_event_id.as_str())
        {
            diagnostics.push(diagnostic(
                event,
                "unknown_parent_event",
                format!(
                    "{} references unknown or forward parent event {}",
                    event.kind, event.parent_event_id
                ),
            ));
        }
        seen_event_ids.insert(event.event_id.as_str());
    }
    for event in events {
        if !KNOWN.contains(&event.kind.as_str()) {
            continue;
        }
        if event.status.trim().is_empty() {
            diagnostics.push(diagnostic(
                event,
                "missing_status",
                format!("{} must declare a status", event.kind),
            ));
        } else if !STATUSES.contains(&event.status.to_ascii_lowercase().as_str()) {
            diagnostics.push(diagnostic(
                event,
                "invalid_status",
                format!("{} uses unknown status '{}'", event.kind, event.status),
            ));
        }
        if !event.payload().is_object() {
            diagnostics.push(diagnostic(
                event,
                "payload_not_object",
                format!("{} payload must be a JSON object", event.kind),
            ));
        }
    }
    for (start, finish) in [
        ("agent.spawn", "agent.result"),
        ("model.request", "model.response"),
        ("tool.invocation", "tool.result"),
        ("approval.request", "approval.decision"),
        ("agent.delegation", "agent.join"),
    ] {
        validate_pair(events, start, finish, &mut diagnostics);
    }
    diagnostics
}

fn diagnostic(event: &TraceEvent, code: &str, message: String) -> TraceDiagnostic {
    TraceDiagnostic {
        severity: DiagnosticSeverity::Warning,
        code: code.into(),
        message,
        event_id: Some(event.event_id.clone()),
        sequence: Some(event.sequence),
    }
}

fn validate_pair(
    events: &[TraceEvent],
    start_kind: &str,
    finish_kind: &str,
    diagnostics: &mut Vec<TraceDiagnostic>,
) {
    let starts: Vec<_> = events
        .iter()
        .filter(|event| event.kind == start_kind)
        .collect();
    let finishes: Vec<_> = events
        .iter()
        .filter(|event| event.kind == finish_kind)
        .collect();
    let mut by_correlation = HashMap::new();
    let mut by_span = HashMap::new();
    let mut by_actor = HashMap::new();
    for start in &starts {
        if !start.correlation_id.is_empty() {
            by_correlation
                .entry(start.correlation_id.as_str())
                .or_insert(*start);
        }
        if !start.span_id.is_empty() {
            by_span.entry(start.span_id.as_str()).or_insert(*start);
        }
        if !start.actor_id.is_empty() {
            by_actor.entry(start.actor_id.as_str()).or_insert(*start);
        }
    }
    let mut matched_starts = HashSet::new();
    for finish in finishes {
        let antecedent = if !finish.correlation_id.is_empty() {
            by_correlation.get(finish.correlation_id.as_str()).copied()
        } else {
            by_span
                .get(finish.span_id.as_str())
                .or_else(|| by_span.get(finish.parent_span_id.as_str()))
                .or_else(|| by_actor.get(finish.actor_id.as_str()))
                .copied()
        };
        let Some(start) = antecedent else {
            diagnostics.push(diagnostic(
                finish,
                "missing_lifecycle_start",
                format!("{finish_kind} has no matching {start_kind}"),
            ));
            continue;
        };
        matched_starts.insert(start.event_id.as_str());
        let causally_linked = finish.parent_event_id == start.event_id
            || finish.links.iter().any(|link| link == &start.event_id)
            || (!finish.parent_span_id.is_empty()
                && (finish.parent_span_id == start.span_id
                    || finish.parent_span_id == start.parent_span_id))
            || (!finish.correlation_id.is_empty() && finish.correlation_id == start.correlation_id);
        if !causally_linked {
            diagnostics.push(diagnostic(
                finish,
                "missing_causal_link",
                format!("{finish_kind} matches {start_kind} but has no causal link"),
            ));
        }
    }
    for start in starts {
        if !matched_starts.contains(start.event_id.as_str()) {
            diagnostics.push(diagnostic(
                start,
                "missing_lifecycle_finish",
                format!("{start_kind} has no matching {finish_kind}"),
            ));
        }
    }
}

pub fn read_events_page(
    root: impl AsRef<Path>,
    after_sequence: u64,
    limit: usize,
) -> Result<Vec<TraceEvent>> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    let final_path = root.join("events").join(FINAL_JOURNAL);
    let active_path = root.join("events").join(ACTIVE_JOURNAL);
    if final_path.exists() {
        let decoder = zstd::stream::read::Decoder::new(BufReader::new(File::open(final_path)?))?;
        read_frames_page(
            decoder,
            after_sequence,
            limit,
            encryption_key.as_ref(),
            &manifest.trace_id,
        )
    } else if active_path.exists() {
        read_frames_page(
            BufReader::new(File::open(active_path)?),
            after_sequence,
            limit,
            encryption_key.as_ref(),
            &manifest.trace_id,
        )
    } else {
        bail!("trace has no event journal")
    }
}

fn read_frames_page(
    mut reader: impl Read,
    after_sequence: u64,
    limit: usize,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::with_capacity(limit.min(1024));
    while events.len() < limit {
        let Some(event) = read_next_frame(&mut reader, encryption_key, trace_id)? else {
            break;
        };
        if event.sequence > after_sequence {
            events.push(event);
        }
    }
    Ok(events)
}

#[derive(Clone, Debug)]
pub struct ActiveEventTail {
    pub events: Vec<TraceEvent>,
    pub next_byte_offset: u64,
}

/// Read only complete frames appended to an active journal after `byte_offset`.
/// An incomplete trailing frame is intentionally left for the next poll.
pub fn read_active_events_after(
    root: impl AsRef<Path>,
    byte_offset: u64,
) -> Result<ActiveEventTail> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    let path = root.join("events").join(ACTIVE_JOURNAL);
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(byte_offset))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let (events, consumed) =
        read_complete_frames(&bytes, encryption_key.as_ref(), &manifest.trace_id)?;
    Ok(ActiveEventTail {
        events,
        next_byte_offset: byte_offset.saturating_add(consumed as u64),
    })
}

fn read_complete_frames(
    bytes: &[u8],
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<(Vec<TraceEvent>, usize)> {
    let mut events = Vec::new();
    let mut offset = 0_usize;
    while bytes.len().saturating_sub(offset) >= 4 {
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if length > MAX_FRAME_BYTES {
            bail!("event frame exceeds the 64 MiB safety limit")
        }
        let frame_end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(length))
            .context("event frame length overflow")?;
        if frame_end > bytes.len() {
            break;
        }
        events.push(decode_frame(
            &bytes[offset + 4..frame_end],
            encryption_key,
            trace_id,
        )?);
        offset = frame_end;
    }
    Ok((events, offset))
}

pub fn read_manifest(root: impl AsRef<Path>) -> Result<TraceManifest> {
    read_manifest_with_optional_key(root.as_ref(), None)
}

pub fn read_manifest_with_key(
    root: impl AsRef<Path>,
    master_key: &EncryptionKey,
) -> Result<TraceManifest> {
    read_manifest_with_optional_key(root.as_ref(), Some(master_key))
}

fn read_manifest_with_optional_key(
    root: &Path,
    master_key: Option<&EncryptionKey>,
) -> Result<TraceManifest> {
    let bytes = fs::read(root.join("manifest.json"))?;
    let mut manifest: TraceManifest = serde_json::from_slice(&bytes)?;
    if manifest.format_version != FORMAT_VERSION {
        bail!(
            "unsupported trace format version {}",
            manifest.format_version
        );
    }
    if let Some(metadata) = manifest.encryption.as_ref() {
        let key = if let Some(master_key) = master_key {
            if master_key.key_id() != metadata.key_id {
                bail!("trace decryption failed: wrong key")
            }
            master_key.for_trace(&manifest.trace_id)?
        } else {
            required_encryption_key(&manifest)?.context("encrypted trace requires a key")?
        };
        let aad = manifest_aad(&manifest);
        let plaintext = key.decrypt(&metadata.private_manifest, aad.as_bytes())?;
        let private: PrivateManifest = serde_json::from_slice(&plaintext)?;
        manifest.name = private.name;
        manifest.command = private.command;
        manifest.ended_at = private.ended_at;
        manifest.exit_code = private.exit_code;
        manifest.termination = private.termination;
        manifest.journal = private.journal;
        manifest.diagnostics = private.diagnostics;
        manifest.capabilities = private.capabilities;
        manifest.redaction = private.redaction;
        manifest.adapter = private.adapter;
    }
    Ok(manifest)
}

pub fn read_events(root: impl AsRef<Path>) -> Result<Vec<TraceEvent>> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    let encryption_key = required_encryption_key(&manifest)?;
    read_events_from_storage(root, &manifest, encryption_key.as_ref())
}

pub fn read_events_with_key(
    root: impl AsRef<Path>,
    master_key: &EncryptionKey,
) -> Result<Vec<TraceEvent>> {
    let root = root.as_ref();
    let manifest = read_manifest_with_key(root, master_key)?;
    let encryption_key = manifest
        .encryption
        .as_ref()
        .map(|_| master_key.for_trace(&manifest.trace_id))
        .transpose()?;
    read_events_from_storage(root, &manifest, encryption_key.as_ref())
}

fn read_events_from_storage(
    root: &Path,
    manifest: &TraceManifest,
    encryption_key: Option<&EncryptionKey>,
) -> Result<Vec<TraceEvent>> {
    let final_path = root.join("events").join(FINAL_JOURNAL);
    let active_path = root.join("events").join(ACTIVE_JOURNAL);
    if final_path.exists() {
        let decoder = zstd::stream::read::Decoder::new(BufReader::new(File::open(final_path)?))?;
        read_frames(decoder, encryption_key, &manifest.trace_id)
    } else if active_path.exists() {
        read_frames(
            BufReader::new(File::open(active_path)?),
            encryption_key,
            &manifest.trace_id,
        )
    } else {
        bail!("trace has no event journal")
    }
}

pub fn verify(root: impl AsRef<Path>) -> Result<TraceManifest> {
    let root = root.as_ref();
    let manifest = read_manifest(root)?;
    verify_journal_digest(root, &manifest)?;
    let events = read_events(root)?;
    verify_event_structure(&manifest, &events)?;
    Ok(manifest)
}

/// Compare the finalized journal on disk against the manifest digest without
/// decoding any frames.
pub fn verify_journal_digest(root: impl AsRef<Path>, manifest: &TraceManifest) -> Result<()> {
    let journal = manifest
        .journal
        .as_ref()
        .context("trace is not finalized")?;
    if journal.path != format!("events/{FINAL_JOURNAL}") {
        bail!("manifest references a non-canonical journal path")
    }
    let actual_hash = sha256_file(&root.as_ref().join(&journal.path))?;
    if actual_hash != journal.sha256 {
        bail!("journal digest mismatch")
    }
    Ok(())
}

/// Check recorder-generated invariants of already-decoded events against the
/// manifest. Producer-controlled semantic references (`parent_event_id`,
/// `links`) are surfaced as [`validate_events`] diagnostics instead of
/// verification failures so a misbehaving subprocess cannot make an honest
/// trace permanently unverifiable.
pub fn verify_event_structure(manifest: &TraceManifest, events: &[TraceEvent]) -> Result<()> {
    let journal = manifest
        .journal
        .as_ref()
        .context("trace is not finalized")?;
    if events.len() as u64 != journal.event_count {
        bail!("event count mismatch")
    }
    if events
        .iter()
        .any(|event| event.trace_id != manifest.trace_id)
    {
        bail!("journal contains an event from a different trace")
    }
    let mut event_ids = HashSet::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if event.sequence != expected_sequence {
            bail!(
                "event sequence is not contiguous: expected {expected_sequence}, found {}",
                event.sequence
            )
        }
        if event.event_id.is_empty() || !event_ids.insert(event.event_id.as_str()) {
            bail!("journal contains an empty or duplicate event id")
        }
    }
    Ok(())
}

fn write_manifest(
    root: &Path,
    manifest: &TraceManifest,
    encryption_key: Option<&EncryptionKey>,
) -> Result<()> {
    let mut stored = manifest.clone();
    if let Some(key) = encryption_key {
        let private = PrivateManifest {
            name: stored.name.take(),
            command: std::mem::take(&mut stored.command),
            ended_at: stored.ended_at.take(),
            exit_code: stored.exit_code.take(),
            termination: stored.termination.take(),
            journal: stored.journal.take(),
            diagnostics: std::mem::take(&mut stored.diagnostics),
            capabilities: std::mem::take(&mut stored.capabilities),
            redaction: stored.redaction.take(),
            adapter: stored.adapter.take(),
        };
        let aad = manifest_aad(&stored);
        let encrypted = key.encrypt(&serde_json::to_vec(&private)?, aad.as_bytes())?;
        stored.encryption = Some(EncryptionMetadata {
            algorithm: "XChaCha20-Poly1305".into(),
            key_id: stored
                .encryption
                .as_ref()
                .map(|metadata| metadata.key_id.clone())
                .unwrap_or_else(|| key.key_id()),
            private_manifest: encrypted,
        });
    } else if stored.encryption.is_some() {
        bail!("refusing to write an encrypted manifest without its key")
    }
    let temporary = root.join("manifest.json.tmp");
    let mut file = private_truncate_file(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(&stored)?)?;
    file.sync_all()?;
    fs::rename(temporary, root.join("manifest.json"))?;
    Ok(())
}

fn required_encryption_key(manifest: &TraceManifest) -> Result<Option<EncryptionKey>> {
    let Some(metadata) = manifest.encryption.as_ref() else {
        return Ok(None);
    };
    if metadata.algorithm != "XChaCha20-Poly1305" {
        bail!("unsupported trace encryption algorithm")
    }
    let master_key = crypto::key_from_environment()?
        .context("encrypted trace requires PREMIER_TRACE_KEY_FILE")?;
    if master_key.key_id() != metadata.key_id {
        bail!("trace decryption failed: wrong key")
    }
    Ok(Some(master_key.for_trace(&manifest.trace_id)?))
}

fn manifest_aad(manifest: &TraceManifest) -> String {
    format!(
        "premier:manifest:v{}:{}:{}",
        manifest.format_version, manifest.trace_id, manifest.tenant_id
    )
}

/// Explicit offline ownership migration. Normal recording and viewer APIs never
/// mutate ownership; only a local trace may be claimed, and the manifest update
/// is atomic and re-encrypted under the existing key when applicable.
pub fn claim_local_trace(root: impl AsRef<Path>, tenant_id: &str) -> Result<TraceManifest> {
    validate_tenant_id(tenant_id)?;
    let root = root.as_ref();
    let mut manifest = read_manifest(root)?;
    if manifest.tenant_id != LOCAL_TENANT {
        bail!("only a local trace may be claimed")
    }
    let key = required_encryption_key(&manifest)?;
    manifest.tenant_id = tenant_id.to_owned();
    write_manifest(root, &manifest, key.as_ref())?;
    Ok(manifest)
}

/// Inspect only the public manifest envelope; no decryption key is required.
pub fn trace_is_encrypted(root: impl AsRef<Path>) -> Result<bool> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(root.as_ref().join("manifest.json"))?)?;
    Ok(value
        .get("encryption")
        .is_some_and(|value| !value.is_null()))
}

/// Encrypt a finalized plaintext trace or rotate an encrypted trace to a new
/// master key. The replacement is fully written and decrypted for verification
/// before the original directory is renamed; any publication failure rolls the
/// original directory back into place.
pub fn reencrypt_finalized_trace(
    root: impl AsRef<Path>,
    new_master_key: EncryptionKey,
) -> Result<TraceManifest> {
    let root = root.as_ref();
    let mut manifest = read_manifest(root)?;
    let events = read_events(root)?;
    let journal = manifest
        .journal
        .as_ref()
        .context("only finalized traces can be encrypted or rotated")?;
    if journal.path != format!("events/{FINAL_JOURNAL}") {
        bail!("trace uses a non-canonical journal path")
    }
    ensure_no_unencrypted_auxiliary_files(root)?;

    let parent = root.parent().context("trace path has no parent")?;
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("trace");
    let nonce = Uuid::now_v7();
    let staging = parent.join(format!(".{name}.encrypt-{nonce}.tmp"));
    let backup = parent.join(format!(".{name}.encrypt-{nonce}.backup"));
    create_private_dir(&staging)?;
    create_private_dir(&staging.join("events"))?;
    create_private_dir(&staging.join("blobs"))?;
    create_private_dir(&staging.join("blobs/sha256"))?;
    create_private_dir(&staging.join("indexes"))?;

    let derived = new_master_key.for_trace(&manifest.trace_id)?;
    let final_path = staging.join("events").join(FINAL_JOURNAL);
    let output = BufWriter::new(private_truncate_file(&final_path)?);
    let mut encoder = zstd::stream::write::Encoder::new(output, 3)?;
    for event in &events {
        write_frame(&mut encoder, event, Some(&derived), &manifest.trace_id)?;
    }
    encoder.finish()?.into_inner()?.sync_all()?;
    manifest.journal = Some(JournalFile {
        path: format!("events/{FINAL_JOURNAL}"),
        sha256: sha256_file(&final_path)?,
        event_count: events.len() as u64,
    });
    if !manifest
        .capabilities
        .contains(&"encrypted-at-rest.xchacha20poly1305".to_owned())
    {
        manifest
            .capabilities
            .push("encrypted-at-rest.xchacha20poly1305".into());
    }
    manifest.encryption = Some(EncryptionMetadata {
        algorithm: "XChaCha20-Poly1305".into(),
        key_id: new_master_key.key_id(),
        private_manifest: String::new(),
    });
    write_manifest(&staging, &manifest, Some(&derived))?;
    let verified_manifest = read_manifest_with_key(&staging, &new_master_key)?;
    let verified_events = read_events_with_key(&staging, &new_master_key)?;
    if verified_events != events {
        fs::remove_dir_all(&staging)?;
        bail!("encrypted trace verification changed event evidence")
    }

    fs::rename(root, &backup)?;
    if let Err(error) = fs::rename(&staging, root) {
        let _ = fs::rename(&backup, root);
        let _ = fs::remove_dir_all(&staging);
        return Err(error.into());
    }
    fs::remove_dir_all(&backup)?;
    Ok(verified_manifest)
}

fn ensure_no_unencrypted_auxiliary_files(root: &Path) -> Result<()> {
    for relative in ["blobs", "indexes"] {
        let directory = root.join(relative);
        if !directory.exists() {
            continue;
        }
        let mut pending = vec![directory];
        while let Some(path) = pending.pop() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    pending.push(entry.path());
                } else {
                    bail!(
                        "cannot claim full at-rest encryption while auxiliary file {} exists",
                        entry.path().display()
                    )
                }
            }
        }
    }
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<()> {
    if tenant_id.is_empty()
        || tenant_id.len() > 128
        || !tenant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("tenant id must be 1-128 ASCII letters, digits, '.', '_' or '-'")
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn private_truncate_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn write_frame(
    writer: &mut impl Write,
    event: &TraceEvent,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<()> {
    let plaintext = event.encode_to_vec();
    let bytes = if let Some(key) = encryption_key {
        let mut envelope = event.sequence.to_le_bytes().to_vec();
        envelope.extend_from_slice(
            key.encrypt(&plaintext, event_aad(trace_id, event.sequence).as_bytes())?
                .as_bytes(),
        );
        envelope
    } else {
        plaintext
    };
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("event frame exceeds the 64 MiB safety limit")
    }
    let length = u32::try_from(bytes.len()).expect("frame length fits in u32");
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&bytes)?;
    Ok(())
}

fn read_frames(
    mut reader: impl Read,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Vec<TraceEvent>> {
    let mut events = Vec::new();
    while let Some(event) = read_next_frame(&mut reader, encryption_key, trace_id)? {
        events.push(event);
    }
    Ok(events)
}

fn read_next_frame(
    reader: &mut impl Read,
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<Option<TraceEvent>> {
    let mut length_bytes = [0_u8; 4];
    match reader.read_exact(&mut length_bytes) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_le_bytes(length_bytes) as usize;
    if length > MAX_FRAME_BYTES {
        bail!("event frame exceeds the 64 MiB safety limit")
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(Some(decode_frame(&bytes, encryption_key, trace_id)?))
}

fn decode_frame(
    bytes: &[u8],
    encryption_key: Option<&EncryptionKey>,
    trace_id: &str,
) -> Result<TraceEvent> {
    let plaintext = if let Some(key) = encryption_key {
        if bytes.len() < 8 {
            bail!("encrypted event frame is truncated")
        }
        let sequence = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let envelope =
            std::str::from_utf8(&bytes[8..]).context("invalid encrypted event envelope")?;
        let plaintext = key.decrypt(envelope, event_aad(trace_id, sequence).as_bytes())?;
        let decoded = TraceEvent::decode(plaintext.as_slice())?;
        if decoded.sequence != sequence {
            bail!("encrypted event sequence binding mismatch")
        }
        return Ok(decoded);
    } else {
        bytes.to_vec()
    };
    Ok(TraceEvent::decode(plaintext.as_slice())?)
}

fn event_aad(trace_id: &str, sequence: u64) -> String {
    format!("premier:journal-frame:v1:{trace_id}:{sequence}")
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::time::Duration as StdDuration;

    fn rewrite_events(root: &Path, events: &[TraceEvent]) {
        let final_path = root.join("events").join(FINAL_JOURNAL);
        let output = BufWriter::new(File::create(&final_path).unwrap());
        let mut encoder = zstd::stream::write::Encoder::new(output, 3).unwrap();
        for event in events {
            write_frame(&mut encoder, event, None, &event.trace_id).unwrap();
        }
        encoder
            .finish()
            .unwrap()
            .into_inner()
            .unwrap()
            .sync_all()
            .unwrap();
        let mut manifest = read_manifest(root).unwrap();
        manifest.journal.as_mut().unwrap().sha256 = sha256_file(&final_path).unwrap();
        write_manifest(root, &manifest, None).unwrap();
    }

    #[test]
    fn writes_reads_and_verifies_finalized_trace() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("test.atrace");
        let mut writer = TraceWriter::create(&root, vec!["echo".into(), "hello".into()]).unwrap();
        writer
            .append(
                "session.start",
                "premier",
                serde_json::json!({"cwd": "/tmp"}),
            )
            .unwrap();
        writer
            .append(
                "process.stdout",
                "command",
                serde_json::json!({"text": "hello\n"}),
            )
            .unwrap();
        let manifest = writer.finish(0).unwrap();

        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        assert_eq!(read_events(&root).unwrap()[1].payload()["text"], "hello\n");
        verify(&root).unwrap();
    }

    #[test]
    fn finalized_manifest_records_normal_exit_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("exit.atrace");
        let writer = TraceWriter::create(&root, vec!["sh".into()]).unwrap();

        let manifest = writer
            .finish_termination(ProcessTermination::exited(42))
            .unwrap();

        assert_eq!(manifest.exit_code, Some(42));
        assert_eq!(
            manifest.termination,
            Some(ProcessTermination {
                kind: TerminationKind::Exit,
                exit_code: Some(42),
                signal: None,
                signal_name: None,
            })
        );
        verify(&root).unwrap();
    }

    proptest! {
        #[test]
        fn normal_exit_codes_round_trip_exactly(code in 0_i32..=255) {
            prop_assert_eq!(ProcessTermination::exited(code).shell_exit_code(), code);
        }

        #[test]
        fn signal_exit_codes_follow_shell_convention(signal in 1_i32..=64) {
            prop_assert_eq!(
                ProcessTermination::signaled(signal, None).shell_exit_code(),
                128 + signal
            );
        }
    }

    #[test]
    fn older_manifests_without_termination_metadata_remain_readable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy.atrace");
        TraceWriter::create(&root, vec!["true".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        let manifest_path = root.join("manifest.json");
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        json.as_object_mut().unwrap().remove("termination");
        fs::write(&manifest_path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        let manifest = read_manifest(&root).unwrap();

        assert_eq!(manifest.exit_code, Some(0));
        assert_eq!(manifest.termination, None);
    }

    #[test]
    fn finalized_manifest_records_exact_signal_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("signal.atrace");
        let writer = TraceWriter::create(&root, vec!["sh".into()]).unwrap();

        let manifest = writer
            .finish_termination(ProcessTermination::signaled(15, Some("SIGTERM".into())))
            .unwrap();

        assert_eq!(manifest.exit_code, Some(143));
        let termination = manifest.termination.unwrap();
        assert_eq!(termination.kind, TerminationKind::Signal);
        assert_eq!(termination.signal, Some(15));
        assert_eq!(termination.signal_name.as_deref(), Some("SIGTERM"));
        verify(&root).unwrap();
    }

    #[test]
    fn recovery_refuses_a_fresh_active_trace_without_force() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("live.atrace");
        let _writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();

        let error = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                minimum_idle: StdDuration::from_secs(300),
                force: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("appears active"));
    }

    #[test]
    fn recovery_discards_a_torn_tail_and_finalizes_valid_frames() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("interrupted.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("session.start", "test", serde_json::json!({"ok": true}))
            .unwrap();
        drop(writer);
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join(ACTIVE_JOURNAL))
            .unwrap()
            .write_all(&[8, 0, 0, 0, 1, 2])
            .unwrap();
        fs::write(root.join(RECORDER_LEASE), "abandoned-recorder").unwrap();

        let manifest = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap();

        assert_eq!(manifest.exit_code, Some(130));
        assert_eq!(
            manifest.termination.as_ref().map(|value| &value.kind),
            Some(&TerminationKind::Interrupted)
        );
        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        let events = read_events(&root).unwrap();
        assert_eq!(events[0].kind, "session.start");
        assert_eq!(events[1].kind, "session.interrupted");
        verify(&root).unwrap();
        assert!(!root.join("events").join(ACTIVE_JOURNAL).exists());
        assert!(!root.join(RECORDER_LEASE).exists());
    }

    #[test]
    fn recovery_refuses_to_rewrite_a_finalized_trace() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("final.atrace");
        TraceWriter::create(&root, vec!["true".into()])
            .unwrap()
            .finish(0)
            .unwrap();

        let error = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("already finalized"));
    }

    #[test]
    fn recovery_resumes_after_a_crash_between_journal_and_manifest_commit() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("half-finalized.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("session.start", "test", serde_json::Value::Null)
            .unwrap();
        drop(writer);
        fs::write(
            root.join("events").join(FINAL_JOURNAL),
            b"orphaned partial finalization",
        )
        .unwrap();

        let manifest = recover_interrupted_trace(
            &root,
            RecoveryOptions {
                force: true,
                ..RecoveryOptions::default()
            },
        )
        .unwrap();

        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 2);
        verify(&root).unwrap();
    }

    #[test]
    fn semantic_validation_is_advisory_and_ignores_custom_kinds() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("diagnostics.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "custom.acme.telemetry".into(),
                status: "company-specific".into(),
                payload: serde_json::Value::Null,
                ..EventInput::default()
            })
            .unwrap();
        writer
            .append_input(EventInput {
                kind: "tool.invocation".into(),
                actor_id: "coder".into(),
                status: "mystery".into(),
                payload: serde_json::Value::Null,
                ..EventInput::default()
            })
            .unwrap();

        let manifest = writer.finish(0).unwrap();

        let codes: Vec<_> = manifest
            .diagnostics
            .iter()
            .map(|item| item.code.as_str())
            .collect();
        assert!(codes.contains(&"invalid_status"));
        assert!(codes.contains(&"payload_not_object"));
        assert!(codes.contains(&"missing_lifecycle_finish"));
        assert_eq!(
            manifest
                .diagnostics
                .iter()
                .filter(|item| item.sequence == Some(1))
                .count(),
            0
        );
        verify(&root).unwrap();
    }

    #[test]
    fn paired_lifecycle_events_with_correlation_are_semantically_clean() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("paired.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "model.request".into(),
                actor_id: "coder".into(),
                span_id: "request".into(),
                correlation_id: "model-call-1".into(),
                status: "running".into(),
                payload: serde_json::json!({"model": "test"}),
                ..EventInput::default()
            })
            .unwrap();
        writer
            .append_input(EventInput {
                kind: "model.response".into(),
                actor_id: "coder".into(),
                span_id: "response".into(),
                correlation_id: "model-call-1".into(),
                status: "ok".into(),
                payload: serde_json::json!({"response": "done"}),
                ..EventInput::default()
            })
            .unwrap();

        let manifest = writer.finish(0).unwrap();

        assert!(
            manifest.diagnostics.is_empty(),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn paginated_event_reads_are_sequence_based_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("page.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        for index in 0..5 {
            writer
                .append("custom.event", "test", serde_json::json!({"index": index}))
                .unwrap();
        }
        writer.finish(0).unwrap();

        let page = read_events_page(&root, 2, 2).unwrap();

        assert_eq!(
            page.iter().map(|event| event.sequence).collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn active_tail_reads_only_new_complete_frames() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tail.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("custom.one", "test", serde_json::Value::Null)
            .unwrap();
        let first = read_active_events_after(&root, 0).unwrap();
        writer
            .append("custom.two", "test", serde_json::Value::Null)
            .unwrap();

        let second = read_active_events_after(&root, first.next_byte_offset).unwrap();

        assert_eq!(
            first
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1]
        );
        assert_eq!(
            second
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2]
        );
        assert!(second.next_byte_offset > first.next_byte_offset);
    }

    #[test]
    fn rejects_modified_journal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("test.atrace");
        let writer = TraceWriter::create(&root, vec!["true".into()]).unwrap();
        writer.finish(0).unwrap();
        OpenOptions::new()
            .append(true)
            .open(root.join("events").join(FINAL_JOURNAL))
            .unwrap()
            .write_all(b"tampered")
            .unwrap();
        assert!(
            verify(&root)
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
    }

    #[test]
    fn preserves_subagent_causality_and_links() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("agents.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        let parent = writer
            .append_input(EventInput {
                kind: "agent.delegation".into(),
                actor_id: "coordinator".into(),
                actor_type: "agent".into(),
                span_id: "span-root".into(),
                status: "running".into(),
                payload: serde_json::json!({"delegate_to": "researcher"}),
                ..EventInput::default()
            })
            .unwrap();
        writer
            .append_input(EventInput {
                kind: "agent.turn".into(),
                actor_id: "researcher".into(),
                actor_type: "subagent".into(),
                parent_event_id: parent.event_id.clone(),
                span_id: "span-child".into(),
                parent_span_id: "span-root".into(),
                links: vec![parent.event_id],
                status: "ok".into(),
                ..EventInput::default()
            })
            .unwrap();
        writer.finish(0).unwrap();
        let events = read_events(&root).unwrap();
        assert_eq!(events[1].actor_type, "subagent");
        assert_eq!(events[1].parent_span_id, "span-root");
        assert_eq!(events[1].links.len(), 1);
    }

    #[test]
    fn rejects_reordered_sequences_even_when_the_manifest_digest_is_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("reordered.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("one", "test", serde_json::Value::Null)
            .unwrap();
        writer
            .append("two", "test", serde_json::Value::Null)
            .unwrap();
        writer.finish(0).unwrap();
        let mut events = read_events(&root).unwrap();
        events.swap(0, 1);
        rewrite_events(&root, &events);
        assert!(verify(&root).unwrap_err().to_string().contains("sequence"));
    }

    #[test]
    fn rejects_duplicate_event_ids_even_when_the_manifest_digest_is_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("duplicate.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append("one", "test", serde_json::Value::Null)
            .unwrap();
        writer
            .append("two", "test", serde_json::Value::Null)
            .unwrap();
        writer.finish(0).unwrap();
        let mut events = read_events(&root).unwrap();
        events[1].event_id = events[0].event_id.clone();
        rewrite_events(&root, &events);
        assert!(verify(&root).unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn unknown_parent_references_are_diagnostics_not_verification_failures() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("bogus-parent.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        writer
            .append_input(EventInput {
                kind: "tool.result".into(),
                parent_event_id: "not-a-recorded-event".into(),
                status: "ok".into(),
                payload: serde_json::json!({}),
                ..EventInput::default()
            })
            .unwrap();
        let manifest = writer.finish(0).unwrap();

        verify(&root).unwrap();
        assert!(
            manifest
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unknown_parent_event"),
            "{:?}",
            manifest.diagnostics
        );
    }

    #[test]
    fn oversized_frames_are_rejected_at_write_time_without_corrupting_the_trace() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("oversized.atrace");
        let mut writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        let error = writer
            .append(
                "blob",
                "test",
                serde_json::json!({"text": "x".repeat(MAX_FRAME_BYTES + 1)}),
            )
            .unwrap_err();
        assert!(error.to_string().contains("64 MiB"), "{error}");

        writer
            .append("small", "test", serde_json::json!({}))
            .unwrap();
        let manifest = writer.finish(0).unwrap();
        assert_eq!(manifest.journal.as_ref().unwrap().event_count, 1);
        verify(&root).unwrap();
    }

    #[test]
    fn encrypted_truncation_is_detected_even_when_the_public_manifest_is_rewritten() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("truncated.atrace");
        let key = EncryptionKey::from_hex(&"71".repeat(32)).unwrap();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into()],
            None,
            "local",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer.append("one", "test", serde_json::json!({})).unwrap();
        writer.append("two", "test", serde_json::json!({})).unwrap();
        writer.finish(0).unwrap();

        let public: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert!(
            public["journal"].is_null(),
            "encrypted manifests must not publish the journal digest: {public}"
        );

        // Attacker without the key: drop the trailing frame at a frame boundary
        // and publish a matching digest/count in the plaintext manifest.
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        let events = read_events_with_key(&root, &key).unwrap();
        let derived = key.for_trace(&manifest.trace_id).unwrap();
        let final_path = root.join("events").join(FINAL_JOURNAL);
        let output = BufWriter::new(File::create(&final_path).unwrap());
        let mut encoder = zstd::stream::write::Encoder::new(output, 3).unwrap();
        write_frame(&mut encoder, &events[0], Some(&derived), &manifest.trace_id).unwrap();
        encoder
            .finish()
            .unwrap()
            .into_inner()
            .unwrap()
            .sync_all()
            .unwrap();
        let mut doctored = public;
        doctored["journal"] = serde_json::json!({
            "path": format!("events/{FINAL_JOURNAL}"),
            "sha256": sha256_file(&final_path).unwrap(),
            "event_count": 1,
        });
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&doctored).unwrap(),
        )
        .unwrap();

        let reread = read_manifest_with_key(&root, &key).unwrap();
        let error = verify_journal_digest(&root, &reread).unwrap_err();
        assert!(error.to_string().contains("digest mismatch"), "{error}");
    }

    #[test]
    fn recording_redacts_nested_secret_fields_before_the_journal_write() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("redacted.atrace");
        let redaction = RedactionConfig::new(
            ["customer_pin"],
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .unwrap();
        let mut writer =
            TraceWriter::create_named_with_redaction(&root, vec!["agent".into()], None, redaction)
                .unwrap();

        writer
            .append_input(EventInput {
                kind: "tool.execution".into(),
                payload: serde_json::json!({
                    "authorization": "Bearer do-not-store",
                    "X-API-Key": "vendor-key",
                    "nested": [{"password": "hunter2", "customer_pin": "4815"}],
                    "safe": "keep me"
                }),
                ..EventInput::default()
            })
            .unwrap();

        let active = fs::read(root.join("events").join(ACTIVE_JOURNAL)).unwrap();
        let active_text = String::from_utf8_lossy(&active);
        assert!(!active_text.contains("do-not-store"));
        assert!(!active_text.contains("hunter2"));
        assert!(!active_text.contains("4815"));
        assert!(!active_text.contains("vendor-key"));

        let manifest = writer.finish(0).unwrap();
        let event = &read_events(&root).unwrap()[0];
        assert_eq!(event.payload()["authorization"], "[REDACTED]");
        assert_eq!(event.payload()["X-API-Key"], "[REDACTED]");
        assert_eq!(event.payload()["nested"][0]["password"], "[REDACTED]");
        assert_eq!(event.payload()["nested"][0]["customer_pin"], "[REDACTED]");
        assert_eq!(event.payload()["safe"], "keep me");
        assert!(
            manifest
                .capabilities
                .contains(&"structured-redaction".into())
        );
        assert_eq!(
            manifest.redaction.as_ref().unwrap().custom_fields,
            vec!["customer_pin"]
        );
    }

    #[test]
    fn terminal_output_is_raw_by_default_and_only_redacted_when_explicitly_configured() {
        let temp = tempfile::tempdir().unwrap();
        let raw_root = temp.path().join("raw.atrace");
        let mut raw = TraceWriter::create(&raw_root, vec!["command".into()]).unwrap();
        raw.append_input(EventInput {
            kind: "process.stdout".into(),
            payload: serde_json::json!({"text": "token=visible-by-default"}),
            ..EventInput::default()
        })
        .unwrap();
        raw.finish(0).unwrap();
        assert_eq!(
            read_events(&raw_root).unwrap()[0].payload()["text"],
            "token=visible-by-default"
        );

        let protected_root = temp.path().join("protected.atrace");
        let redaction = RedactionConfig::new(
            std::iter::empty::<String>(),
            ["literal-secret"],
            [r"token=[A-Za-z0-9-]+"],
        )
        .unwrap();
        let mut protected = TraceWriter::create_named_with_redaction(
            &protected_root,
            vec!["command".into()],
            None,
            redaction,
        )
        .unwrap();
        protected
            .append_input(EventInput {
                kind: "process.stderr".into(),
                payload: serde_json::json!({"text": "literal-secret token=regex-secret"}),
                ..EventInput::default()
            })
            .unwrap();
        let manifest = protected.finish(0).unwrap();
        let text = read_events(&protected_root).unwrap()[0].payload()["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(text, "[REDACTED] [REDACTED]");
        let provenance = manifest.redaction.unwrap();
        assert_eq!(provenance.terminal_literal_count, 1);
        assert_eq!(provenance.terminal_regex_count, 1);
        let manifest_text = fs::read_to_string(protected_root.join("manifest.json")).unwrap();
        assert!(!manifest_text.contains("literal-secret"));
        assert!(!manifest_text.contains("token=[A-Za-z0-9-]+"));
    }

    #[test]
    fn encrypted_trace_hides_manifest_and_active_events_and_round_trips() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("encrypted.atrace");
        let key = EncryptionKey::from_hex(&"41".repeat(32)).unwrap();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into(), "super-secret-argument".into()],
            Some("private investigation".into()),
            "acme",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer
            .append(
                "agent.result",
                "test",
                serde_json::json!({"text":"private evidence"}),
            )
            .unwrap();

        let manifest_on_disk = fs::read_to_string(root.join("manifest.json")).unwrap();
        let active_on_disk = fs::read(root.join("events").join(ACTIVE_JOURNAL)).unwrap();
        assert!(!manifest_on_disk.contains("super-secret-argument"));
        assert!(!manifest_on_disk.contains("private investigation"));
        assert!(!String::from_utf8_lossy(&active_on_disk).contains("private evidence"));
        assert!(trace_is_encrypted(&root).unwrap());

        writer.finish(0).unwrap();
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        assert_eq!(manifest.tenant_id, "acme");
        assert_eq!(manifest.command[1], "super-secret-argument");
        assert_eq!(
            read_events_with_key(&root, &key).unwrap()[0].payload()["text"],
            "private evidence"
        );

        let wrong = EncryptionKey::from_hex(&"42".repeat(32)).unwrap();
        assert!(read_manifest_with_key(&root, &wrong).is_err());
        assert!(read_events_with_key(&root, &wrong).is_err());
    }

    #[test]
    fn encrypted_event_tampering_is_detected_before_decode() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tampered.atrace");
        let key = EncryptionKey::from_hex(&"51".repeat(32)).unwrap();
        let mut writer = TraceWriter::create_named_for_tenant_with_redaction_and_key(
            &root,
            vec!["agent".into()],
            None,
            "local",
            RedactionConfig::default(),
            key.clone(),
        )
        .unwrap();
        writer
            .append("agent.result", "test", serde_json::json!({"ok":true}))
            .unwrap();
        drop(writer);
        let path = root.join("events").join(ACTIVE_JOURNAL);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(read_events_with_key(&root, &key).is_err());
    }

    #[test]
    fn finalized_plaintext_trace_is_atomically_migrated_to_encryption() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("legacy.atrace");
        let mut writer = TraceWriter::create_named(
            &root,
            vec!["agent".into(), "plaintext-command-secret".into()],
            Some("plaintext name".into()),
        )
        .unwrap();
        writer
            .append(
                "agent.result",
                "test",
                serde_json::json!({"text":"plaintext event secret"}),
            )
            .unwrap();
        writer.finish(0).unwrap();

        let key = EncryptionKey::from_hex(&"61".repeat(32)).unwrap();
        reencrypt_finalized_trace(&root, key.clone()).unwrap();
        assert!(trace_is_encrypted(&root).unwrap());
        let disk_manifest = fs::read_to_string(root.join("manifest.json")).unwrap();
        assert!(!disk_manifest.contains("plaintext-command-secret"));
        assert!(!disk_manifest.contains("plaintext name"));
        let manifest = read_manifest_with_key(&root, &key).unwrap();
        assert_eq!(manifest.command[1], "plaintext-command-secret");
        assert_eq!(
            read_events_with_key(&root, &key).unwrap()[0].payload()["text"],
            "plaintext event secret"
        );
        assert!(!temp.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".backup")
        }));
    }

    #[test]
    fn local_trace_claim_is_explicit_and_one_way() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("claim.atrace");
        TraceWriter::create(&root, vec!["agent".into()])
            .unwrap()
            .finish(0)
            .unwrap();
        assert_eq!(claim_local_trace(&root, "acme").unwrap().tenant_id, "acme");
        assert_eq!(read_manifest(&root).unwrap().tenant_id, "acme");
        assert!(claim_local_trace(&root, "other").is_err());
    }

    proptest! {
        #[test]
        fn tenant_validation_matches_the_bounded_identifier_contract(value in ".{0,180}") {
            let expected = !value.is_empty()
                && value.len() <= 128
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                });
            prop_assert_eq!(validate_tenant_id(&value).is_ok(), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn trace_storage_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("private.atrace");
        let writer = TraceWriter::create(&root, vec!["agent".into()]).unwrap();
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("events"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("manifest.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(root.join("events").join(ACTIVE_JOURNAL))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(writer);
    }
}
