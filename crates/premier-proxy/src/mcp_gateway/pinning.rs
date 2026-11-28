//! Tool-poisoning and rug-pull defence: canonical tool-definition hashing, prompt-injection
//! heuristics, and a trust-on-first-use pin registry with drift alerts and quarantine.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use premier_secrets::SecretRedactor;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

/// Longest tool description kept in records and alerts.
const MAX_STORED_DESCRIPTION: usize = 512;
/// Alerts kept in memory (oldest dropped first).
const MAX_ALERTS: usize = 1024;
const BROADCAST_CAPACITY: usize = 256;

/// Deterministic JSON encoding: object keys sorted at every depth, no whitespace.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key).unwrap_or_default());
                out.push(b':');
                if let Some(v) = map.get(key.as_str()) {
                    write_canonical(v, out);
                }
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(v, out);
            }
            out.push(b']');
        }
        scalar => out.extend(serde_json::to_vec(scalar).unwrap_or_default()),
    }
}

/// SHA-256 hex of the canonical `{ name, description, inputSchema, annotations }` of a tool.
/// Missing and `null` keys are omitted, so both spellings hash identically.
pub fn hash_tool_definition(tool: &Value) -> String {
    let mut subset = Map::new();
    for key in ["name", "description", "inputSchema", "annotations"] {
        if let Some(v) = tool.get(key).filter(|v| !v.is_null()) {
            subset.insert(key.to_owned(), v.clone());
        }
    }
    hex::encode(Sha256::digest(canonical_json_bytes(&Value::Object(subset))))
}

const INJECTION_MARKERS: &[&str] = &[
    "<important>",
    "</important>",
    "<system>",
    "</system>",
    "ignore previous instructions",
    "ignore all previous instructions",
    "disregard previous",
    "disregard all previous",
    "exfiltrate",
    ".premier/age.key",
    "~/.ssh/id_",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
];

/// Verbs that turn a mention of `secret_key` into an exfiltration instruction.
const EXFIL_VERBS: &[&str] = &[
    "send", "upload", "post ", "include", "pass ", "forward", "leak",
];

/// Heuristic prompt-injection / hidden-text scan of a tool description. Returns the reason.
pub fn scan_tool_poisoning(description: &str) -> Option<String> {
    if let Some(c) = description.chars().find(|c| {
        matches!(
            c,
            '\u{00AD}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}'
        )
    }) {
        return Some(format!(
            "hidden Unicode control character U+{:04X} in tool description",
            u32::from(c)
        ));
    }
    let lower = description.to_lowercase();
    let normalized = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(marker) = INJECTION_MARKERS
        .iter()
        .find(|m| lower.contains(*m) || normalized.contains(*m))
    {
        return Some(format!(
            "prompt-injection marker '{marker}' in tool description"
        ));
    }
    if (lower.contains("secret_key") || normalized.contains("secret_key"))
        && EXFIL_VERBS
            .iter()
            .any(|v| lower.contains(v) || normalized.contains(v))
    {
        return Some("instruction to move 'secret_key' in tool description".to_owned());
    }
    None
}

/// Trust state of one upstream tool definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPinStatus {
    /// Matches a hash pinned in policy (`pinned_tool_hashes`).
    Pinned,
    /// Matches the hash recorded on first use (or approved by an owner).
    Tofu,
    /// Seen, but neither policy-pinned nor TOFU-pinned (`pin_on_first_use = false`).
    Unverified,
    /// Hidden and uncallable until an owner resolves the alert.
    Quarantined,
}

/// Raised when a tool definition drifts from its pin or looks poisoned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDriftAlert {
    pub id: String,
    pub server: String,
    pub tool: String,
    pub full_name: String,
    /// `policy_pin_mismatch` | `rug_pull_detected` | `tool_poisoning_heuristic`.
    pub kind: String,
    /// `critical` | `high`.
    pub severity: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
    pub observed_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_description: Option<String>,
    pub quarantined: bool,
    pub detected_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
}

/// Last observation of an upstream tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedToolRecord {
    pub server: String,
    pub tool: String,
    pub description: Option<String>,
    pub schema_hash: String,
    pub status: ToolPinStatus,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Trust-on-first-use pin (also written when an owner approves a drift alert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofuPin {
    pub server: String,
    pub tool: String,
    pub hash: String,
    pub description: Option<String>,
    pub pinned_at: DateTime<Utc>,
}

/// A quarantined tool and the definition hash that put it there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub server: String,
    pub tool: String,
    pub hash: String,
}

/// Serializable registry state (persisted as `.premier/mcp-pins.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PinRegistrySnapshot {
    #[serde(default)]
    pub next_alert_seq: u64,
    #[serde(default)]
    pub pins: Vec<TofuPin>,
    #[serde(default)]
    pub records: Vec<ObservedToolRecord>,
    #[serde(default)]
    pub quarantined: Vec<QuarantineEntry>,
    #[serde(default)]
    pub alerts: Vec<ToolDriftAlert>,
}

/// Outcome of [`ToolPinRegistry::verify_or_pin`].
#[derive(Debug, Clone)]
pub struct ToolVerificationResult {
    pub status: ToolPinStatus,
    pub observed_hash: String,
    /// Alert raised by this call (none when an identical open alert already exists).
    pub alert: Option<ToolDriftAlert>,
}

type Key = (String, String);

#[derive(Default)]
struct State {
    version: u64,
    next_alert_seq: u64,
    pins: BTreeMap<Key, TofuPin>,
    records: BTreeMap<Key, ObservedToolRecord>,
    quarantined: BTreeMap<Key, String>,
    alerts: Vec<ToolDriftAlert>,
}

/// Thread-safe pin registry with a live alert broadcast.
pub struct ToolPinRegistry {
    state: Mutex<State>,
    tx: broadcast::Sender<ToolDriftAlert>,
}

impl Default for ToolPinRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ToolPinRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolPinRegistry").finish_non_exhaustive()
    }
}

fn key(server: &str, tool: &str) -> Key {
    (server.to_owned(), tool.to_owned())
}

fn bounded(text: &str) -> String {
    match text.char_indices().nth(MAX_STORED_DESCRIPTION) {
        Some((idx, _)) => format!("{}…", &text[..idx]),
        None => text.to_owned(),
    }
}

impl ToolPinRegistry {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            state: Mutex::new(State::default()),
            tx,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A poisoned lock only means a panic elsewhere; the maps themselves stay consistent.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn version(&self) -> u64 {
        self.lock().version
    }

    /// Check `tool_json` from `server` against its policy pin (`(expected_hash, is_server_layer)`),
    /// heuristics and TOFU pin, quarantining it (and raising an alert) on any failure.
    pub fn verify_or_pin(
        &self,
        server: &str,
        tool_json: &Value,
        policy_pin: Option<(&str, bool)>,
        pin_on_first_use: bool,
        redactor: Option<&SecretRedactor>,
    ) -> ToolVerificationResult {
        let tool = tool_json
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let observed_hash = hash_tool_definition(tool_json);
        let raw_description = tool_json
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let observed_description = {
            let scrubbed = match redactor {
                Some(r) => r.redact_str(raw_description).0,
                None => raw_description.to_owned(),
            };
            (!scrubbed.is_empty()).then(|| bounded(&scrubbed))
        };
        // Poisoning also hides in parameter descriptions, tool names, and annotations.
        let scan_text = {
            let mut parts = vec![tool.to_owned(), raw_description.to_owned()];
            if let Some(schema) = tool_json.get("inputSchema") {
                parts.push(schema.to_string());
            }
            if let Some(ann) = tool_json.get("annotations") {
                parts.push(ann.to_string());
            }
            parts.join("\n")
        };

        let k = key(server, tool);
        let mut st = self.lock();
        let result = |status, alert| ToolVerificationResult {
            status,
            observed_hash: observed_hash.clone(),
            alert,
        };

        if let Some((expected, is_server_layer)) = policy_pin {
            if observed_hash.eq_ignore_ascii_case(expected) {
                if is_server_layer {
                    if st.quarantined.remove(&k).is_some() {
                        st.version = st.version.wrapping_add(1);
                    }
                    upsert_record(
                        &mut st,
                        &k,
                        &observed_description,
                        &observed_hash,
                        ToolPinStatus::Pinned,
                    );
                    return result(ToolPinStatus::Pinned, None);
                }
                if st.quarantined.get(&k) == Some(&observed_hash) {
                    upsert_record(
                        &mut st,
                        &k,
                        &observed_description,
                        &observed_hash,
                        ToolPinStatus::Quarantined,
                    );
                    return result(ToolPinStatus::Quarantined, None);
                }
                if let Some(reason) = scan_tool_poisoning(&scan_text) {
                    let alert = self.raise(
                        &mut st,
                        &k,
                        "tool_poisoning_heuristic",
                        format!("'{server}:{tool}' quarantined: {reason}"),
                        Some(expected.to_owned()),
                        None,
                        &observed_hash,
                        &observed_description,
                    );
                    return result(ToolPinStatus::Quarantined, alert);
                }
                upsert_record(
                    &mut st,
                    &k,
                    &observed_description,
                    &observed_hash,
                    ToolPinStatus::Pinned,
                );
                return result(ToolPinStatus::Pinned, None);
            }
            let alert = self.raise(
                &mut st,
                &k,
                "policy_pin_mismatch",
                format!("'{server}:{tool}' definition does not match its policy-pinned hash"),
                Some(expected.to_owned()),
                None,
                &observed_hash,
                &observed_description,
            );
            return result(ToolPinStatus::Quarantined, alert);
        }

        if st.quarantined.get(&k) == Some(&observed_hash) {
            upsert_record(
                &mut st,
                &k,
                &observed_description,
                &observed_hash,
                ToolPinStatus::Quarantined,
            );
            return result(ToolPinStatus::Quarantined, None);
        }

        let pin = st.pins.get(&k).cloned();
        let pin_matches = pin.as_ref().is_some_and(|p| p.hash == observed_hash);
        // A matching pin was scanned when first trusted, or explicitly approved by an owner.
        if !pin_matches {
            if let Some(reason) = scan_tool_poisoning(&scan_text) {
                let alert = self.raise(
                    &mut st,
                    &k,
                    "tool_poisoning_heuristic",
                    format!("'{server}:{tool}' quarantined: {reason}"),
                    pin.as_ref().map(|p| p.hash.clone()),
                    pin.as_ref().and_then(|p| p.description.clone()),
                    &observed_hash,
                    &observed_description,
                );
                return result(ToolPinStatus::Quarantined, alert);
            }
            if let Some(pin) = &pin {
                let alert = self.raise(
                    &mut st,
                    &k,
                    "rug_pull_detected",
                    format!("'{server}:{tool}' definition changed since it was first trusted"),
                    Some(pin.hash.clone()),
                    pin.description.clone(),
                    &observed_hash,
                    &observed_description,
                );
                return result(ToolPinStatus::Quarantined, alert);
            }
        }

        let status = if st.quarantined.contains_key(&k) {
            ToolPinStatus::Quarantined
        } else if pin_matches {
            ToolPinStatus::Tofu
        } else if pin_on_first_use {
            st.pins.insert(
                k.clone(),
                TofuPin {
                    server: server.to_owned(),
                    tool: tool.to_owned(),
                    hash: observed_hash.clone(),
                    description: observed_description.clone(),
                    pinned_at: Utc::now(),
                },
            );
            st.version = st.version.wrapping_add(1);
            ToolPinStatus::Tofu
        } else {
            ToolPinStatus::Unverified
        };
        upsert_record(&mut st, &k, &observed_description, &observed_hash, status);
        result(status, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn raise(
        &self,
        st: &mut State,
        k: &Key,
        kind: &str,
        message: String,
        expected_hash: Option<String>,
        expected_description: Option<String>,
        observed_hash: &str,
        observed_description: &Option<String>,
    ) -> Option<ToolDriftAlert> {
        st.quarantined.insert(k.clone(), observed_hash.to_owned());
        upsert_record(
            st,
            k,
            observed_description,
            observed_hash,
            ToolPinStatus::Quarantined,
        );
        let duplicate = st.alerts.iter().any(|a| {
            a.resolved_at.is_none()
                && a.server == k.0
                && a.tool == k.1
                && a.observed_hash == observed_hash
        });
        if duplicate {
            return None;
        }
        st.next_alert_seq += 1;
        let alert = ToolDriftAlert {
            id: format!("mcp-alert-{:04}", st.next_alert_seq),
            server: k.0.clone(),
            tool: k.1.clone(),
            full_name: format!("{}:{}", k.0, k.1),
            kind: kind.to_owned(),
            severity: "critical".to_owned(),
            message,
            expected_hash,
            observed_hash: observed_hash.to_owned(),
            expected_description,
            observed_description: observed_description.clone(),
            quarantined: true,
            detected_at: Utc::now(),
            resolved_at: None,
            resolved_by: None,
        };
        if st.alerts.len() >= MAX_ALERTS {
            let evict_idx = st
                .alerts
                .iter()
                .position(|a| a.resolved_at.is_some())
                .unwrap_or(0);
            st.alerts.remove(evict_idx);
        }
        st.alerts.push(alert.clone());
        st.version = st.version.wrapping_add(1);
        tracing::warn!(
            alert = %alert.id,
            kind = %alert.kind,
            tool = %alert.full_name,
            "MCP tool quarantined"
        );
        let _ = self.tx.send(alert.clone());
        Some(alert)
    }

    pub fn is_quarantined(&self, server: &str, tool: &str) -> bool {
        self.lock().quarantined.contains_key(&key(server, tool))
    }

    /// Current status and observed hash; `(Unverified, None)` for a never-seen tool.
    pub fn status_of(
        &self,
        server: &str,
        tool: &str,
        policy_pin: Option<&str>,
    ) -> (ToolPinStatus, Option<String>) {
        let st = self.lock();
        let k = key(server, tool);
        let Some(rec) = st.records.get(&k) else {
            return (ToolPinStatus::Unverified, None);
        };
        let status = if st.quarantined.contains_key(&k) {
            ToolPinStatus::Quarantined
        } else if policy_pin.is_some_and(|p| p.eq_ignore_ascii_case(&rec.schema_hash)) {
            ToolPinStatus::Pinned
        } else {
            rec.status
        };
        (status, Some(rec.schema_hash.clone()))
    }

    pub fn has_observed_tool(&self, server: &str, tool: &str) -> bool {
        self.lock().records.contains_key(&key(server, tool))
    }

    pub fn has_observed_server(&self, server: &str) -> bool {
        self.lock().records.keys().any(|(s, _)| s == server)
    }

    pub fn list_observed_tools(&self, server: &str) -> Vec<ObservedToolRecord> {
        self.lock()
            .records
            .values()
            .filter(|r| r.server == server)
            .cloned()
            .collect()
    }

    /// All alerts, newest first.
    pub fn list_alerts(&self) -> Vec<ToolDriftAlert> {
        self.lock().alerts.iter().rev().cloned().collect()
    }

    /// Owner accepts the observed definition: re-pin to it and lift the quarantine.
    pub fn approve_alert(&self, id: &str, actor: &str) -> Option<ToolDriftAlert> {
        let mut st = self.lock();
        let idx = st.alerts.iter().position(|a| a.id == id)?;
        if st.alerts[idx].resolved_at.is_some() {
            return Some(st.alerts[idx].clone());
        }
        let now = Utc::now();
        let (server, tool, hash, description) = {
            let a = &st.alerts[idx];
            (
                a.server.clone(),
                a.tool.clone(),
                a.observed_hash.clone(),
                a.observed_description.clone(),
            )
        };
        let k = key(&server, &tool);
        st.pins.insert(
            k.clone(),
            TofuPin {
                server,
                tool,
                hash: hash.clone(),
                description,
                pinned_at: now,
            },
        );
        st.quarantined.remove(&k);
        if let Some(rec) = st.records.get_mut(&k)
            && rec.schema_hash == hash
        {
            rec.status = ToolPinStatus::Tofu;
        }
        let alert = &mut st.alerts[idx];
        alert.quarantined = false;
        alert.resolved_at = Some(now);
        alert.resolved_by = Some(actor.to_owned());
        let updated = alert.clone();
        st.version = st.version.wrapping_add(1);
        let _ = self.tx.send(updated.clone());
        Some(updated)
    }

    /// Resolve an alert without trusting the new definition. `keep_quarantined = false` lifts
    /// the quarantine, so the next observation is re-checked from scratch.
    pub fn dismiss_alert(
        &self,
        id: &str,
        actor: &str,
        keep_quarantined: bool,
    ) -> Option<ToolDriftAlert> {
        let mut st = self.lock();
        let idx = st.alerts.iter().position(|a| a.id == id)?;
        if st.alerts[idx].resolved_at.is_some() {
            return Some(st.alerts[idx].clone());
        }
        if !keep_quarantined {
            let k = key(&st.alerts[idx].server, &st.alerts[idx].tool);
            st.quarantined.remove(&k);
        }
        let alert = &mut st.alerts[idx];
        alert.quarantined = keep_quarantined;
        alert.resolved_at = Some(Utc::now());
        alert.resolved_by = Some(actor.to_owned());
        let updated = alert.clone();
        st.version = st.version.wrapping_add(1);
        let _ = self.tx.send(updated.clone());
        Some(updated)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ToolDriftAlert> {
        self.tx.subscribe()
    }

    pub fn snapshot(&self) -> PinRegistrySnapshot {
        let st = self.lock();
        PinRegistrySnapshot {
            next_alert_seq: st.next_alert_seq,
            pins: st.pins.values().cloned().collect(),
            records: st.records.values().cloned().collect(),
            quarantined: st
                .quarantined
                .iter()
                .map(|((server, tool), hash)| QuarantineEntry {
                    server: server.clone(),
                    tool: tool.clone(),
                    hash: hash.clone(),
                })
                .collect(),
            alerts: st.alerts.clone(),
        }
    }

    pub fn restore(&self, snap: PinRegistrySnapshot) {
        let mut st = self.lock();
        let max_seq = snap
            .alerts
            .iter()
            .filter_map(|a| a.id.strip_prefix("mcp-alert-")?.parse::<u64>().ok())
            .max()
            .unwrap_or(0);
        st.next_alert_seq = snap.next_alert_seq.max(max_seq);
        st.pins = snap
            .pins
            .into_iter()
            .map(|p| (key(&p.server, &p.tool), p))
            .collect();
        st.records = snap
            .records
            .into_iter()
            .map(|r| (key(&r.server, &r.tool), r))
            .collect();
        st.quarantined = snap
            .quarantined
            .into_iter()
            .map(|q| (key(&q.server, &q.tool), q.hash))
            .collect();
        st.alerts = snap.alerts;
        st.version = st.version.wrapping_add(1);
    }
}

fn upsert_record(
    st: &mut State,
    k: &Key,
    description: &Option<String>,
    hash: &str,
    status: ToolPinStatus,
) {
    let now = Utc::now();
    let is_new = !st.records.contains_key(k);
    let rec = st
        .records
        .entry(k.clone())
        .or_insert_with(|| ObservedToolRecord {
            server: k.0.clone(),
            tool: k.1.clone(),
            description: None,
            schema_hash: String::new(),
            status,
            first_seen_at: now,
            last_seen_at: now,
        });
    let changed = is_new
        || rec.description != *description
        || rec.schema_hash != hash
        || rec.status != status;
    rec.description = description.clone();
    rec.schema_hash = hash.to_owned();
    rec.status = status;
    rec.last_seen_at = now;
    if changed {
        st.version = st.version.wrapping_add(1);
    }
}
