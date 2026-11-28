//! Core data model for `premier-trace` (`agent-trace`): sessions, spans,
//! causal links, structured evidence payloads, delivery summaries, and live SSE events.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use premier_core::AuditDecision;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Placeholder path substituted when a viewer lacks `READ` on a span's target zone.
pub const REDACTED_ZONE_PATH: &str = "[REDACTED_ZONE_PATH]";

/// Lifecycle status of a traced AI coding agent session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    #[default]
    Active,
    Completed,
    Failed,
    Blocked,
}

/// Classification of an individual span within an `agent-trace` session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    PromptTurn,
    ToolCall,
    FileAccess,
    ProxyEgress,
    ErrorDiagnostic,
    DeliveryReport,
}

/// Cryptographic hash-chain verification status for a trace session.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// Session is still active/recording; chain verified up to current head.
    #[default]
    Live,
    /// Session is finalized and every span matches its tamper-evident SHA-256 chain.
    Verified,
    /// One or more spans failed hash-chain verification (tampered or corrupted).
    Tampered,
}

/// Tamper-evidence report embedded in [`DeliverySummary`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub status: IntegrityStatus,
    #[serde(default)]
    pub verified_spans: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub head_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregated execution, safety, usage, and delivery metrics for a traced session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverySummary {
    pub total_spans: usize,
    pub error_count: usize,
    pub blocked_count: usize,
    pub bytes_scrubbed: usize,
    #[serde(default)]
    pub files_touched: Vec<String>,
    pub duration_ms: u64,
    #[serde(default)]
    pub total_tokens_in: u64,
    #[serde(default)]
    pub total_tokens_out: u64,
    #[serde(default)]
    pub total_cost_usd_micros: u64,
    #[serde(default)]
    pub actors: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub provenance_digest: String,
    #[serde(default)]
    pub integrity: IntegrityReport,
}

/// A single structured trace span emitted by a coding agent, tool hook, or egress proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSpan {
    pub span_id: String,
    pub timestamp: DateTime<Utc>,
    pub kind: SpanKind,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<AuditDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default)]
    pub bytes_scrubbed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default)]
    pub redacted_for_viewer: bool,
    // ── Rich flight-recorder causality, telemetry, and structured evidence ──
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd_micros: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_snippet: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<Value>,
    // ── Tamper-evident hash chain & provenance source ──
    #[serde(default)]
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_hash: Option<String>,
}

impl TraceSpan {
    /// Compute this span's deterministic SHA-256 chain hash linked to `prev_hash`.
    pub fn compute_event_hash(&self, prev_hash: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"premier-trace-v1:");
        hasher.update(prev_hash.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(self.sequence.to_string().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(self.span_id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(format!("{:?}", self.kind).as_bytes());
        hasher.update(b"\x1f");
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(self.summary.as_bytes());
        hasher.update(b"\x1f");
        if let Some(ref p) = self.path {
            hasher.update(p.as_bytes());
        }
        hasher.update(b"\x1f");
        if let Some(ref d) = self.decision {
            hasher.update(format!("{d:?}").as_bytes());
        }
        hasher.update(b"\x1f");
        if let Some(ref diff) = self.diff {
            hasher.update(diff.as_bytes());
        }
        hasher.update(b"\x1f");
        if let Some(ref code) = self.code_snippet {
            hasher.update(code.as_bytes());
        }
        hasher.update(b"\x1f");
        if let Some(code) = self.exit_code {
            hasher.update(code.to_string().as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

impl Default for TraceSpan {
    fn default() -> Self {
        Self {
            span_id: String::new(),
            timestamp: Utc::now(),
            kind: SpanKind::ToolCall,
            summary: String::new(),
            path: None,
            zone: None,
            tool_name: None,
            command: None,
            decision: None,
            error_message: None,
            bytes_scrubbed: 0,
            duration_ms: None,
            redacted_for_viewer: false,
            actor_id: None,
            actor_type: None,
            parent_span_id: None,
            correlation_id: None,
            links: Vec::new(),
            status: None,
            exit_code: None,
            tokens_in: None,
            tokens_out: None,
            cost_usd_micros: None,
            input: None,
            output: None,
            diff: None,
            code_snippet: None,
            language: None,
            authority: None,
            sequence: 0,
            source: None,
            prev_hash: None,
            event_hash: None,
        }
    }
}

/// A complete AI coding agent session linked to a principal, branch, and optional Change-Id / commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceSession {
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub model: String,
    pub tool_name: String,
    pub branch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_oid: Option<String>,
    pub status: SessionStatus,
    #[serde(default)]
    pub spans: Vec<TraceSpan>,
    #[serde(default)]
    pub delivery: DeliverySummary,
}

impl TraceSession {
    /// Recompute `delivery` metrics directly from `self.spans`.
    ///
    /// Redacted zone placeholders are never exposed in `files_touched`.
    pub fn recompute_delivery(&mut self) {
        let mut error_count = 0usize;
        let mut blocked_count = 0usize;
        let mut bytes_scrubbed = 0usize;
        let mut files = BTreeSet::new();
        let mut actors = BTreeSet::new();
        let mut span_duration_sum = 0u64;
        let mut total_tokens_in = 0u64;
        let mut total_tokens_out = 0u64;
        let mut total_cost_usd_micros = 0u64;

        for span in &self.spans {
            if span.kind == SpanKind::ErrorDiagnostic || span.error_message.is_some() {
                error_count += 1;
            }
            if matches!(
                span.decision,
                Some(
                    AuditDecision::Denied
                        | AuditDecision::ExfiltrationBlocked
                        | AuditDecision::RateLimited
                        | AuditDecision::BudgetExceeded
                )
            ) {
                blocked_count += 1;
            }
            bytes_scrubbed = bytes_scrubbed.saturating_add(span.bytes_scrubbed);
            if let Some(ref path) = span.path
                && !path.is_empty()
                && path != REDACTED_ZONE_PATH
            {
                files.insert(path.clone());
            }
            if let Some(ref actor) = span.actor_id
                && !actor.is_empty()
            {
                actors.insert(actor.clone());
            } else if let Some(ref tool) = span.tool_name
                && !tool.is_empty()
            {
                actors.insert(tool.clone());
            }
            if let Some(ms) = span.duration_ms {
                span_duration_sum = span_duration_sum.saturating_add(ms);
            }
            if let Some(t) = span.tokens_in {
                total_tokens_in = total_tokens_in.saturating_add(t);
            }
            if let Some(t) = span.tokens_out {
                total_tokens_out = total_tokens_out.saturating_add(t);
            }
            if let Some(c) = span.cost_usd_micros {
                total_cost_usd_micros = total_cost_usd_micros.saturating_add(c);
            }
        }

        let elapsed_ms = self
            .updated_at
            .signed_duration_since(self.started_at)
            .num_milliseconds();
        let elapsed_u64 = u64::try_from(elapsed_ms).unwrap_or(0);
        let integrity = self.verify_integrity();
        let provenance_digest = if !integrity.head_hash.is_empty() {
            integrity.head_hash.clone()
        } else {
            self.provenance_digest()
        };

        self.delivery = DeliverySummary {
            total_spans: self.spans.len(),
            error_count,
            blocked_count,
            bytes_scrubbed,
            files_touched: files.into_iter().collect(),
            duration_ms: if span_duration_sum > 0 {
                span_duration_sum
            } else {
                elapsed_u64
            },
            total_tokens_in,
            total_tokens_out,
            total_cost_usd_micros,
            actors: actors.into_iter().collect(),
            provenance_digest,
            integrity,
        };
    }

    /// Assign monotonic `sequence` numbers and SHA-256 `prev_hash`/`event_hash` chain links
    /// for any unsealed spans in this session.
    pub fn seal_hash_chain(&mut self) {
        let genesis = self.genesis_hash();
        let mut prev = genesis;
        for (idx, span) in self.spans.iter_mut().enumerate() {
            let expected_seq = (idx as u64) + 1;
            if span.sequence == 0 {
                span.sequence = expected_seq;
            }
            if span.event_hash.is_none() {
                span.prev_hash = Some(prev.clone());
                let digest = span.compute_event_hash(&prev);
                span.event_hash = Some(digest.clone());
                prev = digest;
            } else if let Some(ref existing) = span.event_hash {
                prev = existing.clone();
            }
        }
    }

    /// Verify this session's tamper-evident SHA-256 span hash chain.
    pub fn verify_integrity(&self) -> IntegrityReport {
        if self.spans.is_empty() {
            return IntegrityReport {
                status: if self.status == SessionStatus::Active {
                    IntegrityStatus::Live
                } else {
                    IntegrityStatus::Verified
                },
                verified_spans: 0,
                head_hash: self.genesis_hash(),
                detail: None,
            };
        }

        let mut expected_prev = self.genesis_hash();
        let mut verified = 0usize;
        let mut any_unsealed = false;

        for (idx, span) in self.spans.iter().enumerate() {
            let Some(ref recorded_hash) = span.event_hash else {
                any_unsealed = true;
                expected_prev = span.compute_event_hash(&expected_prev);
                continue;
            };
            let expected_seq = (idx as u64) + 1;
            if span.sequence != expected_seq {
                return IntegrityReport {
                    status: IntegrityStatus::Tampered,
                    verified_spans: verified,
                    head_hash: expected_prev,
                    detail: Some(format!(
                        "span {} sequence mismatch: expected {}, found {}",
                        span.span_id, expected_seq, span.sequence
                    )),
                };
            }
            if span.prev_hash.as_deref() != Some(expected_prev.as_str()) {
                return IntegrityReport {
                    status: IntegrityStatus::Tampered,
                    verified_spans: verified,
                    head_hash: expected_prev,
                    detail: Some(format!(
                        "span {} prev_hash chain break at seq {}",
                        span.span_id, span.sequence
                    )),
                };
            }
            let recomputed = span.compute_event_hash(&expected_prev);
            if recomputed != *recorded_hash {
                return IntegrityReport {
                    status: IntegrityStatus::Tampered,
                    verified_spans: verified,
                    head_hash: expected_prev,
                    detail: Some(format!(
                        "span {} payload hash mismatch at seq {}",
                        span.span_id, span.sequence
                    )),
                };
            }
            verified += 1;
            expected_prev = recomputed;
        }

        let status = if self.status == SessionStatus::Active || any_unsealed {
            IntegrityStatus::Live
        } else {
            IntegrityStatus::Verified
        };
        IntegrityReport {
            status,
            verified_spans: verified,
            head_hash: expected_prev,
            detail: None,
        }
    }

    fn genesis_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"premier-session-genesis:");
        hasher.update(self.session_id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(self.principal.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(self.branch.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute a deterministic SHA-256 hex digest over the session's canonical metadata and span IDs.
    pub fn provenance_digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.session_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.principal.as_bytes());
        hasher.update(b":");
        hasher.update(self.branch.as_bytes());
        if let Some(ref cid) = self.change_id {
            hasher.update(b":");
            hasher.update(cid.as_bytes());
        }
        for span in &self.spans {
            hasher.update(b"|");
            hasher.update(span.span_id.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

/// Real-time event broadcast by [`crate::TraceStore`] for SSE subscribers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TraceEvent {
    SessionRecorded {
        session_id: String,
        principal: String,
        tool_name: String,
        status: SessionStatus,
        timestamp: DateTime<Utc>,
    },
    SpanRecorded {
        session_id: String,
        span: Box<TraceSpan>,
    },
}

/// Generate a compact, deterministic hex-suffixed identifier using SHA-256.
pub fn deterministic_id(prefix: &str, material: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(b":");
    hasher.update(material.as_bytes());
    let digest = hex::encode(hasher.finalize());
    let short = &digest[..12];
    format!("{prefix}_{short}")
}
