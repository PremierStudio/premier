//! Quiet ambient telemetry for live agent sessions: deterministic detectors for an agent that
//! keeps hitting the egress wall, loops on the same error, or is about to run out of time or
//! workspace. Pure: callers feed events with their own clock (`now_ms`), so every decision is
//! reproducible in tests. Insights are upserted by `id`: each kind has one per session.

use std::collections::VecDeque;

use chrono::Utc;
use premier_core::{AuditDecision, AuditEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionInsightKind {
    RepeatedBlocks,
    ErrorLoopChurn,
    ApproachingTimeLimit,
    ApproachingSizeLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InsightSeverity {
    Attention,
    Notice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInsight {
    pub id: String,
    pub session_id: String,
    pub kind: SessionInsightKind,
    pub severity: InsightSeverity,
    pub title: String,
    pub detail: String,
    pub observed_at: String,
    pub metric_value: u64,
    pub threshold: u64,
}

/// A human step-in checkpoint of a paused session's workspace (a manifest, not a git commit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCheckpoint {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub author: String,
    pub edited_paths: Vec<String>,
}

/// One measurement of a workspace: file bytes, directory entries, and a cheap fingerprint of
/// `(name, size, mtime)` that changes when the agent writes anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WorkspaceUsage {
    pub bytes: u64,
    pub entries: usize,
    pub fingerprint: u64,
    pub over_budget: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct TelemetryConfig {
    pub block_window_secs: u64,
    pub block_threshold: usize,
    pub churn_window_secs: u64,
    pub error_line_threshold: usize,
    pub repeat_line_threshold: usize,
    pub stale_progress_secs: u64,
    pub time_warn_pct: u64,
    pub size_warn_pct: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            block_window_secs: 60,
            block_threshold: 3,
            churn_window_secs: 60,
            error_line_threshold: 12,
            repeat_line_threshold: 8,
            stale_progress_secs: 15,
            time_warn_pct: 80,
            size_warn_pct: 80,
        }
    }
}

const ERROR_MARKERS: [&str; 12] = [
    "[stderr]",
    "error",
    "failed",
    "exception",
    "panic",
    "permission denied",
    "traceback",
    "403",
    "429",
    "fatal",
    "econnrefused",
    "enoent",
];

pub struct SessionTelemetryTracker {
    session_id: String,
    config: TelemetryConfig,
    blocks: VecDeque<u64>,
    /// Block count the last `RepeatedBlocks` insight reported (0: none yet).
    blocks_reported: usize,
    error_lines: VecDeque<u64>,
    last_line: String,
    repeat_streak: usize,
    /// Metric the last `ErrorLoopChurn` insight reported (0: none since the last progress).
    churn_reported: u64,
    /// When the workspace last changed (or the first event seen, before any change).
    last_progress_ms: Option<u64>,
    last_usage: Option<WorkspaceUsage>,
    time_reported: bool,
    /// Percentage the last `ApproachingSizeLimit` insight reported (0: none yet).
    size_reported_pct: u64,
}

impl SessionTelemetryTracker {
    pub fn new(session_id: impl Into<String>, config: TelemetryConfig) -> Self {
        Self {
            session_id: session_id.into(),
            config,
            blocks: VecDeque::new(),
            blocks_reported: 0,
            error_lines: VecDeque::new(),
            last_line: String::new(),
            repeat_streak: 0,
            churn_reported: 0,
            last_progress_ms: None,
            last_usage: None,
            time_reported: false,
            size_reported_pct: 0,
        }
    }

    fn insight(
        &self,
        kind: SessionInsightKind,
        title: &str,
        detail: String,
        metric_value: u64,
        threshold: u64,
    ) -> SessionInsight {
        let (slug, severity) = match kind {
            SessionInsightKind::RepeatedBlocks => ("repeated-blocks", InsightSeverity::Attention),
            SessionInsightKind::ErrorLoopChurn => ("error-loop-churn", InsightSeverity::Attention),
            SessionInsightKind::ApproachingTimeLimit => {
                ("approaching-time-limit", InsightSeverity::Notice)
            }
            SessionInsightKind::ApproachingSizeLimit => {
                ("approaching-size-limit", InsightSeverity::Attention)
            }
        };
        SessionInsight {
            id: format!("{}:{slug}", self.session_id),
            session_id: self.session_id.clone(),
            kind,
            severity,
            title: title.to_owned(),
            detail,
            observed_at: Utc::now().to_rfc3339(),
            metric_value,
            threshold,
        }
    }

    fn progress_since(&mut self, now_ms: u64) -> u64 {
        let since = *self.last_progress_ms.get_or_insert(now_ms);
        now_ms.saturating_sub(since)
    }

    /// An egress decision of this session's proxy. Denials, exfiltration blocks and rate limits
    /// within the window count; reports at the threshold and again when the count doubles.
    pub fn record_audit_event(&mut self, ev: &AuditEvent, now_ms: u64) -> Option<SessionInsight> {
        if !matches!(
            ev.decision,
            AuditDecision::Denied | AuditDecision::ExfiltrationBlocked | AuditDecision::RateLimited
        ) {
            return None;
        }
        let window = self.config.block_window_secs.saturating_mul(1000);
        self.blocks.push_back(now_ms);
        while self
            .blocks
            .front()
            .is_some_and(|&t| now_ms.saturating_sub(t) > window)
        {
            self.blocks.pop_front();
        }
        let count = self.blocks.len();
        if count < self.config.block_threshold {
            self.blocks_reported = 0;
            return None;
        }
        // Once at the threshold, again only when the count in the window has doubled.
        if self.blocks_reported != 0 && count < self.blocks_reported.saturating_mul(2) {
            return None;
        }
        self.blocks_reported = count;
        let target = ev.target.as_deref().unwrap_or("an egress target");
        Some(self.insight(
            SessionInsightKind::RepeatedBlocks,
            "Agent keeps hitting blocked egress",
            format!(
                "{count} blocked requests in the last {}s (latest: {target}). It may be retrying something policy will not allow.",
                self.config.block_window_secs
            ),
            count as u64,
            self.config.block_threshold as u64,
        ))
    }

    /// One (already scrubbed) output line of the session. `[cage]` notices are the server's own
    /// and never count.
    pub fn record_output_line(&mut self, line: &str, now_ms: u64) -> Option<SessionInsight> {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("[cage]") {
            return None;
        }
        let stale_for = self.progress_since(now_ms);
        let lower = trimmed.to_lowercase();
        let window = self.config.churn_window_secs.saturating_mul(1000);
        if ERROR_MARKERS.iter().any(|m| lower.contains(m)) {
            self.error_lines.push_back(now_ms);
        }
        while self
            .error_lines
            .front()
            .is_some_and(|&t| now_ms.saturating_sub(t) > window)
        {
            self.error_lines.pop_front();
        }
        if trimmed == self.last_line {
            self.repeat_streak += 1;
        } else {
            trimmed.clone_into(&mut self.last_line);
            self.repeat_streak = 1;
        }
        let repeating = self.repeat_streak >= self.config.repeat_line_threshold;
        let erroring = self.error_lines.len() >= self.config.error_line_threshold
            && stale_for >= self.config.stale_progress_secs.saturating_mul(1000);
        if !repeating && !erroring {
            return None;
        }
        let (metric, threshold) = if repeating {
            (self.repeat_streak, self.config.repeat_line_threshold)
        } else {
            (self.error_lines.len(), self.config.error_line_threshold)
        };
        let metric = metric as u64;
        // Once per loop, again only when it has doubled.
        if self.churn_reported != 0 && metric < self.churn_reported.saturating_mul(2) {
            return None;
        }
        self.churn_reported = metric;
        let detail = if repeating {
            format!(
                "The same output line repeated {metric} times in a row: the agent looks stuck in a loop."
            )
        } else {
            format!(
                "{metric} error lines in the last {}s and no workspace change for {}s.",
                self.config.churn_window_secs,
                stale_for / 1000
            )
        };
        Some(self.insight(
            SessionInsightKind::ErrorLoopChurn,
            "Agent seems stuck on an error loop",
            detail,
            metric,
            threshold as u64,
        ))
    }

    /// A periodic workspace measurement, with the session's limits and how long it has run.
    pub fn record_workspace_sample(
        &mut self,
        usage: WorkspaceUsage,
        max_bytes: u64,
        max_entries: usize,
        elapsed_secs: u64,
        limit_secs: u64,
        now_ms: u64,
    ) -> Vec<SessionInsight> {
        let key = |u: &WorkspaceUsage| (u.bytes, u.entries, u.fingerprint);
        match self.last_usage {
            // The first sample is the baseline, not progress.
            None => {
                self.progress_since(now_ms);
            }
            Some(last) if key(&last) != key(&usage) => {
                self.last_progress_ms = Some(now_ms);
                self.churn_reported = 0;
                self.error_lines.clear();
            }
            Some(_) => {}
        }
        self.last_usage = Some(usage);

        let mut out = Vec::new();
        if !self.time_reported
            && limit_secs >= 5
            && elapsed_secs.saturating_mul(100)
                >= limit_secs.saturating_mul(self.config.time_warn_pct)
        {
            self.time_reported = true;
            out.push(self.insight(
                SessionInsightKind::ApproachingTimeLimit,
                "Session is close to its time limit",
                format!(
                    "{elapsed_secs}s of {limit_secs}s used. Pause it to step in before it is killed."
                ),
                elapsed_secs,
                limit_secs,
            ));
        }
        let pct = |used: u64, max: u64| used.saturating_mul(100) / max.max(1);
        let bytes_pct = if max_bytes > 0 {
            pct(usage.bytes, max_bytes)
        } else {
            0
        };
        let entries_pct = if max_entries > 0 {
            pct(usage.entries as u64, max_entries as u64)
        } else {
            0
        };
        let used_pct = bytes_pct.max(entries_pct);
        if used_pct >= self.config.size_warn_pct
            && (self.size_reported_pct == 0 || used_pct >= self.size_reported_pct + 10)
        {
            self.size_reported_pct = used_pct;
            let detail = if bytes_pct >= entries_pct {
                format!(
                    "Workspace holds {} of {max_bytes} bytes ({bytes_pct}%).",
                    usage.bytes
                )
            } else {
                format!(
                    "Workspace holds {} of {max_entries} entries ({entries_pct}%).",
                    usage.entries
                )
            };
            out.push(self.insight(
                SessionInsightKind::ApproachingSizeLimit,
                "Workspace is close to its size limit",
                detail,
                used_pct,
                self.config.size_warn_pct,
            ));
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use premier_core::{DelegatedIdentity, Principal};

    use super::*;

    fn tracker() -> SessionTelemetryTracker {
        SessionTelemetryTracker::new("cage-0001", TelemetryConfig::default())
    }

    fn event(decision: AuditDecision) -> AuditEvent {
        let who = DelegatedIdentity::human_only(Principal::parse("@owner").unwrap(), Vec::new());
        AuditEvent::now(&who, "premier-proxy", "egress", decision, "blocked")
    }

    #[test]
    fn repeated_blocks_fire_at_the_threshold_within_the_window() {
        let mut t = tracker();
        assert!(
            t.record_audit_event(&event(AuditDecision::Allowed), 0)
                .is_none()
        );
        assert!(
            t.record_audit_event(&event(AuditDecision::Denied), 1_000)
                .is_none()
        );
        assert!(
            t.record_audit_event(&event(AuditDecision::RateLimited), 2_000)
                .is_none()
        );
        let ins = t
            .record_audit_event(&event(AuditDecision::ExfiltrationBlocked), 3_000)
            .unwrap();
        assert_eq!(ins.kind, SessionInsightKind::RepeatedBlocks);
        assert_eq!(ins.severity, InsightSeverity::Attention);
        assert_eq!(ins.id, "cage-0001:repeated-blocks");
        assert_eq!((ins.metric_value, ins.threshold), (3, 3));
        // Further blocks stay quiet until the active window count doubles (3 -> 6).
        assert!(
            t.record_audit_event(&event(AuditDecision::Denied), 4_000)
                .is_none()
        );
        assert!(
            t.record_audit_event(&event(AuditDecision::Denied), 5_000)
                .is_none()
        );
        let ins = t
            .record_audit_event(&event(AuditDecision::Denied), 6_000)
            .unwrap();
        assert_eq!(ins.metric_value, 6);

        // Once older blocks age out of the window, a fresh burst reports again at the threshold.
        assert!(
            t.record_audit_event(&event(AuditDecision::Denied), 100_000)
                .is_none()
        );
        assert!(
            t.record_audit_event(&event(AuditDecision::Denied), 101_000)
                .is_none()
        );
        let ins = t
            .record_audit_event(&event(AuditDecision::Denied), 102_000)
            .unwrap();
        assert_eq!(ins.metric_value, 3);

        // Blocks spread wider than the window never add up.
        let mut t = tracker();
        for i in 0..10 {
            assert!(
                t.record_audit_event(&event(AuditDecision::Denied), i * 61_000)
                    .is_none()
            );
        }
    }

    #[test]
    fn repeated_identical_lines_are_an_error_loop() {
        let mut t = tracker();
        let mut fired = Vec::new();
        for i in 0..40u64 {
            fired.extend(t.record_output_line("  retrying fetch ...  ", i));
        }
        // At 8, then again only when doubled: 16 and 32.
        let metrics: Vec<u64> = fired.iter().map(|i| i.metric_value).collect();
        assert_eq!(metrics, [8, 16, 32]);
        assert!(
            fired
                .iter()
                .all(|i| i.kind == SessionInsightKind::ErrorLoopChurn
                    && i.id == "cage-0001:error-loop-churn"
                    && i.threshold == 8)
        );
    }

    #[test]
    fn many_errors_without_progress_are_churn_and_progress_resets_it() {
        let mut t = tracker();
        // Errors that vary, early in the session: not yet stale.
        for i in 0..12u64 {
            assert!(
                t.record_output_line(&format!("error: attempt {i}"), i * 100)
                    .is_none()
            );
        }
        // 15 s on with no workspace change: churn.
        let ins = t
            .record_output_line("[stderr] fatal: nope", 16_000)
            .unwrap();
        assert_eq!(ins.kind, SessionInsightKind::ErrorLoopChurn);
        assert_eq!(ins.metric_value, 13);

        // The workspace changes: progress, the error window starts over.
        let usage = |fp| WorkspaceUsage {
            bytes: 10,
            entries: 1,
            fingerprint: fp,
            over_budget: false,
        };
        assert!(
            t.record_workspace_sample(usage(1), 0, 0, 0, 0, 17_000)
                .is_empty()
        );
        assert!(
            t.record_workspace_sample(usage(2), 0, 0, 0, 0, 18_000)
                .is_empty()
        );
        for i in 0..20u64 {
            assert!(
                t.record_output_line(&format!("error {i}"), 18_000 + i * 100)
                    .is_none()
            );
        }
        // Stale again later: reported again.
        assert!(t.record_output_line("error again", 34_000).is_some());
    }

    #[test]
    fn cage_notices_and_clean_output_never_fire() {
        let mut t = tracker();
        for i in 0..100u64 {
            assert!(
                t.record_output_line("[cage] killed: time limit reached", i * 1000)
                    .is_none()
            );
            assert!(
                t.record_output_line(&format!("compiled unit {i}"), i * 1000)
                    .is_none()
            );
            assert!(t.record_output_line("", i * 1000).is_none());
        }
    }

    #[test]
    fn approaching_the_time_limit_is_noticed_once() {
        let mut t = tracker();
        let u = WorkspaceUsage::default();
        assert!(
            t.record_workspace_sample(u, 100, 100, 79, 100, 0)
                .is_empty()
        );
        let out = t.record_workspace_sample(u, 100, 100, 80, 100, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SessionInsightKind::ApproachingTimeLimit);
        assert_eq!(out[0].severity, InsightSeverity::Notice);
        assert_eq!(out[0].id, "cage-0001:approaching-time-limit");
        assert!(
            t.record_workspace_sample(u, 100, 100, 95, 100, 2)
                .is_empty()
        );
        // Too short a limit to warn about.
        let mut t = tracker();
        assert!(t.record_workspace_sample(u, 0, 0, 4, 4, 0).is_empty());
    }

    #[test]
    fn approaching_the_size_or_entries_limit_is_reported_and_re_reported_on_jumps() {
        let mut t = tracker();
        let bytes = |b| WorkspaceUsage {
            bytes: b,
            entries: 1,
            fingerprint: b,
            over_budget: false,
        };
        assert!(
            t.record_workspace_sample(bytes(790), 1000, 100, 0, 0, 0)
                .is_empty()
        );
        let out = t.record_workspace_sample(bytes(800), 1000, 100, 0, 0, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SessionInsightKind::ApproachingSizeLimit);
        assert_eq!(out[0].id, "cage-0001:approaching-size-limit");
        assert_eq!((out[0].metric_value, out[0].threshold), (80, 80));
        assert!(
            t.record_workspace_sample(bytes(850), 1000, 100, 0, 0, 2)
                .is_empty()
        );
        assert_eq!(
            t.record_workspace_sample(bytes(900), 1000, 100, 0, 0, 3)[0].metric_value,
            90
        );

        let mut t = tracker();
        let entries = WorkspaceUsage {
            bytes: 1,
            entries: 85,
            fingerprint: 0,
            over_budget: false,
        };
        let out = t.record_workspace_sample(entries, 1000, 100, 0, 0, 0);
        assert_eq!(out.len(), 1);
        assert!(out[0].detail.contains("entries"), "{}", out[0].detail);
    }
}
