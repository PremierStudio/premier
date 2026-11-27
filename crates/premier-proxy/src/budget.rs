//! Per-session autonomy budget enforcement (blast radius + egress + JIT + anomaly caps).
//!
//! A [`BudgetTracker`] is shared (via `Arc`) between the egress proxy, the approval hub and the
//! embedding host. The first metric to exceed its limit trips the session into `Paused` (a human
//! may raise the limits and resume) or `Terminated` (final), per `on_budget_exceeded`.
//! Every request is checked *before* it is forwarded, so a breach never lets one more call out.

use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use chrono::{DateTime, Utc};
use premier_policy::{AutonomyBudget, BudgetAction};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

/// Serializable point-in-time view of a session's budget (limits, usage, breach state).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    pub limits: AutonomyBudget,
    pub files_modified: u64,
    pub lines_changed: u64,
    pub workspace_bytes: u64,
    pub egress_requests: u64,
    pub egress_bytes: u64,
    pub jit_requests: u64,
    pub denied_attempts: u64,
    pub bytes_scrubbed: u64,
    pub elapsed_secs: u64,
    pub max_secs: u64,
    pub paused: bool,
    pub terminated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breached_metric: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breach_reason: Option<String>,
}

/// Emitted once when a metric first exceeds its limit (and on manual termination).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetAlert {
    pub session_id: String,
    pub principal: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_profile: Option<String>,
    pub metric: String,
    pub current: u64,
    pub limit: u64,
    pub action: BudgetAction,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

/// How a paused session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetResumeOutcome {
    Resumed,
    Terminated,
}

/// Whether the session may currently make progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetGateDecision {
    Allowed,
    Paused,
    Terminated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackerState {
    Running,
    Paused,
    Terminated,
}

#[derive(Default)]
struct BudgetState {
    limits: AutonomyBudget,
    files_modified: u64,
    lines_changed: u64,
    workspace_bytes: u64,
    egress_requests: u64,
    egress_bytes: u64,
    jit_requests: u64,
    denied_attempts: u64,
    bytes_scrubbed: u64,
    paused: bool,
    terminated: bool,
    breached_metric: Option<String>,
    breach_reason: Option<String>,
    last_alert: Option<BudgetAlert>,
}

/// Thread-safe budget accounting + gate for one agent session.
pub struct BudgetTracker {
    session_id: String,
    principal: String,
    agent_profile: Option<String>,
    max_secs: u64,
    started_at: Instant,
    state: Mutex<BudgetState>,
    gate: watch::Sender<TrackerState>,
    alerts: broadcast::Sender<BudgetAlert>,
}

impl BudgetTracker {
    pub fn new(
        session_id: impl Into<String>,
        principal: impl Into<String>,
        agent_profile: Option<String>,
        limits: AutonomyBudget,
        max_secs: u64,
    ) -> Self {
        let (gate, _) = watch::channel(TrackerState::Running);
        let (alerts, _) = broadcast::channel(64);
        Self {
            session_id: session_id.into(),
            principal: principal.into(),
            agent_profile,
            max_secs,
            started_at: Instant::now(),
            state: Mutex::new(BudgetState {
                limits,
                ..BudgetState::default()
            }),
            gate,
            alerts,
        }
    }

    // A poisoned lock only means another thread panicked mid-update of plain counters.
    fn lock(&self) -> MutexGuard<'_, BudgetState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn snapshot_of(&self, s: &BudgetState) -> BudgetSnapshot {
        BudgetSnapshot {
            limits: s.limits.clone(),
            files_modified: s.files_modified,
            lines_changed: s.lines_changed,
            workspace_bytes: s.workspace_bytes,
            egress_requests: s.egress_requests,
            egress_bytes: s.egress_bytes,
            jit_requests: s.jit_requests,
            denied_attempts: s.denied_attempts,
            bytes_scrubbed: s.bytes_scrubbed,
            elapsed_secs: self.started_at.elapsed().as_secs(),
            max_secs: self.max_secs,
            paused: s.paused,
            terminated: s.terminated,
            breached_metric: s.breached_metric.clone(),
            breach_reason: s.breach_reason.clone(),
        }
    }

    pub fn snapshot(&self) -> BudgetSnapshot {
        self.snapshot_of(&self.lock())
    }

    pub fn is_paused(&self) -> bool {
        self.lock().paused
    }

    pub fn is_terminated(&self) -> bool {
        self.lock().terminated
    }

    pub fn gate_state(&self) -> BudgetGateDecision {
        let s = self.lock();
        if s.terminated {
            BudgetGateDecision::Terminated
        } else if s.paused {
            BudgetGateDecision::Paused
        } else {
            BudgetGateDecision::Allowed
        }
    }

    pub fn subscribe_alerts(&self) -> broadcast::Receiver<BudgetAlert> {
        self.alerts.subscribe()
    }

    fn alert(&self, metric: &str, current: u64, limit: u64, action: BudgetAction) -> BudgetAlert {
        BudgetAlert {
            session_id: self.session_id.clone(),
            principal: self.principal.clone(),
            agent_profile: self.agent_profile.clone(),
            metric: metric.to_owned(),
            current,
            limit,
            action,
            message: format!("autonomy budget exceeded: {metric} {current} > limit {limit}"),
            timestamp: Utc::now(),
        }
    }

    /// Trip the session into `Paused`/`Terminated`. Only the first breach of a running session
    /// produces an alert; later calls return `None`.
    fn trip(
        &self,
        s: &mut BudgetState,
        metric: &str,
        current: u64,
        limit: u64,
    ) -> Option<BudgetAlert> {
        if s.paused || s.terminated {
            return None;
        }
        let action = s.limits.on_budget_exceeded;
        let alert = self.alert(metric, current, limit, action);
        match action {
            BudgetAction::Pause => s.paused = true,
            BudgetAction::Terminate => s.terminated = true,
        }
        s.breached_metric = Some(metric.to_owned());
        s.breach_reason = Some(alert.message.clone());
        s.last_alert = Some(alert.clone());
        self.gate.send_replace(if s.terminated {
            TrackerState::Terminated
        } else {
            TrackerState::Paused
        });
        // No subscribers is fine: the audit trail still records the breach.
        let _ = self.alerts.send(alert.clone());
        Some(alert)
    }

    /// Trip if `current` exceeds a configured `limit`.
    fn check(
        &self,
        s: &mut BudgetState,
        metric: &str,
        current: u64,
        limit: Option<u64>,
    ) -> Option<BudgetAlert> {
        match limit {
            Some(l) if current > l => self.trip(s, metric, current, l),
            _ => None,
        }
    }

    /// The alert describing why the session is already blocked.
    fn blocked_alert(&self, s: &BudgetState) -> BudgetAlert {
        s.last_alert.clone().unwrap_or_else(|| {
            let action = if s.terminated {
                BudgetAction::Terminate
            } else {
                BudgetAction::Pause
            };
            self.alert("session", 0, 0, action)
        })
    }

    /// Gate + count one outbound request of `req_bytes` BEFORE it is forwarded.
    #[allow(clippy::result_large_err)]
    pub fn check_and_record_egress_request(&self, req_bytes: u64) -> Result<(), BudgetAlert> {
        let mut s = self.lock();
        if s.paused || s.terminated {
            return Err(self.blocked_alert(&s));
        }
        let next_requests = s.egress_requests.saturating_add(1);
        let next_bytes = s.egress_bytes.saturating_add(req_bytes);
        let max_requests = s.limits.max_egress_requests;
        let max_bytes = s.limits.max_egress_bytes;
        if let Some(alert) = self
            .check(&mut s, "egress_requests", next_requests, max_requests)
            .or_else(|| self.check(&mut s, "egress_bytes", next_bytes, max_bytes))
        {
            return Err(alert);
        }
        s.egress_requests = next_requests;
        s.egress_bytes = next_bytes;
        Ok(())
    }

    /// Account bytes that already crossed the wire (responses, tunnel traffic).
    pub fn record_egress_bytes(&self, delta: u64) -> Option<BudgetAlert> {
        let mut s = self.lock();
        s.egress_bytes = s.egress_bytes.saturating_add(delta);
        let (current, max) = (s.egress_bytes, s.limits.max_egress_bytes);
        self.check(&mut s, "egress_bytes", current, max)
    }

    /// Count one JIT approval request BEFORE it is queued for a human.
    #[allow(clippy::result_large_err)]
    pub fn record_jit_request(&self) -> Result<(), BudgetAlert> {
        let mut s = self.lock();
        if s.paused || s.terminated {
            return Err(self.blocked_alert(&s));
        }
        let next = s.jit_requests.saturating_add(1);
        let max = s.limits.max_jit_requests;
        if let Some(alert) = self.check(&mut s, "jit_requests", next, max) {
            return Err(alert);
        }
        s.jit_requests = next;
        Ok(())
    }

    /// Count a policy-denied or exfiltration-blocked attempt (anomaly signal).
    pub fn record_denied_attempt(&self, _reason: &str) -> Option<BudgetAlert> {
        let mut s = self.lock();
        s.denied_attempts = s.denied_attempts.saturating_add(1);
        let (current, max) = (s.denied_attempts, s.limits.max_denied_attempts);
        self.check(&mut s, "denied_attempts", current, max)
    }

    pub fn record_scrubbed(&self, delta: u64) {
        let mut s = self.lock();
        s.bytes_scrubbed = s.bytes_scrubbed.saturating_add(delta);
    }

    /// Replace the workspace usage (absolute values, from a diff/scan of the agent's checkout).
    pub fn update_workspace(
        &self,
        files_modified: u64,
        lines_changed: u64,
        workspace_bytes: u64,
    ) -> Option<BudgetAlert> {
        let mut s = self.lock();
        s.files_modified = files_modified;
        s.lines_changed = lines_changed;
        s.workspace_bytes = workspace_bytes;
        let l = s.limits.clone();
        self.check(
            &mut s,
            "files_modified",
            files_modified,
            l.max_files_modified,
        )
        .or_else(|| self.check(&mut s, "lines_changed", lines_changed, l.max_lines_changed))
        .or_else(|| {
            self.check(
                &mut s,
                "workspace_bytes",
                workspace_bytes,
                l.max_workspace_bytes,
            )
        })
    }

    /// Human budget approval: install new limits and, if `resume`, un-pause the session.
    /// A terminated session never comes back.
    pub fn raise_limits(&self, new_limits: AutonomyBudget, resume: bool) -> BudgetSnapshot {
        let mut s = self.lock();
        s.limits = new_limits;
        if resume && s.paused && !s.terminated {
            s.paused = false;
            s.breached_metric = None;
            s.breach_reason = None;
            s.last_alert = None;
            self.gate.send_replace(TrackerState::Running);
        }
        self.snapshot_of(&s)
    }

    /// Hard-stop the session (human kill switch or a host-detected violation).
    pub fn terminate(&self, reason: &str) {
        let mut s = self.lock();
        if s.terminated {
            return;
        }
        s.terminated = true;
        s.paused = false;
        let alert = BudgetAlert {
            message: reason.to_owned(),
            ..self.alert("terminated", 0, 0, BudgetAction::Terminate)
        };
        s.breached_metric = Some("terminated".to_owned());
        s.breach_reason = Some(reason.to_owned());
        s.last_alert = Some(alert.clone());
        self.gate.send_replace(TrackerState::Terminated);
        let _ = self.alerts.send(alert);
    }

    /// Park until a paused session is resumed or terminated (returns at once if running).
    pub async fn wait_resume_or_terminate(&self) -> BudgetResumeOutcome {
        let mut rx = self.gate.subscribe();
        loop {
            match *rx.borrow_and_update() {
                TrackerState::Running => return BudgetResumeOutcome::Resumed,
                TrackerState::Terminated => return BudgetResumeOutcome::Terminated,
                TrackerState::Paused => {}
            }
            if rx.changed().await.is_err() {
                return BudgetResumeOutcome::Terminated;
            }
        }
    }

    /// Wait until the session enters `Paused` or `Terminated` (returns at once if already blocked).
    pub async fn wait_blocked(&self) {
        let mut rx = self.gate.subscribe();
        loop {
            match *rx.borrow_and_update() {
                TrackerState::Paused | TrackerState::Terminated => return,
                TrackerState::Running => {}
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}
