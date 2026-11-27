import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  errorText,
  type AgentSessionRecord,
  type AutonomyBudget,
  type BudgetSnapshot,
} from "../api";
import { IconCheck, IconClose, IconPlay, IconQuarantine } from "./Icons";
import { DANGER_BTN, ErrorNote, OwnerOnly, SECONDARY_BTN } from "./forms";

interface Props {
  session: AgentSessionRecord;
  owner: boolean;
  onSessionChange: (rec: AgentSessionRecord) => void;
}

type NumericBudgetKey =
  | "max_files_modified"
  | "max_lines_changed"
  | "max_workspace_bytes"
  | "max_egress_requests"
  | "max_egress_bytes"
  | "max_jit_requests"
  | "max_denied_attempts";

interface GaugeMetric {
  key: string;
  limitKey?: NumericBudgetKey;
  label: string;
  current: number;
  limit: number | null;
  format: (value: number) => string;
}

const CUSTOM_FIELDS: {
  key: NumericBudgetKey;
  label: string;
  isBytes?: boolean;
}[] = [
  { key: "max_files_modified", label: "Files modified" },
  { key: "max_lines_changed", label: "Lines changed" },
  { key: "max_workspace_bytes", label: "Workspace bytes", isBytes: true },
  { key: "max_egress_requests", label: "Egress requests" },
  { key: "max_egress_bytes", label: "Egress bytes", isBytes: true },
  { key: "max_jit_requests", label: "JIT requests" },
  { key: "max_denied_attempts", label: "Denied attempts" },
];

const METRIC_TO_LIMIT_KEY: Record<string, NumericBudgetKey> = {
  files_modified: "max_files_modified",
  max_files_modified: "max_files_modified",
  lines_changed: "max_lines_changed",
  max_lines_changed: "max_lines_changed",
  workspace_bytes: "max_workspace_bytes",
  max_workspace_bytes: "max_workspace_bytes",
  egress_requests: "max_egress_requests",
  max_egress_requests: "max_egress_requests",
  egress_bytes: "max_egress_bytes",
  max_egress_bytes: "max_egress_bytes",
  jit_requests: "max_jit_requests",
  max_jit_requests: "max_jit_requests",
  denied_attempts: "max_denied_attempts",
  max_denied_attempts: "max_denied_attempts",
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return s > 0 ? `${m}m ${String(s).padStart(2, "0")}s` : `${m}m`;
}

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

function isBreachedGauge(metric: GaugeMetric, breachedMetric?: string): boolean {
  if (!breachedMetric) return false;
  const norm = breachedMetric.toLowerCase();
  return (
    norm === metric.key ||
    (metric.limitKey !== undefined && norm === metric.limitKey)
  );
}

function gaugeTone(
  current: number,
  limit: number | null,
  breached: boolean,
): { bar: string; text: string; pct: number } {
  if (limit === null || limit <= 0) {
    return {
      bar: breached ? "bg-[#f27c7c]" : "bg-[#7f95f8]",
      text: breached ? "text-[#f27c7c]" : "text-[#b6c3db]",
      pct: breached ? 100 : 0,
    };
  }
  const ratio = current / limit;
  const pct = Math.min(100, Math.max(current > 0 ? 2 : 0, Math.round(ratio * 100)));
  if (breached || ratio > 0.95) {
    return { bar: "bg-[#f27c7c]", text: "text-[#f27c7c]", pct: breached ? 100 : pct };
  }
  if (ratio >= 0.7) {
    return { bar: "bg-[#7f95f8]", text: "text-[#a8c5ff]", pct };
  }
  // Calm until it matters: green/amber/coral are reserved for warning and critical.
  return { bar: "bg-[#7f95f8]", text: "text-[#b6c3db]", pct };
}

function currentValueForLimitKey(budget: BudgetSnapshot, key: NumericBudgetKey): number {
  switch (key) {
    case "max_files_modified":
      return budget.files_modified;
    case "max_lines_changed":
      return budget.lines_changed;
    case "max_workspace_bytes":
      return budget.workspace_bytes;
    case "max_egress_requests":
      return budget.egress_requests;
    case "max_egress_bytes":
      return budget.egress_bytes;
    case "max_jit_requests":
      return budget.jit_requests;
    case "max_denied_attempts":
      return budget.denied_attempts;
  }
}

function buildBumpedLimits(budget: BudgetSnapshot): AutonomyBudget {
  const next: AutonomyBudget = { ...budget.limits };
  for (const field of CUSTOM_FIELDS) {
    const val = budget.limits[field.key];
    if (typeof val === "number" && val > 0) {
      const cur = currentValueForLimitKey(budget, field.key);
      const base = Math.max(val, cur);
      next[field.key] = Math.max(Math.ceil(base * 1.5), cur + 1);
    }
  }
  if (budget.breached_metric) {
    const mapped = METRIC_TO_LIMIT_KEY[budget.breached_metric.toLowerCase()];
    if (mapped) {
      const cur = currentValueForLimitKey(budget, mapped);
      const existing = budget.limits[mapped] ?? 0;
      const base = Math.max(existing, cur, 1);
      next[mapped] = Math.max(Math.ceil(base * 1.5), cur + 1);
    }
  }
  return next;
}

function initialDraft(limits: AutonomyBudget): Record<NumericBudgetKey, string> {
  return {
    max_files_modified: limits.max_files_modified != null ? String(limits.max_files_modified) : "",
    max_lines_changed: limits.max_lines_changed != null ? String(limits.max_lines_changed) : "",
    max_workspace_bytes:
      limits.max_workspace_bytes != null ? String(limits.max_workspace_bytes) : "",
    max_egress_requests:
      limits.max_egress_requests != null ? String(limits.max_egress_requests) : "",
    max_egress_bytes: limits.max_egress_bytes != null ? String(limits.max_egress_bytes) : "",
    max_jit_requests: limits.max_jit_requests != null ? String(limits.max_jit_requests) : "",
    max_denied_attempts:
      limits.max_denied_attempts != null ? String(limits.max_denied_attempts) : "",
  };
}

export function BudgetGauges({ session, owner, onSessionChange }: Props) {
  const budget = session.budget;
  const [customOpen, setCustomOpen] = useState(false);
  const [draft, setDraft] = useState<Record<NumericBudgetKey, string>>(() =>
    initialDraft(budget?.limits ?? {}),
  );
  const [busy, setBusy] = useState<"bump" | "custom" | "stop" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    setCustomOpen(false);
    setError(null);
    setNotice(null);
    setDraft(initialDraft(session.budget?.limits ?? {}));
  }, [session.id]);

  useEffect(() => {
    if (!customOpen && budget) {
      setDraft(initialDraft(budget.limits));
    }
  }, [budget, customOpen]);

  if (!budget) return null;

  const isPaused = Boolean(budget.paused || session.status === "paused");
  const isTerminated = Boolean(budget.terminated || session.status === "budget_exceeded");
  const isLive = isPaused || session.status === "running";

  const allMetrics: GaugeMetric[] = [
    {
      key: "files_modified",
      limitKey: "max_files_modified",
      label: "Files Modified",
      current: budget.files_modified,
      limit: budget.limits.max_files_modified ?? null,
      format: formatCount,
    },
    {
      key: "lines_changed",
      limitKey: "max_lines_changed",
      label: "Lines Changed",
      current: budget.lines_changed,
      limit: budget.limits.max_lines_changed ?? null,
      format: formatCount,
    },
    {
      key: "workspace_bytes",
      limitKey: "max_workspace_bytes",
      label: "Workspace Size",
      current: budget.workspace_bytes,
      limit: budget.limits.max_workspace_bytes ?? null,
      format: formatBytes,
    },
    {
      key: "egress_requests",
      limitKey: "max_egress_requests",
      label: "Egress Requests",
      current: budget.egress_requests,
      limit: budget.limits.max_egress_requests ?? null,
      format: formatCount,
    },
    {
      key: "egress_bytes",
      limitKey: "max_egress_bytes",
      label: "Egress Bytes",
      current: budget.egress_bytes,
      limit: budget.limits.max_egress_bytes ?? null,
      format: formatBytes,
    },
    {
      key: "jit_requests",
      limitKey: "max_jit_requests",
      label: "JIT Requests",
      current: budget.jit_requests,
      limit: budget.limits.max_jit_requests ?? null,
      format: formatCount,
    },
    {
      key: "denied_attempts",
      limitKey: "max_denied_attempts",
      label: "Denied Attempts",
      current: budget.denied_attempts,
      limit: budget.limits.max_denied_attempts ?? null,
      format: formatCount,
    },
    {
      key: "elapsed_secs",
      label: "Time Elapsed",
      current: budget.elapsed_secs,
      limit: budget.max_secs > 0 ? budget.max_secs : null,
      format: formatDuration,
    },
  ];

  const visibleMetrics = allMetrics.filter(
    (m) =>
      (m.limit !== null && m.limit > 0) ||
      m.current > 0 ||
      isBreachedGauge(m, budget.breached_metric),
  );

  const kernelPills: string[] = [];
  if (budget.limits.max_memory_mb != null) kernelPills.push(`mem ≤ ${budget.limits.max_memory_mb} MB`);
  if (budget.limits.max_pids != null) kernelPills.push(`pids ≤ ${budget.limits.max_pids}`);
  if (budget.limits.max_cpu_secs != null) kernelPills.push(`cpu ≤ ${budget.limits.max_cpu_secs}s`);

  const handleQuickBump = async () => {
    setBusy("bump");
    setError(null);
    setNotice(null);
    try {
      const nextLimits = buildBumpedLimits(budget);
      const updated = await api.raiseSessionBudget(session.id, nextLimits, true);
      onSessionChange(updated);
      setNotice("Budget raised +50% and session resumed.");
      setCustomOpen(false);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  const handleCustomSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("custom");
    setError(null);
    setNotice(null);
    const nextLimits: AutonomyBudget = { ...budget.limits };
    for (const field of CUSTOM_FIELDS) {
      const raw = draft[field.key].trim();
      if (raw === "") {
        nextLimits[field.key] = null;
      } else {
        const parsed = Number(raw);
        if (!Number.isFinite(parsed) || parsed < 0 || !Number.isInteger(parsed)) {
          setError(`${field.label} must be a non-negative integer.`);
          setBusy(null);
          return;
        }
        nextLimits[field.key] = parsed;
      }
    }
    try {
      const updated = await api.raiseSessionBudget(session.id, nextLimits, isPaused);
      onSessionChange(updated);
      setNotice(isPaused ? "Budget updated and session resumed." : "Budget limits updated.");
      setCustomOpen(false);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  const handleTerminate = async () => {
    setBusy("stop");
    setError(null);
    setNotice(null);
    try {
      const updated = await api.stopSession(session.id);
      onSessionChange(updated);
      setNotice("Session terminated.");
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="pr-well space-y-2.5 rounded-xl p-3 font-mono text-[12.5px]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
          Autonomy Budget
        </span>
        <div className="flex flex-wrap items-center gap-1.5">
          {owner && !isPaused && isLive && (
            <button
              type="button"
              disabled={busy !== null}
              aria-expanded={customOpen}
              onClick={() => {
                setCustomOpen((o) => !o);
                setError(null);
              }}
              className="pr-pill rounded-full px-2 py-0.5 text-[12px] text-[#9ec0f5] hover:text-[#f3f6fd]"
            >
              {customOpen ? "Cancel edit" : "Adjust limits"}
            </button>
          )}
          {budget.limits.on_budget_exceeded && (
            <span className="rounded-full bg-white/[0.05] px-2 py-0.5 text-[12px] text-[#a6b5cf]">
              on breach: {budget.limits.on_budget_exceeded}
            </span>
          )}
          {budget.bytes_scrubbed > 0 && (
            <span className="rounded-full bg-[#67d6dc]/14 px-2 py-0.5 text-[12px] text-[#67d6dc]">
              {formatBytes(budget.bytes_scrubbed)} scrubbed
            </span>
          )}
        </div>
      </div>

      {/* Paused or Terminated Breach Banner */}
      {isPaused && (
        <div
          role="alert"
          className="space-y-2.5 rounded-xl border border-[#9ec0f5]/40 bg-[#7f95f8]/10 p-3"
        >
          <div className="flex items-start gap-2 text-[#a8c5ff]">
            <IconQuarantine className="mt-0.5 h-4 w-4 shrink-0" />
            <div className="min-w-0 flex-1 space-y-0.5">
              <div className="flex flex-wrap items-center gap-1.5 font-semibold uppercase tracking-wide text-[12.5px]">
                <span>Session paused</span>
                {budget.breached_metric && (
                  <span className="rounded-full bg-[#7f95f8]/20 px-2 py-0.5 text-[12px] normal-case text-[#cfe0ff]">
                    {budget.breached_metric}
                  </span>
                )}
              </div>
              {budget.breach_reason && (
                <p className="font-sans text-[13px] leading-snug text-[#f5ddb0]">
                  {budget.breach_reason}
                </p>
              )}
            </div>
          </div>

          {owner ? (
            <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
              <button
                type="button"
                disabled={busy !== null}
                onClick={() => void handleQuickBump()}
                className="pr-action-btn inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-sans text-[12.5px] disabled:opacity-45"
              >
                <IconPlay className="h-3.5 w-3.5" />
                <span>{busy === "bump" ? "Resuming…" : "+50% & Resume"}</span>
              </button>
              <button
                type="button"
                disabled={busy !== null}
                aria-expanded={customOpen}
                onClick={() => {
                  setCustomOpen((o) => !o);
                  setError(null);
                }}
                className={`${SECONDARY_BTN} rounded-full! px-2.5! py-1! text-[12.5px]!`}
              >
                {customOpen ? "Hide custom" : "Custom limits"}
              </button>
              <button
                type="button"
                disabled={busy !== null}
                onClick={() => void handleTerminate()}
                className={`${DANGER_BTN} ml-auto rounded-full! px-2.5! py-1! text-[12.5px]!`}
              >
                <IconClose className="h-3.5 w-3.5" />
                <span>{busy === "stop" ? "Terminating…" : "Terminate"}</span>
              </button>
            </div>
          ) : (
            <OwnerOnly className="rounded-lg bg-black/25 py-2!" />
          )}
        </div>
      )}

      {!isPaused && isTerminated && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-xl border border-[#f27c7c]/35 bg-[#f27c7c]/10 p-3 text-[#f27c7c]"
        >
          <IconQuarantine className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 flex-1 space-y-0.5">
            <div className="flex flex-wrap items-center gap-1.5 font-semibold uppercase tracking-wide text-[12.5px]">
              <span>Terminated on budget breach</span>
              {budget.breached_metric && (
                <span className="rounded-full bg-[#f27c7c]/20 px-2 py-0.5 text-[12px] normal-case text-[#f9b4b4]">
                  {budget.breached_metric}
                </span>
              )}
            </div>
            {budget.breach_reason && (
              <p className="font-sans text-[13px] leading-snug text-[#f9b4b4]">
                {budget.breach_reason}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Live Progress Gauges */}
      {visibleMetrics.length > 0 ? (
        <div className="space-y-2">
          {visibleMetrics.map((m) => {
            const breached = isBreachedGauge(m, budget.breached_metric);
            const tone = gaugeTone(m.current, m.limit, breached);
            return (
              <div key={m.key} className="space-y-1">
                <div className="flex items-center justify-between gap-2 text-[12.5px]">
                  <span className={breached ? "font-semibold text-[#f27c7c]" : "text-[#b6c3db]"}>
                    {m.label}
                  </span>
                  <span className={tone.text}>
                    {m.format(m.current)}
                    {m.limit !== null ? (
                      <span className="text-[#a6b5cf]"> / {m.format(m.limit)}</span>
                    ) : (
                      <span className="text-[#a6b5cf]"> · unbounded</span>
                    )}
                  </span>
                </div>
                {m.limit !== null && m.limit > 0 && (
                  <div
                    role="progressbar"
                    aria-label={m.label}
                    aria-valuenow={m.current}
                    aria-valuemin={0}
                    aria-valuemax={m.limit}
                    className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]"
                  >
                    <div
                      className={`h-full rounded-full transition-all duration-300 ${tone.bar}`}
                      style={{ width: `${tone.pct}%` }}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-[12.5px] text-[#a6b5cf]">No active budget counters yet.</div>
      )}

      {/* Kernel Resource Limit Pills */}
      {kernelPills.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 border-t border-white/[0.06] pt-2">
          <span className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">Kernel</span>
          {kernelPills.map((pill) => (
            <span
              key={pill}
              className="rounded-full border border-white/[0.08] bg-black/30 px-2 py-0.5 text-[12px] text-[#d2dbee]"
            >
              {pill}
            </span>
          ))}
        </div>
      )}

      {/* Inline Custom Limit Inputs */}
      {owner && customOpen && (
        <form
          onSubmit={(e) => void handleCustomSubmit(e)}
          className="space-y-2.5 border-t border-white/[0.06] pt-2.5"
        >
          <div className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">
            Custom Autonomy Limits (blank = unlimited)
          </div>
          <div className="grid grid-cols-2 gap-2">
            {CUSTOM_FIELDS.map((f) => {
              const rawVal = draft[f.key];
              const parsed = rawVal.trim() ? Number(rawVal) : null;
              return (
                <label key={f.key} className="space-y-1">
                  <span className="flex items-center justify-between gap-1 text-[12px] text-[#b6c3db]">
                    <span className="truncate">{f.label}</span>
                    {f.isBytes && parsed !== null && Number.isFinite(parsed) && parsed > 0 && (
                      <span className="shrink-0 text-[#a6b5cf]">{formatBytes(parsed)}</span>
                    )}
                  </span>
                  <input
                    type="number"
                    min={0}
                    step={1}
                    inputMode="numeric"
                    value={rawVal}
                    onChange={(e) =>
                      setDraft((prev) => ({ ...prev, [f.key]: e.target.value }))
                    }
                    placeholder="unlimited"
                    className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2 py-1 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                  />
                </label>
              );
            })}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="submit"
              disabled={busy !== null}
              className="pr-action-btn inline-flex items-center gap-1 rounded-full px-3 py-1 font-sans text-[12.5px] disabled:opacity-45"
            >
              <IconCheck className="h-3.5 w-3.5" />
              <span>
                {busy === "custom"
                  ? "Saving…"
                  : isPaused
                    ? "Raise & Resume"
                    : "Save Limits"}
              </span>
            </button>
            <button
              type="button"
              disabled={busy !== null}
              onClick={() => setCustomOpen(false)}
              className="pr-pill rounded-full px-2.5 py-1 font-sans text-[12.5px] text-[#d2dbee]"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {notice && (
        <div role="status" className="flex items-center gap-1.5 text-[12.5px] text-[#5bdba2]">
          <IconCheck className="h-3.5 w-3.5 shrink-0" />
          <span>{notice}</span>
        </div>
      )}
      <ErrorNote message={error} />
    </div>
  );
}
