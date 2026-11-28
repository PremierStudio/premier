import { useState } from "react";
import type {
  AgentSessionRecord,
  HygieneAction,
  HygieneInsight,
  HygieneInsightsResponse,
  HygieneSeverity,
} from "../api";
import { ConfirmButton } from "./forms";
import { IconAmbientPulse, IconChevron, IconClose, IconRefresh } from "./Icons";

export function hygieneActionLabel(action: HygieneAction): string {
  switch (action.kind) {
    case "draft_policy_rule":
      return "Draft zone rule";
    case "add_overlay_guard":
      return "Add to Overlay Guard";
    case "configure_secret":
      return "Configure secret";
    case "inspect_branch":
      return "Inspect branch";
    case "review_agent_egress":
      return "Review egress";
  }
}

export interface AmbientWhisperChipProps {
  severity: HygieneSeverity;
  title: string;
  detail?: string;
  actionLabel?: string;
  onAction?: () => void;
  onDismiss?: () => void;
  busy?: boolean;
  compact?: boolean;
  className?: string;
}

/** Quiet contextual inline ambient observation chip (frosted amber for attention, frosted ice for notice). */
export function AmbientWhisperChip({
  severity,
  title,
  detail,
  actionLabel,
  onAction,
  onDismiss,
  busy = false,
  compact = false,
  className = "",
}: AmbientWhisperChipProps) {
  const isAttention = severity === "attention";
  const shellTone = isAttention
    ? "border-[#9ec0f5]/28 bg-[#7f95f8]/8 text-[#cfe0ff]"
    : "border-[#9ec0f5]/28 bg-[#7f95f8]/10 text-[#cfe0ff]";
  const iconTone = isAttention ? "text-[#a8c5ff]" : "text-[#9ec0f5]";
  const actionTone = isAttention
    ? "border-[#9ec0f5]/32 bg-[#7f95f8]/12 text-[#cfe0ff] hover:bg-[#7f95f8]/20"
    : "border-[#9ec0f5]/32 bg-[#7f95f8]/14 text-[#cfe0ff] hover:bg-[#7f95f8]/24";

  return (
    <div
      role="status"
      className={`flex flex-wrap items-center justify-between gap-2 rounded-xl border ${shellTone} ${
        compact ? "px-2.5 py-1.5" : "px-3 py-2"
      } ${className}`}
    >
      <div className="flex min-w-0 flex-1 items-start gap-2">
        <IconAmbientPulse className={`mt-0.5 h-4 w-4 shrink-0 ${iconTone}`} />
        <div className="min-w-0">
          <div className="font-mono text-[13px] font-medium leading-snug">{title}</div>
          {detail && (
            <div className="mt-0.5 font-sans text-[13px] leading-snug opacity-80">{detail}</div>
          )}
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-1.5">
        {actionLabel && onAction && (
          <button
            type="button"
            disabled={busy}
            onClick={onAction}
            className={`rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] transition disabled:opacity-45 ${actionTone}`}
          >
            {busy ? "Working…" : actionLabel}
          </button>
        )}
        {onDismiss && (
          <button
            type="button"
            disabled={busy}
            onClick={onDismiss}
            aria-label={`Dismiss: ${title}`}
            title="Dismiss"
            className="rounded-lg p-1 opacity-70 transition hover:bg-white/[0.08] hover:opacity-100 disabled:opacity-35"
          >
            <IconClose className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
    </div>
  );
}

export interface HygieneDrawerProps {
  hygiene: HygieneInsightsResponse | null;
  loading?: boolean;
  error?: string | null;
  showDismissed: boolean;
  onToggleShowDismissed: () => void;
  onRefresh: () => void;
  /** Running or paused sessions that carry live telemetry insights. */
  sessionsWithInsights: AgentSessionRecord[];
  onStepInSession: (sessionId: string) => void;
  onAction: (insight: HygieneInsight) => void;
  onDismiss: (id: string) => void;
  onRestore: (id: string) => void;
  busyInsightId?: string | null;
}

/** Owner-only collapsible ambient hygiene & live session telemetry drawer inside the Runtime Status popover. */
export function HygieneDrawer({
  hygiene,
  loading = false,
  error = null,
  showDismissed,
  onToggleShowDismissed,
  onRefresh,
  sessionsWithInsights,
  onStepInSession,
  onAction,
  onDismiss,
  onRestore,
  busyInsightId = null,
}: HygieneDrawerProps) {
  const [expanded, setExpanded] = useState(true);

  const insights = hygiene?.insights ?? [];
  const activeInsights = insights.filter((i) => !i.dismissed);
  const dismissedInsights = insights.filter((i) => i.dismissed);
  const dismissedCount = hygiene?.dismissed_count ?? dismissedInsights.length;

  const sessionAlertCount = sessionsWithInsights.reduce(
    (sum, s) => sum + (s.insights?.length ?? 0),
    0,
  );
  const attentionCount =
    activeInsights.filter((i) => i.severity === "attention").length +
    sessionsWithInsights.reduce(
      (sum, s) => sum + (s.insights?.filter((x) => x.severity === "attention").length ?? 0),
      0,
    );
  const totalActive = activeInsights.length + sessionAlertCount;
  // Never claim "All quiet" before a scan has produced a result, or after one failed.
  const scanning = hygiene === null && !error;
  const scanFailed = Boolean(error) && totalActive === 0;

  const badgeTone =
    attentionCount > 0
      ? "border-[#9ec0f5]/28 bg-[#7f95f8]/12 text-[#cfe0ff]"
      : totalActive > 0
        ? "border-[#9ec0f5]/28 bg-[#7f95f8]/12 text-[#cfe0ff]"
        : "border-white/[0.08] bg-white/[0.04] text-[#98a8c4]";

  return (
    <div className="mt-3 border-t border-white/[0.06] pt-2.5">
      <div className="flex items-center justify-between gap-2">
        <button
          type="button"
          onClick={() => setExpanded((e) => !e)}
          aria-expanded={expanded}
          className="flex min-w-0 flex-1 items-center gap-1.5 text-left text-[12.5px] text-[#dce4f5] transition hover:text-white"
        >
          <IconAmbientPulse
            className={`h-4 w-4 shrink-0 ${
              attentionCount > 0
                ? "text-[#a8c5ff]"
                : totalActive > 0
                  ? "text-[#9ec0f5]"
                  : "text-[#98a8c4]"
            }`}
          />
          <span className="truncate font-mono uppercase tracking-wider text-[12.5px]">
            Ambient Hygiene
          </span>
          <span
            className={`rounded-full border px-1.5 py-0.5 font-mono text-[12.5px] leading-none ${badgeTone}`}
          >
            {totalActive > 0 ? totalActive : scanning ? "scanning" : scanFailed ? "failed" : "quiet"}
          </span>
          <IconChevron
            direction={expanded ? "down" : "right"}
            className="ml-auto h-3.5 w-3.5 text-[#98a8c4]"
          />
        </button>

        <button
          type="button"
          onClick={onRefresh}
          disabled={loading}
          title="Refresh hygiene scan"
          aria-label="Refresh hygiene scan"
          className="rounded-lg p-1 text-[#98a8c4] transition hover:bg-white/[0.06] hover:text-[#dce4f5] disabled:opacity-40"
        >
          <IconRefresh className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
        </button>
      </div>

      {expanded && (
        <div className="mt-2.5 space-y-2">
          {error && (
            <div
              role="alert"
              className="rounded-xl border border-[#f27c7c]/25 bg-[#f27c7c]/10 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f27c7c]"
            >
              {error}
            </div>
          )}
          {/* Live session telemetry observations */}
          {sessionsWithInsights.map((session) =>
            (session.insights ?? []).map((ins) => {
              const isAttention = ins.severity === "attention";
              return (
                <div
                  key={`${session.id}:${ins.id}`}
                  className={`rounded-xl border p-2.5 ${
                    isAttention
                      ? "border-[#9ec0f5]/28 bg-[#7f95f8]/8 text-[#cfe0ff]"
                      : "border-[#9ec0f5]/28 bg-[#7f95f8]/10 text-[#cfe0ff]"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5 text-[12.5px] uppercase tracking-wider opacity-80">
                        <span>live cage · {session.status}</span>
                        <span className="truncate font-mono opacity-75">{session.id.slice(0, 8)}</span>
                      </div>
                      <div className="mt-0.5 text-[12.5px] font-medium leading-snug">{ins.title}</div>
                      <div className="mt-0.5 font-sans text-[12.5px] leading-snug opacity-80">
                        {ins.detail}
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 flex items-center justify-between gap-2">
                    <span className="truncate text-[12.5px] opacity-70" title={session.command}>
                      $ {session.command}
                    </span>
                    <button
                      type="button"
                      onClick={() => onStepInSession(session.id)}
                      className={`shrink-0 rounded-full border px-2.5 py-0.5 text-[12.5px] font-medium transition ${
                        isAttention
                          ? "border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#cfe0ff] hover:bg-[#7f95f8]/22"
                          : "border-[#9ec0f5]/35 bg-[#7f95f8]/16 text-[#cfe0ff] hover:bg-[#7f95f8]/25"
                      }`}
                    >
                      Step in →
                    </button>
                  </div>
                </div>
              );
            }),
          )}

          {/* Active repository hygiene insights */}
          {activeInsights.map((insight) => {
            const isAttention = insight.severity === "attention";
            const busy = busyInsightId === insight.id;
            return (
              <div
                key={insight.id}
                className={`rounded-xl border p-2.5 ${
                  isAttention
                    ? "border-[#9ec0f5]/28 bg-[#7f95f8]/8 text-[#cfe0ff]"
                    : "border-[#9ec0f5]/28 bg-[#7f95f8]/10 text-[#cfe0ff]"
                }`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-medium leading-snug">{insight.title}</div>
                    {insight.target && (
                      <div className="mt-0.5 truncate text-[12.5px] opacity-75" title={insight.target}>
                        {insight.target}
                      </div>
                    )}
                    <div className="mt-1 font-sans text-[12.5px] leading-snug opacity-80">
                      {insight.detail}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => onDismiss(insight.id)}
                    aria-label={`Dismiss ${insight.title}`}
                    title="Dismiss"
                    className="shrink-0 rounded-lg p-1 opacity-70 transition hover:bg-white/[0.08] hover:opacity-100 disabled:opacity-35"
                  >
                    <IconClose className="h-3.5 w-3.5" />
                  </button>
                </div>

                {insight.action && (
                  <div className="mt-2 flex items-center justify-end">
                    {insight.action.kind === "add_overlay_guard" ? (
                      // Mounts an encrypted overlay on the repo: confirm in place before mutating.
                      <ConfirmButton
                        disabled={busy}
                        onConfirm={() => onAction(insight)}
                        question="Mount overlay?"
                        confirmLabel="Add"
                        className={`rounded-full border px-2.5 py-0.5 text-[12.5px] font-medium transition disabled:opacity-45 ${
                          isAttention
                            ? "border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#cfe0ff] hover:bg-[#7f95f8]/22"
                            : "border-[#9ec0f5]/35 bg-[#7f95f8]/16 text-[#cfe0ff] hover:bg-[#7f95f8]/25"
                        }`}
                      >
                        {busy ? "Working…" : hygieneActionLabel(insight.action)}
                      </ConfirmButton>
                    ) : (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => onAction(insight)}
                        className={`rounded-full border px-2.5 py-0.5 text-[12.5px] font-medium transition disabled:opacity-45 ${
                          isAttention
                            ? "border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#cfe0ff] hover:bg-[#7f95f8]/22"
                            : "border-[#9ec0f5]/35 bg-[#7f95f8]/16 text-[#cfe0ff] hover:bg-[#7f95f8]/25"
                        }`}
                      >
                        {busy ? "Working…" : hygieneActionLabel(insight.action)}
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}

          {/* Scanning / failed / calm quiet state */}
          {scanning && (
            <div
              role="status"
              aria-busy="true"
              className="pr-well flex items-center gap-2 rounded-xl px-3 py-2.5 text-[12.5px] text-[#a6b5cf]"
            >
              <span aria-hidden="true" className="pr-shimmer h-2.5 w-2.5 shrink-0 rounded-full" />
              <span>Scanning workspace hygiene…</span>
            </div>
          )}
          {scanFailed && (
            <div className="pr-well flex items-center justify-between gap-2 rounded-xl px-3 py-2.5 text-[12.5px] text-[#f27c7c]">
              <span>Scan failed</span>
              <button
                type="button"
                onClick={onRefresh}
                disabled={loading}
                className="pr-pill shrink-0 rounded-full px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5] hover:text-white disabled:opacity-45"
              >
                {loading ? "Retrying…" : "Retry"}
              </button>
            </div>
          )}
          {!scanning && !scanFailed && totalActive === 0 && (
            <div className="pr-well rounded-xl px-3 py-2.5 text-center text-[12.5px] text-[#a6b5cf]">
              All quiet · no drift detected
            </div>
          )}

          {/* Dismissed archive toggle & list */}
          {dismissedCount > 0 && (
            <div className="pt-1">
              <button
                type="button"
                onClick={onToggleShowDismissed}
                className="flex w-full items-center justify-between rounded-lg px-2 py-1 text-[12.5px] text-[#98a8c4] transition hover:bg-white/[0.04] hover:text-[#bcc6da]"
              >
                <span>
                  {dismissedCount} dismissed · {showDismissed ? "Hide" : "Show"}
                </span>
                <IconChevron
                  direction={showDismissed ? "up" : "down"}
                  className="h-3.5 w-3.5"
                />
              </button>

              {showDismissed && (
                <div className="mt-1.5 space-y-1.5">
                  {dismissedInsights.length === 0 ? (
                    <div className="px-2 py-1 text-[12.5px] text-[#a6b5cf]">
                      {loading ? "Loading dismissed…" : "No dismissed insights on this ref"}
                    </div>
                  ) : (
                    dismissedInsights.map((insight) => {
                      const busy = busyInsightId === insight.id;
                      return (
                        <div
                          key={insight.id}
                          className="pr-well flex items-center justify-between gap-2 rounded-xl px-2.5 py-2 text-[12.5px] text-[#a6b5cf]"
                        >
                          <div className="min-w-0">
                            <div className="truncate text-[#d2dbee]">{insight.title}</div>
                            {insight.target && (
                              <div className="truncate text-[12.5px] text-[#a6b5cf]">
                                {insight.target}
                              </div>
                            )}
                          </div>
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => onRestore(insight.id)}
                            className="pr-pill shrink-0 rounded-full px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5] hover:text-white disabled:opacity-45"
                          >
                            {busy ? "…" : "Restore"}
                          </button>
                        </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
