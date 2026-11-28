import { useEffect, useMemo, useState } from "react";
import type { IdentityPreset, TraceSession, TraceSpan, TraceSpanKind } from "../api";
import { BrandIcon, type BrandIconName } from "./BrandIcons";
import { CodeBlock, DiffBlock, EvidenceValue, JsonTreeView, RedactedText } from "./CodeBlock";
import {
  IconBlock,
  IconCheck,
  IconChevron,
  IconClock,
  IconDownload,
  IconLink,
  IconLock,
  IconPanel,
  IconShieldCheck,
} from "./Icons";

export type InspectorTab = "overview" | "data" | "relations" | "raw";

export interface TraceSpanInspectorProps {
  session: TraceSession | null;
  span: TraceSpan | null;
  identity: IdentityPreset;
  startMs: number;
  totalDurationMs: number;
  activeCorrelationId: string | null;
  expanded: boolean;
  onToggleExpanded: () => void;
  onSelectSpan: (spanId: string) => void;
  onScopeCorrelation: (correlationId: string | null) => void;
  onStepSpan: (delta: -1 | 1) => void;
  canStepPrev: boolean;
  canStepNext: boolean;
  harnessBrand: (toolName: string, model: string) => BrandIconName;
  mobileVisible: boolean;
  activeTab?: InspectorTab;
  onTabChange?: (tab: InspectorTab) => void;
  deepLinkUrl?: string;
  centerViewMode?: "timeline" | "diffs" | "security" | "compare";
  onOpenDiffsView?: () => void;
  onOpenFile?: (path: string) => void;
  widthPx?: number;
  resizing?: boolean;
}

const KIND_META: Record<TraceSpanKind, { label: string; dot: string; badge: string }> = {
  prompt_turn: {
    label: "Prompt",
    dot: "bg-[#7f95f8]",
    badge: "border-[#7f95f8]/30 bg-[#7f95f8]/14 text-[#b4c3ff]",
  },
  tool_call: {
    label: "Tool",
    dot: "bg-[#9ec0f5]",
    badge: "border-[#9ec0f5]/30 bg-[#9ec0f5]/14 text-[#cfe0ff]",
  },
  file_access: {
    label: "File",
    dot: "bg-[#5bdba2]",
    badge: "border-[#5bdba2]/30 bg-[#5bdba2]/14 text-[#8beac0]",
  },
  proxy_egress: {
    label: "Egress",
    dot: "bg-[#67d6dc]",
    badge: "border-[#67d6dc]/30 bg-[#67d6dc]/14 text-[#93e6ea]",
  },
  error_diagnostic: {
    label: "Error",
    dot: "bg-[#f27c7c]",
    badge: "border-[#f27c7c]/35 bg-[#f27c7c]/15 text-[#ffb4b4]",
  },
  delivery_report: {
    label: "Delivery",
    dot: "bg-[#c7a7ff]",
    badge: "border-[#c7a7ff]/30 bg-[#c7a7ff]/14 text-[#dcc7ff]",
  },
};

function decisionStyle(decision: string): string {
  switch (decision) {
    case "allowed":
      return "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#8beac0]";
    case "redacted":
      return "border-[#67d6dc]/30 bg-[#67d6dc]/14 text-[#93e6ea]";
    case "approval_required":
      return "border-[#9ec0f5]/35 bg-[#9ec0f5]/15 text-[#cfe0ff]";
    case "denied":
    case "exfiltration_blocked":
    case "rate_limited":
    case "budget_exceeded":
      return "border-[#f27c7c]/35 bg-[#f27c7c]/15 text-[#ffb4b4]";
    default:
      return "border-white/[0.12] bg-white/[0.06] text-[#d2dbee]";
  }
}

function formatDuration(ms?: number | null): string {
  if (ms === undefined || ms === null || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
  const mins = Math.floor(ms / 60_000);
  const secs = Math.round((ms % 60_000) / 1000);
  return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
}

function formatClock(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return iso;
  return new Date(ts).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatOffset(spanIso: string, startMs: number): string {
  const ts = Date.parse(spanIso);
  if (Number.isNaN(ts) || Number.isNaN(startMs)) return "+0ms";
  const deltaMs = Math.max(0, ts - startMs);
  if (deltaMs < 1000) return `+${deltaMs}ms`;
  if (deltaMs < 60_000) return `+${(deltaMs / 1000).toFixed(1)}s`;
  const mins = Math.floor(deltaMs / 60_000);
  const secs = Math.floor((deltaMs % 60_000) / 1000);
  return `+${mins}m${secs.toString().padStart(2, "0")}s`;
}

function formatCost(micros?: number | null): string | null {
  if (!micros || micros <= 0) return null;
  const usd = micros / 1_000_000;
  return usd < 0.01 ? `$${usd.toFixed(4)}` : `$${usd.toFixed(2)}`;
}

function asObjectEntries(val: unknown): [string, unknown][] {
  if (val && typeof val === "object" && !Array.isArray(val)) {
    return Object.entries(val as Record<string, unknown>);
  }
  return [];
}

function downloadJson(filename: string, data: unknown) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function TraceSpanInspector({
  session,
  span,
  identity,
  startMs,
  totalDurationMs,
  activeCorrelationId,
  expanded,
  onToggleExpanded,
  onSelectSpan,
  onScopeCorrelation,
  onStepSpan,
  canStepPrev,
  canStepNext,
  harnessBrand,
  mobileVisible,
  activeTab,
  onTabChange,
  deepLinkUrl,
  centerViewMode = "timeline",
  onOpenDiffsView,
  onOpenFile,
  widthPx = 370,
  resizing = false,
}: TraceSpanInspectorProps) {
  const [internalTab, setInternalTab] = useState<InspectorTab>("overview");
  const tab = activeTab ?? internalTab;
  const setTab = (next: InspectorTab) => {
    setInternalTab(next);
    onTabChange?.(next);
  };
  const [rawScope, setRawScope] = useState<"span" | "session">("span");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    setCopiedKey(null);
  }, [span?.span_id]);

  const copyText = (key: string, text: string) => {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopiedKey(key);
      window.setTimeout(() => {
        setCopiedKey((cur) => (cur === key ? null : cur));
      }, 1500);
    });
  };

  const relations = useMemo(() => {
    if (!session || !span) {
      return {
        ancestors: [] as TraceSpan[],
        parent: null as TraceSpan | null,
        children: [] as TraceSpan[],
        linked: [] as TraceSpan[],
        sameFile: [] as TraceSpan[],
        correlated: [] as TraceSpan[],
        totalCount: 0,
      };
    }
    const byId = new Map(session.spans.map((s) => [s.span_id, s]));
    const ancestors: TraceSpan[] = [];
    const seen = new Set<string>([span.span_id]);
    let curParentId = span.parent_span_id;
    while (curParentId && !seen.has(curParentId)) {
      const p = byId.get(curParentId);
      if (!p) break;
      ancestors.unshift(p);
      seen.add(p.span_id);
      curParentId = p.parent_span_id;
    }
    const parent = span.parent_span_id ? (byId.get(span.parent_span_id) ?? null) : null;
    const children = session.spans.filter((s) => s.parent_span_id === span.span_id);
    const linked = (span.links ?? [])
      .map((id) => byId.get(id))
      .filter((s): s is TraceSpan => Boolean(s));
    const sameFile = span.path
      ? session.spans.filter((s) => s.path === span.path && s.span_id !== span.span_id)
      : [];
    const correlated = span.correlation_id
      ? session.spans.filter(
          (s) => s.correlation_id === span.correlation_id && s.span_id !== span.span_id,
        )
      : [];
    const totalCount =
      (parent ? 1 : 0) +
      children.length +
      linked.length +
      sameFile.length +
      (span.correlation_id ? 1 : 0);
    return { ancestors, parent, children, linked, sameFile, correlated, totalCount };
  }, [session, span]);

  const dataFieldCount = useMemo(() => {
    if (!span) return 0;
    let n = 0;
    if (span.command) n += 1;
    if (span.error_message) n += 1;
    if (span.input !== undefined && span.input !== null) {
      n += Math.max(1, asObjectEntries(span.input).length);
    }
    if (span.output !== undefined && span.output !== null) {
      n += Math.max(1, asObjectEntries(span.output).length);
    }
    if (span.authority !== undefined && span.authority !== null) {
      n += Math.max(1, asObjectEntries(span.authority).length);
    }
    return n;
  }, [span]);

  const durationSharePct = useMemo(() => {
    if (!span?.duration_ms || totalDurationMs <= 0) return 0;
    return Math.min(100, Math.max(2, Math.round((span.duration_ms / totalDurationMs) * 100)));
  }, [span?.duration_ms, totalDurationMs]);

  const kindMeta = span ? (KIND_META[span.kind] ?? KIND_META.tool_call) : KIND_META.tool_call;
  const hasTokens = Boolean((span?.tokens_in ?? 0) > 0 || (span?.tokens_out ?? 0) > 0);
  const costLabel = formatCost(span?.cost_usd_micros);

  return (
    <aside
      aria-label="Span inspector"
      style={{ ["--inspector-w" as string]: `${widthPx}px` }}
      className={`pr-surface min-h-0 shrink-0 flex-col overflow-hidden rounded-2xl xl:flex xl:flex-none xl:w-[var(--inspector-w)] ${
        resizing ? "select-none" : "transition-[width] duration-150"
      } ${mobileVisible ? "flex flex-1 xl:flex-none" : "hidden"}`}
    >
      {/* Top inspector header bar */}
      <div className="flex shrink-0 items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <span className="text-[13px] font-semibold text-[#f5f7fd]">Inspector</span>
          {span && (
            <span className="truncate font-mono text-[12px] text-[#98a8c4]">{span.span_id}</span>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {span && (
            <>
              <button
                type="button"
                onClick={() => onStepSpan(-1)}
                disabled={!canStepPrev}
                title="Previous span (↑)"
                aria-label="Previous span"
                className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-lg text-[#b6c3db] hover:text-white disabled:opacity-35"
              >
                <IconChevron className="h-3.5 w-3.5 rotate-180" />
              </button>
              <button
                type="button"
                onClick={() => onStepSpan(1)}
                disabled={!canStepNext}
                title="Next span (↓)"
                aria-label="Next span"
                className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-lg text-[#b6c3db] hover:text-white disabled:opacity-35"
              >
                <IconChevron className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={() =>
                  copyText(
                    "deep-link",
                    deepLinkUrl ??
                      `${window.location.origin}${window.location.pathname}#traces?run=${encodeURIComponent(session?.session_id ?? "")}&span=${encodeURIComponent(span.span_id)}&tab=${tab}`,
                  )
                }
                title="Copy deep link to this span"
                aria-label="Copy deep link to this span"
                className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-lg text-[#b6c3db] hover:text-white"
              >
                {copiedKey === "deep-link" ? (
                  <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                ) : (
                  <IconLink className="h-3.5 w-3.5 text-[#9ec0f5]" />
                )}
              </button>
            </>
          )}
          <button
            type="button"
            onClick={onToggleExpanded}
            title={expanded ? "Restore inspector width" : "Widen inspector"}
            aria-label={expanded ? "Restore inspector width" : "Widen inspector"}
            className={`hidden h-7 w-7 items-center justify-center rounded-lg xl:inline-flex ${
              expanded ? "pr-pill-active text-white" : "pr-pill text-[#b6c3db] hover:text-white"
            }`}
          >
            <IconPanel className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* 4 Power Tabs */}
      {span && (
        <div
          role="tablist"
          aria-label="Inspector sections"
          className="flex shrink-0 items-center gap-1 border-b border-white/[0.06] bg-[#0a0f1f]/55 px-3 py-2"
        >
          {(
            [
              { id: "overview", label: "Overview", count: null },
              { id: "data", label: "Data", count: dataFieldCount },
              { id: "relations", label: "Relations", count: relations.totalCount },
              { id: "raw", label: "Raw", count: null },
            ] as { id: InspectorTab; label: string; count: number | null }[]
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}
              className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12.5px] font-medium transition ${
                tab === t.id
                  ? "pr-pill-active text-[#f5f7fd]"
                  : "text-[#a6b5cf] hover:bg-white/[0.04] hover:text-[#f5f7fd]"
              }`}
            >
              <span>{t.label}</span>
              {t.count !== null && t.count > 0 && (
                <span className="rounded-full bg-white/[0.08] px-1.5 py-px font-mono text-[11px] text-[#cfe0ff]">
                  {t.count}
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {!span || !session ? (
        <div className="flex flex-1 items-center justify-center p-6 text-center text-[13.5px] text-[#a6b5cf]">
          Select any span in the waterfall to inspect its inputs, diffs, authority rules, and causal
          links.
        </div>
      ) : tab === "overview" ? (
        <div className="min-h-0 flex-1 space-y-3.5 overflow-y-auto p-4">
          {/* Identity, actor & verdict badges */}
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={`rounded-full border px-2.5 py-0.5 font-mono text-[12px] font-medium ${kindMeta.badge}`}
            >
              {kindMeta.label}
            </span>
            {span.decision && (
              <span
                className={`rounded-full border px-2.5 py-0.5 font-mono text-[12px] ${decisionStyle(span.decision)}`}
              >
                {span.decision.replace(/_/g, " ")}
              </span>
            )}
            {span.exit_code !== undefined && span.exit_code !== null && (
              <span
                className={`rounded-full border px-2 py-0.5 font-mono text-[11.5px] ${
                  span.exit_code === 0
                    ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#8beac0]"
                    : "border-[#f27c7c]/35 bg-[#f27c7c]/14 text-[#ffb4b4]"
                }`}
              >
                exit {span.exit_code}
              </span>
            )}
            {(span.actor_id || span.tool_name) && (
              <span className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-0.5 font-mono text-[12px] text-[#d2dbee]">
                {span.actor_type === "human" ? (
                  <span className="h-2 w-2 rounded-full bg-[#5bdba2]" aria-hidden />
                ) : span.actor_type === "system" || span.actor_type === "tool" ? (
                  <span className="h-2 w-2 rounded-full bg-[#67d6dc]" aria-hidden />
                ) : (
                  <BrandIcon
                    name={harnessBrand(span.tool_name ?? session.tool_name, session.model)}
                    className="h-3.5 w-3.5"
                  />
                )}
                <span>{span.actor_id ?? span.tool_name}</span>
                {span.actor_type && (
                  <span className="text-[#8595b0]">· {span.actor_type}</span>
                )}
              </span>
            )}
          </div>

          {/* Summary */}
          <div className="pr-well rounded-xl p-3.5">
            <div className="text-[12px] font-medium text-[#98a8c4]">Summary</div>
            <p className="mt-1.5 whitespace-pre-wrap break-words text-[13.5px] leading-relaxed text-[#f5f7fd]">
              <RedactedText text={span.summary} />
            </p>
          </div>

          {/* ACL redaction banner */}
          {span.redacted_for_viewer && (
            <div className="flex items-start gap-2.5 rounded-xl border border-[#7f95f8]/30 bg-[#7f95f8]/10 p-3.5 text-[13px] text-[#cfe0ff]">
              <IconLock className="mt-0.5 h-4 w-4 shrink-0 text-[#9ec0f5]" />
              <span>
                Path, diff, and structured payloads were server-redacted for{" "}
                <code className="text-white">{identity.label}</code> under Zone ACL policy.
              </span>
            </div>
          )}

          {/* Diagnostic alert */}
          {span.error_message && (
            <div className="rounded-xl border border-[#f27c7c]/35 bg-[#f27c7c]/10 p-3.5">
              <div className="flex items-center gap-1.5 text-[12.5px] font-semibold text-[#ffb4b4]">
                <IconBlock className="h-4 w-4" />
                <span>Diagnostic</span>
              </div>
              <p className="mt-1.5 whitespace-pre-wrap break-words font-mono text-[12.5px] leading-relaxed text-[#ffd2d2]">
                <RedactedText text={span.error_message} />
              </p>
            </div>
          )}

          {/* Primary Evidence Spotlight: omit duplicating diff/code when center view is already in Diffs & Code */}
          {centerViewMode === "diffs" && (span.diff || span.code_snippet) ? (
            <div className="flex items-center justify-between gap-2 rounded-xl border border-[#7f95f8]/25 bg-[#7f95f8]/[0.08] px-3.5 py-2.5 text-[12.5px] text-[#cfe0ff]">
              <span className="truncate font-mono">
                {span.diff ? "Unified diff" : "Code snippet"} open in Diffs &amp; Code
              </span>
              <button
                type="button"
                onClick={() => setTab("data")}
                className="shrink-0 font-mono text-[11.5px] text-[#9ec0f5] hover:text-white hover:underline"
              >
                Inspect I/O →
              </button>
            </div>
          ) : (
            <>
              {span.diff && (
                <DiffBlock
                  patch={span.diff}
                  filePath={span.path ?? undefined}
                  language={span.language ?? undefined}
                />
              )}

              {!span.diff && span.code_snippet && (
                <CodeBlock
                  code={span.code_snippet}
                  label={span.path ?? "Code snippet"}
                  filePath={span.path ?? undefined}
                  language={span.language ?? undefined}
                  showLineNumbers
                />
              )}
            </>
          )}

          {span.command && (
            <CodeBlock
              code={span.command}
              label="Command / Target"
              language="shell"
              compact
            />
          )}

          {(centerViewMode === "diffs" || (!span.diff && !span.code_snippet)) &&
            span.output !== undefined &&
            span.output !== null && <EvidenceValue label="Output" value={span.output} compact />}

          {(centerViewMode === "diffs" ||
            (!span.diff &&
              !span.code_snippet &&
              (span.output === undefined || span.output === null))) &&
            span.authority !== undefined &&
            span.authority !== null && (
              <EvidenceValue label="Authority" value={span.authority} compact />
            )}

          {/* Execution & Telemetry Grid */}
          <div className="grid grid-cols-2 gap-2.5 text-[12.5px]">
            <div className="pr-well rounded-xl p-3">
              <div className="flex items-center gap-1.5 text-[#98a8c4]">
                <IconClock className="h-3.5 w-3.5" />
                <span>Recorded</span>
              </div>
              <div className="mt-1 font-mono text-[#f5f7fd]">{formatClock(span.timestamp)}</div>
              <div className="mt-0.5 font-mono text-[11.5px] text-[#8595b0]">
                {formatOffset(span.timestamp, startMs)} from start
              </div>
            </div>

            <div className="pr-well rounded-xl p-3">
              <div className="text-[#98a8c4]">Duration</div>
              <div className="mt-1 flex items-baseline justify-between font-mono">
                <span className="text-[#f5f7fd]">{formatDuration(span.duration_ms)}</span>
                {durationSharePct > 0 && (
                  <span className="text-[11.5px] text-[#8595b0]">{durationSharePct}%</span>
                )}
              </div>
              <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-white/[0.07]">
                <div
                  className={`h-full rounded-full ${kindMeta.dot} opacity-85`}
                  style={{ width: `${durationSharePct}%` }}
                />
              </div>
            </div>

            {hasTokens && (
              <div className="pr-well rounded-xl p-3">
                <div className="text-[#98a8c4]">Tokens</div>
                <div className="mt-1 font-mono text-[#f5f7fd]">
                  {(span.tokens_in ?? 0).toLocaleString()} in ·{" "}
                  {(span.tokens_out ?? 0).toLocaleString()} out
                </div>
                {costLabel && (
                  <div className="mt-0.5 font-mono text-[11.5px] text-[#8595b0]">
                    est. {costLabel}
                  </div>
                )}
              </div>
            )}

            <div className="pr-well rounded-xl p-3">
              <div className="flex items-center gap-1.5 text-[#98a8c4]">
                <IconShieldCheck className="h-3.5 w-3.5" />
                <span>Scrubbed</span>
              </div>
              <div
                className={`mt-1 font-mono ${
                  span.bytes_scrubbed > 0 ? "text-[#67d6dc]" : "text-[#d2dbee]"
                }`}
              >
                {span.bytes_scrubbed} B
              </div>
              <div className="mt-0.5 font-mono text-[11.5px] text-[#8595b0]">
                pre-write secret filter
              </div>
            </div>

            {!hasTokens && (
              <div className="pr-well rounded-xl p-3">
                <div className="text-[#98a8c4]">Tool / Actor</div>
                <div className="mt-1 truncate font-mono text-[#f5f7fd]">
                  {span.tool_name ?? span.actor_id ?? "—"}
                </div>
                <div className="mt-0.5 font-mono text-[11.5px] text-[#8595b0]">
                  {span.actor_type ?? "agent"}
                </div>
              </div>
            )}
          </div>

          {/* Location & Zone */}
          {span.path && (
            <div className="pr-well space-y-1.5 rounded-xl p-3.5">
              <div className="flex items-center justify-between gap-2 text-[12px] text-[#98a8c4]">
                <span>Target Path</span>
                <div className="flex items-center gap-1.5">
                  {span.zone && (
                    <span className="rounded-md bg-white/[0.06] px-2 py-0.5 font-mono text-[#cfe0ff]">
                      zone:{span.zone}
                    </span>
                  )}
                  {onOpenFile && !span.redacted_for_viewer && (
                    <button
                      type="button"
                      onClick={() => onOpenFile(span.path!)}
                      className="font-mono text-[11.5px] text-[#9ec0f5] hover:text-white hover:underline"
                    >
                      Open file →
                    </button>
                  )}
                </div>
              </div>
              <div className="break-all font-mono text-[12.5px] text-[#9ec0f5]">{span.path}</div>
            </div>
          )}

          {/* Quick causality jump strip */}
          {(relations.parent || relations.children.length > 0) && (
            <div className="pr-well space-y-2 rounded-xl p-3.5">
              <div className="flex items-center justify-between text-[12px] text-[#98a8c4]">
                <span>Causality</span>
                <button
                  type="button"
                  onClick={() => setTab("relations")}
                  className="font-mono text-[11.5px] text-[#9ec0f5] hover:underline"
                >
                  All relations →
                </button>
              </div>
              <div className="flex flex-wrap gap-1.5">
                {relations.parent && (
                  <button
                    type="button"
                    onClick={() => onSelectSpan(relations.parent!.span_id)}
                    className="pr-pill inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 font-mono text-[12px] text-[#cfe0ff] hover:text-white"
                  >
                    <span className="text-[#8595b0]">↑ parent</span>
                    <span>{relations.parent.span_id}</span>
                  </button>
                )}
                {relations.children.slice(0, 3).map((child) => (
                  <button
                    key={child.span_id}
                    type="button"
                    onClick={() => onSelectSpan(child.span_id)}
                    className="pr-pill inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 font-mono text-[12px] text-[#cfe0ff] hover:text-white"
                  >
                    <span className="text-[#8595b0]">↓ child</span>
                    <span>{child.span_id}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : tab === "data" ? (
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
          {/* Inputs & Request */}
          <section className="space-y-2">
            <h3 className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
              Inputs & Request
            </h3>
            {span.command && (
              <CodeBlock code={span.command} label="Command / Target" language="shell" compact />
            )}
            {span.input !== undefined && span.input !== null ? (
              <EvidenceValue label="Structured Input" value={span.input} compact />
            ) : !span.command ? (
              <div className="pr-well rounded-xl px-3.5 py-3 text-[13px] text-[#8595b0]">
                No structured input payload on this span.
              </div>
            ) : null}
          </section>

          {/* Outputs & Effects (pure structured I/O — diffs/code live in Overview & Diffs view, never duplicated here) */}
          <section className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
                Outputs &amp; Effects
              </h3>
              {(span.diff || span.code_snippet) && onOpenDiffsView && centerViewMode !== "diffs" && (
                <button
                  type="button"
                  onClick={onOpenDiffsView}
                  className="font-mono text-[11.5px] text-[#9ec0f5] hover:text-white hover:underline"
                >
                  Open {span.diff ? "diff" : "code"} →
                </button>
              )}
            </div>
            {span.output !== undefined && span.output !== null && (
              <EvidenceValue label="Structured Output" value={span.output} compact />
            )}
            {span.error_message && (
              <div className="rounded-xl border border-[#f27c7c]/35 bg-[#f27c7c]/10 p-3 font-mono text-[12.5px] text-[#ffd2d2]">
                <RedactedText text={span.error_message} />
              </div>
            )}
            {(span.output === undefined || span.output === null) && !span.error_message && (
              <div className="pr-well rounded-xl px-3.5 py-3 text-[13px] text-[#8595b0]">
                {span.diff || span.code_snippet
                  ? "Diff / code evidence is displayed in Overview and the Diffs & Code view."
                  : "No structured output captured on this span."}
              </div>
            )}
          </section>

          {/* Authority & Security */}
          <section className="space-y-2">
            <h3 className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
              Authority & Security
            </h3>
            {span.authority !== undefined && span.authority !== null ? (
              <EvidenceValue label="Policy & Capability Receipt" value={span.authority} compact />
            ) : (
              <div className="pr-well grid grid-cols-2 gap-2 rounded-xl p-3 font-mono text-[12.5px]">
                <div>
                  <span className="text-[#8595b0]">Decision: </span>
                  <span className="text-[#f5f7fd]">{span.decision ?? "none"}</span>
                </div>
                <div>
                  <span className="text-[#8595b0]">Zone: </span>
                  <span className="text-[#f5f7fd]">{span.zone ?? "—"}</span>
                </div>
                <div>
                  <span className="text-[#8595b0]">Scrubbed: </span>
                  <span className="text-[#67d6dc]">{span.bytes_scrubbed} B</span>
                </div>
                <div>
                  <span className="text-[#8595b0]">Redacted: </span>
                  <span className="text-[#f5f7fd]">{span.redacted_for_viewer ? "yes" : "no"}</span>
                </div>
              </div>
            )}
          </section>
        </div>
      ) : tab === "relations" ? (
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
          {/* Visual Causal Lineage Graph (Ancestors → Current → Direct Children) */}
          <section className="pr-well space-y-2.5 rounded-xl p-3.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
                Causal Lineage
              </span>
              <span className="font-mono text-[11.5px] text-[#8595b0]">
                depth {relations.ancestors.length} · {relations.children.length} child
                {relations.children.length === 1 ? "" : "ren"}
              </span>
            </div>

            <div className="space-y-1.5">
              {relations.ancestors.map((anc, depth) => {
                const m = KIND_META[anc.kind] ?? KIND_META.tool_call;
                return (
                  <div
                    key={anc.span_id}
                    style={{ marginLeft: `${Math.min(depth, 3) * 10}px` }}
                    className="relative"
                  >
                    <button
                      type="button"
                      onClick={() => onSelectSpan(anc.span_id)}
                      className="flex w-full items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-[#7f95f8]/45 hover:bg-white/[0.04]"
                    >
                      <span className={`h-2 w-2 shrink-0 rounded-full ${m.dot}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2 font-mono text-[11.5px]">
                          <span className="truncate text-[#cfe0ff]">{anc.span_id}</span>
                          <span className="shrink-0 text-[#8595b0]">{m.label}</span>
                        </div>
                        <div className="truncate text-[12px] text-[#a6b5cf]">{anc.summary}</div>
                      </div>
                    </button>
                  </div>
                );
              })}

              {/* Current Span Node */}
              <div
                style={{ marginLeft: `${Math.min(relations.ancestors.length, 3) * 10}px` }}
                className="flex items-center gap-2 rounded-lg border border-[#7f95f8]/55 bg-[#7f95f8]/14 px-2.5 py-2"
              >
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${kindMeta.dot}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2 font-mono text-[11.5px]">
                    <span className="truncate font-semibold text-white">{span.span_id}</span>
                    <span className="shrink-0 rounded bg-[#7f95f8]/25 px-1.5 py-px text-[10.5px] text-[#e6eeff]">
                      current
                    </span>
                  </div>
                  <div className="truncate text-[12px] text-[#dce4f5]">{span.summary}</div>
                </div>
              </div>

              {/* Direct Children */}
              {relations.children.map((child) => {
                const m = KIND_META[child.kind] ?? KIND_META.tool_call;
                return (
                  <div
                    key={child.span_id}
                    style={{
                      marginLeft: `${Math.min(relations.ancestors.length + 1, 4) * 10}px`,
                    }}
                    className="border-l border-[#7f95f8]/30 pl-2.5"
                  >
                    <button
                      type="button"
                      onClick={() => onSelectSpan(child.span_id)}
                      className="flex w-full items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.02] px-2.5 py-2 text-left transition hover:border-[#7f95f8]/45 hover:bg-white/[0.04]"
                    >
                      <span className={`h-2 w-2 shrink-0 rounded-full ${m.dot}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2 font-mono text-[11.5px]">
                          <span className="truncate text-[#cfe0ff]">{child.span_id}</span>
                          <span className="shrink-0 text-[#8595b0]">
                            {m.label} · {formatDuration(child.duration_ms)}
                          </span>
                        </div>
                        <div className="truncate text-[12px] text-[#a6b5cf]">{child.summary}</div>
                      </div>
                    </button>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Same-File Siblings */}
          {span.path && relations.sameFile.length > 0 && (
            <section className="space-y-2">
              <h3 className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
                Same File ({relations.sameFile.length})
              </h3>
              <div className="space-y-1.5">
                {relations.sameFile.map((sib) => {
                  const m = KIND_META[sib.kind] ?? KIND_META.tool_call;
                  return (
                    <button
                      key={sib.span_id}
                      type="button"
                      onClick={() => onSelectSpan(sib.span_id)}
                      className="pr-well flex w-full flex-col gap-1 rounded-xl border border-white/[0.06] p-2.5 text-left transition hover:border-[#7f95f8]/45 hover:bg-white/[0.03]"
                    >
                      <div className="flex items-center justify-between gap-2 font-mono text-[11.5px]">
                        <span className="text-[#cfe0ff]">{sib.span_id}</span>
                        <span className="text-[#8595b0]">
                          {m.label} · {formatOffset(sib.timestamp, startMs)}
                        </span>
                      </div>
                      <p className="line-clamp-1 text-[12.5px] text-[#d2dbee]">{sib.summary}</p>
                    </button>
                  );
                })}
              </div>
            </section>
          )}

          {/* Correlation group + sibling workflow spans */}
          {span.correlation_id && (
            <section className="pr-well space-y-2.5 rounded-xl p-3.5">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
                  Correlation Chain
                </span>
                <button
                  type="button"
                  onClick={() =>
                    onScopeCorrelation(
                      activeCorrelationId === span.correlation_id ? null : span.correlation_id!,
                    )
                  }
                  className={`rounded-lg px-2.5 py-1 font-mono text-[12px] font-medium transition ${
                    activeCorrelationId === span.correlation_id
                      ? "pr-pill-active text-white"
                      : "pr-pill text-[#cfe0ff] hover:text-white"
                  }`}
                >
                  {activeCorrelationId === span.correlation_id ? "Clear scope" : "Scope timeline"}
                </button>
              </div>
              <div className="font-mono text-[12.5px] text-[#9ec0f5]">{span.correlation_id}</div>
              {relations.correlated.length > 0 && (
                <div className="space-y-1 pt-0.5">
                  {relations.correlated.map((peer) => {
                    const m = KIND_META[peer.kind] ?? KIND_META.tool_call;
                    return (
                      <button
                        key={peer.span_id}
                        type="button"
                        onClick={() => onSelectSpan(peer.span_id)}
                        className="flex w-full items-center justify-between gap-2 rounded-lg bg-white/[0.025] px-2.5 py-1.5 text-left font-mono text-[11.5px] text-[#d2dbee] transition hover:bg-white/[0.06] hover:text-white"
                      >
                        <span className="flex min-w-0 items-center gap-1.5">
                          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${m.dot}`} />
                          <span className="truncate">{peer.span_id}</span>
                        </span>
                        <span className="shrink-0 text-[#8595b0]">
                          {m.label} · {formatOffset(peer.timestamp, startMs)}
                        </span>
                      </button>
                    );
                  })}
                </div>
              )}
            </section>
          )}

          {/* Cross links */}
          {relations.linked.length > 0 && (
            <section className="space-y-2">
              <h3 className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
                Cross-Links ({relations.linked.length})
              </h3>
              <div className="space-y-1.5">
                {relations.linked.map((target) => (
                  <button
                    key={target.span_id}
                    type="button"
                    onClick={() => onSelectSpan(target.span_id)}
                    className="pr-well flex w-full items-center justify-between gap-2 rounded-xl border border-white/[0.06] px-3 py-2 text-left font-mono text-[12.5px] text-[#cfe0ff] hover:border-[#7f95f8]/45"
                  >
                    <span className="truncate">{target.span_id}</span>
                    <span className="shrink-0 text-[#8595b0]">
                      {(KIND_META[target.kind] ?? KIND_META.tool_call).label}
                    </span>
                  </button>
                ))}
              </div>
            </section>
          )}

          {/* Session provenance & per-span SHA-256 tamper-evident hash chain */}
          <section className="pr-well space-y-2 rounded-xl p-3.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-[12px] uppercase tracking-wider text-[#98a8c4]">
                Provenance Integrity
              </span>
              {(() => {
                const integ = session.delivery.integrity;
                const status = integ?.status ?? "verified";
                const cls =
                  status === "tampered"
                    ? "border-[#f27c7c]/40 bg-[#f27c7c]/15 text-[#ffb4b4]"
                    : status === "live"
                      ? "border-[#7f95f8]/35 bg-[#7f95f8]/12 text-[#cfe0ff]"
                      : "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#8beac0]";
                const label =
                  status === "tampered"
                    ? "Tampered"
                    : status === "live"
                      ? `Live · ${integ?.verified_spans ?? session.spans.length} chained`
                      : `Verified · ${integ?.verified_spans ?? session.spans.length}/${session.spans.length}`;
                return (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[11px] ${cls}`}
                  >
                    <IconShieldCheck className="h-3 w-3" />
                    {label}
                  </span>
                );
              })()}
            </div>
            {session.delivery.integrity?.detail && (
              <div className="rounded-lg border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-2.5 py-1.5 font-mono text-[11.5px] text-[#ffb4b4]">
                {session.delivery.integrity.detail}
              </div>
            )}
            <div className="space-y-1 font-mono text-[12px]">
              <div className="flex justify-between gap-2">
                <span className="text-[#8595b0]">Session</span>
                <span className="truncate text-[#dce4f5]">{session.session_id}</span>
              </div>
              {span.sequence && span.sequence > 0 && (
                <div className="flex justify-between gap-2">
                  <span className="text-[#8595b0]">Span Seq</span>
                  <span className="text-[#dce4f5]">
                    #{span.sequence}
                    {span.source ? ` · ${span.source}` : ""}
                  </span>
                </div>
              )}
              {session.change_id && (
                <div className="flex justify-between gap-2">
                  <span className="text-[#8595b0]">Change-Id</span>
                  <span className="text-[#cfe0ff]">{session.change_id}</span>
                </div>
              )}
              {session.commit_oid && (
                <div className="flex justify-between gap-2">
                  <span className="text-[#8595b0]">Commit</span>
                  <span className="text-[#dce4f5]">{session.commit_oid}</span>
                </div>
              )}
              {span.event_hash && (
                <div className="pt-1">
                  <div className="flex items-center justify-between text-[#8595b0]">
                    <span>Span Hash</span>
                    <button
                      type="button"
                      onClick={() => copyText("span-hash", span.event_hash!)}
                      className="text-[#9ec0f5] hover:underline"
                    >
                      {copiedKey === "span-hash" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <div className="mt-1 truncate rounded-lg bg-black/35 px-2.5 py-1 text-[11.5px] text-[#a6b5cf]">
                    {span.event_hash}
                  </div>
                </div>
              )}
              {session.delivery.provenance_digest && (
                <div className="pt-1">
                  <div className="flex items-center justify-between text-[#8595b0]">
                    <span>Chain Head</span>
                    <button
                      type="button"
                      onClick={() => copyText("digest", session.delivery.provenance_digest!)}
                      className="text-[#9ec0f5] hover:underline"
                    >
                      {copiedKey === "digest" ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <div className="mt-1 break-all rounded-lg bg-black/35 px-2.5 py-1.5 text-[11.5px] text-[#a6b5cf]">
                    {session.delivery.provenance_digest}
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      ) : (
        /* Raw tab: full syntax-highlighted JSON / Tree explorer with byte size + Span/Run switcher + download */
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex rounded-lg border border-white/[0.08] bg-white/[0.025] p-0.5 font-mono text-[12px]">
              <button
                type="button"
                onClick={() => setRawScope("span")}
                className={`rounded-md px-2.5 py-1 transition ${
                  rawScope === "span" ? "pr-pill-active text-white" : "text-[#a6b5cf]"
                }`}
              >
                Span JSON
              </button>
              <button
                type="button"
                onClick={() => setRawScope("session")}
                className={`rounded-md px-2.5 py-1 transition ${
                  rawScope === "session" ? "pr-pill-active text-white" : "text-[#a6b5cf]"
                }`}
              >
                Full Run JSON
              </button>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-mono text-[11.5px] text-[#8595b0]">
                {(
                  new Blob([JSON.stringify(rawScope === "span" ? span : session)]).size / 1024
                ).toFixed(1)}{" "}
                KB
              </span>
              <button
                type="button"
                onClick={() =>
                  downloadJson(
                    rawScope === "span"
                      ? `${span.span_id}.json`
                      : `${session.session_id}.trace.json`,
                    rawScope === "span" ? span : session,
                  )
                }
                className="pr-pill inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 font-mono text-[12px] text-[#cfe0ff] hover:text-white"
              >
                <IconDownload className="h-3.5 w-3.5" />
                <span>Export</span>
              </button>
            </div>
          </div>

          <JsonTreeView
            value={rawScope === "span" ? span : session}
            label={rawScope === "span" ? `${span.span_id}.json` : `${session.session_id}.json`}
            defaultMode="code"
            compact={false}
            searchable
            maxHeightClass="max-h-[600px]"
          />
        </div>
      )}
    </aside>
  );
}
