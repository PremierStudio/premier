import type { ReactNode } from "react";
import type {
  ChangeReviewRecord,
  GitCommitDiffResponse,
  IdentityPreset,
  ReviewRound,
} from "../../api";
import { formatTime, isoTime } from "../../lib/format";
import { formatByteSize } from "../../lib/highlight";
import {
  computeRiskRadar,
  extractZoneFootprint,
  type RiskRadarSignal,
} from "../../lib/reviewConcerns";
import type { SessionTimeline } from "../../lib/sessionReplay";
import {
  IconBranchRef,
  IconCage,
  IconCheck,
  IconCopy,
  IconFold,
  IconIntersection,
  IconLock,
  IconQuarantine,
  IconRadar,
  IconShieldCheck,
  IconUnfold,
} from "../Icons";

export interface IntentTrustReceiptProps {
  change: ChangeReviewRecord;
  round: ReviewRound;
  timeline: SessionTimeline;
  identity: IdentityPreset;
  owner: boolean;
  baseBranch: string;
  activeVerdict?: string;
  hasRedactedHunk: boolean;
  copiedKey: string | null;
  onCopy: (key: string, val: string) => void;
  onSelectRound: (roundNum: number) => void;
  onSetVerdict: (verdict: "approved" | "changes") => void;
  onPublishBranch?: (branchName: string) => void;
  /** Extra action (e.g. Steer Agent) rendered in the action cluster so the walkthrough bar never overflows. */
  steerAction?: ReactNode;
  /** Secondary view controls (lane badge, Snapshot | Interdiff) shown in row 2 so they never crowd the walkthrough bar. */
  metaActions?: ReactNode;
}

export interface CommitTrustHeaderProps {
  commitDiff: GitCommitDiffResponse;
  totals: { additions: number; deletions: number };
  allCollapsed: boolean;
  onToggleCollapseAll: () => void;
  copiedKey: string | null;
  onCopy: (key: string, val: string) => void;
}

function radarPillClasses(severity: RiskRadarSignal["severity"]): string {
  switch (severity) {
    case "critical":
      return "border-[#f27c7c]/35 bg-[#f27c7c]/12 text-[#f27c7c]";
    case "warn":
      return "border-[#9ec0f5]/35 bg-[#7f95f8]/12 text-[#a8c5ff]";
    case "info":
      return "border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#9ec0f5]";
  }
}

function radarDotClasses(severity: RiskRadarSignal["severity"]): string {
  switch (severity) {
    case "critical":
      return "bg-[#f27c7c]";
    case "warn":
      return "bg-[#7f95f8]";
    case "info":
      return "bg-[#7f95f8]";
  }
}

function resolveSandboxLabel(timeline: SessionTimeline): {
  label: string;
  tone: "mint" | "amber" | "coral" | "ice";
} {
  if (!timeline.sessionVisible) {
    return { label: "sandbox redacted", tone: "coral" };
  }
  if (timeline.sandbox === "bwrap") {
    return { label: "bwrap sandbox", tone: "mint" };
  }
  if (timeline.sandbox === "unsandboxed-allowed") {
    return { label: "unsandboxed-allowed", tone: "amber" };
  }
  return { label: "isolated workspace", tone: "ice" };
}

export function IntentTrustReceipt({
  change,
  round,
  timeline,
  identity,
  owner,
  baseBranch,
  activeVerdict,
  hasRedactedHunk,
  copiedKey,
  onCopy,
  onSelectRound,
  onSetVerdict,
  onPublishBranch,
  steerAction,
  metaActions,
}: IntentTrustReceiptProps) {
  const footprint = extractZoneFootprint(round.hunks);
  const radarSignals = computeRiskRadar(round.hunks, change.quarantine_flagged);
  const sandboxInfo = resolveSandboxLabel(timeline);

  const hasDistinctPrompt =
    timeline.sessionVisible &&
    Boolean(timeline.promptSummary.trim()) &&
    timeline.promptSummary.trim() !== change.title.trim();
  const intentText = hasDistinctPrompt ? timeline.promptSummary : round.interdiff_summary;

  return (
    <div
      className="shrink-0 border-b border-white/[0.06] bg-[#080c18] px-4 py-2 sm:px-5"
      aria-label="Intent and runtime trust receipt"
    >
      {/* Row 1: title · status · round pills · verdicts */}
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1.5">
        <div className="flex min-w-[12rem] flex-1 basis-[16rem] items-center gap-2">
          <h2
            className="min-w-0 truncate text-[14px] font-semibold tracking-tight text-[#f3f6fd]"
            title={change.title}
          >
            {change.title}
          </h2>
          <span
            className={`shrink-0 rounded-full px-2 py-px font-mono text-[12px] uppercase tracking-wider ${
              change.readiness === "ready"
                ? "border border-[#5bdba2]/30 bg-[#5bdba2]/15 text-[#5bdba2]"
                : "border border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
            }`}
          >
            {change.readiness}
          </span>
          {round.rebased_cleanly && (
            <span className="shrink-0 rounded-full border border-[#5bdba2]/25 bg-[#5bdba2]/12 px-2 py-px font-mono text-[12px] text-[#5bdba2]">
              rebased
            </span>
          )}
          {change.quarantine_flagged ? (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/12 px-2 py-px font-mono text-[12.5px] text-[#a8c5ff]">
              <IconQuarantine className="h-3.5 w-3.5" />
              <span>Quarantine</span>
            </span>
          ) : (
            <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-2 py-px font-mono text-[12.5px] text-[#5bdba2]">
              <IconShieldCheck className="h-3.5 w-3.5" />
              <span>Verified</span>
            </span>
          )}
        </div>

        {/* Round selector pills + Owner Publish + Verdict buttons */}
        <div className="flex shrink-0 flex-wrap items-center gap-1.5">
          {change.rounds.length > 3 ? (
            <select
              value={round.round}
              onChange={(e) => onSelectRound(Number(e.target.value))}
              aria-label="Select round"
              className="pr-pill rounded-full px-2.5 py-0.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none"
            >
              {change.rounds.map((r) => (
                <option key={r.round} value={r.round} className="bg-[#0b0f1b]">
                  R{r.round} · {r.commit_oid}
                </option>
              ))}
            </select>
          ) : (
            change.rounds.map((r) => (
              <button
                key={r.round}
                type="button"
                onClick={() => onSelectRound(r.round)}
                aria-label={`Select round R${r.round}`}
                aria-pressed={round.round === r.round}
                title={`R${r.round} · ${r.commit_oid}`}
                className={`rounded-full px-2.5 py-0.5 font-mono text-[12.5px] transition ${
                  round.round === r.round ? "pr-pill-active" : "pr-pill text-[#a6b5cf]"
                }`}
              >
                R{r.round}
              </button>
            ))
          )}

          {owner && change.branch !== baseBranch && onPublishBranch && (
            <button
              type="button"
              onClick={() => onPublishBranch(change.branch)}
              aria-label={`Publish branch ${change.branch}`}
              className="pr-action-btn inline-flex items-center gap-1 rounded-full px-3 py-0.5 font-mono text-[12.5px]"
            >
              <span>Publish branch →</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => onSetVerdict("approved")}
            aria-label={`Approve round R${round.round}`}
            title={
              change.quarantine_flagged || hasRedactedHunk
                ? "Review includes quarantined or redacted hunks"
                : "Approve round"
            }
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-0.5 font-mono text-[12.5px] transition ${
              activeVerdict === "approved"
                ? "border border-[#5bdba2]/40 bg-[#5bdba2]/18 text-[#5bdba2]"
                : "pr-pill text-[#d2dbee] hover:text-[#5bdba2]"
            }`}
          >
            <IconCheck className="h-3.5 w-3.5" />
            <span>Approve R{round.round}</span>
          </button>

          <button
            type="button"
            onClick={() => onSetVerdict("changes")}
            aria-label={`Request revision for round R${round.round}`}
            className={`rounded-full px-3 py-0.5 font-mono text-[12.5px] transition ${
              activeVerdict === "changes"
                ? "border border-[#9ec0f5]/40 bg-[#7f95f8]/18 text-[#a8c5ff]"
                : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
            }`}
          >
            Revise
          </button>
          {steerAction}
        </div>
      </div>

      {/* Row 2 (single line): branch · change-id · round · intent */}
      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[12.5px] text-[#a6b5cf]">
        <span className="inline-flex shrink-0 items-center gap-1 text-[#d2dbee]">
          <IconBranchRef className="h-3.5 w-3.5 text-[#9ec0f5]" />
          <span>{change.branch}</span>
        </span>
        <button
          type="button"
          onClick={() => onCopy("cid", change.change_id)}
          aria-label={`Copy Change-Id ${change.change_id}`}
          className="inline-flex shrink-0 items-center gap-1 text-[#9ec0f5] hover:underline"
        >
          <span>{change.change_id}</span>
          {copiedKey === "cid" ? (
            <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
          ) : (
            <IconCopy className="h-3.5 w-3.5" />
          )}
        </button>
        <span className="shrink-0 text-[#b6c3db]">{round.label}</span>
        {metaActions}
        {intentText && (
          <span className="min-w-0 truncate text-[13px] text-[#dce4f5]" title={intentText}>
            <span className="mr-1.5 text-[12px] uppercase tracking-wider text-[#9ec0f5]">
              Intent
            </span>
            {intentText}
          </span>
        )}
      </div>

      {/* Row 3 (single line, never wraps): identity · sandbox · zones(+N) · egress · radar */}
      <div className="mt-1.5 flex items-center gap-1.5 whitespace-nowrap font-mono text-[12.5px]">
        <div className="flex min-w-0 flex-1 items-center gap-1.5 overflow-hidden">
        <span
          className="pr-pill inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-px text-[#dce4f5]"
          title={`Effective authority (human ∩ agent_task) · lens: ${identity.label}`}
        >
          <IconIntersection className="h-3 w-3 text-[#9ec0f5]" />
          <span>
            {change.author}
            {change.delegated_agent ? ` ∩ ${change.delegated_agent}` : " · human"}
          </span>
        </span>

        <span
          className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-px ${
            sandboxInfo.tone === "mint"
              ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#5bdba2]"
              : sandboxInfo.tone === "amber"
                ? "border-[#9ec0f5]/30 bg-[#7f95f8]/10 text-[#a8c5ff]"
                : sandboxInfo.tone === "coral"
                  ? "border-[#f27c7c]/30 bg-[#f27c7c]/10 text-[#f27c7c]"
                  : "border-white/[0.08] bg-white/[0.03] text-[#9ec0f5]"
          }`}
          title="Agent runtime sandbox confinement"
        >
          <IconCage className="h-3 w-3" />
          <span>{sandboxInfo.label}</span>
        </span>

        <ZoneChips zones={footprint.zones} redactedCount={footprint.redactedCount} />

        {timeline.sessionVisible ? (
          <span
            className={`inline-flex shrink-0 items-center gap-1 rounded-full border px-2 py-px ${
              timeline.egressBlocked > 0
                ? "border-[#f27c7c]/35 bg-[#f27c7c]/12 text-[#f27c7c]"
                : timeline.bytesScrubbed > 0
                  ? "border-[#67d6dc]/35 bg-[#67d6dc]/10 text-[#67d6dc]"
                  : "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf]"
            }`}
            title="Host egress proxy broker receipt"
          >
            {timeline.egressCalls} proxied · {formatByteSize(timeline.bytesScrubbed)} scrubbed ·{" "}
            {timeline.egressBlocked} blocked
          </span>
        ) : (
          <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-2 py-px text-[#f27c7c]">
            <IconLock className="h-3 w-3" />
            <span>Egress redacted</span>
          </span>
        )}

        </div>

        <span className="ml-auto shrink-0">
          <RadarPill signals={radarSignals} />
        </span>
      </div>
    </div>
  );
}

const ZONE_CAP = 3;

/** Zone chips capped to ZONE_CAP with a +N overflow so the strip never wraps into extra rows. */
function ZoneChips({ zones, redactedCount }: { zones: string[]; redactedCount: number }) {
  const shown = zones.slice(0, ZONE_CAP);
  const extra = zones.length - shown.length;
  return (
    <>
      {shown.map((zone) => (
        <span
          key={zone}
          title={`Visible zone: ${zone}`}
          className="pr-pill inline-flex max-w-[11rem] shrink-0 items-center gap-1 rounded-full px-2 py-px text-[#d2dbee]"
        >
          <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#67d6dc]" />
          <span className="truncate">{zone}</span>
        </span>
      ))}
      {extra > 0 && (
        <span
          title={zones.slice(ZONE_CAP).join(", ")}
          className="pr-pill shrink-0 rounded-full px-2 py-px text-[#a6b5cf]"
        >
          +{extra}
        </span>
      )}
      {redactedCount > 0 && (
        <span
          title="Restricted zones omitted by ACL policy"
          className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-2 py-px text-[#f27c7c]"
        >
          <IconLock className="h-3 w-3" />
          <span>{redactedCount}</span>
        </span>
      )}
    </>
  );
}

/** Compact radar: one pill (worst signal + overflow count), full detail in the tooltip. */
function RadarPill({ signals }: { signals: RiskRadarSignal[] }) {
  if (signals.length === 0) {
    return (
      <span
        title="Radar: no policy or instruction drift"
        className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-2 py-px text-[12.5px] text-[#5bdba2]"
      >
        <IconRadar className="h-3 w-3" />
        <span>No drift</span>
      </span>
    );
  }
  const rank = { critical: 0, warn: 1, info: 2 } as const;
  const sorted = [...signals].sort((a, b) => rank[a.severity] - rank[b.severity]);
  const top = sorted[0]!;
  return (
    <span
      title={sorted.map((s) => `${s.label}: ${s.detail}`).join(" · ")}
      className={`inline-flex max-w-[16rem] shrink-0 items-center gap-1.5 rounded-full border px-2 py-px text-[12.5px] ${radarPillClasses(
        top.severity,
      )}`}
    >
      <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${radarDotClasses(top.severity)}`} />
      <span className="truncate">{top.label}</span>
      {sorted.length > 1 && <span className="opacity-75">+{sorted.length - 1}</span>}
    </span>
  );
}

export function CommitTrustHeader({
  commitDiff,
  totals,
  allCollapsed,
  onToggleCollapseAll,
  copiedKey,
  onCopy,
}: CommitTrustHeaderProps) {
  const footprint = extractZoneFootprint(commitDiff.files);
  const redactedCount = footprint.redactedCount + commitDiff.hidden_files;
  const radarSignals = computeRiskRadar(commitDiff.files, false);

  return (
    <div className="shrink-0 border-b border-white/[0.06] bg-[#080c18] px-4 py-2 sm:px-5">
      {/* Row 1: subject · sha/author/date · stats · radar · collapse */}
      <div className="flex items-center gap-x-3">
        <div className="min-w-0 flex-1 truncate text-[14.5px] font-medium text-[#f3f6fd]" title={commitDiff.subject}>
          {commitDiff.subject}
        </div>
        <RadarPill signals={radarSignals} />
        <span className="flex shrink-0 items-center gap-1.5 font-mono text-[13px]">
          <span className="text-[#5bdba2]">+{totals.additions}</span>
          <span className="text-[#f27c7c]">-{totals.deletions}</span>
        </span>
        <button
          type="button"
          onClick={onToggleCollapseAll}
          title={allCollapsed ? "Expand all files" : "Collapse all files"}
          aria-label={allCollapsed ? "Expand all files" : "Collapse all files"}
          className="pr-pill inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[#a6b5cf] hover:text-[#f3f6fd]"
        >
          {allCollapsed ? <IconUnfold className="h-4 w-4" /> : <IconFold className="h-4 w-4" />}
        </button>
      </div>

      {/* Row 2 (single line, never wraps): sha · author · date · zones(+N) */}
      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 font-mono text-[12.5px] text-[#a6b5cf]">
        <button
          type="button"
          onClick={() => onCopy("oid", commitDiff.oid)}
          aria-label={`Copy commit OID ${commitDiff.oid}`}
          className="inline-flex shrink-0 items-center gap-1 text-[#9ec0f5] hover:underline"
        >
          <span>{commitDiff.oid.slice(0, 8)}</span>
          {copiedKey === "oid" ? (
            <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
          ) : (
            <IconCopy className="h-3.5 w-3.5" />
          )}
        </button>
        <span className="truncate">{commitDiff.author}</span>
        {commitDiff.date && (
          <time
            dateTime={isoTime(commitDiff.date)}
            title={isoTime(commitDiff.date)}
            className="hidden shrink-0 sm:inline"
          >
            · {formatTime(commitDiff.date)}
          </time>
        )}
        <span className="mx-0.5 shrink-0 text-[#3d4960]">│</span>
        <ZoneChips zones={footprint.zones} redactedCount={redactedCount} />
      </div>
    </div>
  );
}
