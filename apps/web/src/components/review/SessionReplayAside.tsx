import { useState } from "react";
import type { ChangeReviewRecord, IdentityPreset, ReviewDiffHunk, ReviewRound } from "../../api";
import type { SessionStep, SessionStepKind, SessionTimeline } from "../../lib/sessionReplay";
import { isSteeringComment, steeringTargetAgent } from "../../lib/steeringPayload";
import { IconCheck, IconClose, IconComment, IconCopy, IconLock, IconTimeline } from "../Icons";

export interface SessionReplayAsideProps {
  change: ChangeReviewRecord | null;
  round: ReviewRound | null;
  activeHunk: ReviewDiffHunk | null;
  timeline: SessionTimeline;
  activeStepIndex: number;
  onSelectStepIndex: (idx: number) => void;
  onSelectHunk: (hunkId: string) => void;
  identity: IdentityPreset;
  asideTab: "replay" | "comments";
  onAsideTabChange: (tab: "replay" | "comments") => void;
  mobileVisible: boolean;
  newCommentBody: string;
  onNewCommentBodyChange: (v: string) => void;
  onSubmitComment: (e: React.FormEvent) => void;
  submitting: boolean;
  copiedKey: string | null;
  onCopy: (key: string, val: string) => void;
  /** Collapse the aside (desktop) so the diff pane can use the full width. */
  onCollapse?: () => void;
}

const KIND_COLOR: Record<SessionStepKind, string> = {
  edit: "#5bdba2",
  egress: "#67d6dc",
  test: "#9ec0f5",
  error: "#f27c7c",
  redacted: "#f27c7c",
  prompt: "#7f95f8",
  read: "#8595b0",
};

export function SessionReplayAside(props: SessionReplayAsideProps) {
  const { change, round, activeHunk, timeline, activeStepIndex, identity, asideTab } = props;
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>({});
  const total = timeline.steps.length;
  const active = timeline.steps[activeStepIndex];

  const select = (step: SessionStep) => {
    props.onSelectStepIndex(step.index);
    const hunkId = step.linkedHunkIds[0];
    if (hunkId) props.onSelectHunk(hunkId);
  };
  const go = (idx: number) => {
    const step = timeline.steps[Math.min(Math.max(idx, 0), total - 1)];
    if (step) select(step);
  };

  const renderStep = (step: SessionStep, nested = false) => {
    const color = KIND_COLOR[step.kind];
    const isActive = step.index === activeStepIndex;
    return (
      <button
        key={step.id}
        type="button"
        onClick={() => select(step)}
        aria-current={isActive ? "step" : undefined}
        className={`flex w-full items-start gap-2.5 rounded-xl px-3 py-2 text-left transition ${
          isActive ? "pr-pill-active" : step.prominent ? "pr-well" : "hover:bg-white/[0.03]"
        } ${nested ? "py-1.5" : ""}`}
        style={step.prominent && !isActive ? { borderColor: `${color}40` } : undefined}
      >
        <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: color }} aria-hidden="true" />
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2 font-mono text-[12.5px] uppercase tracking-wider" style={{ color }}>
            <span>{step.kind}</span>
            {step.badge && step.prominent && (
              <span className="rounded-full border px-1.5 py-px text-[12px]" style={{ borderColor: `${color}55` }}>
                {step.badge}
              </span>
            )}
          </span>
          <span className="mt-0.5 block truncate font-mono text-[13px] text-[#dce4f5]">{step.title}</span>
        </span>
      </button>
    );
  };

  return (
    <aside
      className={`pr-surface min-h-0 shrink-0 flex-col overflow-hidden rounded-2xl bg-[#0b0f1c] lg:w-[300px] xl:w-[320px] 2xl:w-[400px] ${
        props.mobileVisible ? "flex flex-1" : "hidden lg:flex"
      }`}
    >
      <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
        <div role="tablist" className="inline-flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]">
          <button
            type="button"
            role="tab"
            aria-selected={asideTab === "replay"}
            onClick={() => props.onAsideTabChange("replay")}
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 transition ${
              asideTab === "replay" ? "pr-pill-active" : "text-[#a6b5cf]"
            }`}
          >
            <IconTimeline className="h-4 w-4" />
            <span>Replay</span>
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={asideTab === "comments"}
            onClick={() => props.onAsideTabChange("comments")}
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 transition ${
              asideTab === "comments" ? "pr-pill-active" : "text-[#a6b5cf]"
            }`}
          >
            <IconComment className="h-4 w-4" />
            <span>Comments ({change?.comments?.length ?? 0})</span>
          </button>
        </div>
        <div className="flex min-w-0 items-center gap-1.5">
          <span className="pr-pill truncate rounded-full px-2 py-0.5 font-mono text-[12.5px] text-[#9ec0f5]">{identity.label}</span>
          {props.onCollapse && (
            <button
              type="button"
              onClick={props.onCollapse}
              aria-label="Collapse replay panel"
              title="Collapse panel"
              className="hidden shrink-0 rounded-lg p-1 text-[#98a8c4] transition hover:bg-white/[0.06] hover:text-white lg:inline-flex"
            >
              <IconClose className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {asideTab === "replay" ? (
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          {/* Scrubber */}
          <div className="pr-well space-y-2.5 rounded-xl p-3">
            <div className="flex items-center justify-between gap-2 font-mono text-[12.5px]">
              <span className="truncate text-[#f3f6fd]">
                {timeline.agentProfile}
                {timeline.model && <span className="text-[#98a8c4]"> · {timeline.model}</span>}
              </span>
              <span className="shrink-0 text-[#98a8c4]">
                Step {total ? activeStepIndex + 1 : 0} / {total}
              </span>
            </div>
            {total === 0 ? (
              <div className="py-1 font-mono text-[13px] text-[#a6b5cf]">
                {timeline.sessionVisible ? "No recorded steps for this round" : "Session trail not visible to this identity"}
              </div>
            ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => go(activeStepIndex - 1)}
                disabled={activeStepIndex <= 0}
                className="pr-pill rounded-lg px-2 py-1 font-mono text-[12.5px] text-[#d2dbee] disabled:opacity-40"
              >
                Prev
              </button>
              <input
                type="range"
                min={0}
                max={Math.max(0, total - 1)}
                value={activeStepIndex}
                onChange={(e) => go(Number(e.target.value))}
                aria-label="Session replay step"
                className="pr-scrubber min-w-0 flex-1"
              />
              <button
                type="button"
                onClick={() => go(activeStepIndex + 1)}
                disabled={activeStepIndex >= total - 1}
                className="pr-pill rounded-lg px-2 py-1 font-mono text-[12.5px] text-[#d2dbee] disabled:opacity-40"
              >
                Next
              </button>
            </div>
            )}
            <div className="flex flex-wrap gap-1">
              {timeline.steps.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => select(s)}
                  title={`${s.index + 1}. ${s.kind}: ${s.title}`}
                  aria-label={`Step ${s.index + 1}: ${s.kind}`}
                  className={`h-2 w-2 rounded-full transition ${s.index === activeStepIndex ? "scale-150 ring-1 ring-white/70" : "opacity-80 hover:opacity-100"}`}
                  style={{ background: KIND_COLOR[s.kind] }}
                />
              ))}
            </div>
            {(timeline.egressCalls > 0 || timeline.bytesScrubbed > 0 || timeline.egressBlocked > 0) && (
              <div className="flex flex-wrap gap-2 font-mono text-[12.5px] text-[#98a8c4]">
                <span>{timeline.egressCalls} egress</span>
                <span className="text-[#67d6dc]">{timeline.bytesScrubbed} B scrubbed</span>
                {timeline.egressBlocked > 0 && <span className="text-[#f27c7c]">{timeline.egressBlocked} blocked</span>}
              </div>
            )}
          </div>

          {/* Active step inspector */}
          {active && (
            <div className="pr-well space-y-2 rounded-xl p-3.5">
              <div className="flex items-center gap-2 font-mono text-[12.5px] uppercase tracking-wider">
                <span
                  className="rounded-full border px-2 py-0.5"
                  style={{ color: KIND_COLOR[active.kind], borderColor: `${KIND_COLOR[active.kind]}55` }}
                >
                  {active.kind}
                </span>
                {active.timestamp && <span className="normal-case text-[#a6b5cf]">{active.timestamp}</span>}
              </div>
              {active.redacted ? (
                <div className="flex flex-col items-center py-4 text-center">
                  <IconLock className="h-6 w-6 text-[#a6b5cf]" />
                  <div className="mt-2 font-mono text-[14px] text-[#f3f6fd]">Redacted</div>
                  <div className="mt-1 font-mono text-[13px] text-[#98a8c4]">{active.redactionReason}</div>
                </div>
              ) : (
                <>
                  <div className="break-words font-mono text-[13.5px] text-[#f3f6fd]">{active.title}</div>
                  {active.detail !== active.title && (
                    <div className="break-words text-[14px] leading-relaxed text-[#d2dbee]">{active.detail}</div>
                  )}
                </>
              )}
              {active.kind === "prompt" && (
                <button
                  type="button"
                  onClick={() => props.onCopy("prompt", active.detail)}
                  className="inline-flex items-center gap-1.5 font-mono text-[12.5px] text-[#9ec0f5] hover:underline"
                >
                  {props.copiedKey === "prompt" ? (
                    <IconCheck className="h-4 w-4 text-[#5bdba2]" />
                  ) : (
                    <IconCopy className="h-4 w-4" />
                  )}
                  <span>Copy prompt</span>
                </button>
              )}
              {active.kind === "egress" && (
                <div className="flex flex-wrap items-center gap-2 font-mono text-[12.5px]">
                  <span className="text-[#67d6dc]">{active.bytesScrubbed ?? 0} B scrubbed</span>
                  {active.egressDecision && (
                    <span className="pr-pill rounded-full px-2 py-0.5 text-[#d2dbee]">{active.egressDecision}</span>
                  )}
                </div>
              )}
              {active.linkedHunkIds.length > 0 && (
                <button
                  type="button"
                  onClick={() => props.onSelectHunk(active.linkedHunkIds[0])}
                  className={`font-mono text-[12.5px] hover:underline ${
                    activeHunk?.id === active.linkedHunkIds[0] ? "text-[#5bdba2]" : "text-[#9ec0f5]"
                  }`}
                >
                  Jump to hunk →
                </button>
              )}
            </div>
          )}

          {/* Chronological trail */}
          <div className="space-y-1">
            <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">Trail</div>
            {timeline.displayItems.map((item) => {
              if (item.type === "step") return renderStep(item.step);
              const open = !!openGroups[item.id] || item.steps.some((s) => s.index === activeStepIndex);
              return (
                <div key={item.id}>
                  <button
                    type="button"
                    aria-expanded={open}
                    onClick={() => setOpenGroups((g) => ({ ...g, [item.id]: !open }))}
                    className="flex w-full items-center gap-2 rounded-xl px-3 py-1.5 text-left font-mono text-[12.5px] text-[#98a8c4] hover:bg-white/[0.03]"
                  >
                    <span aria-hidden="true">{open ? "▼" : "▶"}</span>
                    <span>{item.label}</span>
                  </button>
                  {open && <div className="ml-3 space-y-0.5 border-l border-white/[0.06] pl-2">{item.steps.map((s) => renderStep(s, true))}</div>}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-4">
            {!change?.comments?.length ? (
              <div className="py-10 text-center font-mono text-[13.5px] text-[#a6b5cf]">No comments yet</div>
            ) : (
              change.comments.map((c) => {
                const steer = isSteeringComment(c);
                const hunk = round?.hunks.find((h) => h.allowed && h.path === c.path);
                const body = (
                  <>
                    <div className="flex items-center justify-between gap-2 font-mono text-[12.5px]">
                      <span className="flex min-w-0 items-center gap-1.5">
                        <span className="truncate text-[#9ec0f5]">{c.author}</span>
                        {steer && (
                          <span className="shrink-0 rounded-full border border-[#7f95f8]/40 bg-[#7f95f8]/10 px-1.5 py-px text-[12px] text-[#67d6dc]">
                            Steer · @{steeringTargetAgent(c)}
                          </span>
                        )}
                      </span>
                      <span className="truncate text-[#a6b5cf]">
                        {c.path}
                        {c.line != null ? `:L${c.line}` : ""}
                      </span>
                    </div>
                    <div className="mt-1.5 text-[14px] leading-relaxed text-[#dce4f5]">{c.body}</div>
                  </>
                );
                return hunk ? (
                  <button
                    key={c.id}
                    type="button"
                    onClick={() => props.onSelectHunk(hunk.id)}
                    className="pr-well block w-full rounded-xl p-3 text-left hover:border-white/[0.12]"
                  >
                    {body}
                  </button>
                ) : (
                  <div key={c.id} className="pr-well rounded-xl p-3">
                    {body}
                  </div>
                );
              })
            )}
          </div>
          <form onSubmit={props.onSubmitComment} className="space-y-2 border-t border-white/[0.06] p-3.5">
            <div className="truncate font-mono text-[12.5px] text-[#a6b5cf]" title={activeHunk?.path}>
              {activeHunk ? activeHunk.path : "Select a hunk to comment on it"}
            </div>
            <div className="flex items-center gap-2">
              <input
                value={props.newCommentBody}
                onChange={(e) => props.onNewCommentBodyChange(e.target.value)}
                disabled={!activeHunk}
                aria-label="Review comment"
                placeholder="Add persisted review comment…"
                className="pr-well min-w-0 flex-1 rounded-xl px-3 py-1.5 text-[13.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none disabled:opacity-50"
              />
              <button
                type="submit"
                disabled={!activeHunk || props.submitting || !props.newCommentBody.trim()}
                className="pr-action-btn shrink-0 rounded-xl px-3 py-1.5 text-[13px] disabled:opacity-45"
              >
                Post
              </button>
            </div>
          </form>
        </div>
      )}
    </aside>
  );
}
