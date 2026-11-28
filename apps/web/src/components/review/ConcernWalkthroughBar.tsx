import type { ReactNode } from "react";
import type { ConcernGroup, ConcernId, RiskLevel } from "../../lib/reviewConcerns";
import { computeProgress, type ReviewViewMode } from "../../lib/reviewProgress";
import { IconCheck, IconCompass } from "../Icons";

export interface ConcernWalkthroughBarProps {
  mode: "commits" | "rounds";
  viewMode: ReviewViewMode;
  onViewModeChange: (mode: ReviewViewMode) => void;
  groups: ConcernGroup<unknown>[];
  reviewedIds: ReadonlySet<string>;
  totalCount: number;
  itemUnit: "hunk" | "file";
  onJumpToConcern: (concernId: ConcernId) => void;
  onResetReviewed?: () => void;
  showKeyboardHints?: boolean;
  /** Controls placed right after the Guided/All toggle (e.g. the diff layout toggle) so the whole toolbar is one row. */
  leading?: ReactNode;
  /** Controls pinned to the far right of the toolbar row (e.g. Steer Agent). */
  trailing?: ReactNode;
}

function riskDotColor(risk: RiskLevel): string {
  switch (risk) {
    case "critical":
      return "bg-[#f27c7c]";
    case "high":
      return "bg-[#7f95f8]";
    case "medium":
      return "bg-[#7f95f8]";
    case "low":
      return "bg-white/35";
  }
}

export function ConcernWalkthroughBar({
  mode,
  viewMode,
  onViewModeChange,
  groups,
  reviewedIds,
  totalCount,
  itemUnit,
  onJumpToConcern,
  onResetReviewed,
  showKeyboardHints = true,
  leading,
  trailing,
}: ConcernWalkthroughBarProps) {
  const allGroupItemIds = groups.flatMap((g) => g.items.map((item) => item.id));
  const overall = computeProgress(allGroupItemIds, reviewedIds);
  const reviewedCount =
    allGroupItemIds.length > 0 ? overall.reviewed : Math.min(totalCount, reviewedIds.size);
  const progressPercent =
    totalCount > 0 ? Math.min(100, Math.round((reviewedCount / totalCount) * 100)) : 0;
  // A single concern needs no jump strip: the section is the whole list.
  const showConcernStrip = viewMode === "guided" && groups.length > 1;

  return (
    <div
      className="shrink-0 border-b border-white/[0.06] bg-[#0a0e1c] px-4 py-1.5 sm:px-5"
      aria-label="Review walkthrough and progress controls"
    >
      {/* Strictly ONE unified toolbar row: tour toggle · layout toggle · concern chips · progress · shortcuts · actions */}
      <div className="flex min-w-0 items-center gap-2 xl:gap-2.5">
        <div
          role="group"
          aria-label="Review layout mode"
          className="inline-flex shrink-0 items-center gap-0.5 rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5"
        >
          <button
            type="button"
            onClick={() => onViewModeChange("guided")}
            aria-label="Guided Tour mode"
            title="Guided Tour"
            aria-pressed={viewMode === "guided"}
            className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[12.5px] font-medium transition ${
              viewMode === "guided" ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#f3f6fd]"
            }`}
          >
            <IconCompass className="h-3.5 w-3.5 text-[#9ec0f5]" />
            <span className="hidden xl:inline">Guided Tour</span>
          </button>
          <button
            type="button"
            onClick={() => onViewModeChange("all")}
            aria-label="All Files mode"
            aria-pressed={viewMode === "all"}
            className={`rounded-full px-2.5 py-0.5 font-mono text-[12.5px] font-medium transition ${
              viewMode === "all" ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#f3f6fd]"
            }`}
          >
            All Files
          </button>
        </div>

        {leading && (
          <div className="flex shrink-0 items-center gap-2">
            {leading}
          </div>
        )}

        {/* Inline concern jump chips share the exact same single toolbar row */}
        {showConcernStrip && (
          <>
            <span aria-hidden="true" className="hidden h-4 w-px shrink-0 bg-white/[0.09] sm:inline-block" />
            <div
              className="flex min-w-[8rem] flex-1 items-center gap-1.5 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
              role="navigation"
              aria-label="Concern walkthrough waypoints"
            >
              {groups.map((g) => {
                const { definition, highestRisk } = g;
                const groupIds = g.items.map((item) => item.id);
                const groupProg = computeProgress(groupIds, reviewedIds);
                const allDone = groupProg.total > 0 && groupProg.reviewed >= groupProg.total;

                return (
                  <button
                    key={definition.id}
                    type="button"
                    onClick={() => onJumpToConcern(definition.id)}
                    aria-label={`Jump to concern ${definition.order}. ${definition.shortLabel} (${groupProg.reviewed} of ${groupProg.total} reviewed)`}
                    className={`pr-pill inline-flex shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 font-mono text-[12.5px] transition ${
                      allDone
                        ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#5bdba2]"
                        : "text-[#dce4f5] hover:text-white"
                    }`}
                  >
                    <span className={`h-1.5 w-1.5 rounded-full ${riskDotColor(highestRisk)}`} />
                    <span className="text-[#98a8c4]">{definition.order}.</span>
                    <span>{definition.shortLabel}</span>
                    <span
                      className={`inline-flex items-center gap-0.5 rounded-full px-1.5 text-[12px] ${
                        allDone ? "bg-[#5bdba2]/20 text-[#5bdba2]" : "bg-white/[0.06] text-[#a6b5cf]"
                      }`}
                    >
                      {allDone && <IconCheck className="h-3 w-3" />}
                      <span>
                        {groupProg.reviewed}/{groupProg.total}
                      </span>
                    </span>
                  </button>
                );
              })}
            </div>
          </>
        )}

        <div className="ml-auto flex shrink-0 items-center gap-2 xl:gap-2.5">
          <div className="flex items-center gap-2 font-mono text-[12.5px] text-[#d2dbee]">
            <span className="whitespace-nowrap" title={`${reviewedCount} of ${totalCount} ${itemUnit}s reviewed`}>
              {reviewedCount}/{totalCount} <span className="text-[#98a8c4]">{itemUnit}s</span>
            </span>
            <div
              role="progressbar"
              aria-label={`Reviewed ${reviewedCount} of ${totalCount} ${itemUnit}s`}
              aria-valuemin={0}
              aria-valuemax={totalCount}
              aria-valuenow={reviewedCount}
              className="hidden h-1.5 w-16 overflow-hidden rounded-full bg-white/[0.08] md:block xl:w-20"
            >
              <div
                className="h-full rounded-full bg-[#5bdba2] transition-all duration-200"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            {reviewedCount > 0 && onResetReviewed && (
              <button
                type="button"
                onClick={onResetReviewed}
                aria-label="Reset reviewed progress"
                title="Reset reviewed progress"
                className="rounded-md px-1.5 py-0.5 font-mono text-[12.5px] text-[#9ec0f5] hover:bg-white/[0.05] hover:underline"
              >
                <span className="2xl:hidden" aria-hidden="true">
                  ↺
                </span>
                <span className="hidden 2xl:inline">Reset</span>
              </button>
            )}
          </div>

          {showKeyboardHints && (
            <div
              className="hidden items-center gap-1 font-mono text-[12.5px] text-[#98a8c4] 2xl:flex"
              aria-label="Keyboard shortcuts"
              title={`j/k navigate · v mark reviewed${mode === "rounds" ? " · c comment" : ""}`}
            >
              <kbd className="pr-kbd">j</kbd>
              <kbd className="pr-kbd">k</kbd>
              <kbd className="pr-kbd">v</kbd>
              {mode === "rounds" && <kbd className="pr-kbd">c</kbd>}
            </div>
          )}

          {trailing}
        </div>
      </div>
    </div>
  );
}
