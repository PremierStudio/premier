/**
 * Geometry-matched, low-glare obsidian skeletons for every top-level Studio view
 * and in-pane cold-load state.
 *
 * Reusing the exact same layout shell in `<Suspense fallback={<ViewSkeleton tab={tab} />}>`
 * and inside each view's cold-load branch eliminates layout jumps and double-flashes
 * when switching tabs or items.
 *
 * Accessibility: the outermost skeleton on screen is the only live region
 * (`role="status" aria-busy`); skeletons nested inside it, and every bar/pill, are `aria-hidden`.
 */

import { createContext, useContext, type ReactNode } from "react";

export type SkeletonTabId =
  | "worktable"
  | "code"
  | "changes"
  | "branches"
  | "agents"
  | "traces"
  | "secrets"
  | "policy"
  | "settings";

const InsideStatus = createContext(false);

/** Live region for the outermost skeleton; a plain hidden wrapper when nested in another one. */
function Region({
  label,
  className = "",
  children,
}: {
  label: string;
  className?: string;
  children: ReactNode;
}) {
  const nested = useContext(InsideStatus);
  if (nested) {
    return (
      <div aria-hidden="true" className={className}>
        {children}
      </div>
    );
  }
  return (
    <div role="status" aria-busy="true" aria-label={label} className={className}>
      <InsideStatus.Provider value={true}>{children}</InsideStatus.Provider>
    </div>
  );
}

export function SkelBar({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`pr-shimmer rounded-md ${className}`} />;
}

export function SkelPill({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`pr-shimmer rounded-full ${className}`} />;
}

/** File explorer tree rows matching ZoneXRayView's left rail (26px rows, 16px chevron slot). */
export function FileTreeSkeleton({ rows = 14 }: { rows?: number }) {
  const specs = [
    { indent: 0, w: "w-24", dir: true },
    { indent: 1, w: "w-28", dir: true },
    { indent: 2, w: "w-32", dir: false },
    { indent: 2, w: "w-24", dir: false },
    { indent: 2, w: "w-36", dir: false },
    { indent: 1, w: "w-20", dir: true },
    { indent: 2, w: "w-28", dir: false },
    { indent: 2, w: "w-32", dir: false },
    { indent: 0, w: "w-20", dir: true },
    { indent: 1, w: "w-32", dir: false },
    { indent: 1, w: "w-24", dir: false },
    { indent: 0, w: "w-28", dir: false },
    { indent: 0, w: "w-24", dir: false },
    { indent: 0, w: "w-32", dir: false },
  ];
  return (
    <Region label="Loading file tree" className="flex flex-col px-1.5 py-1.5">
      {specs.slice(0, rows).map((row, idx) => (
        <div
          key={idx}
          style={{ paddingLeft: `${8 + row.indent * 14}px` }}
          className="flex h-[26px] items-center gap-1.5 pr-2"
        >
          <span className="flex h-4 w-4 shrink-0 items-center justify-center">
            {row.dir && <SkelBar className="h-2.5 w-2.5 rounded-sm" />}
          </span>
          <SkelBar className={`h-3.5 w-3.5 shrink-0 ${row.dir ? "rounded" : "rounded-sm"}`} />
          <SkelBar className={`h-2.5 ${row.w}`} />
        </div>
      ))}
    </Region>
  );
}

// Percent widths so the 30 rows need no per-row Tailwind classes; 0 is a blank line.
const CODE_LINES: { indent: number; pct: number }[] = [
  { indent: 0, pct: 34 },
  { indent: 0, pct: 52 },
  { indent: 0, pct: 28 },
  { indent: 0, pct: 0 },
  { indent: 0, pct: 44 },
  { indent: 1, pct: 56 },
  { indent: 1, pct: 40 },
  { indent: 2, pct: 50 },
  { indent: 2, pct: 38 },
  { indent: 1, pct: 20 },
  { indent: 0, pct: 8 },
  { indent: 0, pct: 0 },
  { indent: 0, pct: 48 },
  { indent: 1, pct: 62 },
  { indent: 1, pct: 36 },
  { indent: 2, pct: 44 },
  { indent: 1, pct: 22 },
  { indent: 0, pct: 10 },
  { indent: 0, pct: 0 },
  { indent: 0, pct: 40 },
  { indent: 1, pct: 54 },
  { indent: 1, pct: 46 },
  { indent: 2, pct: 58 },
  { indent: 2, pct: 32 },
  { indent: 1, pct: 26 },
  { indent: 0, pct: 12 },
  { indent: 0, pct: 0 },
  { indent: 0, pct: 50 },
  { indent: 1, pct: 42 },
  { indent: 0, pct: 14 },
];

/** Code viewer lines: 20px rows, no gap, 48px number gutter, clipped like the real editor. */
export function CodeLinesSkeleton({ className = "" }: { className?: string }) {
  return (
    <Region
      label="Loading file"
      className={`flex min-h-0 flex-1 flex-col overflow-hidden py-2 font-mono ${className}`}
    >
      {CODE_LINES.map((line, i) => (
        <div key={i} className="flex h-5 shrink-0 items-center">
          <div className="flex w-12 shrink-0 justify-end pr-3">
            <SkelBar className="h-2.5 w-5 opacity-45" />
          </div>
          {line.pct > 0 && (
            <div
              aria-hidden="true"
              className="pr-shimmer h-2.5 rounded-md"
              // Percent of the line, indented 20px per level.
              style={{ width: `${line.pct}%`, marginLeft: `${line.indent * 20}px` }}
            />
          )}
        </div>
      ))}
    </Region>
  );
}

/** Code-search hits: path line plus two match lines, as in the Code tab's search results. */
export function SearchResultsSkeleton({ rows = 4 }: { rows?: number }) {
  const paths = ["w-52", "w-40", "w-56", "w-44"];
  return (
    <Region label="Searching files" className="divide-y divide-white/[0.05]">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="space-y-1.5 px-3 py-2">
          <SkelBar className={`h-3 ${paths[i % paths.length]}`} />
          <SkelBar className="h-2.5 w-11/12 opacity-65" />
          <SkelBar className="h-2.5 w-3/4 opacity-50" />
        </div>
      ))}
    </Region>
  );
}

/** Left commit list rows matching ReviewRoundsView (`px-4 py-3`, two-line `line-clamp-2` subject). */
export function CommitListSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <Region label="Loading commits" className="divide-y divide-white/[0.05]">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="px-4 py-3">
          <div className="flex h-[39px] flex-col justify-center gap-2">
            <SkelBar className={`h-3 ${i % 3 === 0 ? "w-11/12" : "w-5/6"}`} />
            <SkelBar className={`h-3 ${i % 2 === 0 ? "w-2/3" : "w-3/4"}`} />
          </div>
          <div className="mt-2 flex items-center justify-between gap-2">
            <SkelBar className="h-2.5 w-14 opacity-80" />
            <SkelBar className="h-2.5 w-24 opacity-60" />
          </div>
        </div>
      ))}
    </Region>
  );
}

function DiffCardsSkeleton({ cards = 3 }: { cards?: number }) {
  return (
    <>
      {Array.from({ length: cards }).map((_, card) => (
        <div
          key={card}
          className="overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.015]"
        >
          <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.02] px-3.5 py-2">
            <div className="flex items-center gap-2">
              <SkelBar className="h-3.5 w-3.5" />
              <SkelBar className={`h-3 ${card === 0 ? "w-56" : card === 1 ? "w-44" : "w-64"}`} />
            </div>
            <div className="flex items-center gap-2">
              <SkelBar className="h-3 w-12" />
              <SkelPill className="h-5 w-16" />
            </div>
          </div>
          <div className="space-y-1.5 px-4 py-3">
            <SkelBar className="h-2.5 w-3/4" />
            <SkelBar className="h-2.5 w-5/6 opacity-80" />
            <SkelBar className="h-2.5 w-2/3 opacity-70" />
            {card === 0 && <SkelBar className="h-2.5 w-4/5 opacity-60" />}
          </div>
        </div>
      ))}
    </>
  );
}

/** Single-row ConcernWalkthroughBar. */
function WalkthroughBarSkeleton() {
  return (
    <div className="flex shrink-0 items-center gap-2.5 border-b border-white/[0.06] bg-[#0a0e1c] px-4 py-1.5 sm:px-5">
      <SkelPill className="h-6 w-40" />
      <SkelPill className="h-6 w-32" />
      <div className="hidden h-4 w-px bg-white/[0.07] sm:block" />
      <div className="hidden flex-1 items-center gap-1.5 sm:flex">
        <SkelPill className="h-5 w-28" />
        <SkelPill className="h-5 w-32" />
        <SkelPill className="h-5 w-24" />
      </div>
      <div className="ml-auto flex items-center gap-2">
        <SkelBar className="h-3 w-16" />
        <SkelPill className="h-1.5 w-20" />
      </div>
    </div>
  );
}

/** Right commit diff pane: CommitTrustHeader + walkthrough bar + concern card header + diff cards. */
export function CommitDiffSkeleton() {
  return (
    <Region label="Loading commit diff" className="flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* CommitTrustHeader (2 compact rows) */}
      <div className="shrink-0 space-y-2 border-b border-white/[0.06] bg-[#0a0f1f]/80 px-4 py-2.5 sm:px-5">
        <div className="flex items-center justify-between gap-3">
          <SkelBar className="h-4 w-72 max-w-[60%]" />
          <div className="flex items-center gap-2">
            <SkelPill className="h-5 w-20" />
            <SkelBar className="h-3.5 w-16" />
            <SkelPill className="h-6 w-20" />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <SkelPill className="h-5 w-16" />
          <SkelBar className="h-3 w-44 opacity-70" />
          <SkelPill className="h-5 w-24" />
        </div>
      </div>

      <WalkthroughBarSkeleton />

      <div className="min-h-0 flex-1 space-y-3 overflow-hidden p-3.5">
        {/* Concern card header */}
        <div className="pr-concern-card flex items-center justify-between gap-3 rounded-xl px-3.5 py-2.5">
          <div className="flex items-center gap-2">
            <SkelPill className="h-5 w-5" />
            <SkelBar className="h-3.5 w-44" />
          </div>
          <SkelPill className="h-5 w-20" />
        </div>
        <DiffCardsSkeleton cards={3} />
      </div>
    </Region>
  );
}

/** Rounds (change review): intent receipt + toolbar + hunk cards beside the SessionReplayAside. */
export function RoundsSkeleton() {
  return (
    <Region label="Loading review rounds" className="flex min-h-0 flex-1 overflow-hidden">
      <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        {/* IntentTrustReceipt (3 rows) */}
        <div className="shrink-0 space-y-2 border-b border-white/[0.06] bg-[#0a0f1f]/80 px-4 py-3 sm:px-5">
          <div className="flex items-center justify-between gap-3">
            <SkelBar className="h-4 w-64 max-w-[60%]" />
            <SkelPill className="h-5 w-24" />
          </div>
          <SkelBar className="h-3 w-5/6 opacity-75" />
          <div className="flex items-center gap-2">
            <SkelPill className="h-5 w-20" />
            <SkelPill className="h-5 w-28" />
            <SkelPill className="h-5 w-24" />
          </div>
        </div>
        {/* Single-row toolbar */}
        <div className="flex shrink-0 items-center gap-2 border-b border-white/[0.06] px-4 py-1.5 sm:px-5">
          <SkelPill className="h-7 w-36" />
          <SkelPill className="h-7 w-24" />
          <div className="ml-auto flex items-center gap-2">
            <SkelBar className="h-3 w-20" />
            <SkelPill className="h-7 w-20" />
          </div>
        </div>
        <div className="min-h-0 flex-1 space-y-3 overflow-hidden p-3.5">
          <DiffCardsSkeleton cards={3} />
        </div>
      </div>
      {/* SessionReplayAside */}
      <aside className="hidden w-full shrink-0 flex-col overflow-hidden border-l border-white/[0.06] lg:flex lg:w-[300px] xl:w-[320px] 2xl:w-[400px]">
        <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2.5">
          <SkelBar className="h-3.5 w-28" />
          <SkelPill className="h-5 w-14" />
        </div>
        <div className="space-y-2.5 p-3.5">
          <SkelPill className="h-2 w-full" />
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="flex items-start gap-2.5">
              <SkelPill className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              <div className="min-w-0 flex-1 space-y-1.5">
                <SkelBar className="h-3 w-3/4" />
                <SkelBar className="h-2.5 w-1/2 opacity-60" />
              </div>
            </div>
          ))}
        </div>
      </aside>
    </Region>
  );
}

/** Interdiff body: a few compact diff cards. */
export function InterdiffSkeleton() {
  return (
    <Region label="Loading interdiff" className="min-h-0 flex-1 space-y-2.5 overflow-hidden p-3.5">
      {[0, 1, 2].map((card) => (
        <div
          key={card}
          className="overflow-hidden rounded-xl border border-white/[0.07] bg-white/[0.015]"
        >
          <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.02] px-3 py-1.5">
            <SkelBar className={`h-3 ${card === 1 ? "w-40" : "w-52"}`} />
            <SkelPill className="h-4 w-14" />
          </div>
          <div className="space-y-1.5 px-3.5 py-2.5">
            <SkelBar className="h-2.5 w-4/5" />
            <SkelBar className="h-2.5 w-2/3 opacity-75" />
          </div>
        </div>
      ))}
    </Region>
  );
}

/** Left branches list rows matching BranchesView (three-line rows, ~76px pitch). */
export function BranchListSkeleton({ rows = 7 }: { rows?: number }) {
  const widths = ["w-36", "w-44", "w-32", "w-48", "w-40", "w-36", "w-44"];
  return (
    <Region label="Loading branches" className="divide-y divide-white/[0.05]">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="space-y-2 px-3 py-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <SkelBar className="h-4 w-4 rounded" />
              <SkelBar className={`h-4 ${widths[i % widths.length]}`} />
            </div>
            <SkelPill className="h-4 w-14" />
          </div>
          <SkelBar className="h-2.5 w-3/4 opacity-70" />
          <div className="flex items-center gap-2">
            <SkelBar className="h-2.5 w-12 opacity-70" />
            <SkelBar className="h-2.5 w-24 opacity-55" />
          </div>
        </div>
      ))}
    </Region>
  );
}

/** Airlock 3-stage pipeline + sticky action footer for BranchesView cold load. */
export function AirlockSkeleton() {
  return (
    <Region label="Loading declassification airlock" className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="flex shrink-0 items-center justify-between gap-3 border-b border-white/[0.06] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <SkelBar className="h-4 w-36" />
          <SkelPill className="h-5 w-20" />
        </div>
        <div className="flex items-center gap-2">
          <SkelPill className="h-7 w-28" />
          <SkelPill className="h-7 w-7" />
        </div>
      </div>
      <AirlockBodySkeleton />
    </Region>
  );
}

/** Airlock body only (3-stage pipeline, 6 gates, diff preview, footer) — shared by the page fallback and in-view branch switches. */
export function AirlockBodySkeleton() {
  return (
    <div className="@container flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="min-h-0 flex-1 overflow-hidden p-4">
        <div className="grid grid-cols-1 gap-3 @2xl:grid-cols-2 @5xl:grid-cols-3">
          {[0, 1, 2].map((stage) => (
            <div
              key={stage}
              className="rounded-2xl border border-white/[0.07] bg-white/[0.02] p-3.5"
            >
              <div className="flex items-center gap-2 border-b border-white/[0.06] pb-2.5">
                <SkelBar className="h-6 w-6 rounded-lg" />
                <div className="space-y-1">
                  <SkelBar className="h-3 w-32" />
                  <SkelBar className="h-2.5 w-24 opacity-60" />
                </div>
              </div>
              <div className="mt-3 space-y-2">
                {stage === 1 ? (
                  // Stage 2: the six gates (incl. Declassification Firewall)
                  Array.from({ length: 6 }).map((_, g) => (
                    <div key={g} className="flex items-center gap-2.5">
                      <SkelPill className="h-4 w-4 shrink-0" />
                      <SkelBar className={`h-3 ${g % 2 === 0 ? "w-3/4" : "w-2/3"}`} />
                    </div>
                  ))
                ) : (
                  <>
                    <SkelBar className="h-10 w-full rounded-xl" />
                    <SkelBar className="h-3 w-3/4 opacity-75" />
                    <SkelBar className="h-3 w-1/2 opacity-60" />
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
        {/* Diff preview card */}
        <div className="mt-3 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-3.5">
          <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] pb-2.5">
            <SkelBar className="h-3 w-40" />
            <SkelPill className="h-5 w-16" />
          </div>
          <div className="mt-3 space-y-1.5">
            <SkelBar className="h-2.5 w-full opacity-70" />
            <SkelBar className="h-2.5 w-5/6 opacity-60" />
            <SkelBar className="h-2.5 w-2/3 opacity-50" />
          </div>
        </div>
      </div>
      {/* Sticky footer */}
      <div className="flex h-[84px] shrink-0 items-center justify-between gap-3 border-t border-white/[0.06] bg-[#0a0e1c]/80 px-4">
        <div className="space-y-1.5">
          <SkelBar className="h-3 w-48" />
          <SkelBar className="h-2.5 w-64 max-w-full opacity-60" />
        </div>
        <SkelPill className="h-9 w-32" />
      </div>
    </div>
  );
}

/** Worktable presence cards (~185px: status row, command line, chip row, footer). */
export function PresenceCardSkeleton({ count = 4 }: { count?: number }) {
  return (
    <Region
      label="Loading workstreams"
      className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-2 min-[1800px]:grid-cols-3"
    >
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="flex min-h-[185px] flex-col gap-2.5 rounded-2xl border border-white/[0.07] bg-white/[0.02] p-3.5"
        >
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <SkelPill className="h-2.5 w-2.5" />
              <SkelBar className="h-3.5 w-32" />
            </div>
            <SkelPill className="h-4 w-16" />
          </div>
          <SkelBar className="h-8 w-full rounded-lg opacity-80" />
          <div className="flex flex-wrap items-center gap-1.5">
            <SkelPill className="h-5 w-16" />
            <SkelPill className="h-5 w-20" />
            <SkelPill className="h-5 w-14" />
          </div>
          <div className="mt-auto flex items-center justify-between gap-2 pt-1">
            <SkelBar className="h-2.5 w-28 opacity-65" />
            <SkelPill className="h-6 w-20" />
          </div>
        </div>
      ))}
    </Region>
  );
}

/** Judgment rail rows matching JudgmentRail's `ROW` (`pr-well space-y-2 rounded-xl px-3 py-2.5`). */
export function JudgmentRowSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <Region label="Loading judgments" className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="pr-well space-y-2 rounded-xl px-3 py-2.5">
          <div className="flex items-center justify-between gap-2">
            <SkelBar className={`h-3.5 ${i % 2 === 0 ? "w-40" : "w-32"}`} />
            <SkelPill className="h-4 w-14" />
          </div>
          <SkelBar className="h-2.5 w-4/5 opacity-70" />
          <div className="flex items-center gap-2">
            <SkelPill className="h-7 w-20" />
            <SkelPill className="h-7 w-16" />
          </div>
        </div>
      ))}
    </Region>
  );
}

/** MCP Gateway panel: status strip, filter bar, two server cards (3 tool rows each) and the aside. */
export function McpGatewaySkeleton() {
  return (
    <Region label="Loading MCP gateway" className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden lg:flex-row">
      <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-3 overflow-hidden">
        <div className="pr-surface flex h-9 shrink-0 items-center justify-between gap-3 rounded-xl px-3">
          <div className="flex items-center gap-2">
            <SkelPill className="h-2.5 w-2.5" />
            <SkelBar className="h-3 w-40" />
          </div>
          <SkelPill className="h-5 w-16" />
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <SkelPill className="h-8 min-w-0 flex-1 opacity-70" />
          <SkelPill className="h-8 w-20" />
          <SkelPill className="h-8 w-20" />
        </div>
        <div className="min-h-0 flex-1 space-y-3 overflow-hidden">
          {[0, 1].map((server) => (
            <div key={server} className="pr-surface overflow-hidden rounded-2xl">
              <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-3.5 py-2.5">
                <div className="flex items-center gap-2.5">
                  <SkelBar className="h-6 w-6 rounded-lg" />
                  <div className="space-y-1">
                    <SkelBar className="h-3.5 w-36" />
                    <SkelBar className="h-2.5 w-24 opacity-60" />
                  </div>
                </div>
                <SkelPill className="h-5 w-16" />
              </div>
              <div className="divide-y divide-white/[0.05]">
                {[0, 1, 2].map((tool) => (
                  <div key={tool} className="flex items-center justify-between gap-3 px-3.5 py-2">
                    <div className="min-w-0 flex-1 space-y-1">
                      <SkelBar className={`h-3 ${tool % 2 === 0 ? "w-44" : "w-36"}`} />
                      <SkelBar className="h-2.5 w-2/3 opacity-55" />
                    </div>
                    <SkelPill className="h-5 w-14" />
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
      <aside className="pr-surface flex max-h-[260px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:w-[376px] xl:w-[424px] 2xl:w-[480px]">
        <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2.5">
          <SkelBar className="h-3.5 w-32" />
          <SkelPill className="h-5 w-14" />
        </div>
        <div className="space-y-2 p-3.5">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="pr-well space-y-1.5 rounded-xl px-3 py-2.5">
              <SkelBar className="h-3 w-3/4" />
              <SkelBar className="h-2.5 w-1/2 opacity-60" />
            </div>
          ))}
        </div>
      </aside>
    </Region>
  );
}

/** Session step-in editor: header bar, 224px file tree beside code lines, footer bar. */
export function StepInSkeleton() {
  return (
    <Region label="Loading step-in editor" className="flex min-h-[300px] flex-1 flex-col overflow-hidden">
      <div className="flex h-10 shrink-0 items-center justify-between gap-3 border-b border-white/[0.06] px-3">
        <SkelBar className="h-3.5 w-48" />
        <div className="flex items-center gap-1.5">
          <SkelPill className="h-6 w-16" />
          <SkelPill className="h-6 w-20" />
        </div>
      </div>
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <div className="hidden w-56 shrink-0 overflow-hidden border-r border-white/[0.06] sm:block">
          <FileTreeSkeleton rows={10} />
        </div>
        <CodeLinesSkeleton />
      </div>
      <div className="flex h-10 shrink-0 items-center justify-between gap-3 border-t border-white/[0.06] px-3">
        <SkelBar className="h-3 w-40 opacity-70" />
        <SkelPill className="h-6 w-24" />
      </div>
    </Region>
  );
}

/** Compact list skeleton for Settings sections, Secrets list, and Agent sub-panels. */
export function SettingsRowsSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <Region label="Loading items" className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3.5 py-2.5"
        >
          <div className="min-w-0 flex-1 space-y-1.5">
            <SkelBar className={`h-3.5 ${i % 2 === 0 ? "w-44" : "w-56"}`} />
            <SkelBar className="h-2.5 w-64 max-w-[85%] opacity-65" />
          </div>
          <SkelPill className="h-6 w-16 shrink-0" />
        </div>
      ))}
    </Region>
  );
}

/** Secrets list rows matching SecretsOverlaysView's `.env.schema` table. */
export function SecretsListSkeleton({ rows = 8 }: { rows?: number }) {
  const widths = ["w-44", "w-52", "w-36", "w-48", "w-40", "w-56", "w-44", "w-36"];
  return (
    <Region label="Loading secrets schema" className="divide-y divide-white/[0.05]">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center justify-between gap-3 px-3 py-2.5">
          <div className="min-w-0 flex-1 space-y-1.5">
            <div className="flex items-center gap-2">
              <SkelBar className={`h-3.5 ${widths[i % widths.length]}`} />
              <SkelPill className="h-4 w-16" />
            </div>
            <SkelBar className="h-2.5 w-60 max-w-[75%] opacity-60" />
          </div>
          <div className="flex items-center gap-1.5">
            <SkelPill className="h-5 w-14" />
            <SkelPill className="h-5 w-16" />
          </div>
        </div>
      ))}
    </Region>
  );
}

/** Generic structured card/row skeleton for lazy sub-panels (diffs, composers, etc.). */
export function PanelRowsSkeleton({
  rows = 4,
  className = "",
}: {
  rows?: number;
  className?: string;
}) {
  return (
    <Region label="Loading panel" className={`flex min-h-0 flex-col gap-2.5 p-3.5 ${className}`}>
      <div className="flex items-center justify-between gap-2">
        <SkelBar className="h-3.5 w-36" />
        <SkelPill className="h-5 w-20" />
      </div>
      <div className="space-y-2">
        {Array.from({ length: rows }).map((_, i) => (
          <div
            key={i}
            className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2"
          >
            <SkelBar className={`h-3 ${i % 2 === 0 ? "w-2/3" : "w-1/2"}`} />
            <SkelPill className="h-4 w-14" />
          </div>
        ))}
      </div>
    </Region>
  );
}

/** Single slim row matching PresenceCanvas's idle status strip (`min-h-[28px]`, `px-1 py-1`). */
export function WorktableCleanCanvasSkeleton() {
  return (
    <Region
      label="Loading worktable presence"
      className="flex min-h-[28px] flex-wrap items-center justify-between gap-2 px-1 py-1"
    >
      <div className="flex items-center gap-2">
        <SkelPill className="h-4 w-4" />
        <SkelBar className="h-3.5 w-64 max-w-[70vw]" />
      </div>
      <SkelPill className="h-6 w-36 opacity-70" />
    </Region>
  );
}

/** Calm centered Judgment Rail skeleton matching the default "All clear" empty state pixel-for-pixel. */
export function JudgmentEmptySkeleton() {
  return (
    <Region
      label="Loading judgment items"
      className="flex flex-1 flex-col items-center justify-center gap-2 py-6 text-center"
    >
      <SkelPill className="h-8 w-8" />
      <SkelBar className="h-3.5 w-20" />
      <SkelBar className="h-3 w-52 opacity-70" />
      <SkelBar className="h-3 w-40 opacity-55" />
    </Region>
  );
}

/* ============================================================================
 * Full-page view skeletons (used as `<Suspense fallback>` in App.tsx)
 * Each one matches the exact outer spacing, rail widths, and surface borders
 * of its corresponding real view.
 * ========================================================================== */

function WorktablePageSkeleton() {
  return (
    <Region
      label="Loading overview"
      className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-hidden p-3 sm:p-3.5 xl:gap-3 xl:p-4 2xl:p-5"
    >
      {/* Hero: 3 live-proof cards (exact min-h-[132px]) + Quick-Start & Refresh row (exact min-h-[42px]) */}
      <div className="shrink-0 space-y-2">
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
          {Array.from({ length: 3 }, (_, i) => (
            <div key={i} className="pr-surface flex min-h-[132px] flex-col justify-between gap-2 rounded-xl p-3">
              <div className="space-y-1">
                <div className="flex items-center gap-1.5">
                  <SkelBar className="h-3.5 w-3.5 shrink-0" />
                  <SkelBar className="h-2.5 w-36 opacity-75" />
                </div>
                <div className="flex min-h-5 items-center">
                  <SkelBar className="h-4 w-32" />
                </div>
                <div className="flex min-h-[22px] items-center gap-1">
                  <SkelPill className="h-5 w-24 opacity-70" />
                  <SkelPill className="h-5 w-20 opacity-55" />
                </div>
                <SkelBar className="h-3 w-full opacity-70" />
                <SkelBar className="h-3 w-4/5 opacity-55" />
              </div>
              <div className="flex items-center gap-1.5">
                <SkelPill className="h-6 w-32" />
                <SkelPill className="h-6 w-20" />
              </div>
            </div>
          ))}
        </div>

        <div className="flex min-h-[42px] items-center gap-2">
          <div className="pr-well flex min-h-[40px] min-w-0 flex-1 items-center gap-2 rounded-xl px-3 py-2">
            <SkelBar className="h-3 w-36 shrink-0" />
            <SkelPill className="hidden h-5 w-28 sm:block" />
            <SkelPill className="hidden h-5 w-32 md:block" />
            <SkelPill className="hidden h-5 w-32 lg:block" />
            <SkelPill className="hidden h-5 w-32 xl:block" />
          </div>
          <SkelPill className="h-7 w-20 shrink-0" />
        </div>
      </div>

      {/* Active Work canvas only: the Action Required rail is hidden by default (nothing pending), and the
          idle canvas is header + one status row, so skeleton → loaded Overview has zero layout shift. */}
      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden lg:flex-row xl:gap-4">
        <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
        <section className="pr-surface flex min-w-0 flex-none flex-col overflow-hidden rounded-2xl">
          {/* Exact PresenceCanvas header */}
          <div className="flex shrink-0 items-center justify-between gap-2.5 border-b border-white/[0.06] px-3.5 py-2.5">
            <div className="flex items-center gap-2">
              <SkelBar className="h-3.5 w-28" />
              <SkelPill className="h-6 w-12" />
              <SkelPill className="hidden h-6 w-16 sm:block" />
              <SkelPill className="hidden h-6 w-20 sm:block" />
              <SkelPill className="hidden h-6 w-16 md:block" />
            </div>
            <div className="flex items-center gap-2">
              <SkelPill className="hidden h-7 w-44 lg:block opacity-65" />
              <SkelPill className="h-5 w-14" />
              <SkelPill className="hidden h-5 w-20 sm:block" />
            </div>
          </div>
          <div className="p-3">
            <WorktableCleanCanvasSkeleton />
          </div>
        </section>
        </div>
      </div>
    </Region>
  );
}

function CodePageSkeleton() {
  return (
    <Region label="Loading code" className="relative flex min-h-0 flex-1 gap-2.5 p-2 sm:p-2.5">
      <aside className="pr-surface hidden w-[248px] shrink-0 flex-col overflow-hidden rounded-2xl lg:flex xl:w-[268px]">
        <div className="flex h-10 shrink-0 items-center justify-between border-b border-white/[0.06] px-2.5">
          <SkelPill className="h-6 w-28" />
          <SkelPill className="h-6 w-14" />
        </div>
        <div className="border-b border-white/[0.06] px-2.5 py-2">
          <SkelBar className="h-5 w-full opacity-60" />
        </div>
        <div className="min-h-0 flex-1 overflow-hidden">
          <FileTreeSkeleton />
        </div>
        {/* Tree footer stats strip */}
        <div className="flex shrink-0 items-center justify-between gap-2 border-t border-white/[0.06] px-3 py-2">
          <SkelBar className="h-2.5 w-20 opacity-65" />
          <SkelBar className="h-2.5 w-14 opacity-50" />
        </div>
      </aside>
      <section className="pr-surface flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
        <div className="flex h-10 shrink-0 items-center justify-between gap-3 border-b border-white/[0.06] px-3">
          <SkelBar className="h-3.5 w-48" />
          <div className="flex items-center gap-1.5">
            <SkelPill className="h-6 w-16" />
            <SkelPill className="h-6 w-20" />
          </div>
        </div>
        <CodeLinesSkeleton />
      </section>
    </Region>
  );
}

function ChangesPageSkeleton() {
  return (
    <Region
      label="Loading changes"
      className="flex min-h-0 flex-1 flex-col gap-3 p-3 sm:gap-4 sm:p-4 xl:p-5"
    >
      <div className="flex shrink-0 items-center justify-between">
        {/* Mode toggle pill */}
        <SkelPill className="h-[42px] w-44" />
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-4 lg:flex-row">
        <aside className="pr-surface flex max-h-[220px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:w-[304px] xl:w-[336px]">
          <div className="border-b border-white/[0.06] px-3 py-2.5">
            <SkelBar className="h-5 w-full opacity-60" />
          </div>
          <CommitListSkeleton />
        </aside>
        <section className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
          <CommitDiffSkeleton />
        </section>
      </div>
    </Region>
  );
}

function BranchesPageSkeleton() {
  return (
    <Region
      label="Loading branches"
      className="flex min-h-0 flex-1 flex-col gap-3 p-3 sm:p-4 xl:p-4"
    >
      {/* Framed top bar */}
      <div className="pr-surface flex h-[44px] shrink-0 items-center justify-between gap-2 rounded-2xl px-3">
        <div className="flex items-center gap-2">
          <SkelBar className="h-4 w-28" />
          <SkelPill className="h-6 w-24" />
        </div>
        <SkelPill className="h-8 w-28" />
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
        <aside className="pr-surface flex max-h-[300px] min-h-[220px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:min-h-0 lg:w-[280px] xl:w-[320px]">
          <div className="space-y-2 border-b border-white/[0.06] px-3 py-2.5">
            <SkelBar className="h-5 w-full opacity-60" />
            <div className="flex gap-1">
              {["w-10", "w-14", "w-12", "w-14", "w-12"].map((w, i) => (
                <SkelPill key={i} className={`h-5 ${w}`} />
              ))}
            </div>
          </div>
          <div className="min-h-0 flex-1 overflow-hidden">
            <BranchListSkeleton />
          </div>
        </aside>
        <section className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
          <AirlockSkeleton />
        </section>
      </div>
    </Region>
  );
}

function AgentsPageSkeleton() {
  return (
    <Region
      label="Loading agents"
      className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-hidden p-3 xl:p-4"
    >
      <div className="pr-surface flex min-h-[46px] shrink-0 items-center justify-between gap-3 rounded-2xl px-3 py-2">
        <div className="flex items-center gap-2">
          <SkelPill className="h-7 w-72 max-w-full" />
          <SkelPill className="h-7 w-28" />
        </div>
        <div className="hidden items-center gap-2 md:flex">
          <SkelPill className="h-6 w-20" />
          <SkelPill className="h-6 w-20" />
          <SkelPill className="h-6 w-24" />
        </div>
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-hidden lg:flex-row">
        <section className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
          <div className="divide-y divide-white/[0.05]">
            {[0, 1, 2, 3, 4, 5, 6].map((i) => (
              <div key={i} className="flex items-center justify-between gap-3 px-3.5 py-3">
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <SkelPill className="h-2.5 w-2.5" />
                    <SkelBar className={`h-3.5 ${i % 2 === 0 ? "w-56" : "w-44"}`} />
                  </div>
                  <SkelBar className="h-2.5 w-2/3 opacity-60" />
                </div>
                <SkelPill className="h-5 w-16" />
              </div>
            ))}
          </div>
        </section>
        <aside className="pr-surface flex max-h-[240px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:w-[368px] xl:w-[420px] 2xl:w-[470px]">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2.5">
            <SkelBar className="h-3.5 w-32" />
            <SkelPill className="h-5 w-14" />
          </div>
          <div className="p-3.5">
            <SettingsRowsSkeleton rows={4} />
          </div>
        </aside>
      </div>
    </Region>
  );
}

function SecretsPageSkeleton() {
  return (
    <Region
      label="Loading secrets"
      className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden p-2.5 sm:p-3 lg:flex-row xl:p-4"
    >
      <section className="pr-surface flex min-h-[280px] min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:min-h-0">
        <div className="flex items-center gap-2.5 border-b border-white/[0.06] px-3 py-2">
          <SkelBar className="h-4 w-24" />
          {/* Sensitivity pills */}
          {["w-12", "w-14", "w-16", "w-14", "w-12"].map((w, i) => (
            <SkelPill key={i} className={`h-5 ${w}`} />
          ))}
          <SkelPill className="ml-auto h-6 w-32 opacity-60" />
        </div>
        <SecretsListSkeleton />
      </section>
      <aside className="pr-surface flex max-h-[280px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:w-[376px] xl:w-[424px] 2xl:w-[480px]">
        <div className="flex items-center gap-1.5 border-b border-white/[0.06] px-3 py-1.5">
          <SkelPill className="h-6 w-20" />
          <SkelPill className="h-6 w-20" />
          <SkelPill className="h-6 w-20" />
        </div>
        <div className="p-3.5">
          <SettingsRowsSkeleton rows={4} />
        </div>
      </aside>
    </Region>
  );
}

function PolicyPageSkeleton() {
  return (
    <Region
      label="Loading policy"
      className="flex min-h-0 flex-1 flex-col gap-2 overflow-hidden p-2.5 sm:p-3 xl:p-4"
    >
      <div className="pr-surface flex shrink-0 items-center justify-between gap-3 rounded-xl px-2.5 py-1.5">
        <div className="flex items-center gap-2">
          <SkelPill className="h-[26px] w-64 max-w-full" />
          <SkelPill className="h-[26px] w-16" />
        </div>
        <div className="flex items-center gap-1.5">
          <SkelPill className="h-[26px] w-20" />
          <SkelPill className="h-[26px] w-24" />
        </div>
      </div>
      <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
        <section className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
          <CodeLinesSkeleton />
        </section>
        <aside className="pr-surface flex max-h-[240px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:w-[404px] xl:w-[452px] 2xl:w-[504px]">
          <div className="flex items-center gap-2 border-b border-white/[0.06] px-3.5 py-1.5">
            <SkelPill className="h-6 w-24" />
            <SkelPill className="h-6 w-24" />
          </div>
          <div className="p-3.5">
            <SettingsRowsSkeleton rows={5} />
          </div>
        </aside>
      </div>
    </Region>
  );
}

const SETTINGS_NAV_GROUPS = [3, 2, 5, 2, 2];

function SettingsPageSkeleton() {
  return (
    <Region
      label="Loading settings"
      className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-hidden p-3 sm:p-4 lg:flex-row lg:gap-4"
    >
      {/* Mobile horizontal nav strip */}
      <div className="pr-surface flex shrink-0 items-center gap-1.5 overflow-hidden rounded-2xl px-2.5 py-2 lg:hidden">
        {["w-20", "w-24", "w-16", "w-24", "w-20"].map((w, i) => (
          <SkelPill key={i} className={`h-7 shrink-0 ${w}`} />
        ))}
      </div>
      <aside className="pr-surface hidden w-[248px] shrink-0 flex-col overflow-hidden rounded-2xl lg:flex xl:w-[272px]">
        <div className="space-y-1.5 border-b border-white/[0.06] px-4 py-2.5">
          <SkelBar className="h-3.5 w-32" />
          <SkelBar className="h-2.5 w-24 opacity-65" />
        </div>
        <div className="space-y-3 p-3">
          {SETTINGS_NAV_GROUPS.map((count, g) => (
            <div key={g} className="space-y-1.5">
              <SkelBar className="h-2.5 w-20 opacity-50" />
              {Array.from({ length: count }).map((_, i) => (
                <div key={i} className="flex items-center gap-2.5 px-2 py-1.5">
                  <SkelBar className="h-4 w-4 rounded" />
                  <SkelBar className="h-3 w-28" />
                </div>
              ))}
            </div>
          ))}
        </div>
      </aside>
      <div className="min-h-0 min-w-0 flex-1 overflow-hidden">
        <div className="mx-auto max-w-3xl space-y-3">
          <div className="flex items-baseline gap-3 px-1">
            <SkelBar className="h-5 w-32" />
            <SkelBar className="h-3 w-64 max-w-full opacity-65" />
          </div>
          {[4, 3].map((rows, c) => (
            <div key={c} className="pr-surface space-y-3 rounded-2xl p-4">
              <SkelBar className="h-4 w-40" />
              <SettingsRowsSkeleton rows={rows} />
            </div>
          ))}
        </div>
      </div>
    </Region>
  );
}

/** Traces (agent-trace flight recorder): top command strip + runs rail + waterfall + inspector. */
export function TracesPageSkeleton() {
  return (
    <Region label="Loading traces" className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="flex shrink-0 items-center gap-3 border-b border-white/[0.07] bg-[#0a0f1f]/75 px-4 py-2.5">
        <SkelPill className="h-8 w-8 rounded-xl" />
        <SkelBar className="h-4 w-20" />
        <SkelPill className="h-9 w-64 rounded-xl" />
        <div className="ml-auto flex items-center gap-2">
          <SkelPill className="h-9 w-28 rounded-xl" />
          <SkelPill className="h-9 w-9 rounded-xl" />
        </div>
      </div>
      <div className="flex min-h-0 flex-1 gap-3 overflow-hidden p-3">
        <aside className="pr-surface hidden w-[300px] shrink-0 flex-col overflow-hidden rounded-2xl lg:flex xl:w-[330px]">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
            <SkelBar className="h-3.5 w-28" />
            <SkelBar className="h-3.5 w-6" />
          </div>
          <div className="space-y-2 p-2.5">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="space-y-2 rounded-xl border border-white/[0.05] p-3">
                <div className="flex items-center justify-between">
                  <SkelBar className="h-3.5 w-28" />
                  <SkelPill className="h-5 w-16" />
                </div>
                <SkelBar className="h-3 w-5/6 opacity-75" />
                <SkelBar className="h-2.5 w-2/3 opacity-55" />
              </div>
            ))}
          </div>
        </aside>
        <div className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
          <div className="space-y-3 border-b border-white/[0.06] px-5 py-4">
            <SkelBar className="h-5 w-52" />
            <div className="grid grid-cols-5 gap-2">
              {[0, 1, 2, 3, 4].map((i) => (
                <div key={i} className="pr-well space-y-1.5 rounded-xl px-3 py-2">
                  <SkelBar className="h-2.5 w-12 opacity-60" />
                  <SkelBar className="h-4 w-10" />
                </div>
              ))}
            </div>
          </div>
          <div className="space-y-2 p-3">
            {[0, 1, 2, 3, 4].map((i) => (
              <div key={i} className="flex items-center gap-3 rounded-xl border border-white/[0.05] p-3">
                <SkelPill className="h-5 w-16 shrink-0" />
                <div className="min-w-0 flex-1 space-y-1.5">
                  <SkelBar className="h-3.5 w-3/4" />
                  <SkelBar className="h-2.5 w-1/2 opacity-65" />
                </div>
                <SkelBar className="h-2 w-24 shrink-0" />
              </div>
            ))}
          </div>
        </div>
        <aside className="pr-surface hidden w-[370px] shrink-0 flex-col overflow-hidden rounded-2xl xl:flex">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
            <SkelBar className="h-3.5 w-28" />
            <SkelPill className="h-6 w-20" />
          </div>
          <div className="space-y-3 p-4">
            <div className="pr-well space-y-2 rounded-xl p-3.5">
              <SkelBar className="h-3 w-20 opacity-60" />
              <SkelBar className="h-3.5 w-full" />
              <SkelBar className="h-3.5 w-4/5" />
            </div>
            <div className="grid grid-cols-2 gap-2.5">
              {[0, 1, 2, 3].map((i) => (
                <div key={i} className="pr-well space-y-1.5 rounded-xl p-3">
                  <SkelBar className="h-2.5 w-14 opacity-60" />
                  <SkelBar className="h-3.5 w-20" />
                </div>
              ))}
            </div>
          </div>
        </aside>
      </div>
    </Region>
  );
}

export function ViewSkeleton({ tab }: { tab: SkeletonTabId }) {
  switch (tab) {
    case "worktable":
      return <WorktablePageSkeleton />;
    case "code":
      return <CodePageSkeleton />;
    case "changes":
      return <ChangesPageSkeleton />;
    case "branches":
      return <BranchesPageSkeleton />;
    case "agents":
      return <AgentsPageSkeleton />;
    case "traces":
      return <TracesPageSkeleton />;
    case "secrets":
      return <SecretsPageSkeleton />;
    case "policy":
      return <PolicyPageSkeleton />;
    case "settings":
      return <SettingsPageSkeleton />;
  }
}
