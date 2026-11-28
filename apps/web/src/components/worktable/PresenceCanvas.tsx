import { useState } from "react";
import {
  api,
  errorText,
  type AgentSessionRecord,
  type IdentityPreset,
  type PendingApproval,
  type WorktableAgentProfile,
  type WorktableBranch,
  type WorktableReviewSummary,
} from "../../api";
import { plural } from "../../lib/format";
import { ConfirmButton, ErrorNote } from "../forms";
import { WorktableCleanCanvasSkeleton } from "../ViewSkeletons";
import {
  IconBranches,
  IconBranchRef,
  IconChanges,
  IconChevron,
  IconIntersection,
  IconLens,
  IconLock,
  IconQuarantine,
  IconSearch,
  IconShieldCheck,
  IconVault,
} from "../Icons";
import {
  findWaitingApprovalForSession,
  formatByteCount,
  formatElapsedSeconds,
  isPrivateVisibility,
  sessionHasUncommittedChanges,
  summarizeZones,
  visibilitySummary,
  type FocusTarget,
  type PresenceFilter,
} from "./types";

export type PresenceCardItem =
  | {
      cardKey: string;
      category: "agent";
      focus: FocusTarget;
      session: AgentSessionRecord;
      waitingApproval?: PendingApproval;
      isRunning: boolean;
      hasUncommitted: boolean;
      settled: boolean;
    }
  | {
      cardKey: string;
      category: "branch";
      focus: FocusTarget;
      branch: WorktableBranch;
      isDefault: boolean;
      reviews: WorktableReviewSummary[];
      runningSessions: AgentSessionRecord[];
    }
  | {
      cardKey: string;
      category: "review";
      focus: FocusTarget;
      review: WorktableReviewSummary;
    };

export interface BuildPresenceCardsInput {
  sessions: AgentSessionRecord[];
  branches: WorktableBranch[];
  reviews: WorktableReviewSummary[];
  pendingApprovals: PendingApproval[];
  defaultBranch: string;
  filter: PresenceFilter;
  query: string;
  showSettled?: boolean | null;
}

export interface BuildPresenceCardsResult {
  activeCards: PresenceCardItem[];
  settledSessionCards: PresenceCardItem[];
  /** Already-merged / in-sync branches (and the default branch): hidden until expanded or searched. */
  syncedBranchCards: PresenceCardItem[];
  visibleCards: PresenceCardItem[];
  counts: {
    all: number;
    agents: number;
    activeAgents: number;
    branches: number;
    reviews: number;
  };
}

const FILTER_TABS: { id: PresenceFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "agents", label: "Agents" },
  { id: "branches", label: "Branches" },
  { id: "reviews", label: "Reviews" },
];

function parseTimeMs(iso: string | undefined): number {
  if (!iso) return 0;
  const parsed = Date.parse(iso);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function matchesQuery(q: string, fields: Array<string | null | undefined>): boolean {
  if (!q) return true;
  for (const field of fields) {
    if (field && field.toLowerCase().includes(q)) return true;
  }
  return false;
}

/**
 * Pure deterministic builder for Presence Canvas cards. Shared with `WorktableView` so `j`/`k`/`Enter`
 * keyboard navigation walks the exact rendered card sequence.
 */
export function buildPresenceCards({
  sessions,
  branches,
  reviews,
  pendingApprovals,
  defaultBranch,
  filter,
  query,
  showSettled = false,
}: BuildPresenceCardsInput): BuildPresenceCardsResult {
  const q = query.trim().toLowerCase();

  const runningSessions = sessions.filter((s) => s.status === "running");

  const activeAgentCards: Extract<PresenceCardItem, { category: "agent" }>[] = [];
  const settledSessionCards: Extract<PresenceCardItem, { category: "agent" }>[] = [];

  for (const session of sessions) {
    const isRunning = session.status === "running";
    const waitingApproval = isRunning
      ? findWaitingApprovalForSession(session, pendingApprovals)
      : undefined;
    const hasUncommitted = sessionHasUncommittedChanges(session);
    const settled = !isRunning && !hasUncommitted;

    const searchFields: Array<string | null | undefined> = [
      session.id,
      session.principal,
      session.agent_profile,
      session.command,
      session.branch,
      session.status,
      ...(session.changes ?? []).map((c) => c.path),
      ...Object.keys(session.placeholders),
      waitingApproval?.var_name,
      waitingApproval?.host,
    ];
    if (!matchesQuery(q, searchFields)) continue;

    const card: Extract<PresenceCardItem, { category: "agent" }> = {
      cardKey: `session:${session.id}`,
      category: "agent",
      focus: { kind: "session", id: session.id },
      session,
      waitingApproval,
      isRunning,
      hasUncommitted,
      settled,
    };

    if (settled) {
      settledSessionCards.push(card);
    } else {
      activeAgentCards.push(card);
    }
  }

  activeAgentCards.sort((a, b) => {
    const rank = (item: Extract<PresenceCardItem, { category: "agent" }>) => {
      if (item.isRunning && item.waitingApproval) return 0;
      if (item.isRunning) return 1;
      return 2;
    };
    const rDiff = rank(a) - rank(b);
    if (rDiff !== 0) return rDiff;
    return parseTimeMs(b.session.started_at) - parseTimeMs(a.session.started_at);
  });

  settledSessionCards.sort(
    (a, b) =>
      parseTimeMs(b.session.finished_at ?? b.session.started_at) -
      parseTimeMs(a.session.finished_at ?? a.session.started_at),
  );

  const nonDefaultBranchCards: Extract<PresenceCardItem, { category: "branch" }>[] = [];
  const syncedNonDefaultCards: Extract<PresenceCardItem, { category: "branch" }>[] = [];
  const defaultBranchCards: Extract<PresenceCardItem, { category: "branch" }>[] = [];
  const nonDefaultBranchNames = new Set<string>();

  for (const branch of branches) {
    const isDefault = branch.name === defaultBranch || (defaultBranch === "" && branch.is_current);
    const attachedReviews = reviews.filter((r) => r.branch === branch.name);
    const branchRunning = runningSessions.filter((s) => s.branch === branch.name);

    const searchFields: Array<string | null | undefined> = [
      branch.name,
      branch.author,
      branch.subject,
      branch.head_oid,
      branch.readiness,
      visibilitySummary(branch.visibility),
      ...branch.private_paths_touched,
      ...branch.quarantine_paths,
      ...attachedReviews.flatMap((r) => [r.change_id, r.title, r.author, r.delegated_agent]),
    ];
    if (!matchesQuery(q, searchFields)) continue;

    const card: Extract<PresenceCardItem, { category: "branch" }> = {
      cardKey: `branch:${branch.name}`,
      category: "branch",
      focus: { kind: "branch", name: branch.name },
      branch,
      isDefault,
      reviews: attachedReviews,
      runningSessions: branchRunning,
    };

    if (isDefault) {
      defaultBranchCards.push(card);
    } else {
      nonDefaultBranchNames.add(branch.name);
      const inFlight =
        branch.ahead_commits > 0 ||
        attachedReviews.length > 0 ||
        branchRunning.length > 0 ||
        branch.quarantine_paths.length > 0;
      (inFlight ? nonDefaultBranchCards : syncedNonDefaultCards).push(card);
    }
  }

  const byRecency = (
    a: Extract<PresenceCardItem, { category: "branch" }>,
    b: Extract<PresenceCardItem, { category: "branch" }>,
  ) => parseTimeMs(b.branch.updated_at) - parseTimeMs(a.branch.updated_at);
  syncedNonDefaultCards.sort(byRecency);
  const syncedBranchCards = [...syncedNonDefaultCards, ...defaultBranchCards];

  nonDefaultBranchCards.sort((a, b) => {
    if (a.branch.publish_candidate !== b.branch.publish_candidate) {
      return a.branch.publish_candidate ? -1 : 1;
    }
    if (a.branch.quarantine_paths.length !== b.branch.quarantine_paths.length) {
      return b.branch.quarantine_paths.length - a.branch.quarantine_paths.length;
    }
    return parseTimeMs(b.branch.updated_at) - parseTimeMs(a.branch.updated_at);
  });

  const matchingReviewCards: Extract<PresenceCardItem, { category: "review" }>[] = [];
  const standaloneReviewCards: Extract<PresenceCardItem, { category: "review" }>[] = [];

  for (const review of reviews) {
    const searchFields: Array<string | null | undefined> = [
      review.change_id,
      review.title,
      review.branch,
      review.author,
      review.delegated_agent,
      review.readiness,
      ...review.quarantine_paths,
    ];
    if (!matchesQuery(q, searchFields)) continue;

    const card: Extract<PresenceCardItem, { category: "review" }> = {
      cardKey: `review:${review.change_id}`,
      category: "review",
      focus: { kind: "review", changeId: review.change_id },
      review,
    };
    matchingReviewCards.push(card);
    if (review.branch === defaultBranch || !nonDefaultBranchNames.has(review.branch)) {
      standaloneReviewCards.push(card);
    }
  }

  let activeCards: PresenceCardItem[] = [];
  let filteredSettled: PresenceCardItem[] = [];

  if (filter === "agents") {
    activeCards = activeAgentCards;
    filteredSettled = settledSessionCards;
  } else if (filter === "branches") {
    activeCards = nonDefaultBranchCards;
    filteredSettled = [];
  } else if (filter === "reviews") {
    activeCards = matchingReviewCards;
    filteredSettled = [];
  } else {
    activeCards = [...activeAgentCards, ...nonDefaultBranchCards, ...standaloneReviewCards];
    filteredSettled = settledSessionCards;
  }

  const filteredSynced = filter === "all" || filter === "branches" ? syncedBranchCards : [];

  const expandSettled =
    filteredSettled.length > 0 &&
    (showSettled ?? (filter === "agents" && activeCards.length === 0));
  // Searching always surfaces merged branches so any branch stays findable.
  const expandSynced = filteredSynced.length > 0 && (showSettled === true || q.length > 0);
  const visibleCards = [
    ...activeCards,
    ...(expandSettled ? filteredSettled : []),
    ...(expandSynced ? filteredSynced : []),
  ];

  return {
    activeCards,
    settledSessionCards: filteredSettled,
    syncedBranchCards: filteredSynced,
    visibleCards,
    counts: {
      all: activeAgentCards.length + nonDefaultBranchCards.length + standaloneReviewCards.length,
      agents: activeAgentCards.length + settledSessionCards.length,
      activeAgents: runningSessions.length,
      branches: nonDefaultBranchCards.length,
      reviews: matchingReviewCards.length,
    },
  };
}

export interface PresenceCanvasProps {
  /** Pre-built (memoized) card groups from `WorktableView`, shared with its j/k navigation. */
  built: BuildPresenceCardsResult;
  owner: boolean;
  identity: IdentityPreset;
  sseConnected: boolean;
  nowMs: number;
  defaultBranch: string;
  agentProfiles: WorktableAgentProfile[];
  filter: PresenceFilter;
  onFilterChange: (filter: PresenceFilter) => void;
  search: string;
  onSearchChange: (value: string) => void;
  showSettled: boolean | null;
  onShowSettledChange: (show: boolean) => void;
  selectedCardKey: string | null;
  onSelectCard: (cardKey: string) => void;
  onFocus: (target: FocusTarget) => void;
  onSessionChange: (rec: AgentSessionRecord) => void;
  loaded: boolean;
  error?: string | null;
  onRetry?: () => void;
  /** Host has no agent sandbox: delegation is unavailable, so empty-state copy must not invite it. */
  agentBlocked?: boolean;
  /** Clean-workspace empty-state shortcuts; a pill renders only when its handler is provided. */
  onOpenGlassWall?: () => void;
  onOpenAgentConnect?: () => void;
  onOpenBranches?: (branchName?: string) => void;
  /** Items awaiting judgment (null while loading). At 0 the Action Required rail is hidden; a quiet pill toggles it. */
  pendingJudgmentCount?: number | null;
  judgmentRailOpen?: boolean;
  onToggleJudgmentRail?: () => void;
}

const CHIP =
  "inline-flex max-w-full items-center gap-1 rounded-full border border-white/[0.08] bg-white/[0.035] px-2 py-0.5 font-mono text-[12.5px] text-[#d2dbee]";

const CARD_PRIMARY_BTN =
  "block w-full text-left focus:outline-none after:absolute after:inset-0 after:rounded-xl after:content-[''] focus-visible:after:ring-2 focus-visible:after:ring-[#9ec0f5]/55";

function AgentPresenceCard({
  item,
  owner,
  nowMs,
  defaultBranch,
  agentProfiles,
  selected,
  stopping,
  onSelect,
  onStop,
}: {
  item: Extract<PresenceCardItem, { category: "agent" }>;
  owner: boolean;
  nowMs: number;
  defaultBranch: string;
  agentProfiles: WorktableAgentProfile[];
  selected: boolean;
  stopping: boolean;
  onSelect: () => void;
  onStop: (session: AgentSessionRecord) => void;
}) {
  const { session, waitingApproval, isRunning, hasUncommitted, settled } = item;
  const matchedProfile = session.agent_profile
    ? agentProfiles.find((p) => p.name === session.agent_profile)
    : undefined;
  const changedPaths = (session.changes ?? []).map((c) => c.path);
  const zoneText =
    changedPaths.length > 0
      ? summarizeZones(changedPaths)
      : matchedProfile && matchedProfile.allow_paths.length > 0
        ? summarizeZones(matchedProfile.allow_paths)
        : "";
  const placeholderKeys = Object.keys(session.placeholders);
  const branchLabel = session.branch || defaultBranch;

  return (
    <article
      className={`pr-well relative flex flex-col justify-between gap-2.5 rounded-xl p-3.5 text-left ${
        selected ? "pr-card-selected" : "pr-card-interactive"
      } ${settled ? "opacity-80" : ""}`}
    >
      <div className="space-y-2">
        {/* Status line + owner Stop button */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <button
            type="button"
            data-card-key={item.cardKey}
            aria-current={selected ? "true" : undefined}
            onClick={onSelect}
            className={`${CARD_PRIMARY_BTN} min-w-0 flex-1 space-y-2`}
          >
            <span className="flex min-w-0 items-center gap-2 font-mono text-[12.5px]">
              {waitingApproval ? (
                <>
                  <span className="pr-presence-dot bg-[#7f95f8]" aria-hidden="true" />
                  <span className="truncate text-[#a8c5ff]">
                    waiting {formatElapsedSeconds(waitingApproval.created_at, nowMs)} on{" "}
                    {waitingApproval.var_name}
                  </span>
                </>
              ) : isRunning ? (
                <>
                  <span className="pr-presence-dot bg-[#5bdba2]" aria-hidden="true" />
                  <span className="text-[#5bdba2]">
                    running · {formatElapsedSeconds(session.started_at, nowMs)}
                  </span>
                </>
              ) : hasUncommitted ? (
                <>
                  <span className="h-2 w-2 shrink-0 rounded-full bg-[#9ec0f5]" aria-hidden="true" />
                  <span className="text-[#9ec0f5]">
                    {plural(session.changes?.length ?? 0, "uncommitted file")}
                  </span>
                </>
              ) : (
                <>
                  <span
                    className={`h-2 w-2 shrink-0 rounded-full ${
                      session.commit
                        ? "bg-[#5bdba2]"
                        : session.discarded
                          ? "bg-[#54627c]"
                          : session.exit_code === 0
                            ? "bg-[#8595b0]"
                            : "bg-[#f27c7c]"
                    }`}
                    aria-hidden="true"
                  />
                  <span className="text-[#a6b5cf]">
                    {session.commit
                      ? `committed ${session.commit.slice(0, 7)}`
                      : session.discarded
                        ? "discarded"
                        : `${session.status}${
                            session.exit_code !== undefined && session.exit_code !== null
                              ? ` (${session.exit_code})`
                              : ""
                          }`}
                  </span>
                </>
              )}
            </span>

            {/* Actor */}
            <span className="flex flex-wrap items-center gap-1.5 text-[13.5px] text-[#dce4f5]">
              <IconIntersection className="h-4 w-4 text-[#9ec0f5]" />
              <span className="min-w-0 truncate font-mono font-medium">
                {session.principal}
                {session.agent_profile ? ` ∩ ${session.agent_profile}` : " · cage"}
              </span>
            </span>

            {/* Command */}
            <span
              title={session.command}
              className="block truncate rounded-xl bg-black/35 px-2.5 py-1.5 font-mono text-[13.5px] text-[#f3f6fd]"
            >
              $ {session.command}
            </span>
          </button>

          {owner && isRunning && (
            <span className="relative z-10 self-start">
              <ConfirmButton
                disabled={stopping}
                confirmLabel="Stop"
                question="Stop this session?"
                aria-label={`Stop session ${session.id.slice(0, 8)}`}
                onConfirm={() => onStop(session)}
                className="rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/12 px-2.5 py-0.5 font-mono text-[12.5px] text-[#f27c7c] transition hover:bg-[#f27c7c]/22 disabled:opacity-45"
              >
                {stopping ? "Stopping…" : "Stop"}
              </ConfirmButton>
            </span>
          )}
        </div>
      </div>

      {/* Context & Containment Telemetry */}
      <div className="space-y-1.5 border-t border-white/[0.06] pt-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {branchLabel && (
            <span className={CHIP} title={`Branch: ${branchLabel}`}>
              <IconBranchRef className="h-3 w-3 text-[#9ec0f5]" />
              <span className="truncate">{branchLabel}</span>
            </span>
          )}
          {session.sandbox === "bwrap" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-2 py-0.5 font-mono text-[12px] text-[#5bdba2]">
              bwrap
            </span>
          )}
          {session.sandbox === "none" && (
            <span className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-2 py-0.5 font-mono text-[12px] text-[#a8c5ff]">
              unsandboxed
            </span>
          )}
          {placeholderKeys.slice(0, 3).map((k) => (
            <span
              key={k}
              title={`Placeholder injected (use ≠ read): ${k}`}
              className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/20 bg-[#7f95f8]/10 px-2 py-0.5 font-mono text-[12px] text-[#b9cdf8]"
            >
              <IconVault className="h-3 w-3" />
              <span>{k}</span>
            </span>
          ))}
          {placeholderKeys.length > 3 && (
            <span className="font-mono text-[12px] text-[#a6b5cf]">
              +{placeholderKeys.length - 3} secrets
            </span>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1 font-mono text-[12.5px] text-[#a6b5cf]">
          <span className="min-w-0 truncate">
            {zoneText ? `zones: ${zoneText}` : `env: ${session.env}`}
          </span>
          {session.bytes_scrubbed > 0 && (
            <span className="text-[#67d6dc]">{formatByteCount(session.bytes_scrubbed)} scrubbed</span>
          )}
        </div>
      </div>
    </article>
  );
}

function BranchPresenceCard({
  item,
  selected,
  onSelect,
  onFocus,
}: {
  item: Extract<PresenceCardItem, { category: "branch" }>;
  selected: boolean;
  onSelect: () => void;
  onFocus: (target: FocusTarget) => void;
}) {
  const { branch, isDefault, reviews, runningSessions } = item;
  const isPrivate = isPrivateVisibility(branch.visibility);
  const zones = summarizeZones(branch.private_paths_touched);
  const primaryReview = reviews[0];

  return (
    <article
      className={`pr-well relative flex flex-col justify-between gap-2.5 rounded-xl p-3.5 text-left ${
        selected ? "pr-card-selected" : "pr-card-interactive"
      } ${isDefault ? "border-dashed border-white/[0.1]" : ""}`}
    >
      <button
        type="button"
        data-card-key={item.cardKey}
        aria-current={selected ? "true" : undefined}
        onClick={onSelect}
        className={`${CARD_PRIMARY_BTN} space-y-1.5`}
      >
        <span className="flex flex-wrap items-center justify-between gap-2">
          <span className="flex min-w-0 items-center gap-2">
            {isPrivate ? (
              <IconLock className="h-4 w-4 text-[#a8c5ff]" />
            ) : (
              <IconBranches className="h-4 w-4 text-[#7f95f8]" />
            )}
            <span
              title={branch.name}
              className="min-w-0 truncate font-mono text-[14px] font-medium text-[#f3f6fd]"
            >
              {branch.name}
            </span>
            {branch.is_current && (
              <span className="rounded-full bg-[#5bdba2]/15 px-2 py-0.5 font-mono text-[12px] text-[#5bdba2]">
                HEAD
              </span>
            )}
          </span>

          <span className="flex shrink-0 items-center gap-1.5">
            <span
              className={`rounded-full border px-2 py-0.5 font-mono text-[12px] leading-4 ${
                isPrivate
                  ? "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]"
                  : "border-white/[0.08] bg-white/[0.04] text-[#9eb0cc]"
              }`}
            >
              {visibilitySummary(branch.visibility)}
            </span>
            {!branch.publish_candidate && (
              <span
                className={`rounded-full border px-2 py-0.5 font-mono text-[12px] leading-4 uppercase ${
                  branch.ahead_commits === 0
                    ? "border-white/[0.10] bg-white/[0.03] text-[#a6b5cf]"
                    : branch.readiness === "ready"
                      ? "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                      : "border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
                }`}
              >
                {branch.ahead_commits === 0 ? "synced" : branch.readiness}
              </span>
            )}
          </span>
        </span>

        <span className="block truncate text-[14px] text-[#dce4f5]" title={branch.subject}>
          {branch.subject || "No commit subject"}
        </span>

        <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[12.5px] text-[#a6b5cf]">
          <span className="text-[#d2dbee]">{branch.author}</span>
          <span>{branch.head_oid.slice(0, 7)}</span>
          <span>{branch.relative_time}</span>
        </span>
      </button>

      {/* Enriched presence chips */}
      <div className="flex flex-wrap items-center gap-1.5 border-t border-white/[0.06] pt-2">
        {branch.ahead_commits > 0 && (
          <span className="rounded-full border border-[#9ec0f5]/20 bg-[#7f95f8]/10 px-2 py-0.5 font-mono text-[12.5px] text-[#9ec0f5]">
            +{plural(branch.ahead_commits, "commit")}
          </span>
        )}
        {zones && (
          <span className={CHIP} title={branch.private_paths_touched.join(", ")}>
            <span className="truncate">{zones}</span>
          </span>
        )}
        {primaryReview && (
          <button
            type="button"
            onClick={() => onFocus({ kind: "review", changeId: primaryReview.change_id })}
            className="pr-pill relative z-10 inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[12.5px] text-[#b9cdf8] hover:text-[#f3f6fd]"
          >
            <IconChanges className="h-3 w-3" />
            <span>
              {primaryReview.change_id} · R{primaryReview.round_count} ·{" "}
              {plural(primaryReview.comment_count, "comment")}
            </span>
          </button>
        )}
        {runningSessions.length > 0 && (
          <button
            type="button"
            onClick={() => onFocus({ kind: "session", id: runningSessions[0].id })}
            className="relative z-10 inline-flex items-center gap-1.5 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/10 px-2 py-0.5 font-mono text-[12.5px] text-[#5bdba2] hover:bg-[#5bdba2]/18"
          >
            <span className="pr-presence-dot bg-[#5bdba2]" aria-hidden="true" />
            <span>{plural(runningSessions.length, "live agent")}</span>
          </button>
        )}
        {branch.quarantine_paths.length > 0 && (
          <span className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/12 px-2 py-0.5 font-mono text-[12.5px] text-[#a8c5ff]">
            <IconQuarantine className="h-3 w-3" />
            <span>{plural(branch.quarantine_paths.length, "instruction file")}</span>
          </span>
        )}
        {branch.publish_candidate && (
          <span className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-2 py-0.5 font-mono text-[12.5px] text-[#5bdba2]">
            <IconShieldCheck className="h-3 w-3" />
            <span>Ready to publish</span>
          </span>
        )}
      </div>
    </article>
  );
}

function ReviewPresenceCard({
  item,
  selected,
  onSelect,
}: {
  item: Extract<PresenceCardItem, { category: "review" }>;
  selected: boolean;
  onSelect: () => void;
}) {
  const { review } = item;
  const isPrivate = isPrivateVisibility(review.visibility);
  const verdictEntries = Object.entries(review.verdicts ?? {});

  return (
    <article
      className={`pr-well relative flex flex-col justify-between gap-2.5 rounded-xl p-3.5 text-left ${
        selected ? "pr-card-selected" : "pr-card-interactive"
      }`}
    >
      <button
        type="button"
        data-card-key={item.cardKey}
        aria-current={selected ? "true" : undefined}
        onClick={onSelect}
        className={`${CARD_PRIMARY_BTN} space-y-1.5`}
      >
        <span className="flex flex-wrap items-center justify-between gap-2">
          <span className="flex min-w-0 items-center gap-2 font-mono text-[13px]">
            <IconChanges className="h-4 w-4 text-[#9ec0f5]" />
            <span className="text-[#9ec0f5]">{review.change_id}</span>
            <span className={CHIP}>
              <IconBranchRef className="h-3 w-3" />
              <span className="truncate">{review.branch}</span>
            </span>
          </span>
          <span
            className={`rounded-full border px-2 py-0.5 font-mono text-[12px] leading-4 ${
              isPrivate
                ? "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]"
                : "border-white/[0.08] bg-white/[0.04] text-[#9eb0cc]"
            }`}
          >
            {visibilitySummary(review.visibility)}
          </span>
        </span>

        <span className="block truncate text-[14px] font-medium text-[#f3f6fd]" title={review.title}>
          {review.title}
        </span>

        <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[12.5px] text-[#a6b5cf]">
          <span className="text-[#d2dbee]">{review.author}</span>
          {review.delegated_agent && (
            <span className="inline-flex items-center gap-1 text-[#9ec0f5]">
              <IconIntersection className="h-3 w-3" />
              {review.delegated_agent}
            </span>
          )}
          <span>R{review.round_count}</span>
          <span>{plural(review.comment_count, "comment")}</span>
        </span>
      </button>

      <div className="flex flex-wrap items-center gap-1.5 border-t border-white/[0.06] pt-2">
        {review.quarantine_paths.length > 0 && (
          <span className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/12 px-2 py-0.5 font-mono text-[12.5px] text-[#a8c5ff]">
            <IconQuarantine className="h-3 w-3" />
            <span>{plural(review.quarantine_paths.length, "instruction file")}</span>
          </span>
        )}
        {verdictEntries.map(([k, v]) => (
          <span
            key={k}
            className={`rounded-full px-2 py-0.5 font-mono text-[12px] ${
              v === "approved"
                ? "bg-[#5bdba2]/15 text-[#5bdba2]"
                : v === "changes_requested" || v === "changes"
                  ? "bg-[#7f95f8]/15 text-[#a8c5ff]"
                  : "bg-white/[0.06] text-[#b6c3db]"
            }`}
          >
            {k}: {v}
          </span>
        ))}
        {verdictEntries.length === 0 && review.quarantine_paths.length === 0 && (
          <span className="font-mono text-[12.5px] text-[#a6b5cf]">
            Base: {review.base_ref} · {review.readiness.toUpperCase()}
          </span>
        )}
      </div>
    </article>
  );
}

/** Calm "Who Is Doing What Right Now" live Presence Canvas built purely from real workspace state. */
export function PresenceCanvas({
  built,
  owner,
  identity,
  sseConnected,
  nowMs,
  defaultBranch,
  agentProfiles,
  filter,
  onFilterChange,
  search,
  onSearchChange,
  showSettled,
  onShowSettledChange,
  selectedCardKey,
  onSelectCard,
  onFocus,
  onSessionChange,
  loaded,
  error,
  onRetry,
  pendingJudgmentCount,
  judgmentRailOpen,
  onToggleJudgmentRail,
}: PresenceCanvasProps) {
  const [stoppingId, setStoppingId] = useState<string | null>(null);
  const [stopError, setStopError] = useState<string | null>(null);

  const handleStop = async (session: AgentSessionRecord) => {
    setStoppingId(session.id);
    setStopError(null);
    try {
      const updated = await api.stopSession(session.id);
      onSessionChange(updated);
    } catch (err: unknown) {
      setStopError(errorText(err));
    } finally {
      setStoppingId(null);
    }
  };

  const settledExpanded =
    built.settledSessionCards.length > 0 &&
    (showSettled ?? (filter === "agents" && built.activeCards.length === 0));
  const searching = search.trim().length > 0;
  const syncedExpanded =
    built.syncedBranchCards.length > 0 && (showSettled === true || searching);

  // Calm default: nothing in flight → one slim status row instead of a hollow box. Also used while loading
  // (built is empty) so skeleton → loaded has zero layout shift.
  const idleView =
    built.activeCards.length === 0 &&
    !searching &&
    filter === "all" &&
    (loaded || (!error && built.visibleCards.length === 0));
  const compactEmpty = idleView && !settledExpanded && !syncedExpanded;
  const idleExtraCount = built.syncedBranchCards.length + built.settledSessionCards.length;
  const idleExpanded = settledExpanded || syncedExpanded;

  const renderCard = (item: PresenceCardItem) => {
    const selected = selectedCardKey === item.cardKey;
    const activate = () => {
      onSelectCard(item.cardKey);
      onFocus(item.focus);
    };
    if (item.category === "agent") {
      return (
        <AgentPresenceCard
          key={item.cardKey}
          item={item}
          owner={owner}
          nowMs={nowMs}
          defaultBranch={defaultBranch}
          agentProfiles={agentProfiles}
          selected={selected}
          stopping={stoppingId === item.session.id}
          onSelect={activate}
          onStop={(s) => void handleStop(s)}
        />
      );
    }
    if (item.category === "branch") {
      return (
        <BranchPresenceCard
          key={item.cardKey}
          item={item}
          selected={selected}
          onSelect={activate}
          onFocus={onFocus}
        />
      );
    }
    return (
      <ReviewPresenceCard
        key={item.cardKey}
        item={item}
        selected={selected}
        onSelect={activate}
      />
    );
  };

  const tabCount = (tab: PresenceFilter): number => {
    switch (tab) {
      case "all":
        return built.counts.all;
      case "agents":
        return built.counts.agents;
      case "branches":
        return built.counts.branches;
      case "reviews":
        return built.counts.reviews;
    }
  };

  return (
    <section
      aria-label="Active Work"
      className={`pr-surface flex min-w-0 flex-col overflow-hidden rounded-2xl ${
        compactEmpty ? "flex-none" : "min-h-[280px] flex-1 lg:min-h-0"
      }`}
    >
      {/* Single-row header: title · filter tabs · search · live status (wraps gracefully when narrow) */}
      <header className="border-b border-white/[0.06] px-3.5 py-2.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <h2 className="text-[14.5px] font-semibold text-[#f3f6fd]">Active Work</h2>

          <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Presence filter">
            {FILTER_TABS.map((tab) => (
              <button
                key={tab.id}
                type="button"
                aria-pressed={filter === tab.id}
                onClick={() => onFilterChange(tab.id)}
                className={`rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                  filter === tab.id
                    ? "pr-pill-active"
                    : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                }`}
              >
                {tab.label} {tabCount(tab.id)}
              </button>
            ))}
          </div>

          <div className="pr-well ml-auto flex min-w-[170px] flex-1 items-center gap-2 rounded-full px-3 py-1 sm:max-w-[280px] 2xl:max-w-[340px]">
            <IconSearch className="h-3.5 w-3.5 shrink-0 text-[#a6b5cf]" />
            <input
              type="search"
              value={search}
              onChange={(e) => onSearchChange(e.target.value)}
              aria-label="Filter presence cards"
              placeholder="Filter people, branches, commands…"
              className="min-w-0 flex-1 bg-transparent text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
          </div>

          <span
            role="status"
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] ${
              sseConnected
                ? "border-[#5bdba2]/25 bg-[#5bdba2]/10 text-[#5bdba2]"
                : "border-[#9ec0f5]/30 bg-[#7f95f8]/10 text-[#a8c5ff]"
            }`}
          >
            <span
              className={`pr-presence-dot ${sseConnected ? "bg-[#5bdba2]" : "bg-[#7f95f8]"}`}
              aria-hidden="true"
            />
            <span>{sseConnected ? "Live" : "Reconnecting"}</span>
          </span>

          {pendingJudgmentCount === 0 && onToggleJudgmentRail && (
            <button
              type="button"
              onClick={onToggleJudgmentRail}
              aria-pressed={Boolean(judgmentRailOpen)}
              title={
                judgmentRailOpen
                  ? "Nothing needs action. Hide the Action Required panel."
                  : "Nothing needs action. Show the Action Required panel."
              }
              className="inline-flex items-center gap-1.5 rounded-full border border-[#5bdba2]/20 bg-[#5bdba2]/[0.06] px-2.5 py-0.5 font-mono text-[12.5px] text-[#5bdba2] transition hover:bg-[#5bdba2]/12"
            >
              <IconShieldCheck className="h-3 w-3" />
              <span>0 pending</span>
            </button>
          )}
        </div>

        {/* Viewing-as lens: compact pill (full explanation in the tooltip) */}
        {owner && identity.id !== "self" && (
          <div
            role="status"
            title="Showing only branches, reviews, sessions, and approvals visible to this lens."
            className="mt-2 inline-flex max-w-full items-center gap-2 rounded-full border border-[#9ec0f5]/25 bg-[#7f95f8]/10 px-2.5 py-0.5 text-[12.5px] text-[#cfe0ff]"
          >
            <IconLens className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
            <span className="truncate">
              Viewing as <strong className="font-mono text-[#f3f6fd]">{identity.label}</strong>
            </span>
          </div>
        )}
      </header>

      {/* Scrollable Card Canvas */}
      <div
        className={`space-y-3 p-3 ${compactEmpty ? "flex-none" : "min-h-0 flex-1 overflow-y-auto"}`}
      >
        <ErrorNote message={stopError} />

        {!loaded && error && built.visibleCards.length === 0 ? (
          <div className="flex min-h-[200px] flex-col items-center justify-center gap-2 px-4 text-center">
            <IconQuarantine className="h-8 w-8 text-[#f27c7c]" />
            <p className="text-[14px] font-medium text-[#dce4f5]">Couldn&apos;t load the worktable</p>
            <p className="max-w-xs break-words text-[13.5px] text-[#a6b5cf]">{error}</p>
            {onRetry && (
              <button
                type="button"
                onClick={onRetry}
                className="pr-pill rounded-full px-3 py-1 text-[13px] text-[#dce4f5]"
              >
                Retry
              </button>
            )}
          </div>
        ) : !loaded && built.visibleCards.length === 0 ? (
          <WorktableCleanCanvasSkeleton />
        ) : built.activeCards.length === 0 &&
          built.settledSessionCards.length === 0 &&
          built.syncedBranchCards.length === 0 &&
          (searching || filter !== "all") ? (
          <div className="flex min-h-[200px] flex-col items-center justify-center gap-2 px-4 text-center">
            <IconShieldCheck className="h-8 w-8 text-[#a6b5cf]" />
            <p className="text-[14px] font-medium text-[#dce4f5]">No matching workstreams</p>
            <p className="max-w-xs text-[13.5px] text-[#a6b5cf]">
              Try clearing the filter or search query to see all visible workstreams.
            </p>
            <button
              type="button"
              onClick={() => {
                onFilterChange("all");
                onSearchChange("");
              }}
              className="pr-pill rounded-full px-3 py-1 text-[13px] text-[#dce4f5]"
            >
              Clear filters
            </button>
          </div>
        ) : (
          <>
            {built.activeCards.length > 0 && (
              <div className="grid gap-3 lg:grid-cols-2 min-[1800px]:grid-cols-3">
                {built.activeCards.map(renderCard)}
              </div>
            )}

            {idleView && (
              <div className="flex min-h-[28px] flex-wrap items-center justify-between gap-2 px-1 py-1">
                <p className="flex items-center gap-2 text-[14px] text-[#dce4f5]">
                  <IconShieldCheck className="h-4 w-4 shrink-0 text-[#5bdba2]" />
                  <span>No active branches, agents, or reviews in flight.</span>
                </p>
                {idleExtraCount > 0 && (
                  <button
                    type="button"
                    aria-expanded={idleExpanded}
                    onClick={() => onShowSettledChange(!idleExpanded)}
                    className="pr-pill inline-flex h-6 items-center gap-1 rounded-full px-2.5 font-mono text-[12.5px] text-[#d2dbee] hover:text-[#f3f6fd]"
                  >
                    <IconChevron direction={idleExpanded ? "down" : "right"} className="h-3 w-3" />
                    <span>
                      {idleExpanded ? "Hide" : "Show"} {idleExtraCount} synced{" "}
                      {built.settledSessionCards.length > 0
                        ? idleExtraCount === 1
                          ? "item"
                          : "items"
                        : idleExtraCount === 1
                          ? "branch"
                          : "branches"}
                    </span>
                  </button>
                )}
              </div>
            )}

            {built.syncedBranchCards.length > 0 && (
              <div className="space-y-2.5">
                {/* In the idle view the inline status-strip toggle controls expansion. */}
                <button
                  type="button"
                  aria-expanded={syncedExpanded}
                  onClick={() => onShowSettledChange(!syncedExpanded)}
                  className={`${idleView ? "hidden" : "flex"} w-full items-center justify-between gap-2 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-left font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf] transition hover:bg-white/[0.04] hover:text-[#dce4f5]`}
                >
                  <span className="inline-flex items-center gap-1.5">
                    <IconChevron
                      direction={syncedExpanded ? "down" : "right"}
                      className="h-3.5 w-3.5"
                    />
                    <span>
                      {syncedExpanded ? "Hide" : "Show"} {built.syncedBranchCards.length} merged /
                      synced {built.syncedBranchCards.length === 1 ? "branch" : "branches"}
                    </span>
                  </span>
                  <span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12.5px] text-[#d2dbee]">
                    {built.syncedBranchCards.length}
                  </span>
                </button>

                {syncedExpanded && (
                  <div className="grid gap-3 lg:grid-cols-2 min-[1800px]:grid-cols-3">
                    {built.syncedBranchCards.map(renderCard)}
                  </div>
                )}
              </div>
            )}

            {built.settledSessionCards.length > 0 && (
              <div className="space-y-2.5">
                <button
                  type="button"
                  aria-expanded={settledExpanded}
                  onClick={() => onShowSettledChange(!settledExpanded)}
                  className={`${idleView ? "hidden" : "flex"} w-full items-center justify-between gap-2 rounded-xl border border-white/[0.06] bg-white/[0.02] px-3 py-2 text-left font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf] transition hover:bg-white/[0.04] hover:text-[#dce4f5]`}
                >
                  <span className="inline-flex items-center gap-1.5">
                    <IconChevron
                      direction={settledExpanded ? "down" : "right"}
                      className="h-3.5 w-3.5"
                    />
                    <span>Recent Completed Sessions</span>
                  </span>
                  <span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12.5px] text-[#d2dbee]">
                    {built.settledSessionCards.length}
                  </span>
                </button>

                {settledExpanded && (
                  <div className="grid gap-3 lg:grid-cols-2 min-[1800px]:grid-cols-3">
                    {built.settledSessionCards.map(renderCard)}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
