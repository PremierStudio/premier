import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import {
  api,
  ApiError,
  branchNameError,
  errorText,
  repoPath,
  shortOid,
  type AgentLane,
  suggestionForApproval,
  type AgentSessionRecord,
  type AuditDecision,
  type AuditEvent,
  type BudgetAlert,
  type HealthResponse,
  type IdentityPreset,
  type LaneConflict,
  type McpDriftAlert,
  type PendingApproval,
  type PolicySuggestion,
  type SessionDiffResponse,
} from "../api";
import {
  detectLanguage,
  parseUnifiedPatch,
  tokenClassName,
  tokenizeLine,
} from "../lib/highlight";
import { unifiedPatchToSides } from "../lib/monaco";
import { BudgetGauges } from "./BudgetGauges";
import {
  IconAmbientPulse,
  IconCheck,
  IconChevron,
  IconCopy,
  IconDownload,
  IconEdit,
  IconIntersection,
  IconLock,
  IconPause,
  IconPlay,
  IconQuarantine,
  IconSearch,
  IconTerminal,
} from "./Icons";
import { ConfirmButton, ErrorNote, Time, useAction } from "./forms";
import { LaneConflictInspector } from "./LaneConflictInspector";
import { ProvenanceTimeline } from "./ProvenanceTimeline";
import { KnockApprovalCard } from "./KnockApprovalCard";
import { McpApprovalCard } from "./McpApprovalCard";

import {
  CodeLinesSkeleton,
  McpGatewaySkeleton,
  PanelRowsSkeleton,
  StepInSkeleton,
} from "./ViewSkeletons";

// Heavy / mode-specific surfaces load on demand: Monaco only when a diff is expanded, the MCP
// gateway only on its tab (it fetches tools + pins on mount), step-in only when opened.
const MonacoDiffViewer = lazy(() =>
  import("./MonacoDiffViewer").then((m) => ({ default: m.MonacoDiffViewer })),
);
const McpGatewayPanel = lazy(() =>
  import("./McpGatewayPanel").then((m) => ({ default: m.McpGatewayPanel })),
);
const SessionStepInEditor = lazy(() =>
  import("./SessionStepInEditor").then((m) => ({ default: m.SessionStepInEditor })),
);

const preloadMcpGateway = () => {
  void import("./McpGatewayPanel");
};

// The skeleton owns the live region; wrapping it again would announce twice.
function PanelFallback({ className = "" }: { className?: string }) {
  return (
    <div aria-busy="true" className={`overflow-hidden ${className}`}>
      <PanelRowsSkeleton rows={3} />
    </div>
  );
}

const DECISIONS: AuditDecision[] = [
  "allowed",
  "redacted",
  "approval_required",
  "denied",
  "exfiltration_blocked",
  "rate_limited",
  "budget_exceeded",
];

/** Max stream rows painted at once. */
const STREAM_RENDER_CAP = 250;

const SESSION_LIMITS = [
  { label: "5 min", secs: 300 },
  { label: "30 min", secs: 1800 },
  { label: "2 h", secs: 7200 },
  { label: "4 h", secs: 14400 },
] as const;

interface Props {
  identity: IdentityPreset;
  /** The logged-in human's own principal (never the simulated "View as" principal). */
  userPrincipal: string;
  /** False for members: owner-only actions are disabled rather than left to 403. */
  owner: boolean;
  /** Agent profiles the policy declares (`[[agent_profiles]]`); empty when there are none. */
  agentProfiles: string[];
  /** From /health: "none" means the server refuses sessions (501). */
  agentSandbox?: HealthResponse["agent_sandbox"];
  /** From /health: why the sandbox is not "bwrap". */
  agentSandboxDetail?: string;
  /** Branches a session's private copy can be taken from, and the header's selected one. */
  branchNames: string[];
  activeRef?: string;
  /** A session was committed, stopped or discarded here: the caller replaces its record. */
  onSessionChange: (rec: AgentSessionRecord) => void;
  /** Jumps straight to a Review Round created from a session. */
  onOpenReview?: (changeId: string) => void;
  /** Refreshes branch list after committing to a new branch. */
  onBranchesChanged?: () => void;
  /** Optional session id requested from ambient hygiene drawer ("Step in →"). */
  requestedSessionId?: string | null;
  onConsumeRequestedSession?: () => void;
  /** Refreshes owner-only hygiene insights after session workspace commits. */
  onHygieneChanged?: () => void;
  auditEvents: AuditEvent[];
  approvals: PendingApproval[];
  sessions: AgentSessionRecord[];
  mcpAlerts: McpDriftAlert[];
  onMcpAlertsChanged: () => void;
  budgetAlerts?: BudgetAlert[];
  onDecided: () => void;
  lanes?: AgentLane[];
  /** A lane was created, rebased, resolved or deleted: the caller reloads its lane list. */
  onLanesChanged?: () => void;
  /** Living-policy proposals (owner only; empty for members). */
  suggestions: PolicySuggestion[];
  onSuggestionsChanged: () => void;
  /** Opens the graduation diff modal, which the app hosts. */
  onPreviewSuggestion: (s: PolicySuggestion) => void;
  onClearRequestedSession?: () => void;
}

function eventFingerprint(ev: AuditEvent): string {
  return `${ev.timestamp}|${ev.action}|${ev.target ?? ""}|${ev.decision}`;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** The conflicts a refused commit captured on the session's lane, if the server sent any. */
function laneConflictsOf(err: unknown): LaneConflict[] | null {
  if (!(err instanceof ApiError)) return null;
  const c = err.body?.lane_conflicts;
  return Array.isArray(c) && c.length > 0 ? (c as LaneConflict[]) : null;
}

/** Readable text for a refused session commit; other errors keep the server's own message. */
function commitErrorText(err: unknown): string {
  if (err instanceof ApiError) {
    const msg = typeof err.body?.error === "string" ? err.body.error : "";
    if (err.status === 409 && laneConflictsOf(err)) {
      return "Overlapping conflict captured on lane — inspect and resolve below.";
    }
    if (err.status === 409 && msg.includes("moved")) {
      return "The branch changed since this session started. Run the agent again on the current branch.";
    }
    if (err.status === 409 && msg.includes("running")) return "The session is still running.";
    if (err.status === 409 && msg.includes("already committed")) {
      return "This session is already committed.";
    }
    if (err.status === 410) return "This session's workspace was discarded.";
    if (err.status === 413) return "The change set is too large to commit.";
    if (err.status === 400 && msg.includes("changed nothing")) return "This session changed nothing.";
  }
  return errorText(err);
}

const CHANGE_TONE = {
  added: "text-[#5bdba2]",
  modified: "text-[#9ec0f5]",
  deleted: "text-[#f27c7c]",
} as const;

/** A finished session's change set, with inline diff, commit/branch+review, and discard for owners. Keyed on the session. */
function SessionChanges({
  session,
  identity,
  userPrincipal,
  owner,
  hasUnsavedStepIn = false,
  onSessionChange,
  onOpenReview,
  onBranchesChanged,
  onLanesChanged,
  onHygieneChanged,
}: {
  session: AgentSessionRecord;
  identity: IdentityPreset;
  userPrincipal: string;
  owner: boolean;
  hasUnsavedStepIn?: boolean;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onOpenReview?: (changeId: string) => void;
  onBranchesChanged?: () => void;
  onLanesChanged?: () => void;
  onHygieneChanged?: () => void;
}) {
  const [message, setMessage] = useState("");
  const [commitMode, setCommitMode] = useState<"current" | "new_branch">("current");
  const [newBranchName, setNewBranchName] = useState(`agent/${session.id}`);
  const [committedBranch, setCommittedBranch] = useState<string | null>(null);
  const [createdReviewId, setCreatedReviewId] = useState<string | null>(null);
  const [pendingReview, setPendingReview] = useState<{
    title: string;
    branch: string;
    baseRef?: string;
  } | null>(null);
  const [retryingReview, setRetryingReview] = useState(false);
  const [rebased, setRebased] = useState(false);
  // Set when a commit is refused because it overlaps what landed on the branch meanwhile.
  const [conflictState, setConflictState] = useState<{
    lane_id: string | null;
    lane_conflicts: LaneConflict[];
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [diffOpen, setDiffOpen] = useState(false);
  const [diffViewMode, setDiffViewMode] = useState<"inline" | "split" | "raw">("inline");
  const [diffData, setDiffData] = useState<SessionDiffResponse | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [expandedDiffPaths, setExpandedDiffPaths] = useState<Set<string>>(() => new Set());

  const changes = session.changes ?? [];
  const conflicts =
    conflictState ??
    (session.conflicts?.length
      ? { lane_id: session.lane_id ?? null, lane_conflicts: session.conflicts }
      : null);
  const branch = committedBranch || session.branch || "the default branch";
  const settled = Boolean(session.commit) || Boolean(session.discarded);

  const parsedDiffFiles = useMemo(() => {
    if (!diffData) return [];
    return diffData.files.map((file) => ({
      file,
      lang: detectLanguage(file.path),
      parsed: !file.binary && file.patch ? parseUnifiedPatch(file.patch) : null,
      sides: !file.binary && file.patch ? unifiedPatchToSides(file.patch) : null,
    }));
  }, [diffData]);

  const loadDiff = async (focusPath?: string) => {
    if (settled) return;
    setDiffOpen(true);
    if (diffData) {
      if (focusPath) {
        setExpandedDiffPaths((prev) => new Set(prev).add(focusPath));
      }
      return;
    }
    setLoadingDiff(true);
    setDiffError(null);
    try {
      const res = await api.sessionDiff(session.id);
      setDiffData(res);
      setExpandedDiffPaths(
        focusPath ? new Set([focusPath]) : new Set(res.files.map((f) => f.path)),
      );
    } catch (err: unknown) {
      setDiffError(errorText(err));
    } finally {
      setLoadingDiff(false);
    }
  };

  const toggleDiff = () => {
    if (settled) return;
    if (diffOpen) {
      setDiffOpen(false);
    } else {
      void loadDiff();
    }
  };

  const toggleDiffFile = (path: string) => {
    setExpandedDiffPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const run = async (fn: () => Promise<AgentSessionRecord>) => {
    setBusy(true);
    setError(null);
    try {
      onSessionChange(await fn());
    } catch (err: unknown) {
      const lane_conflicts = laneConflictsOf(err);
      if (lane_conflicts && err instanceof ApiError) {
        const laneId = err.body?.lane_id;
        setConflictState({
          lane_id: typeof laneId === "string" ? laneId : (session.lane_id ?? null),
          lane_conflicts,
        });
        onLanesChanged?.();
      }
      setError(commitErrorText(err));
    } finally {
      setBusy(false);
    }
  };

  const openReviewForBranch = async (info: { title: string; branch: string; baseRef?: string }) => {
    setRetryingReview(true);
    setError(null);
    try {
      const review = await api.createReview({
        title: info.title,
        branch: info.branch,
        base_ref: info.baseRef,
        author: userPrincipal,
        delegated_agent: session.agent_profile || null,
        session_id: session.id,
      });
      setPendingReview(null);
      setCreatedReviewId(review.change_id);
      onOpenReview?.(review.change_id);
    } catch (err: unknown) {
      setPendingReview(info);
      setError(`Committed to ${info.branch}, but opening review failed: ${errorText(err)}`);
    } finally {
      setRetryingReview(false);
    }
  };

  const handleCommit = () => {
    const commitMsg = message.trim() || undefined;
    if (commitMode === "current") {
      void run(async () => {
        const res = await api.commitSession(session.id, commitMsg, {
          auto_rebase: true,
          lane_id: session.lane_id ?? undefined,
          change_id: session.change_id ?? undefined,
        });
        if (res.branch) setCommittedBranch(res.branch);
        setDiffOpen(false);
        if (res.rebased) setRebased(true);
        setConflictState(null);
        onBranchesChanged?.();
        onLanesChanged?.();
        onHygieneChanged?.();
        return { ...session, commit: res.commit };
      });
      return;
    }

    const targetBranch = newBranchName.trim();
    if (!targetBranch) {
      setError("Enter a branch name.");
      return;
    }
    const nameErr = branchNameError(targetBranch);
    if (nameErr) {
      setError(nameErr);
      return;
    }

    void (async () => {
      setBusy(true);
      setError(null);
      let finalBranch = targetBranch;
      try {
        const res = await api.commitSession(session.id, commitMsg, {
          new_branch: targetBranch,
          auto_rebase: true,
          lane_id: session.lane_id ?? undefined,
          change_id: session.change_id ?? undefined,
        });
        if (res.rebased) setRebased(true);
        setConflictState(null);
        finalBranch = res.branch || targetBranch;
        setCommittedBranch(finalBranch);
        setDiffOpen(false);
        // Immediately persist commit state & refresh branches BEFORE creating the review.
        onSessionChange({ ...session, commit: res.commit, branch: finalBranch });
        onBranchesChanged?.();
        onLanesChanged?.();
        onHygieneChanged?.();
      } catch (err: unknown) {
        const lane_conflicts = laneConflictsOf(err);
        if (lane_conflicts && err instanceof ApiError) {
          const laneId = err.body?.lane_id;
          setConflictState({
            lane_id: typeof laneId === "string" ? laneId : (session.lane_id ?? null),
            lane_conflicts,
          });
          onLanesChanged?.();
        }
        setError(commitErrorText(err));
        setBusy(false);
        return;
      }
      setBusy(false);
      await openReviewForBranch({
        title: commitMsg || `Agent session ${session.id}`,
        branch: finalBranch,
        baseRef: session.branch || undefined,
      });
    })();
  };

  return (
    <div className="max-h-[52%] shrink-0 space-y-2.5 overflow-y-auto border-t border-white/[0.06] px-4 py-3 font-mono text-[13px]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
          Changes{changes.length > 0 ? ` (${changes.length})` : ""}
        </div>
        {changes.length > 0 && !session.commit && !session.discarded ? (
          <button
            type="button"
            onClick={toggleDiff}
            className={`rounded-full px-2.5 py-0.5 text-[12.5px] transition ${
              diffOpen ? "pr-pill-active" : "pr-pill text-[#9ec0f5] hover:text-[#f3f6fd]"
            }`}
          >
            {diffOpen ? "Hide diff" : "View diff"}
          </button>
        ) : changes.length > 0 && session.commit ? (
          <span className="rounded-full bg-white/[0.05] px-2.5 py-0.5 text-[12.5px] text-[#a6b5cf]">
            Committed — view in Changes
          </span>
        ) : null}
      </div>
      {changes.length === 0 && !settled && <div className="text-[#a6b5cf]">No file changes</div>}
      {changes.length > 0 && (
        <ul className="space-y-1">
          {changes.map((c) => (
            <li key={c.path}>
              <button
                type="button"
                disabled={settled}
                onClick={() => void loadDiff(c.path)}
                title={settled ? "Workspace already settled" : "Inspect inline diff"}
                className="flex w-full items-center justify-between gap-3 rounded-lg bg-black/30 px-2.5 py-1 text-left transition hover:bg-white/[0.05] disabled:cursor-default disabled:hover:bg-black/30"
              >
                <span className="min-w-0 truncate text-[#dce4f5]" title={c.path}>
                  {c.path}
                </span>
                <span className="flex shrink-0 items-center gap-2 text-[12.5px]">
                  <span className={CHANGE_TONE[c.kind] ?? "text-[#d2dbee]"}>{c.kind}</span>
                  {c.kind !== "deleted" && (
                    <span className="text-[#a6b5cf]">{formatSize(c.size)}</span>
                  )}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      {diffOpen && !settled && (
        <div className="space-y-2 pt-1">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
              Diff{diffData ? ` (${diffData.files.length})` : ""}
            </span>
            <div
              role="group"
              aria-label="Diff view mode"
              className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 text-[12.5px]"
            >
              {(
                [
                  { id: "inline", label: "Inline" },
                  { id: "split", label: "Split" },
                  { id: "raw", label: "Raw" },
                ] as const
              ).map((mode) => (
                <button
                  key={mode.id}
                  type="button"
                  aria-pressed={diffViewMode === mode.id}
                  onClick={() => setDiffViewMode(mode.id)}
                  className={`rounded-full px-2.5 py-0.5 transition ${
                    diffViewMode === mode.id
                      ? "bg-[#7f95f8]/25 text-[#f3f6fd]"
                      : "text-[#a6b5cf] hover:text-white"
                  }`}
                >
                  {mode.label}
                </button>
              ))}
            </div>
          </div>
          {loadingDiff && <CodeLinesSkeleton />}
          {diffError && (
            <div role="alert" className="break-words text-[#f27c7c]">
              {diffError}
            </div>
          )}
          {diffData?.truncated && (
            <div className="text-[12.5px] text-[#cbd5e8]">
              Diff output was truncated by the server.
            </div>
          )}
          {parsedDiffFiles.map(({ file, lang, parsed, sides }) => {
              const expanded = expandedDiffPaths.has(file.path);
              return (
                <div key={file.path} className="pr-well overflow-hidden rounded-xl">
                  <button
                    type="button"
                    onClick={() => toggleDiffFile(file.path)}
                    className="flex w-full items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-1.5 text-left hover:bg-white/[0.03]"
                  >
                    <span className="flex min-w-0 items-center gap-1.5">
                      <IconChevron
                        direction={expanded ? "down" : "right"}
                        className="h-3.5 w-3.5 text-[#a6b5cf]"
                      />
                      <span className="truncate text-[#dce4f5]">{file.path}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2 text-[12.5px]">
                      <span className={CHANGE_TONE[file.kind] ?? "text-[#d2dbee]"}>
                        {file.kind}
                      </span>
                      {file.binary && (
                        <span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12px] text-[#a6b5cf]">
                          binary
                        </span>
                      )}
                      {file.truncated && (
                        <span className="rounded-full border border-white/[0.11] bg-white/[0.04] px-2 py-0.5 text-[12px] text-[#9eb0cc]">
                          truncated
                        </span>
                      )}
                      {parsed && (
                        <>
                          <span className="text-[#5bdba2]">+{parsed.additions}</span>
                          <span className="text-[#f27c7c]">-{parsed.deletions}</span>
                        </>
                      )}
                    </span>
                  </button>
                  {expanded &&
                    (file.binary ? (
                      <div className="px-3 py-2.5 text-[12.5px] text-[#a6b5cf]">
                        Binary file ({formatSize(file.size)}) — inline diff not shown.
                      </div>
                    ) : !file.patch ? (
                      <div className="px-3 py-2 text-[12.5px] text-[#a6b5cf]">No textual diff</div>
                    ) : diffViewMode !== "raw" && sides ? (
                      <div>
                        <Suspense
                          fallback={<PanelFallback className="h-[130px]" />}
                        >
                          <MonacoDiffViewer
                            original={sides.original}
                            modified={sides.modified}
                            path={file.path}
                            renderSideBySide={diffViewMode === "split"}
                            collapseUnchanged={false}
                            autoHeight={true}
                            minHeight={130}
                            maxHeight={420}
                            originalLineMap={sides.originalLineMap}
                            modifiedLineMap={sides.modifiedLineMap}
                            readOnly={true}
                            ariaLabel={`Diff for ${file.path}`}
                          />
                        </Suspense>
                        {file.truncated && (
                          <div className="border-t border-white/[0.06] px-3 py-1.5 text-[12.5px] text-[#cbd5e8]">
                            File diff truncated.
                          </div>
                        )}
                      </div>
                    ) : parsed && parsed.lines.length > 0 ? (
                      <div className="overflow-x-auto py-1.5 text-[12.5px] leading-[1.58]">
                        {parsed.lines.map((dl, li) => {
                          if (dl.kind === "meta") return null;
                          if (dl.kind === "hunk") {
                            return (
                              <div
                                key={li}
                                className="bg-[#7f95f8]/10 px-3 py-0.5 text-[12.5px] text-[#9ec0f5]"
                              >
                                {dl.body}
                              </div>
                            );
                          }
                          const rowBg =
                            dl.kind === "add"
                              ? "bg-[#5bdba2]/10"
                              : dl.kind === "del"
                                ? "bg-[#f27c7c]/10"
                                : "";
                          const sigilColor =
                            dl.kind === "add"
                              ? "text-[#5bdba2]"
                              : dl.kind === "del"
                                ? "text-[#f27c7c]"
                                : "text-[#a6b5cf]";
                          const tokens = tokenizeLine(dl.body, lang);
                          return (
                            <div key={li} className={`flex px-2 ${rowBg}`}>
                              <span className="w-8 shrink-0 select-none pr-1.5 text-right text-[12px] text-[#a6b5cf]">
                                {dl.oldLine ?? ""}
                              </span>
                              <span className="w-8 shrink-0 select-none pr-1.5 text-right text-[12px] text-[#a6b5cf]">
                                {dl.newLine ?? ""}
                              </span>
                              <span className={`w-3.5 shrink-0 select-none ${sigilColor}`}>
                                {dl.sigil}
                              </span>
                              <span className="whitespace-pre">
                                {tokens.map((tok, ti) => (
                                  <span key={ti} className={tokenClassName(tok.kind)}>
                                    {tok.text}
                                  </span>
                                ))}
                              </span>
                            </div>
                          );
                        })}
                        {file.truncated && (
                          <div className="border-t border-white/[0.06] px-3 pt-1.5 text-[12.5px] text-[#cbd5e8]">
                            File diff truncated.
                          </div>
                        )}
                      </div>
                    ) : (
                      <div className="px-3 py-2 text-[12.5px] text-[#a6b5cf]">No textual diff</div>
                    ))}
                </div>
              );
            })}
        </div>
      )}
      {session.changes_truncated && (
        <p className="text-[#a8c5ff]">
          This list is truncated: the change set is too large to commit.
        </p>
      )}
      {conflicts && !session.commit && (
        <LaneConflictInspector
          laneId={conflicts.lane_id}
          conflicts={conflicts.lane_conflicts}
          branch={branch}
          identity={identity}
          owner={owner}
          onResolved={(res) => {
            setConflictState(null);
            setError(null);
            onSessionChange({
              ...session,
              commit: res.commit_oid ?? session.commit,
              conflicts: [],
            });
            onBranchesChanged?.();
            onLanesChanged?.();
          }}
          onRebased={(res) => {
            setConflictState(res.conflicts.length > 0 ? { ...conflicts, lane_conflicts: res.conflicts } : null);
            if (res.rebased) setError(null);
            onLanesChanged?.();
          }}
        />
      )}
      {session.commit ? (
        <div role="status" className="flex flex-wrap items-center gap-2 text-[#5bdba2]">
          <span>
            Committed <span title={session.commit}>{shortOid(session.commit)}</span> to {branch}
          </span>
          {(rebased || session.rebased) && (
            <span className="rounded-full border border-[#c7a7ff]/30 bg-[#c7a7ff]/12 px-2 py-0.5 text-[12.5px] text-[#c7a7ff]">
              Auto-rebased &amp; committed
            </span>
          )}
          {createdReviewId && onOpenReview && (
            <button
              type="button"
              onClick={() => onOpenReview(createdReviewId)}
              className="pr-pill rounded-full px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
            >
              Open Review ({createdReviewId}) →
            </button>
          )}
          {pendingReview && (
            <button
              type="button"
              disabled={retryingReview}
              onClick={() => void openReviewForBranch(pendingReview)}
              className="pr-action-btn rounded-full px-2.5 py-0.5 font-sans text-[12.5px] disabled:opacity-50"
            >
              {retryingReview ? "Opening Review…" : "Retry Open Review"}
            </button>
          )}
        </div>
      ) : session.discarded ? (
        <p role="status" className="text-[#a6b5cf]">
          Discarded
        </p>
      ) : null}
      {owner && changes.length > 0 && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <div
              role="group"
              aria-label="Commit target"
              className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 text-[12.5px]"
            >
              <button
                type="button"
                disabled={settled || busy}
                onClick={() => setCommitMode("current")}
                className={`rounded-full px-2.5 py-0.5 transition disabled:opacity-50 ${
                  commitMode === "current"
                    ? "bg-[#7f95f8]/25 text-[#f3f6fd]"
                    : "text-[#a6b5cf] hover:text-white"
                }`}
              >
                Current branch
              </button>
              <button
                type="button"
                disabled={settled || busy}
                onClick={() => setCommitMode("new_branch")}
                className={`rounded-full px-2.5 py-0.5 transition disabled:opacity-50 ${
                  commitMode === "new_branch"
                    ? "bg-[#7f95f8]/25 text-[#f3f6fd]"
                    : "text-[#a6b5cf] hover:text-white"
                }`}
              >
                New branch + Review
              </button>
            </div>
            {commitMode === "new_branch" && (
              <input
                value={newBranchName}
                onChange={(e) => setNewBranchName(e.target.value)}
                disabled={settled || busy}
                aria-label="New branch name"
                placeholder={`agent/${session.id}`}
                className="pr-well min-w-[160px] flex-1 rounded-xl px-3 py-1 text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-50"
              />
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={settled || busy}
              aria-label="Commit message"
              placeholder={`Agent session ${session.id}`}
              className="pr-well min-w-[160px] flex-1 rounded-xl px-3 py-1.5 text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-50"
            />
            <button
              type="button"
              disabled={settled || busy || session.changes_truncated || hasUnsavedStepIn}
              title={
                hasUnsavedStepIn
                  ? "Save or discard your Step-In workspace edits before committing"
                  : session.changes_truncated
                    ? "The change set is too large to commit"
                    : undefined
              }
              onClick={handleCommit}
              className="pr-action-btn rounded-full px-3.5 py-1.5 font-sans text-[13.5px] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy
                ? "Working…"
                : commitMode === "new_branch"
                  ? "Commit & Open Review"
                  : `Commit to ${branch}`}
            </button>
            <ConfirmButton
              disabled={settled || busy}
              confirmLabel="Discard"
              onConfirm={() => void run(() => api.discardSession(session.id))}
              className="pr-pill rounded-full px-3.5 py-1.5 font-sans text-[13.5px] text-[#dce4f5] disabled:cursor-not-allowed disabled:opacity-40"
            >
              Discard
            </ConfirmButton>
          </div>
          {hasUnsavedStepIn && !settled && (
            <div role="status" className="text-[12.5px] text-[#cfe0ff]">
              Save or discard Step-In edits before committing.
            </div>
          )}
        </div>
      )}
      {error && (
        <p role="alert" className="break-words text-[#f27c7c]">
          {error}
        </p>
      )}
    </div>
  );
}

const LANE_TONE: Record<string, string> = {
  active: "bg-[#5bdba2]/15 text-[#5bdba2]",
  rebased: "bg-[#9ec0f5]/15 text-[#9ec0f5]",
  conflicted: "bg-[#f27c7c]/15 text-[#f27c7c]",
  merged: "bg-[#c7a7ff]/15 text-[#c7a7ff]",
  discarded: "bg-white/[0.07] text-[#a6b5cf]",
};

/** Agent lanes: create (optionally stacked on a parent), inspect, rebase, resolve and delete. */
function LanesPanel({
  lanes,
  identity,
  owner,
  branchNames,
  agentProfiles,
  activeRef,
  onLanesChanged,
}: {
  lanes: AgentLane[];
  identity: IdentityPreset;
  owner: boolean;
  branchNames: string[];
  agentProfiles: string[];
  activeRef?: string;
  onLanesChanged?: () => void;
}) {
  const [baseBranch, setBaseBranch] = useState("");
  const [parentId, setParentId] = useState("");
  const [profile, setProfile] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [cascade, setCascade] = useState(true);
  const create = useAction();
  const act = useAction();

  const lane = lanes.find((l) => l.lane_id === selectedId) ?? lanes[0] ?? null;
  const base = baseBranch || activeRef || branchNames[0] || "";
  const children = lane ? lanes.filter((l) => l.parent_lane_id === lane.lane_id).length : 0;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    await create.run(async () => {
      const made = await api.createLane({
        base_branch: parentId ? undefined : base || undefined,
        parent_lane_id: parentId || undefined,
        agent_profile: profile || undefined,
      });
      setSelectedId(made.lane_id);
      setParentId("");
      onLanesChanged?.();
    });
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
      <section className="pr-surface flex min-h-[260px] min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:min-h-0">
        <form
          onSubmit={(e) => void handleCreate(e)}
          aria-label="Create lane"
          className="flex flex-wrap items-center gap-2 border-b border-white/[0.06] px-4 py-3"
        >
          <select
            value={parentId ? "" : base}
            onChange={(e) => setBaseBranch(e.target.value)}
            disabled={!owner || Boolean(parentId)}
            aria-label="Base branch"
            title={parentId ? "A stacked lane starts from its parent lane" : "Base branch"}
            className="pr-well max-w-[170px] rounded-full px-3 py-1.5 font-mono text-[13px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
          >
            {parentId && <option value="">↳ from parent lane</option>}
            {!parentId && branchNames.length === 0 && <option value="">default branch</option>}
            {branchNames.map((b) => (
              <option key={b} value={b}>
                {b}
              </option>
            ))}
          </select>
          <select
            value={parentId}
            onChange={(e) => setParentId(e.target.value)}
            disabled={!owner}
            aria-label="Parent lane (stack on)"
            className="pr-well max-w-[200px] rounded-full px-3 py-1.5 font-mono text-[13px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
          >
            <option value="">Not stacked</option>
            {lanes
              .filter((l) => l.status !== "discarded" && l.status !== "merged")
              .map((l) => (
                <option key={l.lane_id} value={l.lane_id}>
                  Stack on {l.lane_id}
                </option>
              ))}
          </select>
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            disabled={!owner}
            aria-label="Agent profile"
            className="pr-well max-w-[200px] rounded-full px-3 py-1.5 font-mono text-[13px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
          >
            <option value="">No agent profile</option>
            {agentProfiles.map((p) => (
              <option key={p} value={p}>
                {p}
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={!owner || create.pending}
            title={owner ? undefined : "Owner only"}
            className="pr-action-btn rounded-full px-4 py-1.5 text-[13.5px] disabled:opacity-45"
          >
            {create.pending ? "Creating…" : "Create Lane"}
          </button>
          {create.error && (
            <p role="alert" className="w-full break-words text-[13.5px] text-[#f27c7c]">
              {create.error}
            </p>
          )}
        </form>
        <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto">
          {lanes.length === 0 ? (
            <div className="flex h-full min-h-[160px] items-center justify-center p-4 text-center font-mono text-[14px] text-[#a6b5cf]">
              No lanes yet — create a private agent branch above.
            </div>
          ) : (
            lanes.map((l) => (
              <button
                key={l.lane_id}
                type="button"
                aria-pressed={lane?.lane_id === l.lane_id}
                onClick={() => setSelectedId(l.lane_id)}
                className={`flex w-full items-start justify-between gap-3 px-4 py-3 text-left transition ${
                  lane?.lane_id === l.lane_id ? "bg-[#7f95f8]/12" : "hover:bg-white/[0.03]"
                }`}
              >
                <div className="min-w-0 font-mono text-[13.5px]">
                  <div className="truncate text-[#f3f6fd]">{l.lane_id}</div>
                  <div className="mt-0.5 truncate text-[12.5px] text-[#a6b5cf]">
                    {l.parent_lane_id ? `↳ stacked on ${l.parent_lane_id}` : `on ${l.base_branch}`}
                    {l.agent_profile ? ` · ${l.agent_profile}` : ""}
                  </div>
                </div>
                <span className="flex shrink-0 items-center gap-2 font-mono text-[12.5px]">
                  {l.conflicts.length > 0 && (
                    <span className="text-[#f27c7c]">{l.conflicts.length} conflict</span>
                  )}
                  <span
                    className={`rounded-full px-2 py-0.5 uppercase ${
                      LANE_TONE[l.status] ?? "bg-white/[0.07] text-[#d2dbee]"
                    }`}
                  >
                    {l.status}
                  </span>
                </span>
              </button>
            ))
          )}
        </div>
      </section>

      <aside className="pr-surface flex shrink-0 flex-col overflow-hidden rounded-2xl lg:w-[368px] xl:w-[420px] 2xl:w-[470px]">
        <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
          <span>Lane Detail</span>
          {lane?.parent_lane_id && <span className="text-[#c7a7ff]">stacked</span>}
        </div>
        {!lane ? (
          <div className="p-4 text-center font-mono text-[13.5px] text-[#a6b5cf]">Select a lane</div>
        ) : (
          <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4 font-mono text-[13px]">
            <div className="pr-well space-y-2 rounded-xl p-3.5">
              {(
                [
                  ["lane", lane.lane_id],
                  ["ref", lane.lane_ref],
                  ["base", lane.base_branch],
                  ["parent", lane.parent_lane_id ?? "—"],
                  ["tip", lane.tip_oid ? shortOid(lane.tip_oid) : "—"],
                  ["owner", lane.owner],
                  ["profile", lane.agent_profile || "—"],
                  ["review", lane.change_id ?? "—"],
                ] as const
              ).map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2 text-[#a6b5cf]">
                  <span>{k}</span>
                  <span className="truncate text-[#dce4f5]" title={v}>
                    {v}
                  </span>
                </div>
              ))}
              <div className="flex justify-between gap-2 text-[#a6b5cf]">
                <span>status</span>
                <span
                  className={`rounded-full px-2 py-0.5 text-[12.5px] uppercase ${
                    LANE_TONE[lane.status] ?? "bg-white/[0.07] text-[#d2dbee]"
                  }`}
                >
                  {lane.status}
                </span>
              </div>
              <div className="flex justify-between gap-2 text-[#a6b5cf]">
                <span>updated</span>
                <Time value={lane.updated_at} />
              </div>
            </div>

            {owner && (
              <div className="flex flex-wrap items-center gap-2 font-sans">
                <button
                  type="button"
                  disabled={act.pending}
                  onClick={() =>
                    void act.run(async () => {
                      await api.rebaseLane(lane.lane_id, { cascade });
                      onLanesChanged?.();
                    })
                  }
                  className="pr-action-btn rounded-full px-3.5 py-1.5 text-[13.5px] disabled:opacity-45"
                >
                  {act.pending ? "Working…" : "Rebase"}
                </button>
                <label className="inline-flex items-center gap-1.5 font-mono text-[13px] text-[#d2dbee]">
                  <input
                    type="checkbox"
                    checked={cascade}
                    onChange={(e) => setCascade(e.target.checked)}
                    className="accent-[#7f95f8]"
                  />
                  Cascade{children > 0 ? ` (${children} stacked)` : ""}
                </label>
                <ConfirmButton
                  disabled={act.pending}
                  confirmLabel="Delete"
                  question={children > 0 ? `${children} stacked lane(s) depend on it.` : "Delete lane?"}
                  onConfirm={() =>
                    void act.run(async () => {
                      await api.deleteLane(lane.lane_id);
                      setSelectedId(null);
                      onLanesChanged?.();
                    })
                  }
                  className="pr-pill rounded-full px-3.5 py-1.5 text-[13.5px] text-[#f27c7c] disabled:opacity-40"
                >
                  Delete
                </ConfirmButton>
              </div>
            )}
            <ErrorNote message={act.error} />

            {lane.conflicts.length > 0 ? (
              <LaneConflictInspector
                key={lane.lane_id}
                laneId={lane.lane_id}
                conflicts={lane.conflicts}
                branch={lane.base_branch}
                identity={identity}
                owner={owner}
                onResolved={() => onLanesChanged?.()}
                onRebased={() => onLanesChanged?.()}
              />
            ) : (
              <div className="text-[#5bdba2]">No conflicts</div>
            )}
          </div>
        )}
      </aside>
    </div>
  );
}

function decisionDot(decision: AuditDecision): string {
  switch (decision) {
    case "allowed":
    case "redacted":
      return "bg-[#5bdba2]";
    case "approval_required":
      return "bg-[#7f95f8]";
    case "denied":
    case "exfiltration_blocked":
    case "rate_limited":
    case "budget_exceeded":
      return "bg-[#f27c7c]";
  }
}

function decisionPillClass(decision: AuditDecision): string {
  switch (decision) {
    case "allowed":
    case "redacted":
      return "bg-[#5bdba2]/14 text-[#5bdba2]";
    case "approval_required":
      return "bg-[#7f95f8]/14 text-[#a8c5ff]";
    case "denied":
    case "exfiltration_blocked":
    case "rate_limited":
    case "budget_exceeded":
      return "bg-[#f27c7c]/16 text-[#f27c7c]";
  }
}

function sessionStatusClass(session: AgentSessionRecord): string {
  if (session.status === "paused" || session.budget?.paused) {
    return "border border-[#9ec0f5]/40 bg-[#7f95f8]/20 text-[#a8c5ff]";
  }
  if (session.status === "budget_exceeded" || session.budget?.terminated) {
    return "border border-[#f27c7c]/40 bg-[#f27c7c]/20 text-[#f27c7c]";
  }
  if (session.status === "running") {
    return "bg-[#7f95f8]/20 text-[#9ec0f5]";
  }
  if (session.status === "stopped" || session.status === "killed") {
    return "bg-white/[0.07] text-[#9eb0cc]";
  }
  if (session.exit_code === 0) {
    return "bg-[#5bdba2]/15 text-[#5bdba2]";
  }
  return "bg-[#f27c7c]/15 text-[#f27c7c]";
}

export function AgentMissionControl({
  identity,
  userPrincipal,
  owner,
  agentProfiles,
  agentSandbox,
  agentSandboxDetail,
  branchNames,
  activeRef,
  onSessionChange,
  onOpenReview,
  onBranchesChanged,
  requestedSessionId,
  onConsumeRequestedSession,
  onHygieneChanged,
  auditEvents,
  approvals,
  sessions,
  mcpAlerts,
  onMcpAlertsChanged,
  budgetAlerts = [],
  onDecided,
  lanes = [],
  onLanesChanged,
  suggestions,
  onSuggestionsChanged,
  onPreviewSuggestion,
  onClearRequestedSession,
}: Props) {
  const noSandbox = agentSandbox === "none";
  // Follows the header's branch until the user picks another one here.
  const [pickedBranch, setPickedBranch] = useState<string | undefined>(undefined);
  const runBranch =
    pickedBranch && branchNames.includes(pickedBranch) ? pickedBranch : activeRef;
  // Follows the "View as" lens until picked here; "" = no profile (the run uses your access).
  const [pickedProfile, setPickedProfile] = useState<string | undefined>(undefined);
  const wantedProfile = pickedProfile ?? identity.agentProfile ?? "";
  const runProfile = agentProfiles.includes(wantedProfile) ? wantedProfile : "";
  const [viewMode, setViewMode] = useState<"stream" | "cage" | "mcp" | "lanes">(() =>
    requestedSessionId ? "cage" : "stream",
  );
  // "" = no lane; "lane:<id>" runs on that lane; "stack:<id>" starts a new lane on top of it.
  const [pickedLane, setPickedLane] = useState("");
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<AuditDecision | "">("");
  const [streamSearch, setStreamSearch] = useState("");
  // Server-side search results; null means "no filter, show the live stream".
  const [searchResults, setSearchResults] = useState<AuditEvent[] | null>(null);
  const [stoppingId, setStoppingId] = useState<string | null>(null);
  const [pausingId, setPausingId] = useState<string | null>(null);
  const [stepInSessionId, setStepInSessionId] = useState<string | null>(null);
  const [stepInDirty, setStepInDirty] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [cageCommand, setCageCommand] = useState("git status -sb");
  const [runEnv, setRunEnv] = useState<"dev" | "preview" | "staging" | "prod">("dev");
  const [spawning, setSpawning] = useState(false);
  const [maxSecs, setMaxSecs] = useState<number>(1800);
  // Why the last run could not start (e.g. 501: no working sandbox). Stays until a run succeeds.
  const [spawnError, setSpawnError] = useState<string | null>(null);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    () => requestedSessionId ?? null,
  );
  const [error, setError] = useState<string | null>(null);

  // A session link (knock or hygiene "Step in"): jump to that cage session, open the step-in
  // editor when the human can still steer it, then clear the request.
  useEffect(() => {
    if (!requestedSessionId) return;
    setViewMode("cage");
    setSelectedSessionId(requestedSessionId);
    const consume = () => {
      onClearRequestedSession?.();
      onConsumeRequestedSession?.();
    };
    const target = sessions.find((s) => s.id === requestedSessionId);
    if (target) {
      if (owner && target.status !== "running" && !target.commit && !target.discarded) {
        setStepInSessionId(target.id);
      }
      consume();
    } else if (sessions.length > 0) {
      consume();
    }
  }, [requestedSessionId, sessions, owner, onClearRequestedSession, onConsumeRequestedSession]);

  const pausedSessions = useMemo(
    () => sessions.filter((s) => s.status === "paused" || Boolean(s.budget?.paused)),
    [sessions],
  );

  const activeSession = useMemo(() => {
    if (selectedSessionId) {
      const found = sessions.find((s) => s.id === selectedSessionId);
      if (found) return found;
    }
    return sessions[0] ?? null;
  }, [sessions, selectedSessionId]);
  // Shown only when the server records why the session ended (e.g. its time limit).
  const endedReason = activeSession?.ended_reason;
  const canStepInActive = Boolean(
    owner &&
      activeSession &&
      activeSession.status !== "running" &&
      !activeSession.commit &&
      !activeSession.discarded,
  );
  const stepInOpen = Boolean(canStepInActive && activeSession && stepInSessionId === activeSession.id);

  useEffect(() => {
    if (!stepInOpen) setStepInDirty(false);
  }, [stepInOpen, activeSession?.id]);

  const handleStopSession = async (session: AgentSessionRecord) => {
    setStoppingId(session.id);
    setError(null);
    try {
      const updated = await api.stopSession(session.id);
      onSessionChange(updated);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setStoppingId(null);
    }
  };

  const handlePauseSession = async (session: AgentSessionRecord) => {
    if (!owner) return;
    setPausingId(session.id);
    setError(null);
    try {
      const updated = await api.pauseSession(session.id);
      onSessionChange(updated);
      setStepInSessionId(updated.id);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setPausingId(null);
    }
  };

  const spawnCageSession = async (overrideCmd?: string) => {
    const cmd = (overrideCmd ?? cageCommand).trim();
    if (!cmd) return;
    setSpawning(true);
    setError(null);
    try {
      const rec = await api.spawnSession({
        command: cmd,
        principal: identity.principal,
        agent_profile: runProfile || undefined,
        env: runEnv,
        max_secs: maxSecs,
        // The branch select is disabled for lane runs; never send its stale value.
        branch: pickedLane.startsWith("lane:") ? undefined : runBranch,
        lane_id: pickedLane.startsWith("lane:") ? pickedLane.slice(5) : undefined,
        parent_lane_id: pickedLane.startsWith("stack:") ? pickedLane.slice(6) : undefined,
      });
      onLanesChanged?.();
      setSpawnError(null);
      setSelectedSessionId(rec.id);
      setViewMode("cage");
    } catch (err: unknown) {
      setSpawnError(errorText(err));
    } finally {
      setSpawning(false);
    }
  };

  const pendingApprovals = approvals.filter((a) => a.status === "pending");
  const activeMcpAlerts = useMemo(
    () => mcpAlerts.filter((a) => a.quarantined || !a.resolved_at),
    [mcpAlerts],
  );
  const hasQuarantinedMcpAlert = useMemo(
    () => activeMcpAlerts.some((a) => a.quarantined),
    [activeMcpAlerts],
  );
  // Proposals already shown on a pending knock's card stay off the strip.
  const unmatchedSuggestions = suggestions.filter(
    (s) => !pendingApprovals.some((ap) => suggestionForApproval([s], ap)),
  );

  const stats = useMemo(() => {
    let bytesScrubbed = 0;
    let blocked = 0;
    for (const ev of auditEvents) {
      bytesScrubbed += ev.bytes_scrubbed;
      if (
        ev.decision === "exfiltration_blocked" ||
        ev.decision === "denied" ||
        ev.decision === "rate_limited" ||
        ev.decision === "budget_exceeded"
      ) {
        blocked += 1;
      }
    }
    return { total: auditEvents.length, bytesScrubbed, blocked };
  }, [auditEvents]);

  // Search and the decision filter run on the server (debounced). Re-runs when a live event
  // arrives so a filtered view stays current without polling.
  const filtering = streamSearch.trim() !== "" || decisionFilter !== "";
  useEffect(() => {
    const q = streamSearch.trim();
    if (!q && !decisionFilter) {
      setSearchResults(null);
      return;
    }
    let active = true;
    const timer = setTimeout(() => {
      api
        .auditList({ q, decision: decisionFilter || undefined, limit: 200 })
        .then((res) => {
          if (active) setSearchResults(res);
        })
        .catch((err: unknown) => {
          if (active) setError(errorText(err));
        });
    }, 300);
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [streamSearch, decisionFilter, auditEvents]);

  const filteredEvents = (filtering ? searchResults : null) ?? auditEvents;

  const selectedEvent = useMemo(() => {
    if (selectedKey) {
      const found = filteredEvents.find((ev) => eventFingerprint(ev) === selectedKey);
      if (found) return found;
    }
    return filteredEvents[0] ?? null;
  }, [filteredEvents, selectedKey]);

  const selectedFp = selectedEvent ? eventFingerprint(selectedEvent) : null;
  // The live stream can hold thousands of events; paint a bounded window to keep the tab snappy.
  const visibleEvents = useMemo(
    () =>
      filteredEvents.length > STREAM_RENDER_CAP
        ? filteredEvents.slice(0, STREAM_RENDER_CAP)
        : filteredEvents,
    [filteredEvents],
  );

  const agentRunCmd = useMemo(() => {
    const groupFlags = identity.groups.map((g) => ` --group ${g}`).join("");
    const profileFlag = runProfile ? ` --profile ${runProfile}` : "";
    return `premier agent run --env ${runEnv} --principal ${identity.principal}${groupFlags}${profileFlag} -- <your-agent>`;
  }, [identity, runProfile, runEnv]);

  const dismissSuggestion = async (s: PolicySuggestion) => {
    setError(null);
    try {
      await api.dismissApprovalSuggestion(s.id);
      onSuggestionsChanged();
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const copyStr = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto p-3 lg:overflow-hidden xl:p-4">
      {/* One condensed toolbar: mode tabs, stream filters, live telemetry and the CLI pill. */}
      <div className="pr-surface flex min-h-[46px] shrink-0 flex-wrap items-center gap-x-3 gap-y-2 rounded-2xl px-3 py-2">
        <div
          role="tablist"
          aria-label="Mission Control view"
          className="inline-flex shrink-0 items-center gap-0.5 rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5"
        >
          {(
            [
              { id: "stream", label: "Activity Log" },
              { id: "mcp", label: "MCP Gateway" },
              { id: "cage", label: "Sandbox" },
              { id: "lanes", label: "Agent Branches" },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={viewMode === tab.id}
              onClick={() => setViewMode(tab.id)}
              onMouseEnter={tab.id === "mcp" ? preloadMcpGateway : undefined}
              onFocus={tab.id === "mcp" ? preloadMcpGateway : undefined}
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-mono text-[13px] transition ${
                viewMode === tab.id ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#f3f6fd]"
              }`}
            >
              <span>{tab.label}</span>
              {tab.id === "cage" && sessions.length > 0 && (
                <span className="tabular-nums text-[#a6b5cf]">{sessions.length}</span>
              )}
              {tab.id === "lanes" && (
                <span className="tabular-nums text-[#a6b5cf]">{lanes.length}</span>
              )}
              {tab.id === "cage" && pausedSessions.length > 0 && (
                <span className="rounded-full bg-[#7f95f8]/22 px-1.5 py-0.5 text-[12px] leading-none tabular-nums text-[#a8c5ff]">
                  {pausedSessions.length} paused
                </span>
              )}
              {tab.id === "mcp" && activeMcpAlerts.length > 0 && (
                <span
                  className={`rounded-full px-1.5 py-0.5 text-[12px] leading-none tabular-nums ${
                    hasQuarantinedMcpAlert
                      ? "bg-[#f27c7c]/22 text-[#f27c7c]"
                      : "bg-[#7f95f8]/22 text-[#a8c5ff]"
                  }`}
                >
                  {activeMcpAlerts.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {viewMode === "stream" && (
          <>
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value as AuditDecision | "")}
              aria-label="Filter audit log by decision"
              disabled={!owner}
              title={owner ? undefined : "Owner only"}
              className="pr-well w-[148px] rounded-full px-3 py-1 font-mono text-[13px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
            >
              <option value="">All decisions</option>
              {DECISIONS.map((d) => (
                <option key={d} value={d}>
                  {d.replace(/_/g, " ")}
                </option>
              ))}
            </select>

            <div
              title={owner ? undefined : "Owner only"}
              className={`pr-well flex min-w-[140px] max-w-[240px] flex-1 items-center gap-2 rounded-full px-3 py-1 ${owner ? "" : "opacity-40"}`}
            >
              <IconSearch className="h-3.5 w-3.5 text-[#a6b5cf]" />
              <input
                type="search"
                value={streamSearch}
                onChange={(e) => setStreamSearch(e.target.value)}
                placeholder="Search audit log…"
                aria-label="Search audit log"
                disabled={!owner}
                className="min-w-0 flex-1 bg-transparent text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
              />
            </div>
          </>
        )}

        <div className="ml-auto flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[12.5px]">
          <span className="text-[#a6b5cf]">
            Blocked{" "}
            <strong className={`tabular-nums ${stats.blocked > 0 ? "text-[#f27c7c]" : "text-[#f3f6fd]"}`}>
              {stats.blocked}
            </strong>
          </span>
          <span className="text-[#a6b5cf]">
            JIT{" "}
            <strong
              className={`tabular-nums ${pendingApprovals.length > 0 ? "text-[#a8c5ff]" : "text-[#dce4f5]"}`}
            >
              {pendingApprovals.length}
            </strong>
          </span>
          <button
            type="button"
            onClick={() => copyStr("cage-cli", agentRunCmd)}
            title={`Copy: ${agentRunCmd}`}
            aria-label="Copy premier agent run command"
            className="pr-pill inline-flex max-w-full items-center gap-1.5 rounded-full px-2.5 py-1 text-[#dce4f5]"
          >
            <IconTerminal className="h-3.5 w-3.5 text-[#9ec0f5]" />
            <span className="hidden 2xl:inline">premier agent run</span>
            {copiedKey === "cage-cli" ? (
              <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
            ) : (
              <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
            )}
          </button>
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="rounded-xl border border-[#f27c7c]/25 bg-[#f27c7c]/10 px-4 py-2 font-mono text-[13px] text-[#f27c7c]"
        >
          {error}
        </div>
      )}

      {/* Paused Budget Alert Banner Strip (surfaces paused sessions in Wire Stream) */}
      {viewMode === "stream" && (pausedSessions.length > 0 || budgetAlerts.length > 0) && (
        <div className="grid max-h-[120px] shrink-0 gap-2 overflow-y-auto md:grid-cols-2">
          {pausedSessions.map((ps) => {
            const alert = budgetAlerts.find((a) => a.session_id === ps.id);
            return (
              <div
                key={ps.id}
                role="alert"
                className="pr-elevated flex flex-wrap items-center justify-between gap-3 rounded-xl border-[#9ec0f5]/35 px-3.5 py-2"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[13.5px] text-[#f3f6fd]">
                    <IconQuarantine className="h-4 w-4 shrink-0 text-[#a8c5ff]" />
                    <span className="font-semibold text-[#a8c5ff]">Paused</span>
                    <span className="truncate text-[#dce4f5]">{ps.id}</span>
                    {(ps.budget?.breached_metric || alert?.metric) && (
                      <span className="rounded-full bg-[#f27c7c]/16 px-2 py-0.5 text-[12px] text-[#f27c7c]">
                        {ps.budget?.breached_metric ?? alert?.metric}
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 truncate font-mono text-[12.5px] text-[#b6c3db]">
                    {ps.budget?.breach_reason ?? alert?.message ?? ps.command}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedSessionId(ps.id);
                    setViewMode("cage");
                  }}
                  className="pr-action-btn shrink-0 rounded-full px-3 py-1 text-[13px]"
                >
                  Inspect &amp; Resume
                </button>
              </div>
            );
          })}
        </div>
      )}

      {/* Knocks: context-rich JIT approvals, scrollable so expanded wire proofs never clip.
          MCP tool calls keep the compact card; egress knocks get the full wire proof. */}
      {pendingApprovals.length > 0 && (
        <div className="grid max-h-[min(38vh,340px)] shrink-0 content-start gap-2.5 overflow-y-auto md:grid-cols-2 2xl:grid-cols-3">
          {pendingApprovals.map((ap) =>
            ap.kind === "mcp_tool" ? (
              <McpApprovalCard key={ap.id} approval={ap} owner={owner} onDecided={onDecided} />
            ) : (
              <KnockApprovalCard
                key={ap.id}
                approval={ap}
                owner={owner}
                variant="queue"
                matchingSuggestion={suggestionForApproval(suggestions, ap)}
                onDecided={onDecided}
                onOpenSession={(sid) => {
                  setSelectedSessionId(sid);
                  setViewMode("cage");
                }}
                onPreviewSuggestion={onPreviewSuggestion}
                onDismissSuggestion={(s) => void dismissSuggestion(s)}
              />
            ),
          )}
        </div>
      )}

      {/* Living policy proposals: repeated approvals the owner can promote to .env.schema */}
      {owner && unmatchedSuggestions.length > 0 && (
        <div className="pr-surface max-h-[132px] shrink-0 space-y-1.5 overflow-y-auto rounded-2xl px-3.5 py-2">
          <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
            Living Policy Proposals ({unmatchedSuggestions.length})
          </div>
          <ul className="space-y-1.5">
            {unmatchedSuggestions.map((s) => (
              <li
                key={s.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#7f95f8]/20 bg-[#7f95f8]/[0.07] px-3 py-1.5 text-[13.5px] text-[#d2dbee]"
              >
                <span className="min-w-0 flex-1 basis-56 break-words">{s.summary}</span>
                <span className="flex shrink-0 items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => onPreviewSuggestion(s)}
                    className="pr-pill rounded-full px-2.5 py-0.5 font-mono text-[12.5px] text-[#f3f6fd]"
                  >
                    Preview diff
                  </button>
                  <button
                    type="button"
                    onClick={() => void dismissSuggestion(s)}
                    className="rounded-full px-2 py-0.5 font-mono text-[12.5px] text-[#a6b5cf] hover:text-white"
                  >
                    Dismiss
                  </button>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Main Split: Live SSE Stream, Live Agent Cage Runner, or Policy-Unified MCP Gateway */}
      {viewMode === "mcp" ? (
        <Suspense fallback={<McpGatewaySkeleton />}>
          <McpGatewayPanel
            identity={identity}
            owner={owner}
            activeRef={activeRef}
            alerts={mcpAlerts}
            auditEvents={auditEvents}
            onAlertsChanged={onMcpAlertsChanged}
          />
        </Suspense>
      ) : viewMode === "cage" ? (
        <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
          <section className="pr-surface flex min-h-[280px] min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:min-h-0">
            {/* Real Host Command Launcher inside Ephemeral premier-proxy Cage */}
            {noSandbox ? (
              <div className="shrink-0 border-b border-white/[0.06] p-3">
                <div className="pr-well flex items-start gap-3 rounded-xl p-3.5">
                  <IconLock className="mt-0.5 h-5 w-5 shrink-0 text-[#a8c5ff]" />
                  <div className="min-w-0 flex-1 space-y-2">
                    <div className="font-mono text-[14px] font-semibold text-[#f3f6fd]">
                      In-browser Sandbox requires Linux
                    </div>
                    {agentSandboxDetail && (
                      <code className="block break-words rounded-md bg-black/40 px-2 py-1 font-mono text-[12.5px] text-[#d2dbee]">
                        {agentSandboxDetail}
                      </code>
                    )}
                    <p className="text-[13.5px] leading-relaxed text-[#b6c3db]">
                      Use MCP Gateway or CLI secret proxying on Windows, macOS, and Linux.
                    </p>
                    <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12.5px]">
                      <button
                        type="button"
                        onClick={() => setViewMode("mcp")}
                        className="inline-flex h-6 items-center rounded-full bg-[#7f95f8] px-3 font-semibold text-[#0b1020] hover:bg-[#98a9fa]"
                      >
                        Open MCP Gateway →
                      </button>
                      {[
                        { key: "nosb-run", label: "premier agent run", text: agentRunCmd },
                        {
                          key: "nosb-serve",
                          label: "premier serve --allow-unsandboxed-agents",
                          text: "premier serve --allow-unsandboxed-agents",
                        },
                      ].map((c) => (
                        <button
                          key={c.key}
                          type="button"
                          onClick={() => copyStr(c.key, c.text)}
                          title={`Copy: ${c.text}`}
                          className="pr-pill inline-flex h-6 items-center gap-1.5 rounded-full px-2.5 text-[#dce4f5]"
                        >
                          <span className="truncate">{c.label}</span>
                          {copiedKey === c.key ? (
                            <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                          ) : (
                            <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
                          )}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void spawnCageSession();
                }}
                className="border-b border-white/[0.06] px-3 py-2"
              >
                <fieldset
                  disabled={!owner || noSandbox}
                  className="m-0 flex min-w-0 flex-col gap-1.5 border-0 p-0"
                >
                  {/* Row 1: command + Run */}
                  <div className="flex items-center gap-1.5">
                    <IconTerminal className="h-[18px] w-[18px] shrink-0 text-[#9ec0f5]" />
                    <input
                      value={cageCommand}
                      onChange={(e) => setCageCommand(e.target.value)}
                      aria-label="Command to run"
                      placeholder="Command to run inside ephemeral premier-proxy capability cage…"
                      className="pr-well h-8 min-w-0 flex-1 rounded-xl px-3 font-mono text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-60"
                    />
                    <button
                      type="submit"
                      disabled={!owner || noSandbox || spawning || !cageCommand.trim()}
                      title={
                        owner ? undefined : "Owner only: starting a caged session needs the repository owner"
                      }
                      className="pr-action-btn inline-flex h-8 shrink-0 items-center gap-1.5 rounded-full px-4 text-[13.5px] disabled:opacity-45"
                    >
                      <IconPlay className="h-4 w-4" />
                      <span>{spawning ? "Spawning…" : "Run in Sandbox"}</span>
                    </button>
                    {agentSandbox === "unsandboxed-allowed" && (
                      <span
                        title={
                          agentSandboxDetail ?? "This server runs agent sessions without a sandbox."
                        }
                        className="inline-flex h-6 shrink-0 items-center rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/12 px-2.5 font-mono text-[12.5px] text-[#a8c5ff]"
                      >
                        unsandboxed-allowed
                      </span>
                    )}
                  </div>

                  {/* Row 2: examples fill the input (never auto-run), compact options, trust note */}
                  <div className="flex flex-wrap items-center gap-1.5 pl-6 font-mono text-[12.5px]">
                    {[
                      { label: "git status", cmd: "git status -sb" },
                      { label: "ls -la", cmd: "ls -la" },
                    ].map((p) => (
                      <button
                        key={p.label}
                        type="button"
                        onClick={() => setCageCommand(p.cmd)}
                        title={`Fill the command with: ${p.cmd}`}
                        className="pr-pill h-6 rounded-full px-2.5 text-[#d2dbee] hover:text-white disabled:opacity-50"
                      >
                        {p.label}
                      </button>
                    ))}
                    {branchNames.length > 0 && (
                      <select
                        value={runBranch ?? ""}
                        onChange={(e) => setPickedBranch(e.target.value)}
                        disabled={!owner || pickedLane.startsWith("lane:")}
                        aria-label="Branch the agent works on"
                        title={
                          !owner
                            ? "Owner only"
                            : pickedLane.startsWith("lane:")
                              ? "A lane run starts from the lane's own branch"
                              : "Branch the agent's private copy is taken from"
                        }
                        className="pr-well h-6 max-w-[150px] rounded-full px-2.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
                      >
                        {branchNames.map((b) => (
                          <option key={b} value={b}>
                            {b}
                          </option>
                        ))}
                      </select>
                    )}
                    {lanes.length > 0 && (
                      <select
                        value={pickedLane}
                        onChange={(e) => setPickedLane(e.target.value)}
                        disabled={!owner}
                        aria-label="Lane the agent works on"
                        title={owner ? "Run on a lane, or stack a new lane on one" : "Owner only"}
                        className="pr-well h-6 max-w-[170px] rounded-full px-2.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
                      >
                        <option value="">No lane</option>
                        {lanes
                          .filter((l) => l.status !== "discarded" && l.status !== "merged")
                          .map((l) => (
                            <optgroup key={l.lane_id} label={l.lane_id}>
                              <option value={`lane:${l.lane_id}`}>Run on {l.lane_id}</option>
                              <option value={`stack:${l.lane_id}`}>Stack on {l.lane_id}</option>
                            </optgroup>
                          ))}
                      </select>
                    )}
                    <select
                      value={runProfile}
                      onChange={(e) => setPickedProfile(e.target.value)}
                      disabled={!owner}
                      aria-label="Agent profile"
                      aria-describedby="agent-profile-help"
                      title={
                        owner
                          ? "An agent profile narrows what the agent may read, write and use. Define profiles under [[agent_profiles]] in the policy."
                          : "Owner only"
                      }
                      className="pr-well h-6 max-w-[170px] rounded-full px-2.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
                    >
                      <option value="">No profile (your access)</option>
                      {agentProfiles.map((p) => (
                        <option key={p} value={p}>
                          {p}
                        </option>
                      ))}
                    </select>
                    <select
                      value={runEnv}
                      onChange={(e) =>
                        setRunEnv(e.target.value as "dev" | "preview" | "staging" | "prod")
                      }
                      disabled={!owner}
                      aria-label="Secret environment"
                      title={owner ? "Secret environment injected via proxy" : "Owner only"}
                      className="pr-well h-6 rounded-full px-2.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
                    >
                      {(["dev", "preview", "staging", "prod"] as const).map((envOpt) => (
                        <option key={envOpt} value={envOpt}>
                          env: {envOpt}
                        </option>
                      ))}
                    </select>
                    <select
                      value={maxSecs}
                      onChange={(e) => setMaxSecs(Number(e.target.value))}
                      disabled={!owner}
                      aria-label="Session time limit"
                      title={owner ? "Session time limit" : "Owner only"}
                      className="pr-well h-6 rounded-full px-2.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none disabled:opacity-40"
                    >
                      {SESSION_LIMITS.map((l) => (
                        <option key={l.secs} value={l.secs}>
                          {l.label}
                        </option>
                      ))}
                    </select>
                    <span
                      className="ml-auto min-w-0 truncate text-[#a6b5cf]"
                      title="The agent works on a private copy containing only the files this identity may read. Nothing reaches the repository until you commit its changes."
                    >
                      Private copy · nothing lands until you commit
                    </span>
                  </div>
                </fieldset>
                <p id="agent-profile-help" className="sr-only">
                  An agent profile narrows what the agent may read, write and use. Define profiles
                  under [[agent_profiles]] in the policy.
                </p>
                {spawnError && (
                  <p role="alert" className="mt-1.5 break-words text-[13.5px] text-[#f27c7c]">
                    The session could not start: {spawnError}
                  </p>
                )}
              </form>
            )}

            {/* Live Streaming Redacted Terminal Output */}
            <div className="min-h-0 flex-1 overflow-auto bg-black/30 p-4 font-mono text-[13.5px] leading-[1.6]">
              {activeSession ? (
                <>
                  <div className="sticky top-0 z-10 -mx-4 -mt-4 mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] bg-[#0b0f1c] px-4 py-2 text-[12.5px] text-[#a6b5cf]">
                    <span className="min-w-0 max-w-full truncate text-[#9ec0f5]" title={activeSession.command}>
                      $ {activeSession.command}
                    </span>
                    <span className="flex flex-wrap items-center gap-2">
                      <span
                        className={`rounded-full px-2 py-0.5 uppercase ${sessionStatusClass(activeSession)}`}
                      >
                        {activeSession.status.replace(/_/g, " ")}
                        {activeSession.exit_code !== undefined &&
                        activeSession.exit_code !== null
                          ? ` (${activeSession.exit_code})`
                          : ""}
                      </span>
                      {owner && activeSession.status === "running" && (
                        <button
                          type="button"
                          disabled={
                            pausingId === activeSession.id || stoppingId === activeSession.id
                          }
                          onClick={() => void handlePauseSession(activeSession)}
                          className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/12 px-2.5 py-0.5 text-[12.5px] font-medium text-[#cfe0ff] transition hover:bg-[#7f95f8]/22 disabled:opacity-50"
                        >
                          <IconPause className="h-3 w-3 text-[#a8c5ff]" />
                          <span>
                            {pausingId === activeSession.id ? "Pausing…" : "Pause & Step In"}
                          </span>
                        </button>
                      )}
                      {owner &&
                        (activeSession.status === "running" ||
                          activeSession.status === "paused") && (
                          <ConfirmButton
                            disabled={stoppingId === activeSession.id || pausingId === activeSession.id}
                            confirmLabel="Stop"
                            question="Stop this session?"
                            onConfirm={() => void handleStopSession(activeSession)}
                            className="rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/14 px-2.5 py-0.5 text-[12.5px] font-medium text-[#f27c7c] transition hover:bg-[#f27c7c]/24 disabled:opacity-50"
                          >
                            {stoppingId === activeSession.id ? "Stopping…" : "Stop"}
                          </ConfirmButton>
                        )}
                      {canStepInActive && (
                        <button
                          type="button"
                          onClick={() =>
                            setStepInSessionId((cur) =>
                              cur === activeSession.id ? null : activeSession.id,
                            )
                          }
                          className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[12.5px] font-medium transition ${
                            stepInOpen
                              ? "pr-pill-active"
                              : "border border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#cfe0ff] hover:bg-[#7f95f8]/20"
                          }`}
                        >
                          <IconEdit className="h-3 w-3" />
                          <span>
                            {stepInOpen ? "Hide Step-In Editor" : "Step In & Edit Workspace"}
                          </span>
                        </button>
                      )}
                      {activeSession.sandbox === "bwrap" && (
                        <span className="rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-2 py-0.5 text-[12.5px] text-[#5bdba2]">
                          Sandboxed
                        </span>
                      )}
                      {activeSession.sandbox === "none" && (
                        <span
                          title="This session ran without a sandbox."
                          className="rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/12 px-2 py-0.5 text-[12.5px] text-[#a8c5ff]"
                        >
                          Unsandboxed
                        </span>
                      )}
                      {activeSession.branch && (
                        <span className="text-[#a6b5cf]">on {activeSession.branch}</span>
                      )}
                      {activeSession.bytes_scrubbed > 0 && (
                        <span className="text-[#67d6dc]">
                          {activeSession.bytes_scrubbed}B scrubbed
                        </span>
                      )}
                    </span>
                  </div>
                  {owner && activeSession.insights && activeSession.insights.length > 0 && (
                    <div
                      role="status"
                      className="mb-2.5 space-y-1 rounded-xl border border-[#9ec0f5]/28 bg-[#7f95f8]/8 px-3 py-2 text-[#cfe0ff]"
                    >
                      {activeSession.insights.map((ins) => (
                        <div
                          key={ins.id}
                          className="flex flex-wrap items-start justify-between gap-2"
                        >
                          <div className="flex min-w-0 flex-1 items-start gap-2">
                            <IconAmbientPulse className="mt-0.5 h-4 w-4 shrink-0 text-[#a8c5ff]" />
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-2 text-[13px] font-medium">
                                <span>{ins.title}</span>
                                <span className="rounded-full bg-black/25 px-1.5 py-0.5 text-[12px] opacity-80">
                                  {ins.metric_value}/{ins.threshold}
                                </span>
                              </div>
                              <div className="mt-0.5 font-sans text-[13px] opacity-80">
                                {ins.detail}
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                      <div className="flex flex-wrap items-center justify-end gap-2 pt-1">
                        {canStepInActive && !stepInOpen && (
                          <button
                            type="button"
                            onClick={() => setStepInSessionId(activeSession.id)}
                            className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/12 px-2.5 py-0.5 text-[12.5px] font-medium text-[#cfe0ff] transition hover:bg-[#7f95f8]/20"
                          >
                            <IconEdit className="h-3 w-3" />
                            <span>Step In & Edit Workspace</span>
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                  {endedReason && (
                    <div className="mb-3 text-[13px] text-[#cbd5e8]">Ended: {endedReason}</div>
                  )}
                  {activeSession.output_lines.length === 0 ? (
                    <div className="text-[#a6b5cf]">Waiting for output…</div>
                  ) : (
                    activeSession.output_lines.map((ln, idx) => (
                      <div key={idx} className="whitespace-pre-wrap break-all text-[#dce4f5]">
                        {ln}
                      </div>
                    ))
                  )}
                </>
              ) : (
                <div className="flex h-full min-h-[160px] items-center justify-center text-[#a6b5cf]">
                  {noSandbox
                    ? "No sandbox sessions. The Sandbox needs Linux on this server."
                    : owner
                      ? "Run a command above to start an isolated sandbox session"
                      : "Starting a sandbox session is owner only"}
                </div>
              )}
            </div>
            {owner && activeSession && stepInOpen && (
              <Suspense
                fallback={
                  <div
                    aria-busy="true"
                    className="min-h-[300px] max-h-[58%] shrink-0 overflow-hidden border-t border-[#9ec0f5]/22 bg-[#0b0f1c]"
                  >
                    <StepInSkeleton />
                  </div>
                }
              >
                <SessionStepInEditor
                  key={`stepin-${activeSession.id}`}
                  session={activeSession}
                  onSessionChange={onSessionChange}
                  onDirtyChange={setStepInDirty}
                  onResumed={(newSession) => {
                    onSessionChange(newSession);
                    setSelectedSessionId(newSession.id);
                    setStepInSessionId(null);
                    setStepInDirty(false);
                  }}
                  onClose={() => {
                    setStepInSessionId(null);
                    setStepInDirty(false);
                  }}
                />
              </Suspense>
            )}
            {activeSession &&
              activeSession.status !== "running" &&
              activeSession.status !== "paused" && (
                <SessionChanges
                  key={activeSession.id}
                  session={activeSession}
                  identity={identity}
                  userPrincipal={userPrincipal}
                  owner={owner}
                  hasUnsavedStepIn={stepInOpen && stepInDirty}
                  onSessionChange={onSessionChange}
                  onOpenReview={onOpenReview}
                  onBranchesChanged={onBranchesChanged}
                  onLanesChanged={onLanesChanged}
                  onHygieneChanged={onHygieneChanged}
                />
              )}
          </section>

          {/* Right: Session History & Injected Placeholders Proof */}
          <aside className="pr-surface flex shrink-0 flex-col overflow-hidden rounded-2xl lg:w-[368px] xl:w-[420px] 2xl:w-[470px]">
            <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
              <span>Sandbox Sessions ({sessions.length})</span>
              {activeSession && <span className="text-[#a6b5cf]">{activeSession.id}</span>}
            </div>

            <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-3 font-mono text-[13px]">
              {/* Sessions first and sticky: the list is the navigation for everything below it. */}
              <div className="sticky top-0 z-10 -mx-3 -mt-3 mb-0 border-b border-white/[0.06] bg-[#0b0f1c] px-3 py-2">
                {sessions.length === 0 ? (
                  <div className="py-2 text-center text-[13px] text-[#a6b5cf]">
                    No cage sessions yet
                  </div>
                ) : (
                  <div className="max-h-[200px] space-y-1.5 overflow-y-auto">
                    {sessions.map((s) => {
                      const sel = activeSession?.id === s.id;
                      const hasInsights = owner && (s.insights?.length ?? 0) > 0;
                      return (
                        <button
                          key={s.id}
                          type="button"
                          aria-pressed={sel}
                          onClick={() => setSelectedSessionId(s.id)}
                          className={`flex w-full items-center justify-between gap-2 rounded-xl px-3 py-1.5 text-left transition ${
                            sel
                              ? "bg-[#7f95f8]/18 text-[#f3f6fd]"
                              : "pr-well text-[#d2dbee] hover:bg-white/[0.04]"
                          }`}
                        >
                          <span className="flex min-w-0 items-center gap-1.5">
                            {hasInsights && (
                              <span
                                title={s.insights?.[0]?.title}
                                className="h-2 w-2 shrink-0 rounded-full bg-[#7f95f8]"
                              />
                            )}
                            <span className="truncate">{s.command}</span>
                          </span>
                          <span className="flex shrink-0 items-center gap-1.5 text-[12.5px]">
                            {s.resumed_from && (
                              <span className="rounded-full bg-[#7f95f8]/15 px-1.5 py-0.5 text-[12px] text-[#9ec0f5]">
                                resumed
                              </span>
                            )}
                            <span
                              className={`rounded-full px-2 py-0.5 text-[12px] ${sessionStatusClass(s)}`}
                            >
                              {s.status.replace(/_/g, " ")}
                            </span>
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              {activeSession && (
                <BudgetGauges
                  session={activeSession}
                  owner={owner}
                  onSessionChange={onSessionChange}
                />
              )}

              {activeSession && (
                <div className="pr-well space-y-1.5 rounded-xl p-3">
                  <div className="flex justify-between gap-2 text-[#a6b5cf]">
                    <span>proxy</span>
                    <span className="truncate text-[#5bdba2]">{activeSession.proxy_url}</span>
                  </div>
                  <div className="flex justify-between gap-2 text-[#a6b5cf]">
                    <span>actor</span>
                    <span className="truncate text-[#f3f6fd]">
                      {activeSession.principal}
                      {activeSession.agent_profile ? ` ∩ ${activeSession.agent_profile}` : ""}
                    </span>
                  </div>
                  {activeSession.resumed_from && (
                    <div className="flex justify-between gap-2 text-[#a6b5cf]">
                      <span>resumed from</span>
                      <button
                        type="button"
                        onClick={() => setSelectedSessionId(activeSession.resumed_from ?? null)}
                        className="truncate text-[#9ec0f5] hover:underline"
                      >
                        {activeSession.resumed_from}
                      </button>
                    </div>
                  )}
                  <div className="border-t border-white/[0.06] pt-2">
                    <div className="text-[12px] uppercase text-[#a6b5cf]">
                      Injected Placeholders (use ≠ read)
                    </div>
                    {Object.keys(activeSession.placeholders).length === 0 ? (
                      <div className="mt-1 text-[12.5px] text-[#a6b5cf]">None configured</div>
                    ) : (
                      <div className="mt-1.5 space-y-1">
                        {Object.entries(activeSession.placeholders).map(([k, v]) => (
                          <div
                            key={k}
                            className="flex items-center justify-between gap-2 rounded-lg bg-black/30 px-2.5 py-1 text-[12.5px]"
                          >
                            <span className="text-[#dce4f5]">{k}</span>
                            <span className="truncate text-[#9ec0f5]">{v}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {activeSession?.provenance_steps && activeSession.provenance_steps.length > 0 && (
                <details className="pr-well group rounded-xl px-3 py-2">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-2 text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                    <span>
                      Provenance{" "}
                      <span className="tabular-nums">({activeSession.provenance_steps.length})</span>
                    </span>
                    <IconChevron
                      direction="down"
                      className="h-3.5 w-3.5 transition group-open:rotate-180"
                    />
                  </summary>
                  <div className="mt-2">
                    <ProvenanceTimeline steps={activeSession.provenance_steps} />
                  </div>
                </details>
              )}
            </div>
          </aside>
        </div>
      ) : viewMode === "lanes" ? (
        <LanesPanel
          lanes={lanes}
          identity={identity}
          owner={owner}
          branchNames={branchNames}
          agentProfiles={agentProfiles}
          activeRef={runBranch}
          onLanesChanged={onLanesChanged}
        />
      ) : (
      <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
        <section className="pr-surface flex min-h-[260px] min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:min-h-0">
          <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
            <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[12.5px]">
              <span className="uppercase tracking-wider text-[#a6b5cf]">
                {filtering ? "Audit Search" : "Agent Activity Log"}{" "}
                <span className="tabular-nums">({filteredEvents.length})</span>
              </span>
              <span className="text-[#a6b5cf]">
                Scrubbed{" "}
                <strong className="tabular-nums text-[#67d6dc]">{stats.bytesScrubbed} B</strong>
              </span>
            </span>
            {owner && (
              <a
                href={repoPath("/v1/audit/export")}
                download
                title="Download the full audit log as NDJSON"
                className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee] hover:text-[#f3f6fd]"
              >
                <IconDownload className="h-4 w-4" />
                <span>Export log</span>
              </a>
            )}
          </div>

          <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto">
            {filteredEvents.length === 0 ? (
              <div className="flex h-full min-h-[160px] flex-col items-center justify-center gap-3 font-mono text-[14px] text-[#a6b5cf]">
<span className="max-w-md px-4 text-center leading-relaxed">
                  {owner
                    ? "No agent calls logged yet. Connect an agent via MCP Gateway."
                    : "The audit log is owner only"}
                </span>
                {owner && (
                  <div className="flex flex-wrap items-center justify-center gap-1.5 text-[12.5px]">
                    <button
                      type="button"
                      onClick={() => setViewMode("mcp")}
                      className="inline-flex h-6 items-center rounded-full bg-[#7f95f8] px-3 font-semibold text-[#0b1020] hover:bg-[#98a9fa]"
                    >
                      Configure MCP Gateway →
                    </button>
                    <button
                      type="button"
                      onClick={() => setViewMode("cage")}
                      className="pr-pill inline-flex h-6 items-center rounded-full px-3 text-[#dce4f5]"
                    >
                      Sandbox
                    </button>
                  </div>
                )}
              </div>
            ) : (
              visibleEvents.map((ev) => {
                const fp = eventFingerprint(ev);
                const active = selectedFp === fp;
                return (
                  <button
                    key={fp}
                    type="button"
                    onClick={() => setSelectedKey(fp)}
                    className={`flex w-full items-start justify-between gap-3 px-4 py-2 text-left transition ${
                      active ? "bg-[#7f95f8]/12" : "hover:bg-white/[0.03]"
                    }`}
                  >
                    <div className="flex min-w-0 items-start gap-3">
                      <span
                        className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${decisionDot(ev.decision)}`}
                      />
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2 font-mono text-[13.5px] text-[#f3f6fd]">
                          <span>{ev.capability ?? ev.action}</span>
                          {ev.decision === "budget_exceeded" && (
                            <span
                              className={`rounded-full px-2 py-0.5 text-[12px] ${decisionPillClass(ev.decision)}`}
                            >
                              budget exceeded
                            </span>
                          )}
                          {ev.target && (
                            <span className="truncate text-[#a6b5cf]">{ev.target}</span>
                          )}
                        </div>
                        <div className="mt-0.5 truncate text-[13.5px] text-[#a6b5cf]">
                          {ev.reason}
                        </div>
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-2 font-mono text-[12.5px] text-[#a6b5cf]">
                      {ev.bytes_scrubbed > 0 && (
                        <span className="text-[#67d6dc]">{ev.bytes_scrubbed}B</span>
                      )}
                      <Time value={ev.timestamp} />
                    </div>
                  </button>
                );
              })
            )}
            {filteredEvents.length > STREAM_RENDER_CAP && (
              <div className="px-4 py-2 text-center font-mono text-[12.5px] text-[#a6b5cf]">
                Showing {STREAM_RENDER_CAP} of {filteredEvents.length} events — filter or export for
                more.
              </div>
            )}
          </div>
        </section>

        <aside
          className={`pr-surface shrink-0 flex-col overflow-hidden rounded-2xl lg:flex lg:w-[368px] xl:w-[420px] 2xl:w-[470px] ${
            selectedEvent ? "flex" : "hidden"
          }`}
        >
          <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
            <span className="inline-flex items-center gap-2 font-mono text-[13px] uppercase tracking-wider text-[#9ec0f5]">
              <IconIntersection className="h-[18px] w-[18px]" />
              <span>Wire Detail</span>
            </span>
            {selectedEvent && (
              <button
                type="button"
                onClick={() => copyStr("ev-json", JSON.stringify(selectedEvent, null, 2))}
                className="pr-pill inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee]"
              >
                {copiedKey === "ev-json" ? (
                  <IconCheck className="h-4 w-4 text-[#5bdba2]" />
                ) : (
                  <IconCopy className="h-4 w-4" />
                )}
                <span>JSON</span>
              </button>
            )}
          </div>

          <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
            {!selectedEvent && (
              <div className="flex h-full min-h-[160px] items-center justify-center text-center font-mono text-[13.5px] text-[#a6b5cf]">
                Select an event to inspect
              </div>
            )}
            {selectedEvent && (
              <div className="pr-well space-y-2 rounded-xl p-3.5 font-mono text-[13px]">
                <div className="flex justify-between gap-2 text-[#a6b5cf]">
                  <span>actor</span>
                  <span className="truncate text-[#f3f6fd]">
                    {selectedEvent.principal}
                    {selectedEvent.agent_profile ? ` ∩ ${selectedEvent.agent_profile}` : ""}
                  </span>
                </div>
                <div className="flex justify-between gap-2 text-[#a6b5cf]">
                  <span>component</span>
                  <span className="text-[#dce4f5]">{selectedEvent.component}</span>
                </div>
                <div className="flex justify-between gap-2 text-[#a6b5cf]">
                  <span>decision</span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[12.5px] ${decisionPillClass(selectedEvent.decision)}`}
                  >
                    {selectedEvent.decision.replace(/_/g, " ")}
                  </span>
                </div>
                {selectedEvent.target && (
                  <div className="flex justify-between gap-2 text-[#a6b5cf]">
                    <span>target</span>
                    <span className="truncate text-[#dce4f5]">{selectedEvent.target}</span>
                  </div>
                )}
                <div className="border-t border-white/[0.06] pt-2 text-[#d2dbee]">
                  {selectedEvent.reason}
                </div>
              </div>
            )}
          </div>
        </aside>
      </div>
      )}
    </div>
  );
}
