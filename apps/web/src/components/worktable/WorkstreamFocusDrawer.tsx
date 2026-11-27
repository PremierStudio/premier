import { useEffect, useRef, useState } from "react";
import {
  api,
  ApiError,
  branchNameError,
  errorText,
  shortOid,
  type AgentSessionRecord,
  type AuditDecision,
  type AuditEvent,
  type GitCommitSummary,
  type IdentityPreset,
  type PendingApproval,
  type PublishBranchResponse,
  type SessionDiffResponse,
  type SquashPreviewResponse,
  type WorktableBranch,
  type WorktableResponse,
  type WorktableReviewSummary,
} from "../../api";
import { plural } from "../../lib/format";
import {
  detectLanguage,
  parseUnifiedPatch,
  tokenClassName,
  tokenizeLine,
} from "../../lib/highlight";
import { ConfirmButton, ErrorNote, Time, useAction } from "../forms";
import { CodeLinesSkeleton, SettingsRowsSkeleton } from "../ViewSkeletons";
import {
  IconBranches,
  IconBranchRef,
  IconCage,
  IconChanges,
  IconCheck,
  IconChevron,
  IconClose,
  IconCode,
  IconCopy,
  IconDeclassify,
  IconIntersection,
  IconLock,
  IconPlay,
  IconQuarantine,
  IconShieldCheck,
  IconTerminal,
  IconVault,
} from "../Icons";
import {
  formatByteCount,
  formatElapsedSeconds,
  isPrivateVisibility,
  sessionHasUncommittedChanges,
  visibilitySummary,
  type FocusTarget,
} from "./types";
import { ApprovalRow } from "./JudgmentRail";

export interface WorkstreamFocusDrawerProps {
  focus: FocusTarget | null;
  owner: boolean;
  identity: IdentityPreset;
  nowMs: number;
  worktable: WorktableResponse | null;
  sessions: AgentSessionRecord[];
  pendingApprovals: PendingApproval[];
  auditEvents: AuditEvent[];
  onClose: () => void;
  onFocus: (target: FocusTarget) => void;
  onApprovalDecided: () => void;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onRefreshWorktable: () => void;
  onBranchesChanged: () => void;
  onOpenCode: (branch: string, path?: string) => void;
  onOpenChanges: (oid?: string) => void;
  onOpenReview: (changeId: string) => void;
  onOpenBranches: (branchName: string) => void;
  onOpenAgents: (sessionId?: string) => void;
}

const PUBLISH_RULE = "A file is published only if anonymous visitors may read it under the policy.";

const CHANGE_TONE = {
  added: "text-[#5bdba2]",
  modified: "text-[#9ec0f5]",
  deleted: "text-[#f27c7c]",
} as const;

// Recent-commit lists per (lens, branch): re-focusing the same branch within 15s does not refetch.
const COMMITS_FRESH_MS = 15_000;
const commitsCache = new Map<string, { list: GitCommitSummary[]; at: number }>();

const JUMP_BTN =
  "pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[13px] text-[#dce4f5] hover:text-white";

function commitErrorText(err: unknown): string {
  if (err instanceof ApiError) {
    const msg = typeof err.body?.error === "string" ? err.body.error : "";
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

function reasonMap(raw: SquashPreviewResponse["held_back_reasons"]): Record<string, string> {
  if (!raw) return {};
  if (!Array.isArray(raw)) return raw;
  return Object.fromEntries(raw.map((r) => [r.path, r.reason]));
}

const stringList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

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
    default:
      return "bg-[#f27c7c]";
  }
}

/** Fixed-height shimmer block standing in for a loading diff / preview. */
function CodeBlockSkeleton() {
  return (
    <div className="pr-well h-24 overflow-hidden rounded-xl">
      <CodeLinesSkeleton />
    </div>
  );
}

/** Session diff viewer & owner commit/branch+review/discard controls; keyed on session.id. */
function DrawerSessionDiffControls({
  session,
  owner,
  identity,
  onSessionChange,
  onRefreshWorktable,
  onBranchesChanged,
  onOpenReview,
}: {
  session: AgentSessionRecord;
  owner: boolean;
  identity: IdentityPreset;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onRefreshWorktable: () => void;
  onBranchesChanged: () => void;
  onOpenReview: (changeId: string) => void;
}) {
  const [diffOpen, setDiffOpen] = useState(false);
  const [diffData, setDiffData] = useState<SessionDiffResponse | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(() => new Set());

  const [mode, setMode] = useState<"current" | "new_branch">("current");
  const [message, setMessage] = useState("");
  const [newBranch, setNewBranch] = useState(`agent/${session.id.slice(0, 8)}`);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createdReviewId, setCreatedReviewId] = useState<string | null>(null);

  const changes = session.changes ?? [];
  const settled = Boolean(session.commit) || Boolean(session.discarded);
  const targetBranchLabel = session.branch || "default branch";

  const loadDiff = async (focusPath?: string) => {
    setDiffOpen(true);
    if (diffData) {
      if (focusPath) {
        setExpandedPaths((prev) => new Set(prev).add(focusPath));
      }
      return;
    }
    setLoadingDiff(true);
    setDiffError(null);
    try {
      const res = await api.sessionDiff(session.id);
      setDiffData(res);
      setExpandedPaths(
        focusPath ? new Set([focusPath]) : new Set(res.files.map((f) => f.path)),
      );
    } catch (err: unknown) {
      setDiffError(errorText(err));
    } finally {
      setLoadingDiff(false);
    }
  };

  const toggleDiff = () => {
    if (diffOpen) setDiffOpen(false);
    else void loadDiff();
  };

  const togglePath = (path: string) => {
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const runMutation = async (fn: () => Promise<AgentSessionRecord>) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await fn();
      onSessionChange(updated);
      onRefreshWorktable();
    } catch (err: unknown) {
      setError(commitErrorText(err));
    } finally {
      setBusy(false);
    }
  };

  const handleCommit = () => {
    const commitMsg = message.trim() || undefined;
    if (mode === "current") {
      void runMutation(async () => {
        const res = await api.commitSession(session.id, commitMsg);
        onBranchesChanged();
        return { ...session, commit: res.commit, branch: res.branch || session.branch };
      });
      return;
    }

    const branchName = newBranch.trim();
    const nameErr = branchName ? branchNameError(branchName) : "Enter a branch name.";
    if (nameErr) {
      setError(nameErr);
      return;
    }

    void runMutation(async () => {
      const res = await api.commitSession(session.id, commitMsg, { new_branch: branchName });
      const finalBranch = res.branch || branchName;
      onBranchesChanged();
      const review = await api.createReview({
        title: commitMsg || `Agent session ${session.id.slice(0, 8)}`,
        branch: finalBranch,
        base_ref: session.branch || undefined,
        author: identity.principal === "anonymous" ? session.principal : identity.principal,
        delegated_agent: session.agent_profile || null,
        session_id: session.id,
      });
      setCreatedReviewId(review.change_id);
      onOpenReview(review.change_id);
      return { ...session, commit: res.commit, branch: finalBranch };
    });
  };

  const handleDiscard = () => {
    void runMutation(() => api.discardSession(session.id));
  };

  return (
    <div className="space-y-2.5 border-t border-white/[0.06] pt-3 font-mono text-[13px]">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
          Workspace Changes ({changes.length})
        </span>
        {changes.length > 0 && !session.discarded && (
          <button
            type="button"
            onClick={toggleDiff}
            className={`rounded-full px-2.5 py-0.5 text-[12.5px] transition ${
              diffOpen ? "pr-pill-active" : "pr-pill text-[#9ec0f5] hover:text-[#f3f6fd]"
            }`}
          >
            {diffOpen ? "Hide diff" : "Expand diff"}
          </button>
        )}
      </div>

      {changes.length > 0 && (
        <ul className="space-y-1">
          {changes.map((c) => (
            <li key={c.path}>
              <button
                type="button"
                disabled={Boolean(session.discarded)}
                onClick={() => void loadDiff(c.path)}
                className="flex w-full items-center justify-between gap-2 rounded-lg bg-black/30 px-2.5 py-1.5 text-left transition hover:bg-white/[0.05] disabled:cursor-default"
              >
                <span className="min-w-0 truncate text-[#dce4f5]" title={c.path}>
                  {c.path}
                </span>
                <span className="flex shrink-0 items-center gap-2 text-[12.5px]">
                  <span className={CHANGE_TONE[c.kind] ?? "text-[#d2dbee]"}>{c.kind}</span>
                  {c.kind !== "deleted" && (
                    <span className="text-[#a6b5cf]">{formatByteCount(c.size)}</span>
                  )}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      {diffOpen && (
        <div className="space-y-2">
          {loadingDiff && <CodeBlockSkeleton />}
          <ErrorNote message={diffError} />
          {diffData?.truncated && (
            <p className="text-[12.5px] text-[#cbd5e8]">Diff output was truncated by the server.</p>
          )}
          {diffData?.files.map((file) => {
            const expanded = expandedPaths.has(file.path);
            const lang = detectLanguage(file.path);
            const parsed = !file.binary && file.patch ? parseUnifiedPatch(file.patch) : null;
            return (
              <div key={file.path} className="pr-well overflow-hidden rounded-xl">
                <button
                  type="button"
                  onClick={() => togglePath(file.path)}
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
                    <span className={CHANGE_TONE[file.kind] ?? "text-[#d2dbee]"}>{file.kind}</span>
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
                    <div className="px-3 py-2 text-[12.5px] text-[#a6b5cf]">
                      Binary file ({formatByteCount(file.size)}) — inline diff not shown.
                    </div>
                  ) : parsed && parsed.lines.length > 0 ? (
                    <div className="max-h-60 overflow-auto py-1 text-[12.5px] leading-[1.55]">
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
                        return (
                          <div key={li} className={`flex px-2 ${rowBg}`}>
                            <span className="w-7 shrink-0 select-none pr-1.5 text-right text-[12px] text-[#6b7b98]">
                              {dl.oldLine ?? ""}
                            </span>
                            <span className="w-7 shrink-0 select-none pr-1.5 text-right text-[12px] text-[#6b7b98]">
                              {dl.newLine ?? ""}
                            </span>
                            <span className={`w-3.5 shrink-0 select-none ${sigilColor}`}>
                              {dl.sigil}
                            </span>
                            <span className="whitespace-pre">
                              {tokenizeLine(dl.body, lang).map((tok, ti) => (
                                <span key={ti} className={tokenClassName(tok.kind)}>
                                  {tok.text}
                                </span>
                              ))}
                            </span>
                          </div>
                        );
                      })}
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

      {session.commit ? (
        <div role="status" className="flex flex-wrap items-center gap-2 text-[#5bdba2]">
          <span>
            Committed {shortOid(session.commit)} to {targetBranchLabel}
          </span>
          {createdReviewId && (
            <button
              type="button"
              onClick={() => onOpenReview(createdReviewId)}
              className="pr-pill rounded-full px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
            >
              Open Review ({createdReviewId}) →
            </button>
          )}
        </div>
      ) : session.discarded ? (
        <p role="status" className="text-[#a6b5cf]">
          Workspace discarded
        </p>
      ) : null}

      {owner && sessionHasUncommittedChanges(session) && (
        <div className="space-y-2 border-t border-white/[0.06] pt-2.5 font-sans">
          <div className="flex flex-wrap items-center gap-2">
            <div
              role="group"
              aria-label="Commit target"
              className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 font-mono text-[12.5px]"
            >
              <button
                type="button"
                disabled={settled || busy}
                aria-pressed={mode === "current"}
                onClick={() => setMode("current")}
                className={`rounded-full px-2.5 py-0.5 transition disabled:opacity-50 ${
                  mode === "current"
                    ? "bg-[#7f95f8]/25 text-[#f3f6fd]"
                    : "text-[#a6b5cf] hover:text-white"
                }`}
              >
                Commit to {targetBranchLabel}
              </button>
              <button
                type="button"
                disabled={settled || busy}
                aria-pressed={mode === "new_branch"}
                onClick={() => setMode("new_branch")}
                className={`rounded-full px-2.5 py-0.5 transition disabled:opacity-50 ${
                  mode === "new_branch"
                    ? "bg-[#7f95f8]/25 text-[#f3f6fd]"
                    : "text-[#a6b5cf] hover:text-white"
                }`}
              >
                Branch + Review
              </button>
            </div>
            {mode === "new_branch" && (
              <input
                value={newBranch}
                onChange={(e) => setNewBranch(e.target.value)}
                disabled={settled || busy}
                aria-label="New branch name"
                className="pr-well min-w-[140px] flex-1 rounded-xl px-2.5 py-1 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-50"
              />
            )}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={settled || busy}
              aria-label="Commit message"
              placeholder={`Agent session ${session.id.slice(0, 8)}`}
              className="pr-well min-w-[150px] flex-1 rounded-xl px-2.5 py-1.5 text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-50"
            />
            <button
              type="button"
              disabled={settled || busy || session.changes_truncated}
              onClick={handleCommit}
              className="pr-action-btn rounded-full px-3.5 py-1.5 text-[13.5px] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Working…" : mode === "new_branch" ? "Commit & Review" : "Commit"}
            </button>
            <ConfirmButton
              disabled={settled || busy}
              confirmLabel="Discard"
              onConfirm={handleDiscard}
              className="pr-pill rounded-full px-3 py-1.5 text-[13.5px] text-[#dce4f5] disabled:cursor-not-allowed disabled:opacity-40"
            >
              Discard
            </ConfirmButton>
          </div>
          <ErrorNote message={error} />
        </div>
      )}
    </div>
  );
}

/** Owner-only Scrub & Publish preview panel for a non-default branch. Keyed on branch.name. */
function DrawerSquashDeclassify({
  branch,
  defaultBranch,
  onOpenCode,
  onRefreshWorktable,
  onBranchesChanged,
}: {
  branch: WorktableBranch;
  defaultBranch: string;
  onOpenCode: (branch: string, path?: string) => void;
  onRefreshWorktable: () => void;
  onBranchesChanged: () => void;
}) {
  const [preview, setPreview] = useState<SquashPreviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [summaryMsg, setSummaryMsg] = useState("");
  const [publishing, setPublishing] = useState(false);
  const [receipt, setReceipt] = useState<PublishBranchResponse | null>(null);
  const [refused, setRefused] = useState<{
    conflicts: string[];
    hidden: number;
    blocked: string[];
    hiddenBlocked: number;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedTrailer, setCopiedTrailer] = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    setRefused(null);
    setReceipt(null);
    api
      .squashPreview(branch.name, defaultBranch)
      .then((res) => {
        if (active) setPreview(res);
      })
      .catch((err: unknown) => {
        if (active) setError(errorText(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [branch.name, defaultBranch]);

  const refreshPreview = async (msg = summaryMsg) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.squashPreview(branch.name, defaultBranch, msg.trim() || undefined);
      setPreview(res);
      setRefused(null);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setLoading(false);
    }
  };

  const handlePublish = async () => {
    setPublishing(true);
    setError(null);
    setReceipt(null);
    setRefused(null);
    try {
      const res = await api.publishBranch(
        branch.name,
        defaultBranch,
        summaryMsg.trim() || undefined,
      );
      setReceipt(res);
      setSummaryMsg("");
      onRefreshWorktable();
      onBranchesChanged();
      await refreshPreview("");
    } catch (err: unknown) {
      const body = err instanceof ApiError && err.status === 409 ? err.body : null;
      const conflicts = stringList(body?.conflicts);
      const hidden = typeof body?.hidden_conflicts === "number" ? body.hidden_conflicts : 0;
      const blocked = stringList(body?.blocked);
      const hiddenBlocked = typeof body?.hidden_blocked === "number" ? body.hidden_blocked : 0;
      if (conflicts.length + hidden + blocked.length + hiddenBlocked > 0) {
        setRefused({ conflicts, hidden, blocked, hiddenBlocked });
      }
      setError(errorText(err));
    } finally {
      setPublishing(false);
    }
  };

  const conflicts = refused?.conflicts ?? preview?.conflicts ?? [];
  const hiddenConflicts = refused?.hidden ?? preview?.hidden_conflicts ?? 0;
  const blocked = refused?.blocked ?? preview?.blocked ?? [];
  const hiddenBlocked = refused?.hiddenBlocked ?? preview?.hidden_blocked ?? 0;
  const heldBackReasons = reasonMap(preview?.held_back_reasons);

  const publishBlocked =
    preview?.reason ||
    (blocked.length + hiddenBlocked > 0
      ? "Remove the blocked files from the branch first"
      : conflicts.length + hiddenConflicts > 0
        ? "Resolve the conflicts first: update the branch and try again"
        : preview && (preview.published_paths ?? []).length === 0
          ? "Nothing to publish"
          : undefined);

  const canPublish =
    !publishing && !publishBlocked && preview?.declassification_gate_passed === true;

  const copyTrailer = () => {
    if (!preview?.attestation_trailer) return;
    navigator.clipboard?.writeText(preview.attestation_trailer).catch(() => {});
    setCopiedTrailer(true);
    setTimeout(() => setCopiedTrailer(false), 1500);
  };

  return (
    <section aria-label="Scrub & Publish preview" className="space-y-3">
      <div className="flex items-center justify-between gap-2">
        <h3 className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
          <IconDeclassify className="h-4 w-4" />
          <span>Scrub & Publish → {defaultBranch}</span>
        </h3>
        {preview?.declassification_gate_passed && (
          <span className="inline-flex items-center gap-1 rounded-full bg-[#5bdba2]/14 px-2 py-0.5 font-mono text-[12px] text-[#5bdba2]">
            <IconShieldCheck className="h-3.5 w-3.5" />
            Gate OK
          </span>
        )}
      </div>

      <div className="pr-well space-y-3 rounded-xl p-3">
        {loading && !preview && <CodeBlockSkeleton />}

        {preview && (
          <>
            <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px] text-[#a6b5cf]">
              <span>
                {preview.source_branch} → {preview.target_branch}
              </span>
              <span>{plural(preview.private_commits_collapsed, "commit")} collapsed</span>
            </div>

            <p className="text-[13px] leading-relaxed text-[#b6c3db]">
              {preview.publish_rule || PUBLISH_RULE}
            </p>

            {/* Published paths */}
            <div className="space-y-1.5">
              <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                Published paths ({(preview.published_paths ?? []).length})
              </div>
              {(preview.published_paths ?? []).length === 0 ? (
                <p className="font-mono text-[12.5px] text-[#b6c3db]">Nothing to publish</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {preview.published_paths.map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => onOpenCode(branch.name, p)}
                      className="rounded-lg border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-2 py-0.5 font-mono text-[12.5px] text-[#5bdba2] hover:bg-[#5bdba2]/18"
                    >
                      {p}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Scrubbed / Held back paths */}
            {(preview.scrubbed_paths ?? []).length > 0 && (
              <div className="space-y-1.5">
                <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                  Held back ({preview.scrubbed_paths.length})
                </div>
                <ul className="max-h-32 space-y-1 overflow-y-auto">
                  {preview.scrubbed_paths.map((p) => (
                    <li
                      key={p}
                      className="rounded-lg border border-white/[0.12] bg-white/[0.045] px-2.5 py-1 font-mono text-[12.5px] text-[#cbd5e8]"
                    >
                      <div className="truncate">{p}</div>
                      {heldBackReasons[p] && (
                        <div className="mt-0.5 font-sans text-[12.5px] text-[#b6c3db]">
                          {heldBackReasons[p]}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Blocked files */}
            {(blocked.length > 0 || hiddenBlocked > 0) && (
              <div className="space-y-1 rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/10 p-2.5">
                <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#f27c7c]">
                  Blocked ({blocked.length + hiddenBlocked})
                </div>
                <p className="text-[12.5px] text-[#f4a0a0]">
                  Private content detected on public paths. Remove these before publishing.
                </p>
                {blocked.map((p) => (
                  <div key={p} className="truncate font-mono text-[12.5px] text-[#f27c7c]">
                    {p}
                  </div>
                ))}
                {hiddenBlocked > 0 && (
                  <div className="font-mono text-[12.5px] text-[#f27c7c]">
                    +{hiddenBlocked} more you can&apos;t list
                  </div>
                )}
              </div>
            )}

            {/* Conflicts */}
            {(conflicts.length > 0 || hiddenConflicts > 0) && (
              <div className="space-y-1 rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/10 p-2.5">
                <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#f27c7c]">
                  Conflicts ({conflicts.length + hiddenConflicts})
                </div>
                <p className="text-[12.5px] text-[#f4a0a0]">
                  Changed on both branches since they diverged. Rebase or update first.
                </p>
                {conflicts.map((p) => (
                  <div key={p} className="truncate font-mono text-[12.5px] text-[#f27c7c]">
                    {p}
                  </div>
                ))}
                {hiddenConflicts > 0 && (
                  <div className="font-mono text-[12.5px] text-[#f27c7c]">
                    +{hiddenConflicts} more you can&apos;t list
                  </div>
                )}
              </div>
            )}

            {/* Attestation trailer */}
            {preview.attestation_trailer && (
              <div className="space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Attestation Trailer
                  </span>
                  <button
                    type="button"
                    onClick={copyTrailer}
                    className="pr-pill inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[12px] text-[#d2dbee]"
                  >
                    {copiedTrailer ? (
                      <IconCheck className="h-3 w-3 text-[#5bdba2]" />
                    ) : (
                      <IconCopy className="h-3 w-3" />
                    )}
                    <span>{copiedTrailer ? "Copied" : "Copy"}</span>
                  </button>
                </div>
                <pre className="max-h-24 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#b6c3db]">
                  {preview.attestation_trailer}
                </pre>
              </div>
            )}

            {/* Optional summary message + 1-click Publish */}
            <div className="space-y-2 border-t border-white/[0.06] pt-2.5">
              <div className="flex items-center gap-2">
                <input
                  value={summaryMsg}
                  onChange={(e) => setSummaryMsg(e.target.value)}
                  aria-label="Optional publish summary message"
                  placeholder={
                    preview.clean_commit_message?.split("\n")[0] ||
                    "Optional release commit summary…"
                  }
                  className="pr-well min-w-0 flex-1 rounded-xl px-2.5 py-1.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                />
                <button
                  type="button"
                  disabled={loading}
                  onClick={() => void refreshPreview()}
                  className="pr-pill shrink-0 rounded-xl px-2.5 py-1.5 text-[13px] text-[#dce4f5] disabled:opacity-40"
                >
                  Refresh
                </button>
              </div>

              <button
                type="button"
                disabled={!canPublish}
                title={publishBlocked}
                onClick={() => void handlePublish()}
                className="pr-action-btn inline-flex w-full items-center justify-center gap-1.5 rounded-xl px-3.5 py-2 text-[13.5px] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <IconPlay className="h-4 w-4" />
                <span>{publishing ? "Publishing…" : "Scrub & Publish"}</span>
              </button>

              {publishBlocked && (
                <p
                  className={`text-[12.5px] ${
                    publishBlocked.startsWith("Nothing to publish") ? "text-[#b6c3db]" : "text-[#a8c5ff]"
                  }`}
                >
                  {publishBlocked}
                </p>
              )}
            </div>
          </>
        )}

        <ErrorNote message={error} />

        {receipt && (
          <div
            role="status"
            className="rounded-xl border border-[#5bdba2]/30 bg-[#5bdba2]/10 p-3 font-mono text-[12.5px] text-[#5bdba2]"
          >
            <div className="flex items-center gap-1.5 font-semibold">
              <IconShieldCheck className="h-4 w-4" />
              <span>
                Published {receipt.new_commit_oid.slice(0, 10)} → {receipt.target_ref}
              </span>
            </div>
            <div className="mt-1 text-[#bcefd9]">
              {plural((receipt.published_paths ?? []).length, "path")} published
              {(receipt.scrubbed_paths ?? []).length > 0 &&
                `, ${receipt.scrubbed_paths.length} held back`}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

/** Cohesive slide-over Workstream Focus Panel for inspecting and acting on any focused workstream. */
export function WorkstreamFocusDrawer({
  focus,
  owner,
  identity,
  nowMs,
  worktable,
  sessions,
  pendingApprovals,
  auditEvents,
  onClose,
  onFocus,
  onApprovalDecided,
  onSessionChange,
  onRefreshWorktable,
  onBranchesChanged,
  onOpenCode,
  onOpenChanges,
  onOpenReview,
  onOpenBranches,
  onOpenAgents,
}: WorkstreamFocusDrawerProps) {
  const [recentCommits, setRecentCommits] = useState<GitCommitSummary[]>([]);
  const [commitsLoading, setCommitsLoading] = useState(false);
  const [commitsError, setCommitsError] = useState<string | null>(null);
  const readinessAct = useAction();
  const stopAct = useAction();
  const verdictAct = useAction();
  const drawerRef = useRef<HTMLElement | null>(null);
  const openerRef = useRef<HTMLElement | null>(null);
  const wasOpenRef = useRef(false);
  const outputRef = useRef<HTMLDivElement | null>(null);
  const [entered, setEntered] = useState(false);
  const [pathsExpandedFor, setPathsExpandedFor] = useState<string | null>(null);
  const [copiedOutput, setCopiedOutput] = useState(false);

  const isOpen = focus !== null;
  // Two-step mount so the slide-over transitions in instead of popping.
  useEffect(() => {
    if (!isOpen) {
      setEntered(false);
      return;
    }
    const id = window.requestAnimationFrame(() => setEntered(true));
    return () => window.cancelAnimationFrame(id);
  }, [isOpen]);
  useEffect(() => {
    if (isOpen && !wasOpenRef.current) {
      openerRef.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      window.requestAnimationFrame(() => drawerRef.current?.focus());
    } else if (!isOpen && wasOpenRef.current) {
      const prev = openerRef.current;
      openerRef.current = null;
      if (prev?.isConnected) prev.focus();
    }
    wasOpenRef.current = isOpen;
  }, [isOpen]);

  const defaultBranch = worktable?.default_branch ?? "main";
  const allBranches = worktable?.branches ?? [];
  const allReviews = worktable?.reviews ?? [];

  // Resolve all connected context for the focused item
  let session: AgentSessionRecord | null = null;
  let branch: WorktableBranch | null = null;
  let reviews: WorktableReviewSummary[] = [];
  let relatedSessions: AgentSessionRecord[] = [];

  if (focus) {
    if (focus.kind === "session") {
      session = sessions.find((s) => s.id === focus.id) ?? null;
      relatedSessions = session ? [session] : [];
      branch = session?.branch
        ? (allBranches.find((b) => b.name === session?.branch) ?? null)
        : null;
      reviews = allReviews.filter(
        (r) => r.session_id === focus.id || (session?.branch && r.branch === session.branch),
      );
    } else if (focus.kind === "branch") {
      branch = allBranches.find((b) => b.name === focus.name) ?? null;
      reviews = allReviews.filter((r) => r.branch === focus.name);
      relatedSessions = sessions.filter((s) => s.branch === focus.name);
      session =
        relatedSessions.find((s) => s.status === "running") ??
        relatedSessions.find(sessionHasUncommittedChanges) ??
        relatedSessions[0] ??
        null;
    } else {
      const targetRev = allReviews.find((r) => r.change_id === focus.changeId) ?? null;
      reviews = targetRev ? [targetRev] : [];
      branch = targetRev ? (allBranches.find((b) => b.name === targetRev.branch) ?? null) : null;
      relatedSessions = targetRev
        ? sessions.filter(
            (s) =>
              (targetRev.session_id && s.id === targetRev.session_id) ||
              s.branch === targetRev.branch,
          )
        : [];
      session =
        (targetRev?.session_id
          ? (sessions.find((s) => s.id === targetRev.session_id) ?? null)
          : null) ??
        relatedSessions.find((s) => s.status === "running") ??
        relatedSessions.find(sessionHasUncommittedChanges) ??
        relatedSessions[0] ??
        null;
    }
  }

  const primaryReview =
    (focus?.kind === "review"
      ? reviews.find((r) => r.change_id === focus.changeId)
      : focus?.kind === "session"
        ? reviews.find((r) => r.session_id === focus.id)
        : undefined) ??
    reviews[0] ??
    null;

  const branchNameForCommits = branch?.name ?? null;
  useEffect(() => {
    if (!focus || !branchNameForCommits) {
      setRecentCommits([]);
      setCommitsError(null);
      setCommitsLoading(false);
      return;
    }
    let active = true;
    const cacheKey = `${identity.id}|${identity.principal}|${identity.agentProfile ?? ""}|${branchNameForCommits}`;
    const cached = commitsCache.get(cacheKey);
    if (cached) {
      // Paint the last known list instantly; skip the network entirely when it is still fresh.
      setRecentCommits(cached.list);
      setCommitsError(null);
      if (Date.now() - cached.at < COMMITS_FRESH_MS) {
        setCommitsLoading(false);
        return;
      }
    } else {
      setCommitsLoading(true);
      setCommitsError(null);
    }
    api
      .commits(identity, { ref: branchNameForCommits, limit: 6 })
      .then((list) => {
        commitsCache.set(cacheKey, { list, at: Date.now() });
        if (active) setRecentCommits(list);
      })
      .catch((err: unknown) => {
        if (active) {
          setRecentCommits([]);
          setCommitsError(errorText(err));
        }
      })
      .finally(() => {
        if (active) setCommitsLoading(false);
      });
    return () => {
      active = false;
    };
  }, [Boolean(focus), branchNameForCommits, identity.id, identity.principal, identity.agentProfile]);

  // Tail live output while the session runs.
  const liveLineCount = session?.output_lines.length ?? 0;
  const sessionRunning = session?.status === "running";
  useEffect(() => {
    const el = outputRef.current;
    if (sessionRunning && el) el.scrollTop = el.scrollHeight;
  }, [liveLineCount, sessionRunning]);

  if (!focus) return null;

  const unresolved = !session && !branch && !primaryReview;

  const matchingApprovals = pendingApprovals.filter((ap) => {
    if (ap.status !== "pending") return false;
    if (session) {
      return (
        ap.principal === session.principal &&
        (!ap.agent_profile || ap.agent_profile === session.agent_profile)
      );
    }
    return relatedSessions.some(
      (s) =>
        ap.principal === s.principal &&
        (!ap.agent_profile || ap.agent_profile === s.agent_profile),
    );
  });

  const targetBranch = branch?.name ?? primaryReview?.branch ?? session?.branch ?? defaultBranch;
  const quarantinePaths = Array.from(
    new Set([...(branch?.quarantine_paths ?? []), ...(primaryReview?.quarantine_paths ?? [])]),
  );

  // Scoped Wire Telemetry: STRICTLY owner-only — never read/inspect auditEvents for !owner.
  const scopedAuditEvents: AuditEvent[] =
    owner && session
      ? auditEvents
          .filter(
            (ev) =>
              ev.principal === session.principal &&
              (!session.agent_profile || ev.agent_profile === session.agent_profile),
          )
          .slice(0, 6)
      : [];

  const headerTitle =
    focus.kind === "session"
      ? session
        ? `$ ${session.command}`
        : `Session ${focus.id.slice(0, 8)}`
      : focus.kind === "branch"
        ? branch?.name ?? focus.name
        : primaryReview?.title ?? focus.changeId;

  const headerSubtitle =
    focus.kind === "session"
      ? session
        ? `${session.principal}${session.agent_profile ? ` ∩ ${session.agent_profile}` : " · cage"}`
        : "Agent session"
      : focus.kind === "branch"
        ? branch
          ? `${branch.author} · ${branch.head_oid.slice(0, 7)} · ${branch.relative_time}`
          : "Branch"
        : primaryReview
          ? `${primaryReview.change_id} · ${primaryReview.author} on ${primaryReview.branch}`
          : "Review";

  const toggleReadiness = () => {
    if (!owner || !branch) return;
    const nextReadiness = branch.readiness === "ready" ? "wip" : "ready";
    void readinessAct.run(async () => {
      await api.updateBranchVisibility(branch.name, branch.visibility, nextReadiness);
      onRefreshWorktable();
      onBranchesChanged();
    });
  };

  const stopSession = () => {
    if (!owner || !session || session.status !== "running") return;
    void stopAct.run(async () => {
      const updated = await api.stopSession(session.id);
      onSessionChange(updated);
    });
  };

  const submitVerdict = (rev: WorktableReviewSummary, verdict: "approved" | "changes") => {
    if (rev.round_count <= 0 || identity.principal === "anonymous") return;
    void verdictAct.run(async () => {
      await api.setReviewVerdict(
        rev.change_id,
        Math.max(1, rev.round_count),
        verdict,
        identity.principal,
      );
      onRefreshWorktable();
    });
  };

  const endedReason = session?.ended_reason || session?.budget?.breach_reason;

  return (
    <div
      className={`fixed inset-0 z-50 flex justify-end bg-[#04060d]/45 transition-opacity duration-200 ${
        entered ? "opacity-100" : "opacity-0"
      }`}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <aside
        ref={drawerRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label="Workstream focus"
        onKeyDown={(e) => {
          const panel = drawerRef.current;
          if (!panel) return;
          if (e.key === "Escape") {
            // Escape inside an open ConfirmButton cancels the confirmation only; the view's Escape handler skips defaultPrevented.
            const group = e.target instanceof HTMLElement ? e.target.closest('[role="group"]') : null;
            const cancel = group
              ? Array.from(group.querySelectorAll("button")).find((b) => b.textContent?.trim() === "Cancel")
              : undefined;
            if (cancel) {
              e.preventDefault();
              cancel.click();
            }
            return;
          }
          if (e.key !== "Tab") return;
          const focusables = Array.from(
            panel.querySelectorAll<HTMLElement>(
              'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
            ),
          ).filter((el) => el.offsetParent !== null);
          if (focusables.length === 0) {
            e.preventDefault();
            panel.focus();
            return;
          }
          const first = focusables[0];
          const last = focusables[focusables.length - 1];
          const activeEl = document.activeElement;
          if (e.shiftKey && (activeEl === first || activeEl === panel)) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && activeEl === last) {
            e.preventDefault();
            first.focus();
          }
        }}
        // Solid obsidian: explicit style guarantees no card text bleeds through regardless of CSS order.
        style={{ backgroundColor: "rgba(11, 15, 28, 0.99)" }}
        className={`pr-elevated flex h-full w-full flex-col border-l border-white/[0.14] shadow-[-24px_0_60px_-12px_rgba(0,0,0,0.65)] transition-transform duration-200 ease-out focus:outline-none sm:max-w-[540px] xl:max-w-[600px] 2xl:max-w-[680px] ${
          entered ? "translate-x-0" : "translate-x-8"
        }`}
      >
        {/* 1. Header + Deep-Jump Bar */}
        <header className="shrink-0 space-y-2 border-b border-white/[0.08] px-4 py-3 sm:px-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                {focus.kind === "session" ? (
                  <IconIntersection className="h-4 w-4 text-[#9ec0f5]" />
                ) : focus.kind === "review" ? (
                  <IconChanges className="h-4 w-4 text-[#9ec0f5]" />
                ) : branch && isPrivateVisibility(branch.visibility) ? (
                  <IconLock className="h-4 w-4 text-[#a8c5ff]" />
                ) : (
                  <IconBranches className="h-4 w-4 text-[#7f95f8]" />
                )}
                <h2
                  title={headerTitle}
                  className="min-w-0 truncate font-mono text-[14px] font-semibold text-[#f3f6fd]"
                >
                  {headerTitle}
                </h2>
              </div>
              <p className="truncate font-mono text-[13px] text-[#a6b5cf]">{headerSubtitle}</p>
            </div>

            <button
              type="button"
              onClick={onClose}
              aria-label="Close workstream focus"
              className="inline-flex items-center gap-1.5 rounded-lg p-1.5 text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-white"
            >
              <kbd className="pr-kbd font-mono">Esc</kbd>
              <IconClose className="h-4 w-4" />
            </button>
          </div>

          {/* Badges + Owner Readiness Toggle + Deep-Jump Bar share one wrapping row */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {branch && (
              <span
                className={`rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] ${
                  isPrivateVisibility(branch.visibility)
                    ? "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]"
                    : "border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]"
                }`}
              >
                {visibilitySummary(branch.visibility)}
              </span>
            )}
            {branch &&
              (owner ? (
                <button
                  type="button"
                  disabled={readinessAct.pending}
                  onClick={toggleReadiness}
                  title="Toggle branch readiness (WIP / READY)"
                  className={`rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] uppercase transition disabled:opacity-50 ${
                    branch.readiness === "ready"
                      ? "border-[#5bdba2]/35 bg-[#5bdba2]/14 text-[#5bdba2] hover:bg-[#5bdba2]/22"
                      : "border-white/[0.11] bg-white/[0.04] text-[#9eb0cc] hover:bg-white/[0.08]"
                  }`}
                >
                  {readinessAct.pending ? "Saving…" : branch.readiness}
                </button>
              ) : (
                <span
                  className={`rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] uppercase ${
                    branch.readiness === "ready"
                      ? "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                      : "border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
                  }`}
                >
                  {branch.readiness}
                </span>
              ))}
            {session && (
              <span
                className={`rounded-full px-2.5 py-0.5 font-mono text-[12.5px] uppercase ${
                  session.status === "running"
                    ? "bg-[#5bdba2]/15 text-[#5bdba2]"
                    : session.exit_code === 0
                      ? "bg-[#9ec0f5]/15 text-[#9ec0f5]"
                      : "bg-[#f27c7c]/15 text-[#f27c7c]"
                }`}
              >
                {session.status}
                {session.exit_code !== undefined && session.exit_code !== null
                  ? ` (${session.exit_code})`
                  : ""}
              </span>
            )}
          </div>

          {/* Deep-Jump Bar */}
          <div className="flex flex-wrap items-center gap-1.5 sm:ml-auto">
            <button
              type="button"
              onClick={() => onOpenCode(targetBranch)}
              className={JUMP_BTN}
            >
              <IconCode className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span>Open Files</span>
            </button>
            <button
              type="button"
              onClick={() =>
                onOpenChanges(
                  branch?.head_oid ??
                    primaryReview?.latest_commit_oid ??
                    session?.commit ??
                    undefined,
                )
              }
              className={JUMP_BTN}
            >
              <IconChanges className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span>Commits</span>
            </button>
            <button
              type="button"
              onClick={() => onOpenBranches(targetBranch)}
              className={JUMP_BTN}
            >
              <IconBranches className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span>Branches</span>
            </button>
            <button
              type="button"
              onClick={() => onOpenAgents(session?.id)}
              className={JUMP_BTN}
            >
              <IconCage className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span>Agents</span>
            </button>
          </div>
          </div>
          <ErrorNote message={readinessAct.error} />
        </header>

        {/* Scrollable Drawer Body */}
        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain px-4 py-3.5 sm:px-5">
          {unresolved &&
            (worktable ? (
              <div
                role="status"
                className="pr-well flex flex-col items-center gap-2 rounded-xl px-4 py-8 text-center"
              >
                <IconShieldCheck className="h-7 w-7 text-[#a6b5cf]" />
                <p className="text-[14px] font-medium text-[#dce4f5]">This item is no longer available</p>
                <p className="max-w-xs text-[13.5px] text-[#a6b5cf]">
                  It may have been merged, discarded, or is not visible to this lens.
                </p>
                <button type="button" onClick={onClose} className={JUMP_BTN}>
                  Close
                </button>
              </div>
            ) : (
              <div role="status" aria-label="Loading workstream" className="space-y-3">
                <SettingsRowsSkeleton rows={3} />
                <CodeBlockSkeleton />
              </div>
            ))}

          {/* 2. Pending JIT Approvals */}
          {matchingApprovals.length > 0 && (
            <section aria-label="Pending JIT Approvals" className="space-y-2">
              <h3 className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#a8c5ff]">
                <IconLock className="h-3.5 w-3.5" />
                <span>Pending JIT Approvals ({matchingApprovals.length})</span>
              </h3>
              <div className="space-y-2">
                {matchingApprovals.map((ap) => (
                  <ApprovalRow
                    key={ap.id}
                    ap={ap}
                    owner={owner}
                    nowMs={nowMs}
                    onDecided={onApprovalDecided}
                  />
                ))}
              </div>
            </section>
          )}

          {/* 3. Agent Telemetry, Live Output & Uncommitted Diff */}
          {session && (
            <section aria-label="Agent Telemetry & Output" className="space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h3 className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                  <IconTerminal className="h-3.5 w-3.5" />
                  <span>Agent Session</span>
                </h3>
                <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12.5px]">
                  {session.status === "running" && (
                    <span className="inline-flex items-center gap-1.5 text-[#5bdba2]">
                      <span className="pr-presence-dot bg-[#5bdba2]" aria-hidden="true" />
                      <span>{formatElapsedSeconds(session.started_at, nowMs)}</span>
                    </span>
                  )}
                  {owner && session.status === "running" && (
                    <ConfirmButton
                      disabled={stopAct.pending}
                      confirmLabel="Stop"
                      question="Stop this session?"
                      onConfirm={stopSession}
                      className="rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/12 px-2.5 py-0.5 text-[12.5px] text-[#f27c7c] hover:bg-[#f27c7c]/22 disabled:opacity-45"
                    >
                      {stopAct.pending ? "Stopping…" : "Stop"}
                    </ConfirmButton>
                  )}
                </div>
              </div>

              {relatedSessions.length > 1 && (
                <div className="flex flex-wrap gap-1.5">
                  {relatedSessions.map((rs) => (
                    <button
                      key={rs.id}
                      type="button"
                      onClick={() => onFocus({ kind: "session", id: rs.id })}
                      className={`max-w-[200px] truncate rounded-full px-2.5 py-0.5 font-mono text-[12.5px] transition ${
                        rs.id === session.id
                          ? "pr-pill-active"
                          : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                      }`}
                    >
                      $ {rs.command}
                    </button>
                  ))}
                </div>
              )}

              <div className="pr-well space-y-3 rounded-xl p-3">
                <div className="space-y-1.5 font-mono text-[13px]">
                  <div className="break-all text-[#f3f6fd]">$ {session.command}</div>
                  <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                    {session.sandbox === "bwrap" && (
                      <span className="rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/10 px-2 py-0.5 text-[#5bdba2]">
                        Sandboxed (bwrap)
                      </span>
                    )}
                    {session.sandbox === "none" && (
                      <span className="rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-2 py-0.5 text-[#a8c5ff]">
                        Unsandboxed
                      </span>
                    )}
                    <span className="text-[#67d6dc]">
                      {formatByteCount(session.bytes_scrubbed)} scrubbed
                    </span>
                    <span className="truncate text-[#a6b5cf]" title={session.proxy_url}>
                      proxy: {session.proxy_url}
                    </span>
                  </div>
                  {endedReason && (
                    <div className="text-[12.5px] text-[#cbd5e8]">Ended: {endedReason}</div>
                  )}
                </div>

                {/* Injected Placeholders */}
                <div className="space-y-1 border-t border-white/[0.06] pt-2 font-mono">
                  <div className="inline-flex items-center gap-1.5 text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                    <IconVault className="h-3 w-3" />
                    <span>Injected Placeholders (use ≠ read)</span>
                  </div>
                  {Object.keys(session.placeholders).length === 0 ? (
                    <p className="text-[12.5px] text-[#a6b5cf]">None configured</p>
                  ) : (
                    <div className="space-y-1">
                      {Object.entries(session.placeholders).map(([k, v]) => (
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

                {/* Live Terminal Output */}
                <div className="relative">
                  <div
                    ref={outputRef}
                    className="pr-well max-h-52 overflow-auto rounded-lg p-2.5 font-mono text-[13px] leading-[1.58]"
                  >
                    {session.output_lines.length === 0 ? (
                      <div className="text-[#a6b5cf]">
                        {session.status === "running" ? "Waiting for output…" : "No output captured"}
                      </div>
                    ) : (
                      session.output_lines.map((ln, idx) => (
                        <div key={idx} className="whitespace-pre-wrap break-all text-[#dce4f5]">
                          {ln}
                        </div>
                      ))
                    )}
                  </div>
                  {session.output_lines.length > 0 && (
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard?.writeText(session.output_lines.join("\n")).catch(() => {});
                        setCopiedOutput(true);
                        window.setTimeout(() => setCopiedOutput(false), 1500);
                      }}
                      className="pr-pill absolute right-3 top-2 inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[12px] text-[#d2dbee]"
                    >
                      {copiedOutput ? (
                        <IconCheck className="h-3 w-3 text-[#5bdba2]" />
                      ) : (
                        <IconCopy className="h-3 w-3" />
                      )}
                      <span>{copiedOutput ? "Copied" : "Copy"}</span>
                    </button>
                  )}
                </div>

                <ErrorNote message={stopAct.error} />

                {session.status !== "running" &&
                  ((session.changes?.length ?? 0) > 0 ||
                    Boolean(session.commit) ||
                    Boolean(session.discarded)) && (
                    <DrawerSessionDiffControls
                      key={session.id}
                      session={session}
                      owner={owner}
                      identity={identity}
                      onSessionChange={onSessionChange}
                      onRefreshWorktable={onRefreshWorktable}
                      onBranchesChanged={onBranchesChanged}
                      onOpenReview={onOpenReview}
                    />
                  )}
              </div>
            </section>
          )}

          {/* 4. Branch Files, Quarantine Alerts & Recent Commits */}
          {(branch || quarantinePaths.length > 0) && (
            <section aria-label="Branch Files, Quarantine & Commits" className="space-y-3">
              {quarantinePaths.length > 0 && (
                <div className="space-y-2">
                  <h3 className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#a8c5ff]">
                    <IconQuarantine className="h-3.5 w-3.5" />
                    <span>Quarantined Instruction Files ({quarantinePaths.length})</span>
                  </h3>
                  <div className="space-y-1.5">
                    {quarantinePaths.map((qp) => (
                      <div
                        key={qp}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-3 py-2"
                      >
                        <div className="min-w-0 flex-1">
                          <div className="truncate font-mono text-[13.5px] text-[#f3f6fd]" title={qp}>
                            {qp}
                          </div>
                          <div className="text-[12.5px] text-[#a8c5ff]">
                            Untrusted instruction surface — inspect before delegating agents
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => onOpenCode(targetBranch, qp)}
                          className="pr-pill shrink-0 rounded-full px-2.5 py-1 text-[12.5px] text-[#f3f6fd]"
                        >
                          Inspect file
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {branch && (
                <>
                  <div className="space-y-1.5">
                    <h3 className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                      Paths Touched ({branch.private_paths_touched.length})
                    </h3>
                    {branch.private_paths_touched.length === 0 ? (
                      <p className="font-mono text-[13px] text-[#a6b5cf]">
                        No branch-specific path deltas reported
                      </p>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {(pathsExpandedFor === branch.name
                          ? branch.private_paths_touched
                          : branch.private_paths_touched.slice(0, 8)
                        ).map((p) => (
                          <button
                            key={p}
                            type="button"
                            onClick={() => onOpenCode(branch.name, p)}
                            className="pr-pill rounded-lg px-2.5 py-1 font-mono text-[12.5px] text-[#dce4f5] hover:text-white"
                          >
                            {p}
                          </button>
                        ))}
                        {pathsExpandedFor !== branch.name && branch.private_paths_touched.length > 8 && (
                          <button
                            type="button"
                            onClick={() => setPathsExpandedFor(branch.name)}
                            className="rounded-lg px-2.5 py-1 font-mono text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                          >
                            +{branch.private_paths_touched.length - 8} more
                          </button>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="space-y-1.5">
                    <h3 className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                      Recent Commits on {branch.name}
                    </h3>
                    {commitsLoading ? (
                      <SettingsRowsSkeleton rows={3} />
                    ) : commitsError ? (
                      <ErrorNote message={commitsError} />
                    ) : recentCommits.length === 0 ? (
                      <p className="font-mono text-[13px] text-[#a6b5cf]">No commits visible</p>
                    ) : (
                      <ul className="pr-well divide-y divide-white/[0.05] overflow-hidden rounded-xl">
                        {recentCommits.map((c) => (
                          <li key={c.oid}>
                            <button
                              type="button"
                              onClick={() => onOpenChanges(c.oid)}
                              className="flex w-full items-center justify-between gap-3 px-3 py-2 text-left transition hover:bg-white/[0.04]"
                            >
                              <div className="min-w-0 flex-1">
                                <div className="truncate text-[13.5px] text-[#f3f6fd]">
                                  {c.subject}
                                </div>
                                <div className="font-mono text-[12.5px] text-[#a6b5cf]">
                                  {c.author} · {c.relative_time} · {plural(c.files_changed, "file")}
                                </div>
                              </div>
                              <span className="shrink-0 font-mono text-[12.5px] text-[#9ec0f5]">
                                {c.short_oid}
                              </span>
                            </button>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </>
              )}
            </section>
          )}

          {/* 5. Review Summary & Quick Verdict */}
          {primaryReview && (
            <section aria-label="Review Summary" className="space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <h3 className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                  <IconChanges className="h-3.5 w-3.5" />
                  <span>Review {primaryReview.change_id}</span>
                </h3>
                <button
                  type="button"
                  onClick={() => onOpenReview(primaryReview.change_id)}
                  className="text-[13px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                >
                  Open Review Rounds →
                </button>
              </div>

              <div className="pr-well space-y-2.5 rounded-xl p-3">
                <div className="text-[14px] font-medium text-[#f3f6fd]">{primaryReview.title}</div>
                <div className="flex flex-wrap items-center gap-2 font-mono text-[12.5px] text-[#a6b5cf]">
                  <span className="inline-flex items-center gap-1">
                    <IconBranchRef className="h-3 w-3" />
                    {primaryReview.branch} → {primaryReview.base_ref}
                  </span>
                  <span>R{primaryReview.round_count}</span>
                  <span>{plural(primaryReview.comment_count, "comment")}</span>
                  {primaryReview.delegated_agent && (
                    <span className="inline-flex items-center gap-1 text-[#9ec0f5]">
                      <IconIntersection className="h-3 w-3" />
                      {primaryReview.delegated_agent}
                    </span>
                  )}
                </div>

                {Object.keys(primaryReview.verdicts ?? {}).length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(primaryReview.verdicts).map(([k, v]) => (
                      <span
                        key={k}
                        className={`rounded-full px-2 py-0.5 font-mono text-[12.5px] ${
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
                  </div>
                )}

                {primaryReview.round_count > 0 && identity.principal !== "anonymous" && (
                  <div className="flex flex-wrap items-center gap-2 border-t border-white/[0.06] pt-2.5">
                    <button
                      type="button"
                      disabled={verdictAct.pending}
                      onClick={() => submitVerdict(primaryReview, "approved")}
                      className="pr-pill inline-flex items-center gap-1 rounded-full border-[#5bdba2]/30 bg-[#5bdba2]/10 px-3 py-1 text-[13px] text-[#5bdba2] hover:bg-[#5bdba2]/18 disabled:opacity-40"
                    >
                      <IconCheck className="h-3.5 w-3.5" />
                      <span>Approve</span>
                    </button>
                    <button
                      type="button"
                      disabled={verdictAct.pending}
                      onClick={() => submitVerdict(primaryReview, "changes")}
                      className="pr-pill inline-flex items-center gap-1 rounded-full px-3 py-1 text-[13px] text-[#f4a0a0] hover:text-[#f27c7c] disabled:opacity-40"
                    >
                      <span>Request changes</span>
                    </button>
                  </div>
                )}
                <ErrorNote message={verdictAct.error} />
              </div>
            </section>
          )}

          {/* 6. Scrub & Publish preview (STRICTLY owner-only, non-default branch) */}
          {owner && branch && branch.name !== defaultBranch && (
            <DrawerSquashDeclassify
              key={branch.name}
              branch={branch}
              defaultBranch={defaultBranch}
              onOpenCode={onOpenCode}
              onRefreshWorktable={onRefreshWorktable}
              onBranchesChanged={onBranchesChanged}
            />
          )}

          {/* 7. Scoped Wire Telemetry (STRICTLY owner-only — NEVER rendered/inspected for !owner) */}
          {owner && session && (
            <section aria-label="Scoped Wire Telemetry" className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <h3 className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                  <IconCage className="h-3.5 w-3.5 text-[#9ec0f5]" />
                  <span>Scoped Wire Telemetry ({scopedAuditEvents.length})</span>
                </h3>
                <button
                  type="button"
                  onClick={() => onOpenAgents(session.id)}
                  className="text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                >
                  Full stream →
                </button>
              </div>
              {scopedAuditEvents.length === 0 ? (
                <p className="pr-well rounded-xl px-3 py-2.5 font-mono text-[13px] text-[#a6b5cf]">
                  No wire events recorded for {session.principal}
                  {session.agent_profile ? ` ∩ ${session.agent_profile}` : ""} yet.
                </p>
              ) : (
                <ul className="pr-well divide-y divide-white/[0.05] overflow-hidden rounded-xl">
                  {scopedAuditEvents.map((ev, idx) => (
                    <li
                      key={`${ev.timestamp}-${ev.action}-${idx}`}
                      className="flex items-start justify-between gap-2.5 px-3 py-2 font-mono text-[12.5px]"
                    >
                      <div className="flex min-w-0 items-start gap-2">
                        <span
                          className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${decisionDot(ev.decision)}`}
                          aria-hidden="true"
                        />
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-1.5 text-[#f3f6fd]">
                            <span>{ev.capability ?? ev.action}</span>
                            {ev.target && (
                              <span className="truncate text-[#a6b5cf]">{ev.target}</span>
                            )}
                          </div>
                          <div className="truncate font-sans text-[12.5px] text-[#a6b5cf]">
                            {ev.reason}
                          </div>
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2 text-[12.5px] text-[#a6b5cf]">
                        {ev.bytes_scrubbed > 0 && (
                          <span className="text-[#67d6dc]">
                            {formatByteCount(ev.bytes_scrubbed)}
                          </span>
                        )}
                        <Time value={ev.timestamp} />
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          )}
        </div>
      </aside>
    </div>
  );
}
