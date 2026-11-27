import { Fragment, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CommitDiffSkeleton,
  CommitListSkeleton,
  InterdiffSkeleton,
  RoundsSkeleton,
} from "./ViewSkeletons";
import {
  api,
  ApiError,
  errorText,
  type AgentLane,
  type AgentSessionRecord,
  type AuditEvent,
  type BranchRecord,
  type ChangeReviewRecord,
  type GitCommitDiffResponse,
  type GitCommitSummary,
  type HealthResponse,
  type IdentityPreset,
  type ReviewComment,
  type ReviewDiffHunk,
  type ReviewInterdiffResponse,
  type SteerReviewResponse,
} from "../api";
import {
  detectLanguage,
  parseUnifiedPatch,
  tokenClassName,
  tokenizeLine,
} from "../lib/highlight";
import { isEditableEventTarget } from "../lib/platform";
import { isoTime, plural } from "../lib/format";
import { unifiedPatchToSides, type UnifiedPatchSides } from "../lib/monaco";
import { DiffBlock } from "./CodeBlock";
import { Time } from "./forms";
import type { MonacoDiffCommentBadge } from "./MonacoDiffViewer";
import { LaneConflictInspector } from "./LaneConflictInspector";
import {
  groupItemsByConcern,
  type ConcernGroup,
  type ConcernId,
  type RiskLevel,
} from "../lib/reviewConcerns";
import {
  computeProgress,
  flattenOrderedIds,
  loadReviewedSet,
  resolveReviewKeyAction,
  saveReviewedSet,
  stepNavigationId,
  toggleReviewedId,
  type ReviewViewMode,
} from "../lib/reviewProgress";
import {
  buildSessionTimeline,
  findStepIndexForHunk,
  type SessionTimeline,
} from "../lib/sessionReplay";
import { isSteeringComment, steeringTargetAgent } from "../lib/steeringPayload";
import { ConcernWalkthroughBar } from "./review/ConcernWalkthroughBar";
import { InlineSteeringComposer } from "./review/InlineSteeringComposer";
import { CommitTrustHeader, IntentTrustReceipt } from "./review/IntentTrustReceipt";
import { SessionReplayAside } from "./review/SessionReplayAside";
import {
  IconBranchRef,
  IconChanges,
  IconCheck,
  IconChevron,
  IconClose,
  IconLock,
  IconPlus,
  IconSearch,
  IconSteer,
  IconTimeline,
} from "./Icons";

interface Props {
  identity: IdentityPreset;
  /** Branch selected in the header; the commit log follows it. */
  refName?: string;
  initialOid?: string;
  initialChangeId?: string;
  requestedOid?: string;
  requestedChangeId?: string;
  onConsumeRequested?: () => void;
  owner?: boolean;
  branches?: BranchRecord[];
  sessions?: AgentSessionRecord[];
  /** Agent profiles the policy declares; offered when steering an agent. */
  agentProfiles?: string[];
  agentSandbox?: HealthResponse["agent_sandbox"];
  lanes?: AgentLane[];
  /** Bumped when the server reports a review changed; open reviews reload. */
  reviewRevision?: number;
  onLanesChanged?: () => void;
  auditEvents?: AuditEvent[];
  viewerPrincipal?: string;
  onPublishBranch?: (branchName: string) => void;
  onSelectOid?: (oid: string) => void;
  onSelectChange?: (changeId: string) => void;
  onOpenAgents?: () => void;
  /** False when this tab stays mounted while hidden; pauses global hotkeys. */
  active?: boolean;
}

interface HunkLineRow {
  kind: "add" | "del" | "ctx" | "meta";
  oldLine: number | null;
  newLine: number | null;
  anchorLine: number | null;
  side: "old" | "new" | null;
  sigil: string;
  body: string;
}

function isNonCommentableHunkMeta(line: string): boolean {
  const trimmed = line.trim();
  if (line.startsWith("\\")) return true;
  if (/^\.\.\..*(truncat|omitted|more line)/i.test(trimmed)) return true;
  if (/^\[.*truncat.*\]$/i.test(trimmed)) return true;
  if (/^---\s*truncated/i.test(trimmed)) return true;
  return false;
}

const GIT_HEADER_LINE =
  /^(diff --git |index [0-9a-f]|(new|deleted) file mode |old mode |new mode |(dis)?similarity index |rename (from|to) |copy (from|to) |--- (a\/|\/dev\/null)|\+\+\+ (b\/|\/dev\/null)|Binary files )/;

function computeHunkRows(hunk: ReviewDiffHunk): HunkLineRow[] {
  const m = hunk.header.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
  let oldNum = m ? Number(m[1]) : 1;
  let newNum = m ? Number(m[2]) : 1;
  // Git extended-header lines ("new file mode", "index", "rename from", ...) can lead the body;
  // they are not code, so they get no line number or comment button.
  let start = 0;
  while (start < hunk.lines.length && GIT_HEADER_LINE.test(hunk.lines[start])) start++;
  return hunk.lines.slice(start).map((line) => {
    if (isNonCommentableHunkMeta(line)) {
      return {
        kind: "meta",
        oldLine: null,
        newLine: null,
        anchorLine: null,
        side: null,
        sigil: "",
        body: line,
      };
    }
    if (line.startsWith("+")) {
      const cur = newNum++;
      return {
        kind: "add",
        oldLine: null,
        newLine: cur,
        anchorLine: cur,
        side: "new",
        sigil: "+",
        body: line.slice(1),
      };
    }
    if (line.startsWith("-")) {
      const cur = oldNum++;
      return {
        kind: "del",
        oldLine: cur,
        newLine: null,
        anchorLine: cur,
        side: "old",
        sigil: "-",
        body: line.slice(1),
      };
    }
    const curOld = oldNum++;
    const curNew = newNum++;
    const hasLeadingSpace = line.startsWith(" ");
    return {
      kind: "ctx",
      oldLine: curOld,
      newLine: curNew,
      anchorLine: curNew,
      side: "new",
      sigil: " ",
      body: hasLeadingSpace ? line.slice(1) : line,
    };
  });
}

function hunkChurn(hunk: ReviewDiffHunk): number {
  if (!hunk.allowed) return 0;
  let count = 0;
  for (const line of hunk.lines) {
    if (line.startsWith("+") || line.startsWith("-")) count += 1;
  }
  return count;
}

function riskBadgeClasses(risk: RiskLevel): string {
  switch (risk) {
    case "critical":
      return "border-[#f27c7c]/35 bg-[#f27c7c]/14 text-[#f27c7c]";
    case "high":
      return "border-[#9ec0f5]/35 bg-[#7f95f8]/12 text-[#a8c5ff]";
    case "medium":
      return "border-[#7f95f8]/30 bg-[#7f95f8]/12 text-[#9ec0f5]";
    case "low":
      return "border-white/[0.08] bg-white/[0.04] text-[#a6b5cf]";
  }
}

function riskLabel(risk: RiskLevel): string {
  switch (risk) {
    case "critical":
      return "Critical";
    case "high":
      return "High risk";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
  }
}

const EMPTY_TIMELINE: SessionTimeline = {
  steps: [],
  displayItems: [],
  sessionVisible: false,
  agentProfile: "human",
  model: "",
  promptSummary: "",
  sandbox: null,
  egressCalls: 0,
  bytesScrubbed: 0,
  egressBlocked: 0,
  redactedStepsCount: 0,
};

const COMMIT_PAGE = 25;
const COMMIT_HIDDEN_MESSAGE = "This commit isn't visible to this identity";

/** One neutral, lock-styled card for content this identity cannot read (never error-red). */
function RedactedNotice({ label }: { label?: string }) {
  return (
    <div
      role="note"
      className="flex items-center gap-2.5 px-4 py-4 font-mono text-[13.5px] text-[#a6b5cf]"
    >
      <IconLock className="h-4 w-4 shrink-0 text-[#a6b5cf]" />
      <span>{label ?? "Redacted — this identity cannot read this content"}</span>
    </div>
  );
}

function InlineSpinner() {
  return (
    <span
      aria-hidden="true"
      className="inline-block h-3 w-3 animate-spin rounded-full border border-current border-t-transparent"
    />
  );
}

type DiffLayout = "split" | "inline" | "raw";

const GUTTER_CLS = "w-10 shrink-0 select-none pr-2 text-right text-[12.5px] text-[#a6b5cf]";

function CodeTokens({ body, lang }: { body: string; lang: Parameters<typeof tokenizeLine>[1] }) {
  return (
    <>
      {tokenizeLine(body, lang).map((tok, ti) => (
        <span key={ti} className={tokenClassName(tok.kind)}>
          {tok.text}
        </span>
      ))}
    </>
  );
}

interface SplitCell<T> {
  row: T;
  idx: number;
}
type SplitEntry<T> =
  | { full: SplitCell<T> }
  | { left: SplitCell<T> | null; right: SplitCell<T> | null };

/** Pair consecutive del/add blocks row-by-row for a side-by-side grid; ctx rows sit on both sides. */
function pairSplitRows<T extends { kind: string }>(rows: T[]): SplitEntry<T>[] {
  const out: SplitEntry<T>[] = [];
  let i = 0;
  while (i < rows.length) {
    const r = rows[i]!;
    if (r.kind === "ctx") {
      out.push({ left: { row: r, idx: i }, right: { row: r, idx: i } });
      i++;
      continue;
    }
    const dels: SplitCell<T>[] = [];
    const adds: SplitCell<T>[] = [];
    while (i < rows.length && rows[i]!.kind === "del") dels.push({ row: rows[i]!, idx: i++ });
    while (i < rows.length && rows[i]!.kind === "add") adds.push({ row: rows[i]!, idx: i++ });
    if (dels.length === 0 && adds.length === 0) {
      out.push({ full: { row: r, idx: i } });
      i++;
      continue;
    }
    const n = Math.max(dels.length, adds.length);
    for (let k = 0; k < n; k++) out.push({ left: dels[k] ?? null, right: adds[k] ?? null });
  }
  return out;
}

// Monaco (~4.6 MB + one editor instance per diff) is code-split and only auto-mounted for small
// diffs; larger commits/rounds paint the lightweight highlighted renderer instantly, with a
// per-file "Monaco" opt-in.
const MonacoDiffViewer = lazy(() =>
  import("./MonacoDiffViewer").then((m) => ({ default: m.MonacoDiffViewer })),
);
const MONACO_AUTO_MAX = 3;
// shortcut: lightweight diff renders at most this many rows until expanded; raise if reviewers complain.
const LIGHT_DIFF_ROWS = 400;

function defaultDiffLayout(): "split" | "inline" {
  return typeof window !== "undefined" && window.innerWidth >= 1440 ? "split" : "inline";
}

function isBinaryPatch(patch: string): boolean {
  return /(?:^|\r?\n)(?:Binary files .* differ|GIT binary patch)\b/.test(patch);
}

function extractPatchTruncationNotice(patch: string): string | null {
  for (const line of patch.split(/\r?\n/)) {
    if (isNonCommentableHunkMeta(line) && !line.startsWith("\\")) {
      return line.trim();
    }
  }
  return null;
}

const DEFAULT_STEER_INSTRUCTION = "Address the inline review comments cleanly";

/** Syntax-highlighted files of an interdiff; unreadable files show as a lock card. */
function InterdiffFiles({ data }: { data: ReviewInterdiffResponse }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 font-mono text-[12.5px] text-[#b6c3db]">
        <span className="text-[#f3f6fd]">
          R{data.from_round === 0 ? "0 (base)" : data.from_round} → R{data.to_round}
        </span>
        {data.rebased_between_rounds && (
          <span className="rounded-full bg-[#5bdba2]/12 px-2 py-0.5 text-[12px] text-[#5bdba2]">
            rebased
          </span>
        )}
        <span className="text-[#98a8c4]">{plural(data.files.length, "file")} changed by this round</span>
      </div>
      {data.files.length === 0 && data.hidden_files === 0 && (
        <div className="py-8 text-center font-mono text-[13.5px] text-[#a6b5cf]">
          No changes between these rounds
        </div>
      )}
      {data.files.map((f) => {
        const parsed = f.allowed && !f.binary && f.patch ? parseUnifiedPatch(f.patch) : null;
        const lang = detectLanguage(f.path);
        return (
          <div key={f.path} className="pr-well overflow-hidden rounded-xl">
            <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-3.5 py-2.5">
              <span className="truncate font-mono text-[13.5px] text-[#dce4f5]">{f.path}</span>
              <span className="flex shrink-0 items-center gap-2 font-mono text-[12.5px]">
                <span className="text-[#98a8c4]">{f.status}</span>
                {f.allowed ? (
                  <>
                    <span className="text-[#5bdba2]">+{f.additions}</span>
                    <span className="text-[#f27c7c]">-{f.deletions}</span>
                  </>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[#a6b5cf]">
                    <IconLock className="h-4 w-4" /> Redacted
                  </span>
                )}
              </span>
            </div>
            {!f.allowed ? (
              <RedactedNotice label="This identity cannot read this file" />
            ) : f.binary ? (
              <div className="px-4 py-4 font-mono text-[13.5px] text-[#98a8c4]">Binary file changed</div>
            ) : parsed ? (
              <div className="overflow-x-auto py-2 font-mono text-[13px] leading-[1.6]">
                {parsed.lines.map((dl, li) => {
                  if (dl.kind === "meta") return null;
                  if (dl.kind === "hunk") {
                    return (
                      <div key={li} className="bg-[#7f95f8]/10 px-3 py-1 text-[12.5px] text-[#9ec0f5]">
                        {dl.body}
                      </div>
                    );
                  }
                  const rowBg =
                    dl.kind === "add" ? "bg-[#5bdba2]/10" : dl.kind === "del" ? "bg-[#f27c7c]/10" : "";
                  const sigilColor =
                    dl.kind === "add"
                      ? "text-[#5bdba2]"
                      : dl.kind === "del"
                        ? "text-[#f27c7c]"
                        : "text-[#a6b5cf]";
                  return (
                    <div key={li} className={`flex px-2 ${rowBg}`}>
                      <span className="w-10 shrink-0 select-none pr-2 text-right text-[12.5px] text-[#a6b5cf]">
                        {dl.oldLine ?? ""}
                      </span>
                      <span className="w-10 shrink-0 select-none pr-2 text-right text-[12.5px] text-[#a6b5cf]">
                        {dl.newLine ?? ""}
                      </span>
                      <span className={`w-4 shrink-0 select-none ${sigilColor}`}>{dl.sigil}</span>
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
              <div className="px-4 py-4 font-mono text-[13.5px] text-[#a6b5cf]">No textual diff</div>
            )}
          </div>
        );
      })}
      {data.hidden_files > 0 && (
        <div className="flex items-center gap-2 rounded-xl border border-white/[0.06] bg-black/25 px-3.5 py-3 font-mono text-[13px] text-[#a6b5cf]">
          <IconLock className="h-4 w-4 shrink-0 text-[#a6b5cf]" />
          <span>{plural(data.hidden_files, "file")} not visible to this identity</span>
        </div>
      )}
    </div>
  );
}

export function ReviewRoundsView({
  identity,
  refName,
  initialOid,
  initialChangeId,
  requestedOid,
  requestedChangeId,
  onConsumeRequested,
  owner = false,
  branches = [],
  sessions = [],
  agentProfiles = [],
  agentSandbox,
  lanes = [],
  reviewRevision = 0,
  onLanesChanged,
  auditEvents = [],
  viewerPrincipal,
  onPublishBranch,
  onSelectOid,
  onSelectChange,
  onOpenAgents,
  active = true,
}: Props) {
  const [mode, setMode] = useState<"commits" | "rounds">(() =>
    requestedChangeId || initialChangeId ? "rounds" : "commits",
  );
  const [viewMode, setViewMode] = useState<ReviewViewMode>("guided");

  // Real Git history on disk
  const [commits, setCommits] = useState<GitCommitSummary[]>([]);
  // False until the first page arrives, so "No commits" never flashes while loading.
  const [commitsLoaded, setCommitsLoaded] = useState(false);
  const [hasMoreCommits, setHasMoreCommits] = useState(false);
  const [commitSkip, setCommitSkip] = useState(0);
  const [loadingMore, setLoadingMore] = useState(false);
  const [commitSearch, setCommitSearch] = useState("");
  const [selectedOid, setSelectedOid] = useState<string | null>(
    requestedOid ?? initialOid ?? null,
  );
  const [commitDiff, setCommitDiff] = useState<GitCommitDiffResponse | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const commitDiffRef = useRef<GitCommitDiffResponse | null>(null);
  const [collapsedFiles, setCollapsedFiles] = useState<Set<string>>(() => new Set());
  const [commitDiffView, setCommitDiffView] = useState<"split" | "inline" | "raw">(
    defaultDiffLayout,
  );
  const [roundDiffView, setRoundDiffView] = useState<"split" | "inline">(
    defaultDiffLayout,
  );
  const [focusedCommitFile, setFocusedCommitFile] = useState<string | null>(null);
  // Per-file/hunk opt-in to the heavy Monaco renderer, and "show all rows" for long light diffs.
  const [monacoOptIn, setMonacoOptIn] = useState<Set<string>>(() => new Set());
  const [fullRows, setFullRows] = useState<Set<string>>(() => new Set());
  const toggleInSet = (setter: typeof setMonacoOptIn, key: string) =>
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Persisted Change-Id Review Rounds + Scrubbable Session Replay + Inline Steering
  const [changes, setChanges] = useState<ChangeReviewRecord[]>([]);
  const [selectedChangeId, setSelectedChangeId] = useState<string>(
    requestedChangeId ?? initialChangeId ?? "",
  );
  const [roundNumber, setRoundNumber] = useState<number>(1);
  const [selectedHunkId, setSelectedHunkId] = useState<string | null>(null);
  const [syncedHunkId, setSyncedHunkId] = useState<string | null>(null);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(0);
  const [mobileRoundPane, setMobileRoundPane] = useState<"hunks" | "replay">("hunks");
  const [asideTab, setAsideTab] = useState<"replay" | "comments">("replay");
  const [asideOpen, setAsideOpen] = useState(true);
  const [createReviewOpen, setCreateReviewOpen] = useState(false);
  const [newRevTitle, setNewRevTitle] = useState("");
  const baseBranch = branches.find((b) => b.is_current)?.name ?? branches[0]?.name ?? "";
  const defaultReviewBranch =
    branches.find((b) => !b.is_current)?.name ?? baseBranch;
  const [newRevBranch, setNewRevBranch] = useState("");
  const [newRevSessionId, setNewRevSessionId] = useState("");
  const [newCommentBody, setNewCommentBody] = useState("");
  const [commentAnchor, setCommentAnchor] = useState<{
    hunkId: string;
    path: string;
    line: number;
    side: "old" | "new";
    rowIdx: number;
  } | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // False until the first reviews response (or failure), so "No reviews yet" never flashes.
  const [reviewsLoaded, setReviewsLoaded] = useState(false);
  const [reviewsFailed, setReviewsFailed] = useState(false);
  const selectedChangeIdRef = useRef(selectedChangeId);
  selectedChangeIdRef.current = selectedChangeId;

  const reloadReviews = useCallback(
    (preferChangeId?: string) => {
      api
        .reviews(identity)
        .then((res) => {
          setReviewsLoaded(true);
          setReviewsFailed(false);
          setChanges(res);
          const targetId =
            preferChangeId || selectedChangeIdRef.current || requestedChangeId || initialChangeId;
          const cur = res.find((c) => c.change_id === targetId) ?? res[0];
          if (cur) {
            if (cur.change_id !== selectedChangeIdRef.current) {
              setCommentAnchor(null);
            }
            setSelectedChangeId(cur.change_id);
            const latest = cur.rounds[cur.rounds.length - 1];
            if (latest) {
              setRoundNumber(latest.round);
              setSelectedHunkId((prev) =>
                prev && latest.hunks.some((h) => h.id === prev)
                  ? prev
                  : (latest.hunks[0]?.id ?? null),
              );
            }
          }
        })
        .catch((err: unknown) => {
          setReviewsLoaded(true);
          setReviewsFailed(true);
          setError(errorText(err));
        });
    },
    [identity, requestedChangeId, initialChangeId],
  );
  const [steeringNotice, setSteeringNotice] = useState<{
    message: string;
    sessionId?: string;
  } | null>(null);

  // Concern collapse state (boilerplate auto-collapsed by default) & reviewed tracker
  const [collapsedConcerns, setCollapsedConcerns] = useState<Set<ConcernId>>(
    () => new Set<ConcernId>(["boilerplate"]),
  );
  const [reviewedIds, setReviewedIds] = useState<Set<string>>(() => new Set());
  const lastGPressRef = useRef<number>(0);

  useEffect(() => {
    if (!requestedOid) return;
    setMode("commits");
    setSelectedOid(requestedOid);
    onConsumeRequested?.();
  }, [requestedOid, onConsumeRequested]);

  useEffect(() => {
    if (!requestedChangeId) return;
    setMode("rounds");
    setCommentAnchor(null);
    setSelectedChangeId(requestedChangeId);
    const match = changes.find((c) => c.change_id === requestedChangeId);
    if (match) {
      const latest = match.rounds[match.rounds.length - 1];
      if (latest) {
        setRoundNumber(latest.round);
        setSelectedHunkId(latest.hunks[0]?.id ?? null);
      }
    } else if (reviewsLoaded) {
      reloadReviews(requestedChangeId);
    }
    onConsumeRequested?.();
  }, [requestedChangeId, changes, reviewsLoaded, reloadReviews, onConsumeRequested]);

  const commitsKeyRef = useRef<string | null>(null);
  useEffect(() => {
    let active = true;
    // A different branch or identity must not keep the old commits, selection or diff.
    const key = `${identity.id}|${refName ?? ""}`;
    if (commitsKeyRef.current !== null && commitsKeyRef.current !== key) {
      setCommits([]);
      setCommitsLoaded(false);
      setHasMoreCommits(false);
      setCommitSkip(0);
      setSelectedOid(null);
      setCommitDiff(null);
      setLoadingDiff(false);
      setDiffError(null);
    }
    commitsKeyRef.current = key;
    api
      .commits(identity, { ref: refName, limit: COMMIT_PAGE })
      .then((res) => {
        if (!active) return;
        setCommits(res);
        setCommitsLoaded(true);
        setCommitSkip(COMMIT_PAGE);
        setHasMoreCommits(res.length >= COMMIT_PAGE);
        setSelectedOid((prev) => prev ?? res[0]?.oid ?? null);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setCommitsLoaded(true);
        setError(errorText(err));
      });
    return () => {
      active = false;
    };
  }, [refName, identity]);

  const loadMoreCommits = () => {
    setLoadingMore(true);
    api
      .commits(identity, { ref: refName, limit: COMMIT_PAGE, skip: commitSkip })
      .then((res) => {
        setCommitSkip((s) => s + COMMIT_PAGE);
        setHasMoreCommits(res.length > 0);
        setCommits((prev) => [...prev, ...res.filter((c) => !prev.some((p) => p.oid === c.oid))]);
      })
      .catch((err: unknown) => setError(errorText(err)))
      .finally(() => setLoadingMore(false));
  };

  useEffect(() => {
    if (!selectedOid) return;
    let active = true;
    setLoadingDiff(true);
    setCollapsedFiles(new Set());
    setCollapsedConcerns(new Set<ConcernId>(["boilerplate"]));
    setFocusedCommitFile(null);
    setDiffError(null);
    // ~120ms debounce while a diff is already on screen, so holding j/k doesn't fire a fetch per commit.
    const timer = setTimeout(
      () => {
        api
          .commitDiff(selectedOid, identity)
          .then((res) => {
            if (active) setCommitDiff(res);
          })
          .catch((err: unknown) => {
            if (!active) return;
            setCommitDiff(null);
            setDiffError(
              err instanceof ApiError && err.status === 404
                ? COMMIT_HIDDEN_MESSAGE
                : errorText(err),
            );
          })
          .finally(() => {
            if (active) setLoadingDiff(false);
          });
      },
      commitDiffRef.current ? 120 : 0,
    );
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [selectedOid, identity]);

  // Keep the keyboard-selected commit visible in the list.
  useEffect(() => {
    if (mode !== "commits" || !selectedOid) return;
    document
      .querySelector(`[data-oid="${selectedOid}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [selectedOid, mode, commitsLoaded]);

  // Errors belong to the view that raised them.
  useEffect(() => {
    setError(null);
  }, [mode]);

  useEffect(() => {
    setCommentAnchor(null);
    setReviewsLoaded(false);
    reloadReviews(requestedChangeId || initialChangeId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [identity]);

  const filteredCommits = useMemo(() => {
    const q = commitSearch.trim().toLowerCase();
    if (!q) return commits;
    return commits.filter(
      (c) =>
        c.subject.toLowerCase().includes(q) ||
        c.short_oid.toLowerCase().includes(q) ||
        c.author.toLowerCase().includes(q),
    );
  }, [commits, commitSearch]);

  commitDiffRef.current = commitDiff;
  const diffPending = !!selectedOid && commitDiff?.oid !== selectedOid && !diffError;

  const parsedCommitFiles = useMemo(() => {
    if (!commitDiff) return [];
    return commitDiff.files.map((f) => {
      const binary = f.allowed && isBinaryPatch(f.patch);
      const parsed = f.allowed ? parseUnifiedPatch(f.patch) : null;
      const sides = f.allowed && !binary && f.patch ? unifiedPatchToSides(f.patch) : null;
      const truncationNotice = f.allowed && f.patch ? extractPatchTruncationNotice(f.patch) : null;
      return {
        ...f,
        lang: detectLanguage(f.path),
        binary,
        parsed,
        sides,
        truncationNotice,
      };
    });
  }, [commitDiff]);

  const commitFileIndexByPath = useMemo(() => {
    const map = new Map<string, number>();
    parsedCommitFiles.forEach((f, idx) => map.set(f.path, idx));
    return map;
  }, [parsedCommitFiles]);

  const commitTotals = useMemo(() => {
    let additions = 0;
    let deletions = 0;
    for (const f of parsedCommitFiles) {
      if (f.parsed) {
        additions += f.parsed.additions;
        deletions += f.parsed.deletions;
      }
    }
    return { additions, deletions };
  }, [parsedCommitFiles]);

  const commitConcernGroups = useMemo(
    () =>
      groupItemsByConcern(parsedCommitFiles, (f) => ({
        id: f.path,
        path: f.path,
        allowed: f.allowed,
        zone: f.zone,
        churn: f.parsed ? f.parsed.additions + f.parsed.deletions : 0,
      })),
    [parsedCommitFiles],
  );

  const orderedCommitFileIds = useMemo(
    () =>
      flattenOrderedIds(
        commitConcernGroups,
        parsedCommitFiles.map((f) => f.path),
        viewMode,
      ),
    [commitConcernGroups, parsedCommitFiles, viewMode],
  );

  const activeChange = changes.find((c) => c.change_id === selectedChangeId) ?? changes[0] ?? null;
  const activeRound =
    activeChange?.rounds.find((r) => r.round === roundNumber) ??
    activeChange?.rounds[activeChange.rounds.length - 1] ??
    null;

  const roundConcernGroups = useMemo(
    () =>
      activeRound
        ? groupItemsByConcern(activeRound.hunks, (h) => ({
            id: h.id,
            path: h.path,
            allowed: h.allowed,
            zone: h.zone,
            churn: hunkChurn(h),
          }))
        : [],
    [activeRound],
  );

  const orderedRoundHunkIds = useMemo(
    () =>
      activeRound
        ? flattenOrderedIds(
            roundConcernGroups,
            activeRound.hunks.map((h) => h.id),
            viewMode,
          )
        : [],
    [activeRound, roundConcernGroups, viewMode],
  );

  const hunkConcernMap = useMemo(() => {
    const map = new Map<string, ConcernId>();
    for (const g of roundConcernGroups) {
      for (const entry of g.items) {
        map.set(entry.id, g.definition.id);
      }
    }
    return map;
  }, [roundConcernGroups]);

  const activeHunk: ReviewDiffHunk | null =
    activeRound?.hunks.find((h) => h.id === selectedHunkId) ??
    (orderedRoundHunkIds[0]
      ? activeRound?.hunks.find((h) => h.id === orderedRoundHunkIds[0])
      : undefined) ??
    activeRound?.hunks[0] ??
    null;

  const timeline: SessionTimeline = useMemo(() => {
    if (!activeChange || !activeRound) return EMPTY_TIMELINE;
    return buildSessionTimeline({
      round: activeRound,
      change: activeChange,
      identity,
      viewerPrincipal,
      sessions,
      auditEvents,
    });
  }, [activeChange, activeRound, identity, viewerPrincipal, sessions, auditEvents]);

  // Scope key for persisted Reviewed progress tracker
  const reviewScopeKey = useMemo(() => {
    if (mode === "commits" && commitDiff) {
      return `commit:${identity.id}:${commitDiff.oid}`;
    }
    if (mode === "rounds" && activeChange && activeRound) {
      return `round:${identity.id}:${activeChange.change_id}:r${activeRound.round}`;
    }
    return "";
  }, [mode, identity.id, commitDiff, activeChange, activeRound]);

  useEffect(() => {
    if (!reviewScopeKey) {
      setReviewedIds(new Set());
      return;
    }
    setReviewedIds(loadReviewedSet(reviewScopeKey));
  }, [reviewScopeKey]);

  const isSimulatingLens = Boolean(
    viewerPrincipal && (identity.principal !== viewerPrincipal || identity.agentProfile),
  );

  // Reset concern collapse, composer anchor & step index on change/round switch
  useEffect(() => {
    setCollapsedConcerns(new Set<ConcernId>(["boilerplate"]));
    setSyncedHunkId(null);
    setSteeringNotice(null);
    setCommentAnchor(null);
    setActiveStepIndex(0);
  }, [activeChange?.change_id, activeRound?.round]);

  // Keep activeStepIndex clamped if timeline shrinks
  useEffect(() => {
    setActiveStepIndex((idx) => {
      if (timeline.steps.length === 0) return 0;
      return Math.min(idx, timeline.steps.length - 1);
    });
  }, [timeline.steps.length]);

  const handleToggleReviewed = useCallback(
    (id: string) => {
      setReviewedIds((prev) => {
        const next = toggleReviewedId(prev, id);
        if (reviewScopeKey) saveReviewedSet(reviewScopeKey, next);
        return next;
      });
    },
    [reviewScopeKey],
  );

  const handleResetReviewed = useCallback(() => {
    const empty = new Set<string>();
    setReviewedIds(empty);
    if (reviewScopeKey) saveReviewedSet(reviewScopeKey, empty);
  }, [reviewScopeKey]);

  const expandConcern = useCallback((concernId: ConcernId) => {
    setCollapsedConcerns((prev) => {
      if (!prev.has(concernId)) return prev;
      const next = new Set(prev);
      next.delete(concernId);
      return next;
    });
  }, []);

  const toggleConcern = useCallback((concernId: ConcernId) => {
    setCollapsedConcerns((prev) => {
      const next = new Set(prev);
      if (next.has(concernId)) next.delete(concernId);
      else next.add(concernId);
      return next;
    });
  }, []);

  const selectHunkWithSync = useCallback(
    (hunkId: string, opts?: { fromTimeline?: boolean; scroll?: boolean }) => {
      setSelectedHunkId(hunkId);
      const parentConcern = hunkConcernMap.get(hunkId);
      if (parentConcern) expandConcern(parentConcern);
      if (opts?.fromTimeline) {
        setSyncedHunkId(hunkId);
      } else {
        setSyncedHunkId(null);
        setActiveStepIndex(findStepIndexForHunk(timeline, hunkId));
      }
      if (opts?.scroll) {
        requestAnimationFrame(() => {
          document
            .getElementById(`review-hunk-${hunkId}`)
            ?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        });
      }
    },
    [expandConcern, hunkConcernMap, timeline],
  );

  const jumpToConcern = useCallback(
    (concernId: ConcernId) => {
      expandConcern(concernId);
      const prefix = mode === "commits" ? "concern-commit-" : "concern-round-";
      requestAnimationFrame(() => {
        document
          .getElementById(`${prefix}${concernId}`)
          ?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    },
    [expandConcern, mode],
  );

  // Keyboard navigation: Commits preserves j/k commit switch + v reviewed;
  // Rounds provides j/k hunk nav (in Guided Tour / All order), v reviewed, c inline composer, Esc close.
  useEffect(() => {
    if (!active) return;
    const onKeyDown = (e: KeyboardEvent) => {
      const editable = isEditableEventTarget(e);
      const hasMods = e.metaKey || e.ctrlKey || e.altKey;
      if (!editable && !hasMods && !e.shiftKey && e.key.toLowerCase() === "g") {
        lastGPressRef.current = Date.now();
        return;
      }

      const withinGChord = Date.now() - lastGPressRef.current < 800;
      lastGPressRef.current = 0;

      const action = resolveReviewKeyAction(e.key, {
        mode,
        isEditable: editable,
        hasModifiers: hasMods,
        shiftKey: e.shiftKey,
        withinGChord,
        composerOpen: commentAnchor !== null,
      });
      if (!action) return;

      if (action === "close_composer") {
        e.preventDefault();
        setCommentAnchor(null);
        return;
      }

      if (mode === "commits") {
        if (action === "next" || action === "prev") {
          if (filteredCommits.length === 0) return;
          const curIdx = filteredCommits.findIndex((c) => c.oid === selectedOid);
          const nextIdx =
            action === "next"
              ? Math.min(filteredCommits.length - 1, curIdx + 1)
              : Math.max(0, curIdx - 1);
          if (filteredCommits[nextIdx]) {
            e.preventDefault();
            setSelectedOid(filteredCommits[nextIdx].oid);
            onSelectOid?.(filteredCommits[nextIdx].oid);
          }
          return;
        }
        if (action === "toggle_reviewed") {
          const targetPath =
            focusedCommitFile ??
            orderedCommitFileIds.find((id) => !reviewedIds.has(id)) ??
            orderedCommitFileIds[0];
          if (targetPath) {
            e.preventDefault();
            setFocusedCommitFile(targetPath);
            handleToggleReviewed(targetPath);
          }
        }
        return;
      }

      // Rounds mode shortcuts
      if (!activeRound || orderedRoundHunkIds.length === 0) return;
      if (action === "next" || action === "prev") {
        const nextId = stepNavigationId(
          orderedRoundHunkIds,
          activeHunk?.id ?? null,
          action === "next" ? "next" : "prev",
        );
        if (nextId) {
          e.preventDefault();
          selectHunkWithSync(nextId, { scroll: true });
        }
        return;
      }

      if (action === "toggle_reviewed" && activeHunk) {
        e.preventDefault();
        handleToggleReviewed(activeHunk.id);
        return;
      }

      if (action === "open_comment" && activeHunk && activeHunk.allowed) {
        e.preventDefault();
        const rows = computeHunkRows(activeHunk);
        const preferredIdx = rows.findIndex((r) => r.kind === "add" || r.kind === "del");
        const rowIdx = preferredIdx >= 0 ? preferredIdx : 0;
        const row = rows[rowIdx];
        if (row && row.anchorLine !== null) {
          const parentConcern = hunkConcernMap.get(activeHunk.id);
          if (parentConcern) expandConcern(parentConcern);
          setCommentAnchor({
            hunkId: activeHunk.id,
            path: activeHunk.path,
            line: row.anchorLine,
            side: row.kind === "del" ? "old" : "new",
            rowIdx,
          });
          requestAnimationFrame(() => {
            document
              .getElementById(`review-hunk-${activeHunk.id}`)
              ?.scrollIntoView({ behavior: "smooth", block: "nearest" });
          });
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    active,
    mode,
    commentAnchor,
    filteredCommits,
    selectedOid,
    onSelectOid,
    focusedCommitFile,
    orderedCommitFileIds,
    reviewedIds,
    handleToggleReviewed,
    activeRound,
    orderedRoundHunkIds,
    activeHunk,
    selectHunkWithSync,
    hunkConcernMap,
    expandConcern,
  ]);

  const roundHunkData = useMemo(() => {
    const map = new Map<
      string,
      {
        sides: UnifiedPatchSides;
        origLineSet: Set<number>;
        modLineSet: Set<number>;
        metaLines: string[];
      }
    >();
    if (!activeRound) return map;
    for (const hunk of activeRound.hunks) {
      if (!hunk.allowed) continue;
      const metaLines: string[] = [];
      const diffLines: string[] = [];
      for (const line of hunk.lines) {
        if (isNonCommentableHunkMeta(line)) {
          metaLines.push(line.trim());
        } else {
          diffLines.push(line);
        }
      }
      const sides = unifiedPatchToSides(`${hunk.header}\n${diffLines.join("\n")}`);
      const origLineSet = new Set(sides.originalLineMap.filter((n) => n > 0));
      const modLineSet = new Set(sides.modifiedLineMap.filter((n) => n > 0));
      map.set(hunk.id, { sides, origLineSet, modLineSet, metaLines });
    }
    return map;
  }, [activeRound]);

  const roundHunkComments = useMemo(() => {
    const map = new Map<
      string,
      {
        badges: MonacoDiffCommentBadge[];
        comments: NonNullable<ChangeReviewRecord["comments"]>;
      }
    >();
    if (!activeRound || !activeChange?.comments) return map;
    for (const hunk of activeRound.hunks) {
      const data = roundHunkData.get(hunk.id);
      if (!data) continue;
      const matching = activeChange.comments.filter((c) => {
        if (c.path !== hunk.path || c.line === undefined || c.line === null) return false;
        const side: "old" | "new" = c.side === "old" ? "old" : "new";
        return side === "old" ? data.origLineSet.has(c.line) : data.modLineSet.has(c.line);
      });
      const counts = new Map<string, MonacoDiffCommentBadge>();
      for (const c of matching) {
        const line = c.line!;
        const side: "old" | "new" = c.side === "old" ? "old" : "new";
        const key = `${side}:${line}`;
        const existing = counts.get(key);
        if (existing) {
          existing.count += 1;
        } else {
          counts.set(key, { line, side, count: 1 });
        }
      }
      map.set(hunk.id, {
        badges: Array.from(counts.values()),
        comments: matching,
      });
    }
    return map;
  }, [activeRound, activeChange?.comments, roundHunkData]);
  // Snapshot of one round, or what changed between two rounds (R(a) → R(b)).
  const [viewKind, setViewKind] = useState<"snapshot" | "interdiff">("snapshot");
  const [fromRound, setFromRound] = useState(0);
  const [toRound, setToRound] = useState(1);
  const [interdiff, setInterdiff] = useState<ReviewInterdiffResponse | null>(null);
  const [interdiffLoading, setInterdiffLoading] = useState(false);
  const [interdiffError, setInterdiffError] = useState<string | null>(null);

  // Closed-loop steering: package comments, run an agent on the review's lane, land the next round.
  const [steerOpen, setSteerOpen] = useState(false);
  const [steerIds, setSteerIds] = useState<Set<string>>(() => new Set());
  const [steerInstruction, setSteerInstruction] = useState(DEFAULT_STEER_INSTRUCTION);
  const [steerCommand, setSteerCommand] = useState("");
  const [steerProfile, setSteerProfile] = useState("");
  const [steerAutoCommit, setSteerAutoCommit] = useState(true);
  const [steerMarkRevise, setSteerMarkRevise] = useState(true);
  const [steerBusy, setSteerBusy] = useState(false);
  const [steerError, setSteerError] = useState<string | null>(null);
  const [steerResult, setSteerResult] = useState<SteerReviewResponse | null>(null);
  const [steerHandled, setSteerHandled] = useState(false);

  const rounds = activeChange?.rounds ?? [];
  const latestRoundNumber = rounds.reduce((m, r) => Math.max(m, r.round), 0);
  const nextRound = latestRoundNumber + 1;
  const activeLane = lanes.find((l) => l.lane_id === activeChange?.lane_id);
  const laneConflicts = activeChange?.lane_conflicts?.length
    ? activeChange.lane_conflicts
    : (activeRound?.conflicts ?? []);
  const sandboxOff = agentSandbox === "none";
  const addressedRound = (c: ReviewComment): number | null =>
    c.addressed_in_round ??
    rounds.find((r) => r.addressed_comment_ids?.includes(c.id))?.round ??
    null;

  const activeRoundNumber = activeRound?.round;
  useEffect(() => {
    if (activeRoundNumber === undefined) return;
    setToRound(activeRoundNumber);
    setFromRound(activeRoundNumber > 1 ? activeRoundNumber - 1 : 0);
  }, [activeChange?.change_id, activeRoundNumber]);

  const interdiffReady = viewKind === "interdiff" && rounds.length > 1;
  useEffect(() => {
    if (!interdiffReady || !activeChange || fromRound >= toRound) {
      setInterdiff(null);
      return;
    }
    let active = true;
    setInterdiffLoading(true);
    setInterdiffError(null);
    api
      .reviewInterdiff(activeChange.change_id, identity, fromRound, toRound)
      .then((res) => {
        if (active) setInterdiff(res);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setInterdiff(null);
        setInterdiffError(errorText(err));
      })
      .finally(() => {
        if (active) setInterdiffLoading(false);
      });
    return () => {
      active = false;
    };
  }, [interdiffReady, activeChange?.change_id, fromRound, toRound, identity, reviewRevision]);

  // A review changed on the server: refresh in place, keeping the round being read.
  const firstRevision = useRef(reviewRevision);
  useEffect(() => {
    if (reviewRevision === firstRevision.current) return;
    api
      .reviews(identity)
      .then(setChanges)
      .catch((err: unknown) => setError(errorText(err)));
  }, [reviewRevision]);

  // The steering session ended: load the round it produced.
  const steerSession = steerResult
    ? (sessions.find((s) => s.id === steerResult.session.id) ?? steerResult.session)
    : null;
  const steerRunning = steerSession?.status === "running";
  useEffect(() => {
    if (!steerResult || !steerSession || steerRunning || steerHandled) return;
    setSteerHandled(true);
    reloadReviews(steerResult.change_id);
    onLanesChanged?.();
  }, [steerResult, steerSession?.status]);

  const openSteer = (commentIds?: string[], instruction?: string) => {
    const comments = activeChange?.comments ?? [];
    setSteerIds(
      new Set(commentIds ?? comments.filter((c) => addressedRound(c) === null).map((c) => c.id)),
    );
    setSteerInstruction(instruction ?? DEFAULT_STEER_INSTRUCTION);
    setSteerProfile(activeChange?.delegated_agent ?? identity.agentProfile ?? "");
    setSteerError(null);
    setSteerOpen(true);
  };

  const handleSteer = async () => {
    if (!activeChange) return;
    setSteerBusy(true);
    setSteerError(null);
    try {
      const res = await api.steerReview(activeChange.change_id, {
        comment_ids: [...steerIds],
        instruction: steerInstruction.trim() || undefined,
        command: steerCommand.trim() || undefined,
        agent_profile: steerProfile || undefined,
        auto_commit: steerAutoCommit,
        mark_changes_requested: steerMarkRevise,
      });
      setSteerResult(res);
      setSteerHandled(false);
      setSteerOpen(false);
      onLanesChanged?.();
    } catch (err: unknown) {
      setSteerError(errorText(err));
    } finally {
      setSteerBusy(false);
    }
  };

  const verdictKey =
    activeChange && activeRound ? `r${activeRound.round}:${identity.principal}` : "";
  const activeVerdict =
    activeChange && verdictKey ? activeChange.verdicts?.[verdictKey] : undefined;
  const hasRedactedHunk = activeRound?.hunks.some((h) => !h.allowed) ?? false;

  const handleSetVerdict = async (verdict: "approved" | "changes") => {
    if (!activeChange || !activeRound) return;
    setError(null);
    try {
      await api.setReviewVerdict(
        activeChange.change_id,
        activeRound.round,
        verdict,
        identity.principal,
      );
      reloadReviews(activeChange.change_id);
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const handleCreateReview = async (e: React.FormEvent) => {
    e.preventDefault();
    const title = newRevTitle.trim();
    const chosenBranch = newRevBranch || defaultReviewBranch;
    if (!title || !chosenBranch) return;
    setSubmitting(true);
    setError(null);
    try {
      const created = await api.createReview({
        title,
        branch: chosenBranch,
        base_ref: baseBranch || undefined,
        author: identity.principal,
        delegated_agent: identity.agentProfile ?? null,
        session_id: newRevSessionId || null,
      });
      setNewRevTitle("");
      setCreateReviewOpen(false);
      onSelectChange?.(created.change_id);
      reloadReviews(created.change_id);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleAddComment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeChange || !activeHunk?.path || !newCommentBody.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      await api.addReviewComment(activeChange.change_id, {
        path: activeHunk.path,
        body: newCommentBody.trim(),
        author: identity.principal,
        kind: "comment",
      });
      setNewCommentBody("");
      reloadReviews(activeChange.change_id);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmitInlineComment = async (body: string): Promise<boolean> => {
    if (!activeChange || !commentAnchor) return false;
    setSubmitting(true);
    setError(null);
    try {
      await api.addReviewComment(activeChange.change_id, {
        path: commentAnchor.path,
        line: commentAnchor.line,
        side: commentAnchor.side,
        body,
        author: identity.principal,
        kind: "comment",
      });
      setCommentAnchor(null);
      reloadReviews(activeChange.change_id);
      return true;
    } catch (err: unknown) {
      setError(errorText(err));
      return false;
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmitInlineSteer = async (opts: {
    body: string;
    targetAgent: string;
    triggerRevision: boolean;
  }): Promise<boolean> => {
    if (!activeChange || !commentAnchor) return false;
    setSubmitting(true);
    setError(null);
    setSteeringNotice(null);
    const anchorPath = commentAnchor.path;
    const anchorLine = commentAnchor.line;
    const anchorSide = commentAnchor.side;
    const targetAgent = opts.targetAgent.trim();
    try {
      const createdComment = await api.addReviewComment(activeChange.change_id, {
        path: anchorPath,
        line: anchorLine,
        side: anchorSide,
        body: opts.body,
        author: identity.principal,
        kind: "steer",
        target_agent: targetAgent || null,
      });

      const safeAgentAllowed = /^[a-z0-9._-]+$/i.test(targetAgent);
      const canLiveRevise =
        opts.triggerRevision &&
        owner &&
        !isSimulatingLens &&
        Boolean(agentSandbox && agentSandbox !== "none") &&
        safeAgentAllowed &&
        agentProfiles.includes(targetAgent);

      setCommentAnchor(null);

      if (canLiveRevise) {
        try {
          const res = await api.steerReview(activeChange.change_id, {
            comment_ids: createdComment?.id ? [createdComment.id] : [],
            instruction: `Address steering directive on ${anchorPath}:L${anchorLine}: ${opts.body}`,
            agent_profile: targetAgent,
            auto_commit: true,
            mark_changes_requested: true,
          });
          setSteerResult(res);
          setSteerHandled(false);
          onLanesChanged?.();
          setSteeringNotice({
            message: `Revision R${res.target_round} started in caged session ${res.session.id.slice(0, 8)} for @${targetAgent}.`,
            sessionId: res.session.id,
          });
        } catch (steerErr: unknown) {
          setError(
            `Steering directive saved on ${anchorPath}:L${anchorLine}, but starting revision failed: ${errorText(steerErr)}`,
          );
        }
      } else if (opts.triggerRevision) {
        setSteeringNotice({
          message: targetAgent
            ? `Steering directive queued for @${targetAgent} on ${anchorPath}:L${anchorLine}.`
            : `Steering directive queued on ${anchorPath}:L${anchorLine}.`,
        });
      } else {
        setSteeringNotice({
          message: targetAgent
            ? `Steering directive posted for @${targetAgent} on ${anchorPath}:L${anchorLine}.`
            : `Steering directive posted on ${anchorPath}:L${anchorLine}.`,
        });
      }
      reloadReviews(activeChange.change_id);
      return true;
    } catch (err: unknown) {
      setError(errorText(err));
      return false;
    } finally {
      setSubmitting(false);
    }
  };

  const copyStr = (key: string, val: string) => {
    navigator.clipboard?.writeText(val).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1400);
  };

  const toggleFileCollapse = (path: string) => {
    setCollapsedFiles((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  // Fast syntax-highlighted diff (no Monaco) honoring the Split | Inline | Raw layout;
  // rows beyond LIGHT_DIFF_ROWS are opt-in.
  const renderLightDiff = (f: (typeof parsedCommitFiles)[number], layout: DiffLayout = "inline") => {
    if (!f.parsed) return null;
    if (layout === "raw") {
      return (
        <div className="p-2">
          <DiffBlock
            patch={f.patch}
            filePath={f.path}
            maxHeightClass="max-h-[540px]"
          />
        </div>
      );
    }
    const all = f.parsed.lines.filter((dl) => dl.kind !== "meta");
    const showAll = fullRows.has(f.path) || all.length <= LIGHT_DIFF_ROWS;
    const rows = showAll ? all : all.slice(0, LIGHT_DIFF_ROWS);
    const hunkHeader = (key: number, body: string) => (
      <div key={key} className="bg-[#7f95f8]/10 px-3 py-1 text-[12.5px] leading-[20px] text-[#9ec0f5]">
        {body}
      </div>
    );
    const bgFor = (kind: string) =>
      kind === "add" ? "bg-[#5bdba2]/10" : kind === "del" ? "bg-[#f27c7c]/10" : "";
    const sigilFor = (kind: string) =>
      kind === "add" ? "text-[#5bdba2]" : kind === "del" ? "text-[#f27c7c]" : "text-[#a6b5cf]";
    const more = !showAll && (
      <button
        type="button"
        onClick={() => toggleInSet(setFullRows, f.path)}
        className="mt-1 w-full border-t border-white/[0.06] px-3 py-1.5 text-center text-[12.5px] text-[#9ec0f5] hover:bg-white/[0.04]"
      >
        Show {all.length - LIGHT_DIFF_ROWS} more rows
      </button>
    );
    if (layout === "split") {
      const cell = (row: (typeof rows)[number] | null, side: "old" | "new") =>
        row ? (
          <div className={`flex min-w-0 px-2 ${bgFor(row.kind)}`}>
            <span className={GUTTER_CLS}>{side === "old" ? row.oldLine : row.newLine}</span>
            <span className={`w-4 shrink-0 select-none ${sigilFor(row.kind)}`}>
              {row.kind === "ctx" ? "" : row.sigil}
            </span>
            <span className="min-w-0 whitespace-pre-wrap break-words">
              <CodeTokens body={row.body} lang={f.lang} />
            </span>
          </div>
        ) : (
          <div aria-hidden="true" className="bg-white/[0.02]" />
        );
      return (
        <div className="overflow-x-auto py-2 font-mono text-[13.5px] leading-[20px]">
          <div className="min-w-[560px]">
            {pairSplitRows(rows).map((entry, pi) =>
              "full" in entry ? (
                hunkHeader(pi, entry.full.row.body)
              ) : (
                <div key={pi} className="grid grid-cols-2 divide-x divide-white/[0.06]">
                  {cell(entry.left?.row ?? null, "old")}
                  {cell(entry.right?.row ?? null, "new")}
                </div>
              ),
            )}
          </div>
          {more}
        </div>
      );
    }
    return (
      <div className="overflow-x-auto py-2 font-mono text-[13.5px] leading-[20px]">
        {rows.map((dl, li) => {
          if (dl.kind === "hunk") return hunkHeader(li, dl.body);
          return (
            <div key={li} className={`flex px-2 ${bgFor(dl.kind)}`}>
              <span className={GUTTER_CLS}>{dl.oldLine ?? ""}</span>
              <span className={GUTTER_CLS}>{dl.newLine ?? ""}</span>
              <span className={`w-4 shrink-0 select-none ${sigilFor(dl.kind)}`}>{dl.sigil}</span>
              <span className="whitespace-pre">
                <CodeTokens body={dl.body} lang={f.lang} />
              </span>
            </div>
          );
        })}
        {more}
      </div>
    );
  };

  const renderCommitFileCard = (
    f: (typeof parsedCommitFiles)[number],
    idx: number,
    meta?: { risk?: RiskLevel; riskReasons?: string[] },
  ) => {
    const collapsed = collapsedFiles.has(f.path);
    const isReviewed = reviewedIds.has(f.path);
    const isFocused = focusedCommitFile === f.path;
    const hasSides = Boolean(
      f.sides && (f.sides.originalLineMap.length > 0 || f.sides.modifiedLineMap.length > 0),
    );
    const monacoToggleable = f.allowed && !f.binary && hasSides && commitDiffView !== "raw";
    // monacoOptIn holds paths whose renderer was flipped away from the size-based default.
    const autoMonaco = parsedCommitFiles.length - collapsedFiles.size <= MONACO_AUTO_MAX;
    const monacoOn = monacoToggleable && autoMonaco !== monacoOptIn.has(f.path);
    return (
      <div
        id={`diff-file-${idx}`}
        key={f.path}
        style={{ contentVisibility: "auto", containIntrinsicSize: "auto 220px" }}
        className={`pr-well overflow-hidden rounded-xl transition ${
          isFocused
            ? "border-[#9ec0f5]/35"
            : isReviewed
              ? "border-[#5bdba2]/25 opacity-85"
              : ""
        }`}
      >
        <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-3.5 py-2.5">
          <button
            type="button"
            onClick={() => {
              setFocusedCommitFile(f.path);
              toggleFileCollapse(f.path);
            }}
            className="flex min-w-0 flex-1 items-center gap-2 text-left hover:text-white"
          >
            <IconChevron
              direction={collapsed ? "right" : "down"}
              className="h-4 w-4 text-[#98a8c4]"
            />
            <span className="truncate font-mono text-[13.5px] text-[#dce4f5]">{f.path}</span>
            {f.allowed && f.zone && (
              <span className="hidden rounded-full border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-[12px] text-[#67d6dc] sm:inline">
                {f.zone}
              </span>
            )}
            {meta?.risk && meta.risk !== "low" && (
              <span
                title={meta.riskReasons?.join(" · ")}
                className={`hidden shrink-0 rounded-full border px-2 py-0.5 font-mono text-[12px] sm:inline ${riskBadgeClasses(
                  meta.risk,
                )}`}
              >
                {riskLabel(meta.risk)}
              </span>
            )}
          </button>

          <div className="flex shrink-0 items-center gap-2 font-mono text-[12.5px]">
            {f.allowed && f.binary ? (
              <span className="rounded-full border border-white/[0.1] bg-white/[0.05] px-2 py-0.5 text-[12px] text-[#b6c3db]">
                Binary
              </span>
            ) : f.allowed && f.parsed ? (
              <>
                <span className="text-[#5bdba2]">+{f.parsed.additions}</span>
                <span className="text-[#f27c7c]">-{f.parsed.deletions}</span>
              </>
            ) : (
              <span className="inline-flex items-center gap-1 text-[#a6b5cf]">
                <IconLock className="h-4 w-4" /> Redacted
              </span>
            )}
            {monacoToggleable && !collapsed && (
              <button
                type="button"
                onClick={() => toggleInSet(setMonacoOptIn, f.path)}
                aria-pressed={monacoOn}
                title={monacoOn ? "Switch to fast lightweight diff" : "Open in Monaco diff"}
                className={`hidden rounded-full border px-2 py-0.5 text-[12.5px] transition sm:inline-flex ${
                  monacoOn
                    ? "border-[#9ec0f5]/40 bg-[#7f95f8]/16 text-[#9ec0f5]"
                    : "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf] hover:text-[#f3f6fd]"
                }`}
              >
                Monaco
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                setFocusedCommitFile(f.path);
                handleToggleReviewed(f.path);
              }}
              aria-pressed={isReviewed}
              aria-label={`Mark ${f.path} as ${isReviewed ? "unreviewed" : "reviewed"}`}
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[12.5px] transition ${
                isReviewed
                  ? "border-[#5bdba2]/40 bg-[#5bdba2]/16 text-[#5bdba2]"
                  : "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf] hover:text-[#f3f6fd]"
              }`}
            >
              <IconCheck className="h-3 w-3" />
              <span className="hidden sm:inline">{isReviewed ? "Reviewed" : "Mark"}</span>
            </button>
          </div>
        </div>

        {!collapsed &&
          (!f.allowed ? (
            <RedactedNotice label={`Zero bytes transmitted for ${identity.label}`} />
          ) : f.binary ? (
            <div className="px-4 py-4 font-mono text-[13.5px] text-[#a6b5cf]">
              Binary file — inline diff preview unavailable
            </div>
          ) : f.parsed ? (
            commitDiffView === "raw" || hasSides ? (
              <>
                {monacoOn && f.sides ? (
                  <Suspense fallback={renderLightDiff(f, commitDiffView)}>
                    <MonacoDiffViewer
                      original={f.sides.original}
                      modified={f.sides.modified}
                      path={f.path}
                      renderSideBySide={commitDiffView === "split"}
                      collapseUnchanged={false}
                      autoHeight={true}
                      minHeight={140}
                      maxHeight={540}
                      originalLineMap={f.sides.originalLineMap}
                      modifiedLineMap={f.sides.modifiedLineMap}
                      readOnly={true}
                      ariaLabel={`Diff for ${f.path}`}
                    />
                  </Suspense>
                ) : (
                  renderLightDiff(f, commitDiffView)
                )}
                {f.truncationNotice && (
                  <div className="border-t border-white/[0.06] bg-black/25 px-3.5 py-1.5 font-mono text-[12.5px] italic text-[#98a8c4]">
                    {f.truncationNotice}
                  </div>
                )}
              </>
            ) : (
              <div className="px-4 py-4 font-mono text-[13.5px] text-[#98a8c4]">
                {f.truncationNotice ?? "No textual diff hunks"}
              </div>
            )
          ) : null)}
      </div>
    );
  };

  const renderRoundHunkCard = (
    hunk: ReviewDiffHunk,
    meta?: { risk?: RiskLevel; riskReasons?: string[] },
  ) => {
    if (!activeChange || !activeRound) return null;
    const selected = activeHunk?.id === hunk.id;
    const synced = syncedHunkId === hunk.id;
    const isReviewed = reviewedIds.has(hunk.id);
    const hLang = detectLanguage(hunk.path);
    const hunkData = roundHunkData.get(hunk.id);
    const hunkCommentInfo = roundHunkComments.get(hunk.id);
    const monacoToggleable =
      hunk.allowed && Boolean(hunkData) && (roundDiffView === "split" || roundDiffView === "inline");
    // monacoOptIn holds hunks flipped away from the size-based default (Monaco only for tiny rounds).
    const autoMonaco = activeRound.hunks.length <= MONACO_AUTO_MAX;
    const isMonacoRoundMode = monacoToggleable && autoMonaco !== monacoOptIn.has(hunk.id);
    const hunkRows = hunk.allowed && !isMonacoRoundMode ? computeHunkRows(hunk) : [];
    const newLineRowIndex = new Map<number, number>();
    hunkRows.forEach((row, idx) => {
      if (row.newLine !== null && !newLineRowIndex.has(row.newLine)) {
        newLineRowIndex.set(row.newLine, idx);
      }
    });
    const hunkComments = (activeChange.comments ?? []).filter(
      (c) => c.path === hunk.path && c.line !== undefined && c.line !== null,
    );
    const renderedCommentKeys = new Set<string>();

    const renderComment = (c: ReviewComment) => {
      const steer = isSteeringComment(c);
      const done = addressedRound(c);
      return (
        <div key={c.id} className="space-y-0.5">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px]">
            <span className="inline-flex flex-wrap items-center gap-1.5">
              <span className="text-[#9ec0f5]">{c.author}</span>
              {steer && (
                <span className="inline-flex items-center gap-1 rounded-full border border-[#67d6dc]/35 bg-[#7f95f8]/14 px-2 py-px text-[12px] text-[#67d6dc]">
                  <IconSteer className="h-3 w-3" />
                  <span>Steer · @{steeringTargetAgent(c)}</span>
                </span>
              )}
              {c.steer_session_id && (
                <span className="rounded-full bg-[#5bdba2]/12 px-1.5 py-px text-[12px] text-[#5bdba2]">
                  session:{c.steer_session_id.slice(0, 8)}
                </span>
              )}
            </span>
            <span className="flex flex-wrap items-center gap-2">
              {done !== null && (
                <span className="rounded-full bg-[#5bdba2]/12 px-2 py-0.5 text-[12px] text-[#5bdba2]">
                  Addressed in R{done}
                </span>
              )}
              {owner && (
                <button
                  type="button"
                  onClick={() => openSteer([c.id])}
                  className="pr-pill rounded-full px-2 py-0.5 text-[12px] text-[#9ec0f5] hover:text-white"
                >
                  Send to Agent → R{nextRound}
                </button>
              )}
              <span className="text-[#a6b5cf]">
                L{c.line}
                {c.side === "old" ? " (old)" : ""}
              </span>
              {c.created_at && (
                <span className="text-[#98a8c4]">
                  <Time value={c.created_at} />
                </span>
              )}
            </span>
          </div>
          <div className="whitespace-pre-wrap text-[13.5px] leading-relaxed text-[#dce4f5]">
            {c.body}
          </div>
        </div>
      );
    };

    const renderComposer = () =>
      commentAnchor && activeRound ? (
        <InlineSteeringComposer
          change={activeChange}
          hunk={hunk}
          line={commentAnchor.line}
          viewerIdentity={identity}
          agentProfiles={agentProfiles}
          agentSandbox={agentSandbox}
          owner={owner}
          isSimulatingLens={isSimulatingLens}
          visibleHunks={activeRound.hunks}
          submitting={submitting}
          onCancel={() => setCommentAnchor(null)}
          onSubmitComment={handleSubmitInlineComment}
          onSubmitSteer={handleSubmitInlineSteer}
        />
      ) : null;

    const isComposerAt = (i: number) =>
      commentAnchor?.hunkId === hunk.id && commentAnchor.rowIdx === i;

    // Match both line AND side so old-side comments stay on deleted lines
    // and new-side comments stay on added/context lines. Call once per row (it tracks rendered keys).
    const commentsForRow = (row: HunkLineRow, i: number): ReviewComment[] => {
      const isDel = row.kind === "del";
      const anchorLine = row.anchorLine ?? 1;
      const commentKey = `${isDel ? "old" : "new"}:${anchorLine}`;
      const preferredNewIdx = newLineRowIndex.get(anchorLine);
      const found = renderedCommentKeys.has(commentKey)
        ? []
        : hunkComments.filter((c) => {
            if (c.line !== anchorLine) return false;
            if (c.side === "old") return isDel;
            if (c.side === "new") return !isDel && preferredNewIdx === i;
            // Legacy comments without `side`: prefer new-side row if present in hunk.
            return preferredNewIdx !== undefined ? preferredNewIdx === i : true;
          });
      if (found.length > 0) renderedCommentKeys.add(commentKey);
      return found;
    };

    const rowExtras = (row: HunkLineRow, i: number) => {
      if (row.kind === "meta") return null;
      const lineComments = commentsForRow(row, i);
      const here = isComposerAt(i);
      if (lineComments.length === 0 && !here) return null;
      return (
        <Fragment key={i}>
          {lineComments.length > 0 && (
            <div className="mx-3 my-1.5 space-y-1.5 rounded-xl border border-[#7f95f8]/25 bg-[#0b1020] p-2.5 font-sans">
              {lineComments.map((c) => renderComment(c))}
            </div>
          )}
          {here && renderComposer()}
        </Fragment>
      );
    };

    const commentButton = (row: HunkLineRow, i: number) => {
      const rowSide: "old" | "new" = row.kind === "del" ? "old" : "new";
      const anchorLine = row.anchorLine ?? 1;
      const here = isComposerAt(i);
      return (
        <button
          type="button"
          onClick={() => {
            selectHunkWithSync(hunk.id);
            if (here) {
              setCommentAnchor(null);
            } else {
              setCommentAnchor({
                hunkId: hunk.id,
                path: hunk.path,
                line: anchorLine,
                side: rowSide,
                rowIdx: i,
              });
            }
          }}
          aria-label={`Comment or steer agent on ${hunk.path} ${rowSide === "old" ? "deleted " : ""}line ${anchorLine}`}
          title={`Comment or steer agent on ${rowSide === "old" ? "old " : ""}line ${anchorLine}`}
          className={`mr-1 mt-0.5 inline-flex h-4 w-4 shrink-0 items-center justify-center rounded text-[12.5px] transition ${
            here
              ? "bg-[#7f95f8] text-[#070912] opacity-100"
              : "bg-[#7f95f8]/20 text-[#9ec0f5] opacity-0 hover:bg-[#7f95f8] hover:text-[#070912] focus:opacity-100 group-hover:opacity-100"
          }`}
        >
          +
        </button>
      );
    };

    const rowBg = (kind: HunkLineRow["kind"]) =>
      kind === "add" ? "bg-[#5bdba2]/10" : kind === "del" ? "bg-[#f27c7c]/10" : "";
    const rowSigilCls = (kind: HunkLineRow["kind"]) =>
      kind === "add" ? "text-[#5bdba2]" : kind === "del" ? "text-[#f27c7c]" : "text-[#a6b5cf]";
    const metaRow = (row: HunkLineRow, i: number) => (
      <div key={i} className="flex items-start px-2 py-0.5 text-[12.5px] italic text-[#a6b5cf]">
        <span className="mr-1 w-4 shrink-0" />
        <span className="w-10 shrink-0 pr-2" />
        <span className="w-10 shrink-0 pr-2" />
        <span className="w-4 shrink-0" />
        <span className="whitespace-pre">{row.body}</span>
      </div>
    );

    // Non-interactive rows: the Monaco Suspense fallback, so the card never collapses to a flat box.
    const renderStaticRows = () => (
      <div className="overflow-x-auto py-2 font-mono text-[13.5px] leading-[20px]">
        {computeHunkRows(hunk).map((row, i) =>
          row.kind === "meta" ? (
            metaRow(row, i)
          ) : (
            <div key={i} className={`flex px-2 ${rowBg(row.kind)}`}>
              <span className="mr-1 w-4 shrink-0" />
              <span className={GUTTER_CLS}>{row.oldLine ?? ""}</span>
              <span className={GUTTER_CLS}>{row.newLine ?? ""}</span>
              <span className={`w-4 shrink-0 select-none ${rowSigilCls(row.kind)}`}>{row.sigil}</span>
              <span className="whitespace-pre">
                <CodeTokens body={row.body} lang={hLang} />
              </span>
            </div>
          ),
        )}
      </div>
    );

    const renderInteractiveRows = () => {
      const allRows = hunkRows.length > 0 ? hunkRows : computeHunkRows(hunk);
      if (roundDiffView === "split") {
        const side = (cell: SplitCell<HunkLineRow> | null, which: "old" | "new") => {
          if (!cell) return <div aria-hidden="true" className="bg-white/[0.02]" />;
          const { row, idx } = cell;
          const showBtn = which === "old" ? row.kind === "del" : row.kind !== "del";
          return (
            <div className={`group flex min-w-0 items-start px-2 ${rowBg(row.kind)}`}>
              {showBtn ? commentButton(row, idx) : <span className="mr-1 w-4 shrink-0" />}
              <span className={GUTTER_CLS}>
                {which === "old" ? (row.oldLine ?? "") : (row.newLine ?? "")}
              </span>
              <span className={`w-4 shrink-0 select-none ${rowSigilCls(row.kind)}`}>
                {row.kind === "ctx" ? "" : row.sigil}
              </span>
              <span className="min-w-0 whitespace-pre-wrap break-words">
                <CodeTokens body={row.body} lang={hLang} />
              </span>
            </div>
          );
        };
        return (
          <div className="min-w-[560px]">
            {pairSplitRows(allRows).map((entry, pi) => {
              if ("full" in entry) return metaRow(entry.full.row, entry.full.idx);
              const extraCells =
                entry.left && entry.left.row.kind !== "ctx"
                  ? [entry.left, entry.right]
                  : [entry.right];
              return (
                <div key={pi}>
                  <div className="grid grid-cols-2 divide-x divide-white/[0.06]">
                    {side(entry.left, "old")}
                    {side(entry.right, "new")}
                  </div>
                  {extraCells.map((c) => (c ? rowExtras(c.row, c.idx) : null))}
                </div>
              );
            })}
          </div>
        );
      }
      return (
        <>
          {allRows.map((row, i) =>
            row.kind === "meta" ? (
              metaRow(row, i)
            ) : (
              <div key={i}>
                <div className={`group flex items-start px-2 ${rowBg(row.kind)}`}>
                  {commentButton(row, i)}
                  <span className={GUTTER_CLS}>{row.oldLine ?? ""}</span>
                  <span className={GUTTER_CLS}>{row.newLine ?? ""}</span>
                  <span className={`w-4 shrink-0 select-none ${rowSigilCls(row.kind)}`}>
                    {row.sigil}
                  </span>
                  <span className="whitespace-pre">
                    <CodeTokens body={row.body} lang={hLang} />
                  </span>
                </div>
                {rowExtras(row, i)}
              </div>
            ),
          )}
        </>
      );
    };

    return (
      <div
        id={`review-hunk-${hunk.id}`}
        key={hunk.id}
        role="region"
        aria-label={hunk.path}
        style={{ contentVisibility: "auto", containIntrinsicSize: "auto 200px" }}
        className={`overflow-hidden rounded-xl border transition ${
          synced
            ? "pr-hunk-synced bg-[#7f95f8]/10"
            : selected
              ? "border-[#9ec0f5]/38 bg-[#7f95f8]/10"
              : isReviewed
                ? "border-[#5bdba2]/25 bg-[#060810]/55 opacity-85 hover:opacity-100"
                : "border-white/[0.06] bg-[#060810]/65 hover:border-white/[0.14]"
        }`}
      >
        <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] px-3.5 py-2.5">
          <button
            type="button"
            onClick={() => selectHunkWithSync(hunk.id)}
            className="flex min-w-0 flex-1 items-center gap-2 text-left"
          >
            <span className="truncate font-mono text-[13.5px] text-[#e6ecf8]">{hunk.path}</span>
            {hunk.allowed && hunk.zone && (
              <span className="hidden shrink-0 rounded-full border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 font-mono text-[12px] text-[#67d6dc] sm:inline">
                {hunk.zone}
              </span>
            )}
            {meta?.risk && meta.risk !== "low" && (
              <span
                title={meta.riskReasons?.join(" · ")}
                className={`hidden shrink-0 rounded-full border px-2 py-0.5 font-mono text-[12px] sm:inline ${riskBadgeClasses(
                  meta.risk,
                )}`}
              >
                {riskLabel(meta.risk)}
              </span>
            )}
          </button>

          <div className="flex shrink-0 items-center gap-2 font-mono text-[12.5px] text-[#98a8c4]">
            {isMonacoRoundMode && (
              <span className="hidden text-[#a6b5cf] sm:inline">Click gutter to comment</span>
            )}
            {selected && <span className="text-[#9ec0f5]">Replay</span>}
            {monacoToggleable && (
              <button
                type="button"
                onClick={() => toggleInSet(setMonacoOptIn, hunk.id)}
                aria-pressed={isMonacoRoundMode}
                title={isMonacoRoundMode ? "Switch to fast lightweight diff" : "Open in Monaco diff"}
                className={`hidden rounded-full border px-2 py-0.5 text-[12.5px] transition sm:inline-flex ${
                  isMonacoRoundMode
                    ? "border-[#9ec0f5]/40 bg-[#7f95f8]/16 text-[#9ec0f5]"
                    : "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf] hover:text-[#f3f6fd]"
                }`}
              >
                Monaco
              </button>
            )}
            <button
              type="button"
              onClick={() => {
                selectHunkWithSync(hunk.id);
                handleToggleReviewed(hunk.id);
              }}
              aria-pressed={isReviewed}
              aria-label={`Mark ${hunk.path} as ${isReviewed ? "unreviewed" : "reviewed"}`}
              className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[12.5px] transition ${
                isReviewed
                  ? "border-[#5bdba2]/40 bg-[#5bdba2]/16 text-[#5bdba2]"
                  : "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf] hover:text-[#f3f6fd]"
              }`}
            >
              <IconCheck className="h-3 w-3" />
              <span>{isReviewed ? "Reviewed" : "Review"}</span>
            </button>
          </div>
        </div>

        <div className="bg-[#7f95f8]/8 px-3.5 py-1 font-mono text-[12.5px] text-[#9ec0f5]">
          {hunk.header}
        </div>

        {!hunk.allowed ? (
          <RedactedNotice label="Redacted — this identity cannot read this hunk" />
        ) : isMonacoRoundMode && hunkData ? (
          <div>
            <Suspense fallback={renderStaticRows()}>
              <MonacoDiffViewer
                path={hunk.path}
                original={hunkData.sides.original}
                modified={hunkData.sides.modified}
                renderSideBySide={roundDiffView === "split"}
                collapseUnchanged={false}
                autoHeight={true}
                minHeight={130}
                maxHeight={460}
                originalLineMap={hunkData.sides.originalLineMap}
                modifiedLineMap={hunkData.sides.modifiedLineMap}
                commentedLines={hunkCommentInfo?.badges}
                readOnly={true}
                ariaLabel={`Review hunk for ${hunk.path}`}
                onLineCommentClick={(line, side) => {
                  selectHunkWithSync(hunk.id);
                  setCommentAnchor({
                    hunkId: hunk.id,
                    path: hunk.path,
                    line,
                    side,
                    rowIdx: -1,
                  });
                }}
              />
            </Suspense>

            {commentAnchor && commentAnchor.hunkId === hunk.id && renderComposer()}

            {hunkCommentInfo && hunkCommentInfo.comments.length > 0 && (
              <div className="space-y-2 border-t border-white/[0.06] bg-[#0b1020] px-3.5 py-2.5 font-sans">
                {hunkCommentInfo.comments.map((c) => (
                  <div
                    key={c.id}
                    className="rounded-xl border border-[#7f95f8]/20 bg-[#0b1020] p-2.5"
                  >
                    {renderComment(c)}
                  </div>
                ))}
              </div>
            )}

            {hunkData.metaLines.length > 0 && (
              <div className="border-t border-white/[0.06] bg-black/25 px-3.5 py-1.5 font-mono text-[12.5px] italic text-[#a6b5cf]">
                {hunkData.metaLines.join(" · ")}
              </div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto py-2 font-mono text-[13.5px] leading-[20px]">
            {renderInteractiveRows()}
          </div>
        )}
      </div>
    );
  };

  const renderConcernSection = <T,>(
    group: ConcernGroup<T>,
    scope: "commit" | "round",
    renderEntry: (entry: ConcernGroup<T>["items"][number]) => React.ReactNode,
  ) => {
    const { definition, items, highestRisk } = group;
    const isCollapsed = collapsedConcerns.has(definition.id);
    const prog = computeProgress(
      items.map((it) => it.id),
      reviewedIds,
    );
    const allReviewed = prog.total > 0 && prog.reviewed >= prog.total;

    return (
      <section
        key={definition.id}
        id={`concern-${scope}-${definition.id}`}
        className="pr-concern-card overflow-hidden rounded-2xl"
      >
        <button
          type="button"
          onClick={() => toggleConcern(definition.id)}
          aria-expanded={!isCollapsed}
          className="flex w-full flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.02] px-4 py-2.5 text-left transition hover:bg-white/[0.04]"
        >
          <div className="flex min-w-0 items-center gap-2">
            <IconChevron
              direction={isCollapsed ? "right" : "down"}
              className="h-4 w-4 shrink-0 text-[#98a8c4]"
            />
            <span className="truncate text-[14px] font-semibold text-[#f3f6fd]">
              {definition.label}
            </span>
            {(highestRisk === "high" || highestRisk === "critical") && (
              <span
                className={`shrink-0 rounded-full border px-2 py-0.5 font-mono text-[12px] ${riskBadgeClasses(
                  highestRisk,
                )}`}
              >
                {riskLabel(highestRisk)}
              </span>
            )}
            {definition.defaultCollapsed && isCollapsed && (
              <span className="hidden rounded-full bg-white/[0.05] px-2 py-0.5 font-mono text-[12px] text-[#98a8c4] sm:inline">
                auto-collapsed
              </span>
            )}
          </div>

          <div className="flex shrink-0 items-center gap-2 font-mono text-[12.5px]">
            <span className="text-[#98a8c4]">
              {plural(items.length, scope === "commit" ? "file" : "hunk")}
            </span>
            <span
              className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[12.5px] ${
                allReviewed
                  ? "bg-[#5bdba2]/16 text-[#5bdba2]"
                  : "bg-white/[0.06] text-[#b6c3db]"
              }`}
            >
              {allReviewed && <IconCheck className="h-3 w-3" />}
              <span>
                {prog.reviewed}/{prog.total}
              </span>
            </span>
          </div>
        </button>

        {!isCollapsed && (
          <div className="space-y-3 p-3.5 sm:p-4">{items.map((entry) => renderEntry(entry))}</div>
        )}
      </section>
    );
  };

  const roundViewControls =
    activeChange && (activeChange.lane_id || rounds.length > 1) ? (
      <>
                {activeChange.lane_id && (
                  <span
                    title={`Lane ${activeChange.lane_id}`}
                    className={`rounded-full px-2 py-0.5 font-mono text-[12.5px] ${
                      (activeLane?.status ?? activeChange.lane_status) === "conflicted"
                        ? "bg-[#f27c7c]/15 text-[#f27c7c]"
                        : "bg-white/[0.07] text-[#d2dbee]"
                    }`}
                  >
                    lane {activeLane?.status ?? activeChange.lane_status ?? "active"}
                  </span>
                )}
                {rounds.length > 1 && (
                  <>
                    <div
                      role="group"
                      aria-label="Round view"
                      className="inline-flex shrink-0 rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]"
                    >
                      {(["snapshot", "interdiff"] as const).map((k) => (
                        <button
                          key={k}
                          type="button"
                          aria-pressed={viewKind === k}
                          onClick={() => setViewKind(k)}
                          className={`rounded-full px-2.5 py-0.5 capitalize transition ${
                            viewKind === k
                              ? "pr-pill-active"
                              : "text-[#a6b5cf] hover:text-[#f3f6fd]"
                          }`}
                        >
                          {k}
                        </button>
                      ))}
                    </div>
                    {viewKind === "interdiff" && (
                      <>
                        <label className="inline-flex shrink-0 items-center gap-1.5 font-mono text-[12.5px] text-[#a6b5cf]">
                          From
                          <select
                            value={fromRound}
                            onChange={(e) => setFromRound(Number(e.target.value))}
                            className="pr-well rounded-full px-2.5 py-0.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none"
                          >
                            <option value={0}>R0 (base)</option>
                            {rounds.map((r) => (
                              <option key={r.round} value={r.round}>
                                R{r.round}
                              </option>
                            ))}
                          </select>
                        </label>
                        <span className="text-[#a6b5cf]">→</span>
                        <label className="inline-flex shrink-0 items-center gap-1.5 font-mono text-[12.5px] text-[#a6b5cf]">
                          To
                          <select
                            value={toRound}
                            onChange={(e) => setToRound(Number(e.target.value))}
                            className="pr-well rounded-full px-2.5 py-0.5 font-mono text-[12.5px] text-[#dce4f5] [color-scheme:dark] focus:outline-none"
                          >
                            {rounds.map((r) => (
                              <option key={r.round} value={r.round}>
                                R{r.round}
                              </option>
                            ))}
                          </select>
                        </label>
                        {fromRound >= toRound && (
                          <span className="shrink-0 font-mono text-[12.5px] text-[#a8c5ff]">
                            Pick a From round earlier than To
                          </span>
                        )}
                      </>
                    )}
                  </>
                )}

      </>
    ) : null;

  const roundLayoutToggle = (
    <div
          role="group"
          aria-label="Review diff layout"
          className="inline-flex items-center rounded-full border border-white/[0.08] bg-white/[0.03] shrink-0 p-0.5 font-mono text-[12.5px]"
        >
          {(
            [
              { id: "split", label: "Split" },
              { id: "inline", label: "Inline" },
            ] as const
          ).map((opt) => (
            <button
              key={opt.id}
              type="button"
              aria-pressed={roundDiffView === opt.id}
              onClick={() => setRoundDiffView(opt.id)}
              className={`rounded-full px-2.5 py-0.5 transition ${
                roundDiffView === opt.id
                  ? "pr-pill-active"
                  : "text-[#a6b5cf] hover:text-[#f3f6fd]"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
  );

  const roundSteerButton = owner ? (
    <button
      type="button"
      aria-expanded={steerOpen}
      onClick={() => (steerOpen ? setSteerOpen(false) : openSteer())}
      aria-label={`Steer Agent → R${nextRound}`}
      title={`Steer Agent → R${nextRound}`}
      className="pr-action-btn shrink-0 rounded-full px-3 py-0.5 font-mono text-[12.5px]"
    >
      Steer → R{nextRound}
    </button>
  ) : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 p-3 sm:gap-4 sm:p-4 xl:p-5">
      {/* Compact mode switch bar */}
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2.5">
        <div className="inline-flex shrink-0 items-center gap-0.5 rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5">
          <button
            type="button"
            onClick={() => setMode("commits")}
            className={`rounded-full px-3.5 py-1 text-[14px] font-medium transition ${
              mode === "commits" ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#f3f6fd]"
            }`}
          >
            Commits
          </button>
          <button
            type="button"
            onClick={() => setMode("rounds")}
            className={`rounded-full px-3.5 py-1 text-[14px] font-medium transition ${
              mode === "rounds" ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#f3f6fd]"
            }`}
          >
            Rounds
          </button>
        </div>

        {mode === "commits" && (
          <div className="flex min-w-0 items-center gap-2.5 font-mono text-[12.5px] text-[#a6b5cf]">
            {(refName || baseBranch) && (
              <span
                title={`Commit log for ${refName || baseBranch}`}
                className="pr-pill inline-flex min-w-0 max-w-[16rem] items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[#d2dbee]"
              >
                <IconBranchRef className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
                <span className="truncate">{refName || baseBranch}</span>
              </span>
            )}
            {commitsLoaded && (
              <span className="shrink-0">
                {plural(commits.length, "commit")}
                {hasMoreCommits ? "+" : ""}
              </span>
            )}
            <span
              className="hidden shrink-0 items-center gap-1 md:inline-flex"
              aria-label="Keyboard shortcuts"
              title="j/k navigate commits · v mark reviewed"
            >
              <kbd className="pr-kbd">j</kbd>
              <kbd className="pr-kbd">k</kbd>
              <span>navigate</span>
              <kbd className="pr-kbd ml-1">v</kbd>
              <span>reviewed</span>
            </span>
          </div>
        )}

        {mode === "rounds" && (
          <div className="flex flex-wrap items-center gap-1.5">
            {changes.map((ch) => (
              <button
                key={ch.change_id}
                type="button"
                onClick={() => {
                  setSelectedChangeId(ch.change_id);
                  setCommentAnchor(null);
                  setActiveStepIndex(0);
                  onSelectChange?.(ch.change_id);
                  const latest = ch.rounds[ch.rounds.length - 1];
                  if (latest) {
                    setRoundNumber(latest.round);
                    setSelectedHunkId(latest.hunks[0]?.id ?? null);
                  }
                }}
                className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 font-mono text-[13px] transition ${
                  activeChange?.change_id === ch.change_id
                    ? "pr-pill-active"
                    : "pr-pill text-[#a6b5cf]"
                }`}
              >
                <IconChanges className="h-4 w-4" />
                <span>{ch.change_id}</span>
                {ch.quarantine_flagged && <span className="h-2 w-2 rounded-full bg-[#7f95f8]" />}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setCreateReviewOpen((o) => !o)}
              className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px]"
            >
              <IconPlus className="h-4 w-4" />
              <span>New Review</span>
            </button>
          </div>
        )}
      </div>

      {mode === "rounds" && createReviewOpen && (
        <form
          onSubmit={(e) => void handleCreateReview(e)}
          className="pr-elevated flex shrink-0 flex-wrap items-center justify-between gap-2.5 rounded-2xl px-4 py-3"
        >
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
            <input
              value={newRevTitle}
              onChange={(e) => setNewRevTitle(e.target.value)}
              aria-label="Review title"
              placeholder="Review title…"
              className="pr-well min-w-[180px] flex-1 rounded-xl px-3 py-1.5 font-mono text-[13.5px] text-[#f3f6fd] focus:outline-none"
            />
            <select
              value={newRevBranch || defaultReviewBranch}
              onChange={(e) => setNewRevBranch(e.target.value)}
              disabled={branches.length === 0}
              aria-label="Branch to review"
              className="pr-well rounded-xl px-2.5 py-1.5 font-mono text-[13px] text-[#dce4f5] focus:outline-none disabled:opacity-50"
            >
              {branches.length === 0 ? (
                <option value="" className="bg-[#0b0f1b]">
                  No branches available
                </option>
              ) : (
                branches.map((b) => (
                  <option key={b.name} value={b.name} className="bg-[#0b0f1b]">
                    {b.name}
                  </option>
                ))
              )}
            </select>
            {sessions.length > 0 && (
              <select
                value={newRevSessionId}
                onChange={(e) => setNewRevSessionId(e.target.value)}
                aria-label="Cage session to attach"
                className="pr-well rounded-xl px-2.5 py-1.5 font-mono text-[13px] text-[#dce4f5] focus:outline-none"
              >
                <option value="" className="bg-[#0b0f1b]">
                  Attach cage session (optional)
                </option>
                {sessions.map((s) => (
                  <option key={s.id} value={s.id} className="bg-[#0b0f1b]">
                    {s.id} · {s.command.slice(0, 28)}
                  </option>
                ))}
              </select>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="submit"
              disabled={submitting || !newRevTitle.trim() || !(newRevBranch || defaultReviewBranch)}
              className="pr-action-btn rounded-full px-3.5 py-1.5 text-[13px] disabled:opacity-45"
            >
              Create
            </button>
            <button
              type="button"
              onClick={() => setCreateReviewOpen(false)}
              aria-label="Close"
              className="rounded-lg p-1 text-[#98a8c4] hover:text-white"
            >
              <IconClose className="h-4 w-4" />
            </button>
          </div>
        </form>
      )}

      {error && (
        <div
          role="alert"
          className="rounded-xl border border-[#f27c7c]/25 bg-[#f27c7c]/10 px-4 py-2 font-mono text-[13px] text-[#f27c7c]"
        >
          {error}
        </div>
      )}

      {steeringNotice && (
        <div
          role="status"
          className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[#67d6dc]/30 bg-[#67d6dc]/10 px-4 py-2 font-mono text-[13px] text-[#dce4f5]"
        >
          <span className="inline-flex min-w-0 items-center gap-2">
            <IconSteer className="h-4 w-4 shrink-0 text-[#67d6dc]" />
            <span>{steeringNotice.message}</span>
          </span>
          <span className="flex shrink-0 items-center gap-2">
            {steeringNotice.sessionId && onOpenAgents && (
              <button
                type="button"
                onClick={onOpenAgents}
                className="rounded-full border border-[#67d6dc]/35 bg-[#67d6dc]/15 px-2.5 py-0.5 text-[12.5px] text-[#67d6dc] hover:bg-[#67d6dc]/25"
              >
                Open Agents →
              </button>
            )}
            <button
              type="button"
              onClick={() => setSteeringNotice(null)}
              aria-label="Dismiss steering notice"
              className="rounded p-0.5 text-[#98a8c4] hover:text-white"
            >
              <IconClose className="h-3.5 w-3.5" />
            </button>
          </span>
        </div>
      )}

      {mode === "commits" ? (
        <div className="flex min-h-0 flex-1 flex-col gap-4 lg:flex-row">
          {/* Left / Top: Searchable Real Git Log on Disk */}
          <aside className="pr-surface flex max-h-[220px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:w-[304px] xl:w-[336px]">
            <div className="flex items-center gap-2 border-b border-white/[0.06] px-3 py-2.5">
              <IconSearch className="h-4 w-4 text-[#98a8c4]" />
              <input
                value={commitSearch}
                onChange={(e) => setCommitSearch(e.target.value)}
                aria-label="Filter commits"
                placeholder="Filter commits… (j/k)"
                className="min-w-0 flex-1 bg-transparent text-[14px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
              />
            </div>
            <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto">
              {!commitsLoaded && filteredCommits.length === 0 && <CommitListSkeleton />}
              {commitsLoaded && filteredCommits.length === 0 && (
                <div className="p-4 text-center font-mono text-[13.5px] text-[#98a8c4]">
                  {commits.length === 0 ? "No commits yet" : "No commits match"}
                </div>
              )}
              {filteredCommits.map((c) => {
                const active = c.oid === selectedOid;
                return (
                  <button
                    key={c.oid}
                    type="button"
                    data-oid={c.oid}
                    onClick={() => {
                      setSelectedOid(c.oid);
                      onSelectOid?.(c.oid);
                    }}
                    className={`w-full px-4 py-3 text-left transition ${
                      active ? "bg-[#7f95f8]/14" : "hover:bg-white/[0.03]"
                    }`}
                  >
                    <div className="line-clamp-2 text-[14px] font-medium text-[#f3f6fd]">
                      {c.subject}
                    </div>
                    <div className="mt-1.5 flex items-center justify-between gap-2 font-mono text-[12.5px] text-[#98a8c4]">
                      <span className="text-[#9ec0f5]">{c.short_oid}</span>
                      <span
                        className="truncate"
                        title={isoTime(c.date ?? c.committed_at ?? c.timestamp)}
                      >
                        {plural(c.files_changed, "file")} · {c.relative_time}
                      </span>
                    </div>
                  </button>
                );
              })}
              {hasMoreCommits && (
                <button
                  type="button"
                  disabled={loadingMore}
                  onClick={loadMoreCommits}
                  className="w-full px-4 py-2.5 text-center font-mono text-[13px] text-[#9ec0f5] hover:bg-white/[0.03] disabled:opacity-50"
                >
                  {loadingMore ? (
                    <span className="inline-flex items-center gap-2">
                      <InlineSpinner />
                      <span>Loading</span>
                    </span>
                  ) : (
                    "Load more"
                  )}
                </button>
              )}
            </div>
          </aside>

          {/* Right / Bottom: ACL-Enforced Real Git Commit Diff with Guided Tour */}
          <section className="pr-surface relative flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
            {loadingDiff && commitDiff && commitDiff.oid !== selectedOid && (
              <div
                aria-hidden="true"
                className="pr-shimmer pointer-events-none absolute inset-x-0 top-0 z-20 h-0.5 !bg-[#7f95f8]/70"
              />
            )}
            {!commitDiff && (diffPending || !commitsLoaded) && <CommitDiffSkeleton />}
            {!commitDiff && !diffPending && commitsLoaded && (
              <div className="flex min-h-[160px] flex-1 items-center justify-center p-4 text-center font-mono text-[14px] text-[#a6b5cf]">
                {diffError ? (
                  diffError === COMMIT_HIDDEN_MESSAGE ? (
                    <RedactedNotice label={diffError} />
                  ) : (
                    <span role="alert" className="text-[#f27c7c]">
                      {diffError}
                    </span>
                  )
                ) : commits.length === 0 ? (
                  "No commits yet"
                ) : (
                  "Select a commit to see its changes"
                )}
              </div>
            )}
            {commitDiff && (
              <div
                aria-busy={loadingDiff && commitDiff.oid !== selectedOid}
                className={`flex min-h-0 flex-1 flex-col overflow-hidden transition-opacity duration-150 ${
                  loadingDiff && commitDiff.oid !== selectedOid ? "opacity-65" : "opacity-100"
                }`}
              >
                <CommitTrustHeader
                  commitDiff={commitDiff}
                  totals={commitTotals}
                  allCollapsed={collapsedFiles.size >= parsedCommitFiles.length}
                  onToggleCollapseAll={() =>
                    setCollapsedFiles((prev) =>
                      prev.size >= parsedCommitFiles.length
                        ? new Set()
                        : new Set(parsedCommitFiles.map((f) => f.path)),
                    )
                  }
                  copiedKey={copiedKey}
                  onCopy={copyStr}
                />

                {parsedCommitFiles.length > 0 && (
                  <ConcernWalkthroughBar
                    mode="commits"
                    leading={
                      <div
                        role="group"
                        aria-label="Commit diff layout"
                        className="inline-flex shrink-0 items-center rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]"
                      >
                        {(
                          [
                            { id: "split", label: "Split" },
                            { id: "inline", label: "Inline" },
                            { id: "raw", label: "Raw" },
                          ] as const
                        ).map((opt) => (
                          <button
                            key={opt.id}
                            type="button"
                            aria-pressed={commitDiffView === opt.id}
                            onClick={() => setCommitDiffView(opt.id)}
                            className={`rounded-full px-2.5 py-0.5 transition ${
                              commitDiffView === opt.id
                                ? "pr-pill-active"
                                : "text-[#a6b5cf] hover:text-[#f3f6fd]"
                            }`}
                          >
                            {opt.label}
                          </button>
                        ))}
                      </div>
                    }
                    viewMode={viewMode}
                    onViewModeChange={setViewMode}
                    groups={commitConcernGroups}
                    reviewedIds={reviewedIds}
                    totalCount={parsedCommitFiles.length}
                    itemUnit="file"
                    onJumpToConcern={jumpToConcern}
                    onResetReviewed={handleResetReviewed}
                  />
                )}

                {viewMode === "all" && parsedCommitFiles.length > 1 && (
                  <div className="flex shrink-0 items-center gap-1.5 overflow-x-auto border-b border-white/[0.06] px-4 py-2 sm:px-5">
                    {parsedCommitFiles.map((f, idx) => (
                      <a
                        key={f.path}
                        href={`#diff-file-${idx}`}
                        onClick={(e) => {
                          e.preventDefault();
                          document.getElementById(`diff-file-${idx}`)?.scrollIntoView();
                        }}
                        className="pr-pill inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee] hover:text-[#f3f6fd]"
                      >
                        {!f.allowed && <IconLock className="h-4 w-4 text-[#a6b5cf]" />}
                        <span>{f.path.split("/").pop()}</span>
                        {f.parsed && (
                          <span className="text-[12px] text-[#98a8c4]">
                            +{f.parsed.additions}/-{f.parsed.deletions}
                          </span>
                        )}
                      </a>
                    ))}
                  </div>
                )}

                <div
                  className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4 sm:p-5"
                >
                  {viewMode === "guided"
                    ? commitConcernGroups.map((group) =>
                        renderConcernSection(group, "commit", (entry) =>
                          renderCommitFileCard(
                            entry.item,
                            commitFileIndexByPath.get(entry.path) ?? 0,
                            {
                              risk: entry.classification.risk,
                              riskReasons: entry.classification.riskReasons,
                            },
                          ),
                        ),
                      )
                    : parsedCommitFiles.map((f, idx) => renderCommitFileCard(f, idx))}

                  {commitDiff.hidden_files > 0 && (
                    <div className="px-1 font-mono text-[13px] text-[#a6b5cf]">
                      {plural(commitDiff.hidden_files, "file")} not visible to this identity
                    </div>
                  )}
                </div>
              </div>
            )}
          </section>
        </div>
      ) : !reviewsLoaded ? (
        <RoundsSkeleton />
      ) : !activeChange ? (
        <div className="pr-surface flex min-h-[200px] flex-1 flex-col items-center justify-center gap-1.5 rounded-2xl p-6 text-center">
          {reviewsFailed ? (
            <>
              <div className="text-[14.5px] font-medium text-[#dce4f5]">Couldn't load reviews</div>
              <button
                type="button"
                onClick={() => {
                  setError(null);
                  setReviewsLoaded(false);
                  reloadReviews();
                }}
                className="pr-pill mt-1 rounded-full px-3.5 py-1 font-mono text-[13px] text-[#9ec0f5]"
              >
                Retry
              </button>
            </>
          ) : (
            <>
              <div className="text-[14.5px] font-medium text-[#dce4f5]">No reviews yet</div>
              <div className="text-[13.5px] text-[#a6b5cf]">
                Use New Review to open one for a branch.
              </div>
            </>
          )}
        </div>
      ) : !activeRound ? (
        <div className="pr-surface flex min-h-[200px] flex-1 flex-col items-center justify-center gap-1.5 rounded-2xl p-6 text-center">
          <div className="text-[14.5px] font-medium text-[#dce4f5]">
            No rounds yet for {activeChange.change_id}
          </div>
          <div className="text-[13.5px] text-[#a6b5cf]">
            The first round appears once the branch has commits to review.
          </div>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row lg:gap-4">
          {/* Mobile/Tablet Hunks vs Session Replay switch */}
          <div className="inline-flex shrink-0 self-start rounded-full border border-white/[0.08] bg-white/[0.03] p-1 lg:hidden">
            <button
              type="button"
              onClick={() => setMobileRoundPane("hunks")}
              className={`rounded-full px-3 py-1 font-mono text-[13px] ${
                mobileRoundPane === "hunks" ? "pr-pill-active" : "text-[#a6b5cf]"
              }`}
            >
              Hunks
            </button>
            <button
              type="button"
              onClick={() => setMobileRoundPane("replay")}
              className={`rounded-full px-3 py-1 font-mono text-[13px] ${
                mobileRoundPane === "replay" ? "pr-pill-active" : "text-[#a6b5cf]"
              }`}
            >
              Replay
            </button>
          </div>

          {/* Left: Intent & Trust Receipt + Concern-Grouped Walkthrough + Hunks */}
          <section
            className={`pr-surface min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl ${
              mobileRoundPane === "replay" ? "hidden lg:flex" : "flex"
            }`}
          >
            {activeChange && activeRound && (
              <>
                <IntentTrustReceipt
                  change={activeChange}
                  round={activeRound}
                  timeline={timeline}
                  identity={identity}
                  owner={owner}
                  baseBranch={baseBranch}
                  activeVerdict={activeVerdict}
                  hasRedactedHunk={hasRedactedHunk}
                  copiedKey={copiedKey}
                  onCopy={copyStr}
                  onSelectRound={(rNum) => {
                    const found = activeChange.rounds.find((r) => r.round === rNum);
                    setRoundNumber(rNum);
                    setSelectedHunkId(found?.hunks[0]?.id ?? null);
                    setCommentAnchor(null);
                    setActiveStepIndex(0);
                  }}
                  onSetVerdict={(v) => void handleSetVerdict(v)}
                  onPublishBranch={onPublishBranch}
                  steerAction={roundSteerButton}
                  metaActions={interdiffReady ? null : roundViewControls}
                />

                {interdiffReady ? (
                  <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-white/[0.06] bg-[#0a0e1c] px-4 py-1.5 font-mono text-[12.5px] sm:px-5">
                    {roundViewControls}
                  </div>
                ) : (
                  <ConcernWalkthroughBar
                    mode="rounds"
                    viewMode={viewMode}
                    onViewModeChange={setViewMode}
                    groups={roundConcernGroups}
                    reviewedIds={reviewedIds}
                    totalCount={activeRound.hunks.length}
                    itemUnit="hunk"
                    onJumpToConcern={jumpToConcern}
                    onResetReviewed={handleResetReviewed}
                    leading={roundLayoutToggle}
                  />
                )}

                {steerResult && steerResult.change_id === activeChange.change_id && (
                  <div
                    role="status"
                    className="space-y-1 border-b border-white/[0.06] bg-[#7f95f8]/[0.07] px-4 py-2.5 font-mono text-[13px] sm:px-5"
                  >
                    <div className="flex flex-wrap items-center gap-2 text-[#f3f6fd]">
                      <span
                        className={`h-2 w-2 rounded-full ${
                          steerRunning ? "animate-pulse bg-[#67d6dc]" : "bg-[#5bdba2]"
                        }`}
                      />
                      <span>
                        {steerRunning
                          ? `Agent working on R${steerResult.target_round}…`
                          : `Agent finished (${steerSession?.status ?? "done"}) — R${steerResult.target_round}`}
                      </span>
                      <span className="text-[#98a8c4]">
                        session {steerResult.session.id.slice(0, 8)} · lane {steerResult.lane_id}
                      </span>
                    </div>
                    <div className="text-[#b6c3db]">
                      Sent {plural(steerResult.packaged_comments, "comment")} to the agent
                      {steerResult.packaged_conflicts > 0 &&
                        ` and ${plural(steerResult.packaged_conflicts, "conflict")}`}
                      .
                      {steerResult.redacted_comments > 0 && (
                        <span className="text-[#a8c5ff]">
                          {" "}
                          {plural(steerResult.redacted_comments, "comment")} withheld from the agent
                          (ACL-redacted).
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {owner && steerOpen && (
                  <form
                    aria-label="Steer agent"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void handleSteer();
                    }}
                    className="max-h-[50%] shrink-0 space-y-2.5 overflow-y-auto border-b border-white/[0.06] bg-[#7f95f8]/[0.05] px-4 py-3 sm:px-5"
                  >
                    <div className="flex items-center justify-between gap-2 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                      <span>Steer agent → R{nextRound}</span>
                      <button
                        type="button"
                        onClick={() => setSteerOpen(false)}
                        aria-label="Close steering"
                        className="rounded p-0.5 text-[#98a8c4] hover:text-white"
                      >
                        <IconClose className="h-4 w-4" />
                      </button>
                    </div>
                    <fieldset className="space-y-1">
                      <legend className="font-mono text-[12.5px] text-[#98a8c4]">
                        Comments to send ({steerIds.size} selected)
                      </legend>
                      {(activeChange.comments ?? []).length === 0 && (
                        <div className="font-mono text-[13px] text-[#a6b5cf]">
                          No comments yet — the agent gets only your instruction.
                        </div>
                      )}
                      {(activeChange.comments ?? []).map((c) => {
                        const done = addressedRound(c);
                        return (
                          <label
                            key={c.id}
                            className="flex cursor-pointer items-start gap-2 rounded-lg px-1.5 py-1 font-mono text-[13px] hover:bg-white/[0.04]"
                          >
                            <input
                              type="checkbox"
                              checked={steerIds.has(c.id)}
                              onChange={(e) =>
                                setSteerIds((prev) => {
                                  const next = new Set(prev);
                                  if (e.target.checked) next.add(c.id);
                                  else next.delete(c.id);
                                  return next;
                                })
                              }
                              className="mt-0.5 accent-[#7f95f8]"
                            />
                            <span className="min-w-0">
                              <span className="text-[#9ec0f5]">
                                {c.path}
                                {c.line != null ? `:L${c.line}` : ""}
                              </span>
                              {done !== null && (
                                <span className="ml-1.5 text-[#5bdba2]">addressed in R{done}</span>
                              )}
                              <span className="block truncate text-[#d2dbee]">{c.body}</span>
                            </span>
                          </label>
                        );
                      })}
                    </fieldset>
                    <input
                      value={steerInstruction}
                      onChange={(e) => setSteerInstruction(e.target.value)}
                      aria-label="Steering instruction"
                      placeholder={DEFAULT_STEER_INSTRUCTION}
                      className="pr-well w-full rounded-xl px-3 py-1.5 text-[13.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
                    />
                    <input
                      value={steerCommand}
                      onChange={(e) => setSteerCommand(e.target.value)}
                      aria-label="Agent command override"
                      placeholder="Optional command — blank uses the server's agent command (reads $PREMIER_STEERING_FILE)"
                      className="pr-well w-full rounded-xl px-3 py-1.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
                    />
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 font-mono text-[13px] text-[#d2dbee]">
                      <select
                        value={steerProfile}
                        onChange={(e) => setSteerProfile(e.target.value)}
                        aria-label="Agent profile"
                        className="pr-well max-w-[220px] rounded-full px-3 py-1 text-[13px] text-[#dce4f5] [color-scheme:dark] focus:outline-none"
                      >
                        <option value="">No agent profile</option>
                        {[
                          ...new Set(
                            [activeChange.delegated_agent, ...agentProfiles].filter(
                              (p): p is string => Boolean(p),
                            ),
                          ),
                        ].map((p) => (
                          <option key={p} value={p}>
                            {p}
                          </option>
                        ))}
                      </select>
                      <label className="inline-flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={steerAutoCommit}
                          onChange={(e) => setSteerAutoCommit(e.target.checked)}
                          className="accent-[#7f95f8]"
                        />
                        Auto-commit → R{nextRound}
                      </label>
                      <label className="inline-flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={steerMarkRevise}
                          onChange={(e) => setSteerMarkRevise(e.target.checked)}
                          className="accent-[#7f95f8]"
                        />
                        Mark Revise
                      </label>
                    </div>
                    <p className="font-mono text-[12.5px] text-[#98a8c4]">
                      Comments in paths the agent cannot read are withheld by the server.
                    </p>
                    {sandboxOff && (
                      <p role="status" className="font-mono text-[13px] text-[#a8c5ff]">
                        Agent sessions are disabled: this server has no working sandbox.
                      </p>
                    )}
                    {steerError && (
                      <p role="alert" className="break-words font-mono text-[13px] text-[#f27c7c]">
                        {steerError}
                      </p>
                    )}
                    <div className="flex items-center gap-2">
                      <button
                        type="submit"
                        disabled={steerBusy || sandboxOff || (steerIds.size === 0 && !steerInstruction.trim())}
                        className="pr-action-btn rounded-full px-3.5 py-1.5 text-[13.5px] disabled:cursor-not-allowed disabled:opacity-45"
                      >
                        {steerBusy ? "Sending…" : `Steer Agent → R${nextRound}`}
                      </button>
                      <button
                        type="button"
                        onClick={() => setSteerOpen(false)}
                        className="pr-pill rounded-full px-3.5 py-1.5 text-[13.5px] text-[#dce4f5]"
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                )}

                {laneConflicts.length > 0 && (
                  <div className="max-h-[45%] shrink-0 overflow-y-auto px-4 pt-3 sm:px-5">
                    <LaneConflictInspector
                      laneId={activeChange.lane_id}
                      conflicts={laneConflicts}
                      branch={activeChange.branch}
                      identity={identity}
                      owner={owner}
                      onResolved={() => {
                        reloadReviews(activeChange.change_id);
                        onLanesChanged?.();
                      }}
                      onRebased={() => {
                        reloadReviews(activeChange.change_id);
                        onLanesChanged?.();
                      }}
                      onSteerToResolve={(cs) =>
                        openSteer(
                          [],
                          `Resolve the lane conflicts in: ${cs.map((c) => c.path).join(", ")}`,
                        )
                      }
                    />
                  </div>
                )}

                {interdiffReady ? (
                  <div
                    className={`min-h-0 flex-1 overflow-y-auto p-4 transition-opacity sm:p-5 ${
                      interdiffLoading && interdiff ? "opacity-65" : "opacity-100"
                    }`}
                  >
                    {interdiffError && (
                      <div role="alert" className="font-mono text-[13px] text-[#f27c7c]">
                        {interdiffError}
                      </div>
                    )}
                    {interdiff ? (
                      <InterdiffFiles data={interdiff} />
                    ) : (
                      !interdiffError && (
                        fromRound >= toRound ? (
                          <div className="py-8 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                            Choose two different rounds
                          </div>
                        ) : (
                          <InterdiffSkeleton />
                        )
                      )
                    )}
                  </div>
                ) : (
                  <>
                    <div className="min-h-0 flex-1 space-y-3.5 overflow-y-auto p-4 sm:p-5">
                      {activeRound.hunks.length === 0 ? (
                        <div className="py-12 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                          No visible hunks in this round for {identity.label}
                        </div>
                      ) : viewMode === "guided" ? (
                        roundConcernGroups.map((group) =>
                          renderConcernSection(group, "round", (entry) =>
                            renderRoundHunkCard(entry.item, {
                              risk: entry.classification.risk,
                              riskReasons: entry.classification.riskReasons,
                            }),
                          ),
                        )
                      ) : (
                        activeRound.hunks.map((hunk) => renderRoundHunkCard(hunk))
                      )}
                    </div>
                  </>
                )}
              </>
            )}
          </section>

          {/* Right: Synchronized Scrubbable Session Replay Timeline & Persisted Comments */}
          {!asideOpen && mobileRoundPane !== "replay" && (
            <button
              type="button"
              onClick={() => setAsideOpen(true)}
              aria-label="Open replay panel"
              title="Open replay panel"
              className="pr-surface hidden w-9 shrink-0 flex-col items-center gap-2 rounded-2xl py-3 text-[#a6b5cf] transition hover:text-white lg:flex"
            >
              <IconTimeline className="h-4 w-4" />
              <span className="font-mono text-[12.5px] [writing-mode:vertical-rl]">Replay</span>
            </button>
          )}
          {(asideOpen || mobileRoundPane === "replay") && (
          <SessionReplayAside
            onCollapse={() => {
              setAsideOpen(false);
              setMobileRoundPane("hunks");
            }}
            change={activeChange}
            round={activeRound}
            activeHunk={activeHunk}
            timeline={timeline}
            activeStepIndex={activeStepIndex}
            onSelectStepIndex={setActiveStepIndex}
            onSelectHunk={(hunkId) => {
              setMobileRoundPane("hunks");
              selectHunkWithSync(hunkId, { fromTimeline: true, scroll: true });
            }}
            identity={identity}
            asideTab={asideTab}
            onAsideTabChange={setAsideTab}
            mobileVisible={mobileRoundPane === "replay"}
            newCommentBody={newCommentBody}
            onNewCommentBodyChange={setNewCommentBody}
            onSubmitComment={(e) => void handleAddComment(e)}
            submitting={submitting}
            copiedKey={copiedKey}
            onCopy={copyStr}
          />
          )}
        </div>
      )}
    </div>
  );
}
