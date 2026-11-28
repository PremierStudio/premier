import { memo, useEffect, useMemo, useRef, useState } from "react";
import {
  shortOid,
  type BranchRecord,
  type HeldBackRuleInfo,
  type PublicDiffFile,
  type PublishBranchResponse,
  type SquashPreviewResponse,
  type Visibility,
} from "../api";
import { analyzeCommitMessageHygiene, type HygieneWarning } from "../lib/airlockHygiene";
import { plural } from "../lib/format";
import {
  detectLanguage,
  parseUnifiedPatch,
  tokenClassName,
  tokenizeLine,
} from "../lib/highlight";
import { SECONDARY_BTN, Time } from "./forms";
import { AirlockBodySkeleton, SkelBar } from "./ViewSkeletons";
import {
  IconBlock,
  IconBranches,
  IconCheck,
  IconChevron,
  IconClose,
  IconCopy,
  IconDeclassify,
  IconFileNode,
  IconFold,
  IconLink,
  IconLock,
  IconPanel,
  IconPlay,
  IconQuarantine,
  IconRefresh,
  IconShieldCheck,
  IconTerminal,
  IconUnfold,
} from "./Icons";

const PUBLISH_RULE = "Only anonymous-readable files are published.";

/** The branch's visibility as the server reports it: the scope, and who it is restricted to. */
export function visibilityLabel(vis: Visibility): string {
  const scope: string = vis.scope;
  if (vis.scope === "restricted") {
    const allow = vis.allow ?? [];
    if (allow.length === 1 && allow[0] === "group:owners") return "owners only";
    return allow.length > 0 ? `restricted: ${allow.join(", ")}` : "restricted";
  }
  if (vis.scope === "personal") return vis.allow ? `personal (${vis.allow})` : "personal";
  return scope.replace(/_/g, " ");
}

export const isPrivateScope = (vis: Visibility): boolean =>
  vis.scope === "restricted" || vis.scope === "personal";

export function visibilityPillTone(vis: { scope: string }): string {
  if (vis.scope === "restricted") return "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]";
  if (vis.scope === "personal" || vis.scope === "org") {
    return "border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]";
  }
  return "border-white/[0.08] bg-white/[0.04] text-[#9eb0cc]";
}

/** `held_back_reasons` as a path → reason map, whichever of its two shapes the server sent. */
function reasonMap(raw: SquashPreviewResponse["held_back_reasons"]): Record<string, string> {
  if (!raw) return {};
  if (!Array.isArray(raw)) return raw;
  return Object.fromEntries(raw.map((r) => [r.path, r.reason]));
}

function diffElementId(path: string): string {
  return `airlock-diff-${encodeURIComponent(path).replace(/%/g, "_")}`;
}

type GateStatus = "pass" | "warn" | "fail" | "pending";

function GateBadge({ status, label }: { status: GateStatus; label?: string }) {
  if (status === "pending") {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-white/[0.12] bg-white/[0.05] px-2 py-0.5 font-mono text-[12px] font-semibold uppercase tracking-wider text-[#b6c3db]">
        WAIT
      </span>
    );
  }
  if (status === "pass") {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-2 py-0.5 font-mono text-[12px] font-semibold uppercase tracking-wider text-[#5bdba2]">
        <IconCheck className="h-3 w-3" />
        PASS
      </span>
    );
  }
  if (status === "warn") {
    return (
      <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/14 px-2 py-0.5 font-mono text-[12px] font-semibold uppercase tracking-wider text-[#a8c5ff]">
        <IconQuarantine className="h-3 w-3" />
        WARN
      </span>
    );
  }
  return (
    <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/14 px-2 py-0.5 font-mono text-[12px] font-semibold uppercase tracking-wider text-[#f27c7c]">
      <IconBlock className="h-3 w-3" />
      {label ?? "FAIL"}
    </span>
  );
}

function DiffKindPill({ kind }: { kind: PublicDiffFile["kind"] }) {
  const cls =
    kind === "added"
      ? "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
      : kind === "deleted"
        ? "border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f27c7c]"
        : "border-[#9ec0f5]/30 bg-[#7f95f8]/14 text-[#9ec0f5]";
  return (
    <span
      className={`shrink-0 rounded-full border px-2 py-0.5 font-mono text-[12px] uppercase tracking-wider ${cls}`}
    >
      {kind}
    </span>
  );
}

type ParsedDiffFile = PublicDiffFile & {
  lang: ReturnType<typeof detectLanguage>;
  parsed: ReturnType<typeof parseUnifiedPatch> | null;
};

/** Diff lines drawn before "Show all"; a huge patch otherwise stalls every re-render. */
const DIFF_LINE_CAP = 600;

/** One file's hunks. Memoized with pre-tokenized lines so typing the commit title never re-highlights. */
const DiffFileBody = memo(function DiffFileBody({ f }: { f: ParsedDiffFile }) {
  const [showAll, setShowAll] = useState(false);
  const rows = useMemo(
    () =>
      (f.parsed?.lines ?? [])
        .filter((dl) => dl.kind !== "meta")
        .map((dl) => ({ dl, tokens: dl.kind === "hunk" ? null : tokenizeLine(dl.body, f.lang) })),
    [f.parsed, f.lang],
  );
  const shown = showAll ? rows : rows.slice(0, DIFF_LINE_CAP);
  return (
    <div>
      {f.binary ? (
        <div className="px-4 py-3 font-mono text-[13px] text-[#a6b5cf]">
          Binary file — line-by-line diff preview omitted.
        </div>
      ) : rows.length > 0 ? (
        <div className="overflow-x-auto py-1.5 font-mono text-[13px] leading-[1.6]">
          {shown.map(({ dl, tokens }, li) => {
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
                <span className="w-10 shrink-0 select-none pr-2 text-right text-[12.5px] text-[#6b7b98]">
                  {dl.oldLine ?? ""}
                </span>
                <span className="w-10 shrink-0 select-none pr-2 text-right text-[12.5px] text-[#6b7b98]">
                  {dl.newLine ?? ""}
                </span>
                <span className={`w-4 shrink-0 select-none text-center ${sigilColor}`}>
                  {dl.sigil}
                </span>
                <span className="min-w-0 flex-1 whitespace-pre">
                  {(tokens ?? []).map((tok, ti) => (
                    <span key={ti} className={tokenClassName(tok.kind)}>
                      {tok.text}
                    </span>
                  ))}
                </span>
              </div>
            );
          })}
          {rows.length > shown.length && (
            <button
              type="button"
              onClick={() => setShowAll(true)}
              className="mx-3 mt-1.5 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1 font-mono text-[12.5px] text-[#9ec0f5] hover:text-white"
            >
              Show all {rows.length} lines ({rows.length - shown.length} more)
            </button>
          )}
        </div>
      ) : (
        <div className="px-4 py-3 font-mono text-[13px] text-[#a6b5cf]">
          {f.old_mode && f.new_mode && f.old_mode !== f.new_mode
            ? `Mode change only (${f.old_mode} → ${f.new_mode}).`
            : "No textual diff hunks (empty file or unchanged text)."}
        </div>
      )}

      {f.truncated && (
        <div className="border-t border-white/[0.08] bg-white/[0.03] px-3.5 py-1.5 font-mono text-[12.5px] text-[#b6c3db]">
          Patch preview truncated by server size limit.
        </div>
      )}
    </div>
  );
});

export interface DeclassificationAirlockProps {
  branch: BranchRecord | null;
  branches: BranchRecord[];
  baseBranch?: string;
  targetBranch: string;
  onSelectTargetBranch: (branchName: string) => void;
  member: boolean;
  preview: SquashPreviewResponse | null;
  loadingPreview: boolean;
  /** The last preview request failed (or came back for another branch/target). */
  previewFailed: boolean;
  /** The declassification firewall report for THIS branch and target blocks the landing. */
  firewallBlocked: boolean;
  firewallBlockingCount: number;
  canOwnerOverride: boolean;
  onOpenOverride: () => void;
  railOpen: boolean;
  onToggleRail: () => void;
  ghConnected: boolean;
  /** Select a different source branch (used by the self-target empty state). */
  onSelectBranch: (branchName: string) => void;
  /** True while commit-message hygiene warnings exist that the owner has not acknowledged. */
  onWarningsPendingChange?: (pending: boolean) => void;
  refused: {
    conflicts: string[];
    hidden: number;
    blocked: string[];
    hiddenBlocked: number;
  } | null;
  summaryMsg: string;
  onSummaryMsgChange: (value: string) => void;
  onRefreshPreview: () => void;
  onExecutePublish: () => void;
  publishing: boolean;
  publishReceipt: PublishBranchResponse | null;
  onDismissReceipt: () => void;
  wideMode: boolean;
  onToggleWideMode: () => void;
  newPrincipal: string;
  onNewPrincipalChange: (value: string) => void;
  onAddPrincipal: (e: React.FormEvent) => void;
  onRemovePrincipal: (principal: string) => void;
  repoName?: string;
  isDefaultRepo?: boolean;
  defaultBranch?: string | null;
  onOpenCommit?: (oid: string, refName?: string) => void;
  /** False while the owning tab is hidden-but-mounted; global key handlers must stay inert. */
  active?: boolean;
}

export function DeclassificationAirlock({
  branch,
  branches,
  baseBranch,
  targetBranch,
  onSelectTargetBranch,
  member,
  preview,
  loadingPreview,
  previewFailed,
  firewallBlocked,
  firewallBlockingCount,
  canOwnerOverride,
  onOpenOverride,
  railOpen,
  onToggleRail,
  ghConnected,
  onSelectBranch,
  onWarningsPendingChange,
  refused,
  summaryMsg,
  onSummaryMsgChange,
  onRefreshPreview,
  onExecutePublish,
  publishing,
  publishReceipt,
  onDismissReceipt,
  wideMode,
  onToggleWideMode,
  newPrincipal,
  onNewPrincipalChange,
  onAddPrincipal,
  onRemovePrincipal,
  repoName,
  isDefaultRepo,
  defaultBranch,
  onOpenCommit,
  active = true,
}: DeclassificationAirlockProps) {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [expandedHeldBack, setExpandedHeldBack] = useState(false);
  const [diffDrawerOpen, setDiffDrawerOpen] = useState(true);
  const [collapsedDiffFiles, setCollapsedDiffFiles] = useState<Set<string>>(() => new Set());
  const [receiptTab, setReceiptTab] = useState<"published" | "held_back" | null>("published");
  const [receiptMsgOpen, setReceiptMsgOpen] = useState(false);
  const [warningsAcked, setWarningsAcked] = useState(false);
  const [confirmingLand, setConfirmingLand] = useState(false);
  const diffSectionRef = useRef<HTMLDivElement>(null);

  const copyText = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey((cur) => (cur === key ? null : cur)), 1600);
  };

  const target = targetBranch || baseBranch || preview?.target_branch || "main";
  const isSelfTarget = !!branch && branch.name === target;
  const previewMatches =
    !!preview &&
    !!branch &&
    preview.source_branch === branch.name &&
    preview.target_branch === target;
  // Derived synchronously so a branch switch never flashes "PREVIEW UNAVAILABLE" for one frame.
  const inspecting =
    loadingPreview || (!member && !isSelfTarget && !previewMatches && !previewFailed);
  // While the same source branch re-targets, keep its last preview on screen (dimmed, gates
  // "WAIT", landing disabled by `previewMatches`). A different source branch's data never shows.
  const lastPreviewRef = useRef<SquashPreviewResponse | null>(null);
  if (previewMatches && preview) lastPreviewRef.current = preview;
  const lastForBranch =
    !member && inspecting && lastPreviewRef.current?.source_branch === branch?.name
      ? lastPreviewRef.current
      : null;
  const activePreview = previewMatches ? preview : lastForBranch;
  // A cached revisit revalidates behind a thin shimmer; its gates never flip back to WAIT.
  const gatesReady = !!activePreview && previewMatches;
  const pendingFresh = inspecting && !gatesReady;

  // Derived preview lists (never populated for members or mismatched branch/target)
  const publishedPaths = useMemo(
    () => (member ? [] : (activePreview?.published_paths ?? [])),
    [member, activePreview?.published_paths],
  );
  const scrubbedPaths = useMemo(
    () => (member ? [] : (activePreview?.scrubbed_paths ?? [])),
    [member, activePreview?.scrubbed_paths],
  );
  const conflicts = useMemo(
    () => (member ? [] : (refused?.conflicts ?? activePreview?.conflicts ?? [])),
    [member, refused?.conflicts, activePreview?.conflicts],
  );
  const hiddenConflicts = member ? 0 : (refused?.hidden ?? activePreview?.hidden_conflicts ?? 0);
  const blocked = useMemo(
    () => (member ? [] : (refused?.blocked ?? activePreview?.blocked ?? [])),
    [member, refused?.blocked, activePreview?.blocked],
  );
  const hiddenBlocked = member ? 0 : (refused?.hiddenBlocked ?? activePreview?.hidden_blocked ?? 0);
  const overlayBlockedPaths = useMemo(
    () => (member ? [] : (activePreview?.overlay_blocked_paths ?? [])),
    [member, activePreview?.overlay_blocked_paths],
  );
  const threeWayMergedPaths = useMemo(
    () => (member ? [] : (activePreview?.three_way_merged_paths ?? [])),
    [member, activePreview?.three_way_merged_paths],
  );
  const publicDiff = useMemo(
    () => (member ? [] : (activePreview?.public_diff ?? [])),
    [member, activePreview?.public_diff],
  );
  const collapsedCommits = useMemo(
    () => (member ? [] : (activePreview?.collapsed_commits ?? [])),
    [member, activePreview?.collapsed_commits],
  );
  const legacyReasons = useMemo(
    () => (member ? {} : reasonMap(activePreview?.held_back_reasons)),
    [member, activePreview?.held_back_reasons],
  );
  const heldBackRules: Record<string, HeldBackRuleInfo> = useMemo(
    () => (member ? {} : (activePreview?.held_back_rules ?? {})),
    [member, activePreview?.held_back_rules],
  );
  const quarantinePaths = useMemo(() => {
    if (member) return [];
    const fromPreview = activePreview?.quarantine_paths ?? [];
    if (fromPreview.length > 0) return fromPreview;
    return publicDiff.filter((f) => f.is_instruction_file).map((f) => f.path);
  }, [member, activePreview?.quarantine_paths, publicDiff]);

  const restrictedZones = useMemo(() => {
    if (member) return [];
    const zones = new Set<string>(activePreview?.restricted_zones ?? []);
    for (const info of Object.values(heldBackRules)) {
      for (const z of info.zones ?? []) {
        if (z) zones.add(z);
      }
    }
    return Array.from(zones);
  }, [member, activePreview?.restricted_zones, heldBackRules]);

  const diffByPath = useMemo(() => {
    const map = new Map<string, PublicDiffFile>();
    for (const f of publicDiff) map.set(f.path, f);
    return map;
  }, [publicDiff]);

  const parsedPublicDiff = useMemo(
    () =>
      publicDiff.map((f) => ({
        ...f,
        lang: detectLanguage(f.path),
        parsed: f.binary ? null : parseUnifiedPatch(f.patch),
      })),
    [publicDiff],
  );

  const diffTotals = useMemo(() => {
    let additions = 0;
    let deletions = 0;
    for (const f of publicDiff) {
      additions += f.additions;
      deletions += f.deletions;
    }
    return { additions, deletions };
  }, [publicDiff]);

  // Default diff drawer state when switching source/target or preview payload size
  useEffect(() => {
    setDiffDrawerOpen(publicDiff.length > 0 && publicDiff.length <= 6);
    setCollapsedDiffFiles(new Set());
  }, [branch?.name, target, publicDiff.length]);

  const serverMessage = activePreview?.clean_commit_message ?? "";
  const proposedMessage = summaryMsg.trim()
    ? serverMessage
      ? serverMessage.replace(/^[^\n]*/, () => summaryMsg.trim())
      : summaryMsg.trim()
    : serverMessage;
  const messageForHygiene = summaryMsg.trim() || (serverMessage.split("\n")[0] ?? "");

  const hygieneWarnings: HygieneWarning[] = useMemo(() => {
    if (member || !branch || !activePreview || !messageForHygiene) return [];
    return analyzeCommitMessageHygiene(messageForHygiene, {
      scrubbedPaths,
      blockedPaths: blocked,
      restrictedZones,
      publishedPaths,
      sourceBranch: branch.name,
      targetBranch: target,
      isPrivateSource: isPrivateScope(branch.visibility),
    });
  }, [
    member,
    branch,
    activePreview,
    messageForHygiene,
    scrubbedPaths,
    blocked,
    restrictedZones,
    publishedPaths,
    target,
  ]);

  const hasHardBlockers =
    conflicts.length + hiddenConflicts > 0 ||
    blocked.length + hiddenBlocked > 0 ||
    overlayBlockedPaths.length > 0 ||
    firewallBlocked ||
    (activePreview !== null && !activePreview.declassification_gate_passed);

  const hasWarnings = hygieneWarnings.length > 0 || quarantinePaths.length > 0;

  const warningKey = useMemo(
    () =>
      `${hygieneWarnings.map((w) => `${w.category}:${w.token}`).join("|")}::${quarantinePaths.join("|")}`,
    [hygieneWarnings, quarantinePaths],
  );

  // Automatically reset acknowledgement & two-step confirmation when anything material changes
  useEffect(() => {
    setWarningsAcked(false);
    setConfirmingLand(false);
  }, [
    branch?.name,
    target,
    summaryMsg,
    warningKey,
    activePreview?.source_commit_oid,
    activePreview?.target_commit_oid,
    activePreview?.source_head_oid,
    activePreview?.target_head_oid,
  ]);

  const warningsPending = hasWarnings && !warningsAcked;
  useEffect(() => {
    onWarningsPendingChange?.(warningsPending);
  }, [warningsPending, onWarningsPendingChange]);

  // Allow Escape to cancel two-step landing confirmation
  useEffect(() => {
    if (!active) {
      setConfirmingLand(false);
      return;
    }
    if (!confirmingLand) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !e.defaultPrevented) {
        e.preventDefault();
        setConfirmingLand(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [confirmingLand, active]);

  // Routine waits are neutral; only real blocks are red. Gold is reserved for unacked warnings.
  const publishBlock: { text: string; danger: boolean } | null = isSelfTarget
    ? {
        text: branch?.is_current
          ? "The default branch cannot be published onto itself."
          : "Choose a different target branch.",
        danger: false,
      }
    : firewallBlocked
      ? {
          text: `Leak & secret scanner: ${plural(firewallBlockingCount, "blocking finding")}.`,
          danger: true,
        }
      : inspecting
        ? { text: "Checking…", danger: false }
        : !activePreview
          ? { text: "Publish preview unavailable; refresh before publishing.", danger: false }
          : activePreview.reason
            ? { text: activePreview.reason, danger: true }
            : overlayBlockedPaths.length > 0
              ? { text: "Unmount or exclude overlay-blocked paths before publishing.", danger: true }
              : blocked.length + hiddenBlocked > 0
                ? { text: "Remove blocked files containing copied private content first.", danger: true }
                : conflicts.length + hiddenConflicts > 0
                  ? { text: "Resolve merge conflicts on the branch before publishing.", danger: true }
                  : publishedPaths.length === 0
                    ? { text: "Nothing to publish", danger: false }
                    : null;
  const publishBlocked = publishBlock?.text;

  const canPublish =
    !member &&
    !isSelfTarget &&
    !loadingPreview &&
    previewMatches &&
    !publishBlocked &&
    activePreview?.declassification_gate_passed === true &&
    !!branch;

  const canExecuteLand = canPublish && !publishing && (!hasWarnings || warningsAcked);

  const publishCmd = branch
    ? `premier branch publish ${branch.name} --to ${target} --squash-declassify${
        summaryMsg.trim() ? ` --message "${summaryMsg.trim().replace(/"/g, '\\"')}"` : ""
      }`
    : "";

  const targetSelectRef = useRef<HTMLSelectElement>(null);
  const reviewCandidate = useMemo(
    () =>
      branch
        ? (branches.find((b) => b.name !== branch.name && !b.is_current && b.ahead_commits > 0) ??
          null)
        : null,
    [branches, branch],
  );
  const targetCandidates = useMemo(
    () => branches.filter((b) => !branch || b.name !== branch.name),
    [branches, branch],
  );

  const jumpToDiffFile = (path: string) => {
    setDiffDrawerOpen(true);
    setCollapsedDiffFiles((prev) => {
      if (!prev.has(path)) return prev;
      const next = new Set(prev);
      next.delete(path);
      return next;
    });
    window.requestAnimationFrame(() => {
      document.getElementById(diffElementId(path))?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    });
  };

  const jumpToDiffPanel = () => {
    setDiffDrawerOpen(true);
    window.requestAnimationFrame(() => {
      diffSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const toggleDiffFile = (path: string) => {
    setCollapsedDiffFiles((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  // Build #changes deep link for receipt
  const receiptTargetShort = publishReceipt
    ? publishReceipt.target_ref.replace(/^refs\/heads\//, "")
    : "";
  const receiptDeepLink = useMemo(() => {
    if (!publishReceipt || typeof window === "undefined") return "";
    const params = new URLSearchParams();
    if (repoName && !isDefaultRepo) params.set("repo", repoName);
    if (receiptTargetShort && receiptTargetShort !== defaultBranch) {
      params.set("ref", receiptTargetShort);
    }
    params.set("oid", publishReceipt.new_commit_oid);
    return `${window.location.origin}${window.location.pathname}#changes?${params.toString()}`;
  }, [publishReceipt, repoName, isDefaultRepo, receiptTargetShort, defaultBranch]);

  if (!branch) {
    return (
      <section className="pr-surface flex min-h-[280px] min-w-0 flex-1 items-center justify-center rounded-2xl p-6 text-center">
        <div className="max-w-sm space-y-2">
          <IconDeclassify className="mx-auto h-7 w-7 text-[#7f95f8]/70" />
          <div className="text-[14px] font-semibold text-[#f3f6fd]">Safe Publish</div>
          <p className="text-[14px] leading-relaxed text-[#a6b5cf]">
            Select a branch to preview and scrub public changes.
          </p>
        </div>
      </section>
    );
  }

  // Gate status badge in header
  const nothingToLandClean =
    !!activePreview &&
    publishedPaths.length === 0 &&
    conflicts.length + hiddenConflicts === 0 &&
    blocked.length + hiddenBlocked === 0 &&
    overlayBlockedPaths.length === 0;

  const headerStatus: { label: string; cls: string } = member
    ? {
        label: "OWNER-GATED",
        cls: "border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#9ec0f5]",
      }
    : isSelfTarget
      ? {
          label: branch.is_current ? "DEFAULT BRANCH" : "SAME BRANCH",
          cls: "border-white/[0.12] bg-white/[0.05] text-[#b6c3db]",
        }
      : pendingFresh
        ? {
            label: "CHECKING…",
            cls: "border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#9ec0f5]",
          }
        : !activePreview
          ? {
              label: "PREVIEW UNAVAILABLE",
              cls: "border-white/[0.12] bg-white/[0.05] text-[#b6c3db]",
            }
          : publishReceipt && nothingToLandClean
            ? {
                label: "LANDED",
                cls: "border-[#5bdba2]/35 bg-[#5bdba2]/14 text-[#5bdba2]",
              }
            : nothingToLandClean
              ? {
                  label: "NOTHING TO LAND",
                  cls: "border-white/[0.12] bg-white/[0.05] text-[#b6c3db]",
                }
              : hasHardBlockers
                ? {
                    label: "PUBLISH BLOCKED",
                    cls: "border-[#f27c7c]/35 bg-[#f27c7c]/14 text-[#f27c7c]",
                  }
                : hasWarnings
                  ? {
                      label: "WARNINGS",
                      cls: "border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#a8c5ff]",
                    }
                  : canPublish
                    ? {
                        label: "READY TO PUBLISH",
                        cls: "border-[#5bdba2]/35 bg-[#5bdba2]/14 text-[#5bdba2]",
                      }
                    : {
                        label: "PUBLISH BLOCKED",
                        cls: "border-[#f27c7c]/35 bg-[#f27c7c]/14 text-[#f27c7c]",
                      };

  // Member-safe fallback: never fetches squashPreview or renders hidden counts/conflicts/reasons
  if (member) {
    const visibleTouched = branch.private_paths_touched ?? [];
    return (
      <section className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2.5 border-b border-white/[0.06] px-4 py-3">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
              <IconDeclassify className="h-[18px] w-[18px]" />
              <span>Safe Publish</span>
            </span>
            <span className="text-[#6b7b98]">·</span>
            <span className="inline-flex items-center gap-1.5 font-mono text-[14px] font-medium text-[#f3f6fd]">
              {isPrivateScope(branch.visibility) ? (
                <IconLock className="h-4 w-4 text-[#a8c5ff]" />
              ) : (
                <IconBranches className="h-4 w-4 text-[#7f95f8]" />
              )}
              <span className="truncate">{branch.name}</span>
            </span>
            <span
              className={`rounded-full border px-2 py-0.5 font-mono text-[12px] leading-4 ${visibilityPillTone(branch.visibility)}`}
            >
              {visibilityLabel(branch.visibility)}
            </span>
            <span
              className={`rounded-full border px-2.5 py-0.5 font-mono text-[12px] font-semibold tracking-wider ${headerStatus.cls}`}
            >
              {headerStatus.label}
            </span>
          </div>

          <button
            type="button"
            onClick={onToggleWideMode}
            aria-pressed={wideMode}
            className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee] hover:text-[#f3f6fd]"
          >
            <IconPanel className="h-3.5 w-3.5 text-[#9ec0f5]" />
            <span>{wideMode ? "Show Branches" : "Wide Safe Publish"}</span>
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4 sm:p-5">
          {branch.visibility.scope === "restricted" && (
            <div className="pr-well space-y-2 rounded-xl p-3.5">
              <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                Authorized Principals
              </div>
              <div className="flex flex-wrap gap-1.5">
                {branch.visibility.allow.map((p) => (
                  <span
                    key={p}
                    className="rounded-full border border-white/[0.12] bg-white/[0.045] px-2.5 py-0.5 font-mono text-[12.5px] text-[#cbd5e8]"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div className="pr-well space-y-2 rounded-xl p-4">
            <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
              Visible Paths Touched ({visibleTouched.length})
            </div>
            {visibleTouched.length === 0 ? (
              <div className="font-mono text-[13.5px] text-[#a6b5cf]">No visible changes</div>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {visibleTouched.map((p) => (
                  <span
                    key={p}
                    className="rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 font-mono text-[13px] text-[#d2dbee]"
                  >
                    {p}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="pr-elevated flex items-start gap-3 rounded-2xl border border-[#7f95f8]/25 p-5">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-[#9ec0f5]/25 bg-[#7f95f8]/12 text-[#9ec0f5]">
              <IconLock className="h-4 w-4" />
            </div>
            <div className="space-y-1">
              <div className="text-[14.5px] font-semibold text-[#f3f6fd]">
                Owner-Gated Safe Publish
              </div>
              <p className="text-[14px] leading-relaxed text-[#b6c3db]">
                Safety checks, diff preview, and publishing require owner access.
              </p>
            </div>
          </div>
        </div>
      </section>
    );
  }

  // Compute stage statuses for Owner view — never show green PASS before activePreview exists
  const gate1Status: GateStatus = !gatesReady
    ? "pending"
    : overlayBlockedPaths.length > 0
      ? "fail"
      : "pass";
  const gate2Status: GateStatus = !gatesReady
    ? "pending"
    : blocked.length + hiddenBlocked > 0
      ? "fail"
      : "pass";
  const gate3Status: GateStatus = !gatesReady
    ? "pending"
    : conflicts.length + hiddenConflicts > 0
      ? "fail"
      : "pass";
  const gate4Status: GateStatus = !gatesReady
    ? "pending"
    : hygieneWarnings.length > 0
      ? "warn"
      : "pass";
  const gate5Status: GateStatus = !gatesReady
    ? "pending"
    : quarantinePaths.length > 0
      ? "warn"
      : "pass";
  const gate6Status: GateStatus = !gatesReady ? "pending" : firewallBlocked ? "fail" : "pass";
  // Skeleton bar while a fresh preview is in flight; a plain note once it has settled without one.
  const pendingLine = pendingFresh ? (
    <SkelBar className="mt-1 h-3 w-2/3" />
  ) : (
    <p className="mt-1 text-[13px] text-[#a6b5cf]">Preview unavailable</p>
  );

  const totalCommitsCollapsed = activePreview?.private_commits_collapsed ?? 0;
  const publicCommitsCount = activePreview?.public_commits_collapsed;
  const privateOnlyCommitsCount =
    publicCommitsCount !== undefined
      ? Math.max(0, totalCommitsCollapsed - publicCommitsCount)
      : undefined;
  const targetInCandidates = targetCandidates.some((b) => b.name === target);

  // Uncached branch switch: keep the real header mounted and skeleton only the body/footer.
  const showBodySkeleton = !isSelfTarget && pendingFresh && !activePreview;

  return (
    <section className="pr-surface flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
      {/* Airlock Header Bar */}
      <div className="relative shrink-0 border-b border-white/[0.06] px-3.5 py-2.5">
        {inspecting && (
          <div aria-hidden="true" className="pr-shimmer absolute inset-x-0 top-0 h-0.5" />
        )}
        <div className="flex items-center justify-between gap-2.5">
          {/* Route Display + Gate Status Pill */}
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <span className="inline-flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
              <IconDeclassify className="h-[18px] w-[18px]" />
              <span className="hidden sm:inline">Safe Publish</span>
            </span>

            <div className="flex min-w-0 flex-1 items-center gap-1.5 rounded-xl border border-white/[0.08] bg-black/30 px-2.5 py-1">
              {isPrivateScope(branch.visibility) ? (
                <IconLock className="h-3.5 w-3.5 text-[#a8c5ff]" />
              ) : (
                <IconBranches className="h-3.5 w-3.5 text-[#7f95f8]" />
              )}
              <span
                title={`${branch.name} · ${visibilityLabel(branch.visibility)}`}
                className="min-w-0 max-w-[200px] truncate font-mono text-[13.5px] font-semibold text-[#f3f6fd]"
              >
                {branch.name}
              </span>

              <span className="shrink-0 px-1 font-mono text-[13.5px] text-[#7f95f8]" aria-hidden="true">
                →
              </span>

              {targetCandidates.length > 0 ? (
                <select
                  ref={targetSelectRef}
                  aria-label="Target branch for declassification"
                  value={targetInCandidates ? target : ""}
                  onChange={(e) => {
                    if (e.target.value) onSelectTargetBranch(e.target.value);
                  }}
                  style={{ colorScheme: "dark" }}
                  className="min-w-0 max-w-[180px] truncate rounded-lg border border-white/[0.1] bg-[#0b0f1c] px-2 py-0.5 font-mono text-[13.5px] font-medium text-[#dce4f5] focus:border-[#9ec0f5]/50 focus:outline-none"
                >
                  {!targetInCandidates && (
                    <option value="" disabled className="bg-[#0b0f1c]">
                      {isSelfTarget ? `${target} (self)` : target || "Select target"}
                    </option>
                  )}
                  {targetCandidates.map((b) => (
                    <option key={b.name} value={b.name} className="bg-[#0b0f1c] text-[#dce4f5]">
                      {`${b.name}${b.is_current ? " (default)" : ""}${
                        b.visibility.scope === "public" ? "" : ` · ${b.visibility.scope}`
                      }`}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="font-mono text-[13.5px] text-[#b6c3db]">{target}</span>
              )}
            </div>

            <span
              className={`inline-flex min-w-[9.5rem] shrink-0 items-center justify-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] font-semibold tracking-wider ${headerStatus.cls}`}
            >
              {(headerStatus.label === "READY TO PUBLISH" || headerStatus.label === "LANDED") && (
                <IconShieldCheck className="h-3.5 w-3.5" />
              )}
              {headerStatus.label === "WARNINGS" && <IconQuarantine className="h-3.5 w-3.5" />}
              {headerStatus.label === "PUBLISH BLOCKED" && <IconBlock className="h-3.5 w-3.5" />}
              <span>{headerStatus.label}</span>
            </span>
          </div>

          {/* Compact Action Buttons */}
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="button"
              onClick={onToggleRail}
              aria-pressed={railOpen}
              title={railOpen ? "Hide scanner & GitHub rail" : "Show scanner & GitHub rail"}
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                railOpen ? "pr-pill-active text-[#f3f6fd]" : "pr-pill text-[#d2dbee] hover:text-[#f3f6fd]"
              }`}
            >
              <IconDeclassify className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span className="hidden 2xl:inline">Scanner & GitHub</span>
              {(firewallBlocked || ghConnected) && (
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 rounded-full ${firewallBlocked ? "bg-[#f27c7c]" : "bg-[#5bdba2]"}`}
                />
              )}
              {firewallBlocked && (
                <span className="rounded-full bg-[#f27c7c]/20 px-1.5 text-[12px] text-[#f27c7c]">
                  {firewallBlockingCount}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={onToggleWideMode}
              aria-pressed={wideMode}
              title={wideMode ? "Show branch list" : "Expand airlock to full width"}
              aria-label={wideMode ? "Show branch list" : "Expand airlock to full width"}
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                wideMode
                  ? "pr-pill-active text-[#f3f6fd]"
                  : "pr-pill text-[#d2dbee] hover:text-[#f3f6fd]"
              }`}
            >
              <IconPanel className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span className="hidden 2xl:inline">{wideMode ? "Branches" : "Wide"}</span>
            </button>

            <button
              type="button"
              onClick={onRefreshPreview}
              disabled={inspecting}
              title="Refresh airlock preview"
              aria-label="Refresh airlock preview"
              className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee] hover:text-[#f3f6fd] disabled:opacity-50"
            >
              <IconRefresh
                className={`h-3.5 w-3.5 text-[#9ec0f5] ${inspecting ? "animate-spin" : ""}`}
              />
              <span className="hidden sm:inline">Refresh</span>
            </button>

            {activePreview?.attestation_trailer && (
              <button
                type="button"
                onClick={() => copyText("attestation", activePreview.attestation_trailer)}
                title={activePreview.attestation_trailer}
                aria-label="Copy attestation trailer"
                className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#dce4f5]"
              >
                {copiedKey === "attestation" ? (
                  <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                ) : (
                  <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
                )}
                <span className="hidden 2xl:inline">Attestation</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => copyText("cli", publishCmd)}
              title={publishCmd}
              aria-label="Copy CLI publish command"
              className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#9ec0f5]"
            >
              {copiedKey === "cli" ? (
                <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
              ) : (
                <IconTerminal className="h-3.5 w-3.5" />
              )}
              <span className="hidden 2xl:inline">CLI</span>
            </button>
          </div>
        </div>

        {/* Authorized Principals Strip for Restricted Branches */}
        {branch.visibility.scope === "restricted" && (
          <div className="mt-2 flex flex-wrap items-center justify-between gap-x-2 gap-y-1 rounded-xl border border-white/[0.08] bg-white/[0.025] px-2.5 py-1.5">
            <div className="flex min-w-0 flex-wrap items-center gap-1">
              <span className="mr-1 font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                Authorized Principals
              </span>
              {branch.visibility.allow.map((p) => (
                <span
                  key={p}
                  className="inline-flex items-center gap-1 rounded-full border border-white/[0.12] bg-white/[0.045] px-2.5 py-0.5 font-mono text-[12.5px] text-[#cbd5e8]"
                >
                  <span>{p}</span>
                  <button
                    type="button"
                    onClick={() => onRemovePrincipal(p)}
                    aria-label={`Remove ${p}`}
                    className="rounded-full p-0.5 hover:bg-white/10 hover:text-white"
                  >
                    <IconClose className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
            <form onSubmit={onAddPrincipal} className="flex shrink-0 items-center gap-1.5">
              <input
                value={newPrincipal}
                onChange={(e) => onNewPrincipalChange(e.target.value)}
                aria-label="Add an authorized principal"
                placeholder="Add @user or group:team…"
                className="w-40 rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-0.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:border-[#9ec0f5]/45 focus:outline-none"
              />
              <button
                type="submit"
                className="pr-pill rounded-lg px-2.5 py-1 font-mono text-[12.5px] text-[#e6ecf8]"
              >
                Add
              </button>
            </form>
          </div>
        )}
      </div>

      {showBodySkeleton ? (
        <AirlockBodySkeleton />
      ) : (
        <>
      {/* Scrollable Airlock Body */}
      <div className="@container min-h-0 flex-1 space-y-3 overflow-y-auto p-3.5">
        {/* Post-Publish Declassification Receipt Card */}
        {publishReceipt && (
          <div
            role="status"
            className="pr-elevated relative overflow-hidden rounded-2xl border border-[#5bdba2]/35 p-3.5"
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 rounded-full border border-[#5bdba2]/35 bg-[#5bdba2]/16 px-2.5 py-0.5 font-mono text-[12.5px] font-semibold uppercase tracking-wider text-[#5bdba2]">
                    <IconShieldCheck className="h-3.5 w-3.5" />
                    <span>Declassification Receipt</span>
                  </span>
                  <span className="inline-flex items-center overflow-hidden rounded-lg border border-[#5bdba2]/25 bg-black/30 font-mono text-[13px] text-[#e6fff4]">
                    <button
                      type="button"
                      onClick={() =>
                        onOpenCommit
                          ? onOpenCommit(publishReceipt.new_commit_oid, receiptTargetShort || undefined)
                          : copyText("receipt-oid", publishReceipt.new_commit_oid)
                      }
                      title={
                        onOpenCommit
                          ? `Open ${publishReceipt.new_commit_oid} in #changes`
                          : `Copy full OID ${publishReceipt.new_commit_oid}`
                      }
                      className="px-2 py-0.5 hover:bg-[#5bdba2]/12"
                    >
                      {publishReceipt.new_commit_oid.slice(0, 10)}
                    </button>
                    <button
                      type="button"
                      onClick={() => copyText("receipt-oid", publishReceipt.new_commit_oid)}
                      title={`Copy full OID ${publishReceipt.new_commit_oid}`}
                      aria-label="Copy commit OID"
                      className="border-l border-[#5bdba2]/20 px-1.5 py-0.5 hover:bg-[#5bdba2]/12"
                    >
                      {copiedKey === "receipt-oid" ? (
                        <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                      ) : (
                        <IconCopy className="h-3.5 w-3.5 text-[#5bdba2]/80" />
                      )}
                    </button>
                  </span>
                  <span className="font-mono text-[13.5px] text-[#5bdba2]/80">→</span>
                  <span className="font-mono text-[13.5px] font-medium text-[#f3f6fd]">
                    {publishReceipt.target_ref}
                  </span>
                </div>

                {/* Audit Trail Stamp */}
                <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12.5px] text-[#bcefd9]/85">
                  <span>Recorded in audit log</span>
                  {publishReceipt.actor && (
                    <>
                      <span>·</span>
                      <span className="text-[#f3f6fd]">{publishReceipt.actor}</span>
                    </>
                  )}
                  {publishReceipt.published_at && (
                    <>
                      <span>·</span>
                      <Time value={publishReceipt.published_at} />
                    </>
                  )}
                  {publishReceipt.policy_fingerprint && (
                    <>
                      <span>·</span>
                      <span>policy {publishReceipt.policy_fingerprint}</span>
                    </>
                  )}
                </div>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                {receiptDeepLink && (
                  <button
                    type="button"
                    onClick={() => copyText("receipt-link", receiptDeepLink)}
                    title={receiptDeepLink}
                    className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#dce4f5]"
                  >
                    {copiedKey === "receipt-link" ? (
                      <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                    ) : (
                      <IconLink className="h-3.5 w-3.5 text-[#9ec0f5]" />
                    )}
                    <span>Copy commit link</span>
                  </button>
                )}

                {onOpenCommit && (
                  <button
                    type="button"
                    onClick={() =>
                      onOpenCommit(publishReceipt.new_commit_oid, receiptTargetShort || undefined)
                    }
                    className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[13px]"
                  >
                    <span>Open in #changes →</span>
                  </button>
                )}

                <button
                  type="button"
                  onClick={onDismissReceipt}
                  aria-label="Dismiss declassification receipt"
                  className="rounded-lg p-1 text-[#b6c3db] hover:bg-white/[0.08] hover:text-white"
                >
                  <IconClose className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Toggleable Published vs Held Back Path Chips */}
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => setReceiptTab((t) => (t === "published" ? null : "published"))}
                aria-pressed={receiptTab === "published"}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] transition ${
                  receiptTab === "published"
                    ? "border-[#5bdba2]/50 bg-[#5bdba2]/20 text-[#e6fff4]"
                    : "border-[#5bdba2]/25 bg-black/25 text-[#5bdba2] hover:bg-[#5bdba2]/12"
                }`}
              >
                <span>Published ({(publishReceipt.published_paths ?? []).length})</span>
                <IconChevron
                  direction={receiptTab === "published" ? "down" : "right"}
                  className="h-3 w-3"
                />
              </button>

              <button
                type="button"
                onClick={() => setReceiptTab((t) => (t === "held_back" ? null : "held_back"))}
                aria-pressed={receiptTab === "held_back"}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 font-mono text-[12.5px] transition ${
                  receiptTab === "held_back"
                    ? "border-white/[0.22] bg-white/[0.1] text-[#f3f6fd]"
                    : "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8] hover:bg-white/[0.08]"
                }`}
              >
                <span>Held Back ({(publishReceipt.scrubbed_paths ?? []).length})</span>
                <IconChevron
                  direction={receiptTab === "held_back" ? "down" : "right"}
                  className="h-3 w-3"
                />
              </button>

              <button
                type="button"
                onClick={() => setReceiptMsgOpen((o) => !o)}
                aria-expanded={receiptMsgOpen}
                className="ml-auto inline-flex items-center gap-1 font-mono text-[12.5px] text-[#bcefd9] hover:text-white"
              >
                <IconChevron direction={receiptMsgOpen ? "down" : "right"} className="h-3.5 w-3.5" />
                <span>{receiptMsgOpen ? "Hide commit message" : "Commit message & trailer"}</span>
              </button>
            </div>

            {receiptTab === "published" && (publishReceipt.published_paths ?? []).length > 0 && (
              <div className="mt-2.5 flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                {publishReceipt.published_paths.map((p) => (
                  <span
                    key={p}
                    className="rounded-lg border border-[#5bdba2]/25 bg-black/30 px-2 py-0.5 font-mono text-[12.5px] text-[#5bdba2]"
                  >
                    {p}
                  </span>
                ))}
              </div>
            )}

            {receiptTab === "held_back" && (
              <div className="mt-2.5 flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                {(publishReceipt.scrubbed_paths ?? []).length === 0 ? (
                  <span className="font-mono text-[12.5px] text-[#bcefd9]/70">
                    No private files were held back in this landing.
                  </span>
                ) : (
                  publishReceipt.scrubbed_paths.map((p) => (
                    <span
                      key={p}
                      className="rounded-lg border border-white/[0.12] bg-white/[0.045] px-2 py-0.5 font-mono text-[12.5px] text-[#cbd5e8]"
                    >
                      {p}
                    </span>
                  ))
                )}
              </div>
            )}

            {receiptMsgOpen && (
              <pre className="pr-well mt-2.5 max-h-40 overflow-y-auto whitespace-pre-wrap break-words rounded-xl px-3 py-2 font-mono text-[12.5px] text-[#d6f7e8]">
                {publishReceipt.commit_message || publishReceipt.attestation_trailer}
              </pre>
            )}
          </div>
        )}

        {/* Self-target: nothing to inspect, so offer the next useful step */}
        {isSelfTarget && (
          <div className="flex min-h-[260px] flex-col items-center justify-center gap-3 px-4 text-center">
            <IconDeclassify className="h-7 w-7 text-[#7f95f8]/70" />
            <div className="space-y-1">
              <div className="text-[14px] font-semibold text-[#f3f6fd]">
                Nothing to publish here
              </div>
              <p className="max-w-sm text-[14px] leading-relaxed text-[#b6c3db]">
                <strong className="font-mono text-[#f3f6fd]">{branch.name}</strong>{" "}
                {branch.is_current
                  ? "is the default branch. Pick a private branch to publish."
                  : "matches the target branch. Pick another branch or switch target."}
              </p>
            </div>
            {reviewCandidate ? (
              <button
                type="button"
                onClick={() => onSelectBranch(reviewCandidate.name)}
                className="pr-action-btn inline-flex items-center gap-2 rounded-xl px-4 py-2 text-[14px]"
              >
                <IconBranches className="h-4 w-4" />
                <span>Review {reviewCandidate.name}</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={() => targetSelectRef.current?.focus()}
                className="pr-action-btn inline-flex items-center gap-2 rounded-xl px-4 py-2 text-[14px]"
              >
                <span>Switch target branch</span>
              </button>
            )}
          </div>
        )}

        {/* 3-Stage Airlock Pipeline */}
        {!isSelfTarget && (
          <div
            aria-busy={inspecting}
            className={`grid grid-cols-1 gap-3 transition-opacity @2xl:grid-cols-2 @5xl:grid-cols-3 ${
              pendingFresh && activePreview ? "opacity-60" : "opacity-100"
            }`}
          >
            {/* STAGE 01: Incoming Private Branch */}
            <div className="pr-well relative flex min-w-0 flex-col rounded-2xl p-3.5">
              <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] pb-2.5">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-white/[0.12] bg-white/[0.045] font-mono text-[12.5px] font-semibold text-[#cbd5e8]">
                    01
                  </span>
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12.5px] font-semibold uppercase tracking-wider text-[#f3f6fd]">
                      Your Private Branch
                    </div>
                    <div className="truncate font-mono text-[12px] text-[#a6b5cf]">
                      Local history &amp; private files
                    </div>
                  </div>
                </div>
                <span
                  aria-hidden="true"
                  className="hidden h-6 w-6 shrink-0 items-center justify-center rounded-full border border-white/[0.08] bg-white/[0.03] font-mono text-[12.5px] text-[#7f95f8] @5xl:inline-flex"
                >
                  →
                </span>
              </div>

              <div className="mt-3 space-y-3">
                {/* Branch identity card */}
                <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-2.5">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="truncate font-mono text-[13.5px] font-semibold text-[#f3f6fd]">
                      {branch.name}
                    </span>
                    <span className="font-mono text-[12.5px] text-[#9ec0f5]">
                      {shortOid((previewMatches && activePreview?.source_head_oid) || branch.head_oid)}
                    </span>
                  </div>
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                    <span
                      className={`rounded-full border px-2 py-0.5 font-mono text-[12px] leading-4 ${visibilityPillTone(branch.visibility)}`}
                    >
                      {visibilityLabel(branch.visibility)}
                    </span>
                    <span
                      className={`rounded-full border px-2 py-0.5 font-mono text-[12px] uppercase ${
                        branch.readiness === "ready"
                          ? "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                          : "border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
                      }`}
                    >
                      {branch.readiness}
                    </span>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-3 gap-2">
                  <div className="rounded-xl border border-white/[0.06] bg-black/30 p-2.5">
                    <div className="font-mono text-[16px] font-semibold text-[#f3f6fd]">
                      {totalCommitsCollapsed}
                    </div>
                    <div className="mt-0.5 font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Commits
                    </div>
                    {publicCommitsCount !== undefined && privateOnlyCommitsCount !== undefined && (
                      <div className="mt-1 font-mono text-[12px] text-[#b6c3db]">
                        {publicCommitsCount} pub · {privateOnlyCommitsCount} priv
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-[#5bdba2]/18 bg-[#5bdba2]/[0.05] p-2.5">
                    <div className="font-mono text-[16px] font-semibold text-[#5bdba2]">
                      {publishedPaths.length}
                    </div>
                    <div className="mt-0.5 font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Crossing
                    </div>
                  </div>
                  <div className="rounded-xl border border-white/[0.1] bg-white/[0.04] p-2.5">
                    <div className="font-mono text-[16px] font-semibold text-[#cbd5e8]">
                      {scrubbedPaths.length + blocked.length + hiddenBlocked}
                    </div>
                    <div className="mt-0.5 font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Held back
                    </div>
                  </div>
                </div>

                {/* Internal History */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Internal History (Will NOT Cross Boundary)
                    </span>
                  </div>
                  <p className="text-[12.5px] leading-relaxed text-[#a6b5cf]">
                    Ancestry discarded; 1 squashed commit lands on{" "}
                    <span className="font-mono text-[#d2dbee]">{target}</span>.
                  </p>
                  {collapsedCommits.length === 0 ? (
                    <div className="rounded-xl border border-white/[0.05] bg-black/25 px-3 py-2 font-mono text-[12.5px] text-[#a6b5cf]">
                      {pendingFresh
                        ? <SkelBar className="h-3 w-2/3" />
                        : !activePreview
                          ? "Preview unavailable"
                          : totalCommitsCollapsed > 0
                            ? `${plural(totalCommitsCollapsed, "commit")} will be collapsed.`
                            : `No unlanded commits ahead of ${target}.`}
                    </div>
                  ) : (
                    <ul className="max-h-44 space-y-1 overflow-y-auto pr-0.5">
                      {collapsedCommits.map((c) => (
                        <li
                          key={c.short_oid}
                          className="flex items-start justify-between gap-2 rounded-lg border border-white/[0.05] bg-black/30 px-2.5 py-1.5"
                        >
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5">
                              <span className="font-mono text-[12.5px] text-[#9ec0f5]">
                                {c.short_oid}
                              </span>
                              <span
                                className="truncate text-[13px] text-[#dce4f5]"
                                title={c.subject}
                              >
                                {c.subject}
                              </span>
                            </div>
                          </div>
                          <span
                            className={`shrink-0 rounded-full border px-2 py-0.5 font-mono text-[12px] ${
                              c.touches_public
                                ? "border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]"
                                : "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]"
                            }`}
                          >
                            {c.touches_public ? "touches public" : "private-only"}
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                  {totalCommitsCollapsed > collapsedCommits.length && collapsedCommits.length > 0 && (
                    <div className="font-mono text-[12.5px] text-[#a6b5cf]">
                      +{totalCommitsCollapsed - collapsedCommits.length} older commits also
                      collapsed
                    </div>
                  )}
                </div>

                {/* Restricted Paths Touched */}
                <div className="space-y-1.5">
                  <div className="font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                    Restricted Paths Touched ({scrubbedPaths.length + blocked.length})
                  </div>
                  {scrubbedPaths.length === 0 && blocked.length === 0 ? (
                    <div className="rounded-xl border border-white/[0.05] bg-black/25 px-3 py-2 font-mono text-[12.5px] text-[#a6b5cf]">
                      None on this branch
                    </div>
                  ) : (
                    <ul className="max-h-36 space-y-1 overflow-y-auto pr-0.5">
                      {blocked.map((p) => (
                        <li
                          key={`blk-${p}`}
                          title={p}
                          className="flex items-center justify-between gap-2 rounded-lg border border-[#f27c7c]/25 bg-[#f27c7c]/[0.07] px-2.5 py-1 font-mono text-[12.5px] text-[#f27c7c]"
                        >
                          <span className="truncate">{p}</span>
                          <span className="shrink-0 text-[12px] uppercase">blocked</span>
                        </li>
                      ))}
                      {scrubbedPaths.map((p) => (
                        <li
                          key={`scb-${p}`}
                          title={p}
                          className="flex items-center justify-between gap-2 rounded-lg border border-white/[0.1] bg-white/[0.035] px-2.5 py-1 font-mono text-[12.5px] text-[#cbd5e8]"
                        >
                          <span className="truncate">{p}</span>
                          <span className="shrink-0 text-[12px] uppercase text-[#a6b5cf]">
                            held back
                          </span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>

            {/* STAGE 02: Airlock Scrub & Safety Checklist */}
            <div className="pr-well relative flex min-w-0 flex-col rounded-2xl p-3.5">
              <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] pb-2.5">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-[#7f95f8]/35 bg-[#7f95f8]/15 font-mono text-[12.5px] font-semibold text-[#9ec0f5]">
                    02
                  </span>
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12.5px] font-semibold uppercase tracking-wider text-[#f3f6fd]">
                      Safety Checks
                    </div>
                    <div className="truncate font-mono text-[12px] text-[#a6b5cf]">
                      6 automatic leak & secret checks
                    </div>
                  </div>
                </div>
                <span
                  aria-hidden="true"
                  className="hidden h-6 w-6 shrink-0 items-center justify-center rounded-full border border-white/[0.08] bg-white/[0.03] font-mono text-[12.5px] text-[#7f95f8] @5xl:inline-flex"
                >
                  →
                </span>
              </div>

              <div className="mt-3 space-y-2.5">
                {/* Gate 1: Restricted Paths Stripped */}
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13.5px] font-medium text-[#f3f6fd]">
                      1. Restricted Paths Stripped
                    </span>
                    <GateBadge status={gate1Status} />
                  </div>
                  <div className="mt-1 flex flex-wrap items-center justify-between gap-1.5 text-[13px] text-[#b6c3db]">
                    {!gatesReady ? (
                      pendingFresh ? (
                        <SkelBar className="h-3 w-2/3" />
                      ) : (
                        <span>Preview unavailable</span>
                      )
                    ) : (
                      <span>
                        {scrubbedPaths.length > 0
                          ? `${plural(scrubbedPaths.length, "private path")} held back on source.`
                          : "No restricted paths need stripping."}
                      </span>
                    )}
                    {scrubbedPaths.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setExpandedHeldBack((v) => !v)}
                        aria-expanded={expandedHeldBack}
                        className="inline-flex items-center gap-1 font-mono text-[12.5px] text-[#9ec0f5] hover:underline"
                      >
                        <IconChevron
                          direction={expandedHeldBack ? "down" : "right"}
                          className="h-3 w-3"
                        />
                        <span>{expandedHeldBack ? "Hide rules" : "Rule traces"}</span>
                      </button>
                    )}
                  </div>

                  {expandedHeldBack && scrubbedPaths.length > 0 && (
                    <ul className="mt-2 max-h-40 space-y-1.5 overflow-y-auto border-t border-white/[0.05] pt-2">
                      {scrubbedPaths.map((p) => {
                        const info = heldBackRules[p];
                        const reason =
                          info?.reason || legacyReasons[p] || "Not readable by anonymous visitors";
                        return (
                          <li
                            key={p}
                            className="rounded-lg border border-white/[0.05] bg-white/[0.02] px-2.5 py-1.5"
                          >
                            <div className="flex flex-wrap items-center gap-1.5">
                              <span className="truncate font-mono text-[12.5px] text-[#cbd5e8]">
                                {p}
                              </span>
                              {info?.layer && (
                                <span
                                  className={`rounded-full border px-2 py-0.5 font-mono text-[12px] uppercase ${
                                    info.layer === "server"
                                      ? "border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f27c7c]"
                                      : "border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]"
                                  }`}
                                >
                                  {info.layer}
                                </span>
                              )}
                              {info?.rule_id && (
                                <span className="font-mono text-[12px] text-[#a6b5cf]">
                                  #{info.rule_id}
                                </span>
                              )}
                              {(info?.zones ?? []).map((z) => (
                                <span
                                  key={z}
                                  className="rounded-full border border-[#7f95f8]/25 bg-[#7f95f8]/10 px-2 py-0.5 font-mono text-[12px] text-[#b8cef8]"
                                >
                                  zone:{z}
                                </span>
                              ))}
                            </div>
                            <div className="mt-0.5 text-[12.5px] leading-snug text-[#b6c3db]">
                              {reason}
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  )}

                  {overlayBlockedPaths.length > 0 && (
                    <div className="mt-2 space-y-1 rounded-lg border border-[#f27c7c]/25 bg-[#f27c7c]/10 p-2">
                      <div className="font-mono text-[12.5px] font-semibold text-[#f27c7c]">
                        Overlay-blocked ({overlayBlockedPaths.length})
                      </div>
                      <p className="text-[12.5px] text-[#f7baba]">
                        Mounted overlays cannot be published:
                      </p>
                      <ul className="space-y-0.5 font-mono text-[12.5px] text-[#f27c7c]">
                        {overlayBlockedPaths.map((p) => (
                          <li key={p} className="truncate">
                            {p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Gate 2: Ancestry & Copyfrom Lineage Scrubbed */}
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13.5px] font-medium text-[#f3f6fd]">
                      2. Ancestry &amp; Copyfrom Lineage
                    </span>
                    <GateBadge status={gate2Status} />
                  </div>
                  {gate2Status === "pending" ? (
                    pendingLine
                  ) : gate2Status === "pass" ? (
                    <p className="mt-1 text-[13px] text-[#b6c3db]">
                      0 private blob copies; parent ancestry severed.
                    </p>
                  ) : (
                    <div className="mt-1.5 space-y-1">
                      <p className="text-[12.5px] leading-snug text-[#f7baba]">
                        Private content copied to public paths. Remove before publishing:
                      </p>
                      <ul className="max-h-28 space-y-1 overflow-y-auto font-mono text-[12.5px] text-[#f27c7c]">
                        {blocked.map((p) => (
                          <li key={p} className="truncate rounded bg-[#f27c7c]/10 px-2 py-0.5">
                            {p}
                          </li>
                        ))}
                      </ul>
                      {hiddenBlocked > 0 && (
                        <div className="font-mono text-[12.5px] text-[#f27c7c]">
                          +{hiddenBlocked} hidden
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Gate 3: 3-Way Merge Safety */}
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate text-[13.5px] font-medium text-[#f3f6fd]">
                      3. 3-Way Merge Safety ({target})
                    </span>
                    <GateBadge status={gate3Status} />
                  </div>
                  {gate3Status === "pending" ? (
                    pendingLine
                  ) : gate3Status === "pass" ? (
                    <div className="mt-1 space-y-1.5">
                      <p className="text-[13px] text-[#b6c3db]">
                        {threeWayMergedPaths.length > 0
                          ? `3-way merge verified (${plural(threeWayMergedPaths.length, "file")}).`
                          : `Clean apply on ${target} (0 conflicts).`}
                      </p>
                      {threeWayMergedPaths.length > 0 && (
                        <div className="flex flex-wrap gap-1">
                          {threeWayMergedPaths.map((p) => (
                            <span
                              key={p}
                              className="rounded-md border border-[#9ec0f5]/25 bg-[#7f95f8]/12 px-2 py-0.5 font-mono text-[12px] text-[#9ec0f5]"
                            >
                              3-way: {p}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="mt-1.5 space-y-1">
                      <p className="text-[12.5px] leading-snug text-[#f7baba]">
                        Merge conflicts block publish:
                      </p>
                      <ul className="max-h-28 space-y-1 overflow-y-auto font-mono text-[12.5px] text-[#f27c7c]">
                        {conflicts.map((p) => (
                          <li key={p} className="truncate rounded bg-[#f27c7c]/10 px-2 py-0.5">
                            {p}
                          </li>
                        ))}
                      </ul>
                      {hiddenConflicts > 0 && (
                        <div className="font-mono text-[12.5px] text-[#f27c7c]">
                          +{hiddenConflicts} hidden
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Gate 4: Public Commit Message Hygiene */}
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13.5px] font-medium text-[#f3f6fd]">
                      4. Public Commit Message Hygiene
                    </span>
                    <GateBadge status={gate4Status} />
                  </div>
                  {gate4Status === "pending" ? (
                    pendingLine
                  ) : hygieneWarnings.length === 0 ? (
                    <p className="mt-1 text-[13px] text-[#b6c3db]">
                      No restricted paths or branch names matched.
                    </p>
                  ) : (
                    <div className="mt-1.5 space-y-1.5">
                      <p className="text-[12.5px] leading-snug text-[#cfe0ff]">
                        Commit messages are <strong>NOT</strong> filtered. Matched tokens:
                      </p>
                      <ul className="max-h-32 space-y-1 overflow-y-auto">
                        {hygieneWarnings.map((w) => (
                          <li
                            key={`${w.category}:${w.token.toLowerCase()}`}
                            className="flex flex-wrap items-center gap-1.5 rounded-lg border border-[#9ec0f5]/25 bg-[#7f95f8]/[0.08] px-2 py-1"
                          >
                            <span className="font-mono text-[12.5px] font-semibold text-[#a8c5ff]">
                              {w.token}
                            </span>
                            <span className="rounded-full bg-black/35 px-1.5 py-0.5 font-mono text-[12px] uppercase text-[#cfe0ff]">
                              {w.category}
                            </span>
                            <span className="text-[12.5px] text-[#b6c3db]">{w.detail}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Gate 5: Quarantined Instruction Files */}
                <div className="rounded-xl border border-white/[0.06] bg-black/30 p-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13.5px] font-medium text-[#f3f6fd]">
                      5. Quarantined Instruction Files
                    </span>
                    <GateBadge status={gate5Status} />
                  </div>
                  {gate5Status === "pending" ? (
                    pendingLine
                  ) : quarantinePaths.length === 0 ? (
                    <p className="mt-1 text-[13px] text-[#b6c3db]">
                      No public instruction files modified.
                    </p>
                  ) : (
                    <div className="mt-1.5 space-y-1.5">
                      <p className="text-[12.5px] leading-snug text-[#cfe0ff]">
                        Inspect untrusted instruction file diffs before publishing:
                      </p>
                      <div className="flex flex-wrap gap-1">
                        {quarantinePaths.map((p) => (
                          <button
                            key={p}
                            type="button"
                            onClick={() => jumpToDiffFile(p)}
                            className="inline-flex items-center gap-1 rounded-lg border border-[#9ec0f5]/30 bg-[#7f95f8]/12 px-2 py-0.5 font-mono text-[12.5px] text-[#a8c5ff] hover:bg-[#7f95f8]/20"
                          >
                            <IconQuarantine className="h-3 w-3" />
                            <span>{p}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Gate 6: Declassification Firewall (static analysis of the public diff) */}
                <div
                  className={`rounded-xl border p-2.5 ${
                    gate6Status === "fail"
                      ? "border-[#f27c7c]/30 bg-[#f27c7c]/[0.06]"
                      : "border-white/[0.06] bg-black/30"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[13.5px] font-medium text-[#f3f6fd]">
                      6. Leak & Secret Scanner
                    </span>
                    <GateBadge
                      status={gate6Status}
                      label={
                        gate6Status === "fail"
                          ? `${firewallBlockingCount} blocking`
                          : undefined
                      }
                    />
                  </div>
                  {gate6Status === "pending" ? (
                    pendingLine
                  ) : gate6Status === "pass" ? (
                    <p className="mt-1 text-[13px] text-[#b6c3db]">
                      No blocking findings.
                    </p>
                  ) : (
                    <div className="mt-1.5 space-y-1.5">
                      <p className="text-[12.5px] leading-snug text-[#f7baba]">
                        {plural(firewallBlockingCount, "blocking finding")} — owner override required.
                      </p>
                      <div className="flex flex-wrap items-center gap-1.5">
                        {canOwnerOverride && (
                          <button
                            type="button"
                            onClick={onOpenOverride}
                            className="inline-flex items-center gap-1 rounded-lg border border-[#9ec0f5]/35 bg-[#7f95f8]/14 px-2 py-0.5 font-mono text-[12.5px] text-[#a8c5ff] hover:bg-[#7f95f8]/22"
                          >
                            <IconQuarantine className="h-3 w-3" />
                            <span>Open override</span>
                          </button>
                        )}
                        {!railOpen && (
                          <button
                            type="button"
                            onClick={onToggleRail}
                            className="pr-pill rounded-lg px-2 py-0.5 font-mono text-[12.5px] text-[#9ec0f5]"
                          >
                            View findings
                          </button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* STAGE 03: Clean Public Output */}
            <div className="pr-well flex min-w-0 flex-col rounded-2xl p-3.5 @2xl:col-span-2 @5xl:col-span-1">
              <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] pb-2.5">
                <div className="flex min-w-0 items-center gap-2">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg border border-[#5bdba2]/35 bg-[#5bdba2]/14 font-mono text-[12.5px] font-semibold text-[#5bdba2]">
                    03
                  </span>
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12.5px] font-semibold uppercase tracking-wider text-[#f3f6fd]">
                      Clean Public Output
                    </div>
                    <div className="truncate font-mono text-[12px] text-[#5bdba2]/85">
                      Exact diff landing on target or GitHub
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-3 flex flex-1 flex-col space-y-3">
                {/* Single Squashed Commit Summary */}
                <div className="rounded-xl border border-[#5bdba2]/20 bg-[#5bdba2]/[0.05] p-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-1.5 font-mono text-[13px]">
                    <span className="font-semibold text-[#f3f6fd]">
                      1 commit → refs/heads/{target}
                    </span>
                    <span className="text-[12.5px] text-[#b6c3db]">
                      parent{" "}
                      <span className="text-[#9ec0f5]">
                        {previewMatches && activePreview?.target_head_oid ? (
                          shortOid(activePreview.target_head_oid)
                        ) : previewMatches ? (
                          "root"
                        ) : pendingFresh ? (
                          <SkelBar className="inline-block h-3 w-14 align-middle" />
                        ) : (
                          "—"
                        )}
                      </span>
                    </span>
                  </div>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-[#b6c3db]">
                    {activePreview?.publish_rule || PUBLISH_RULE}
                  </p>
                </div>

                {/* Exact Public Files Manifest */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Exact Public Files Manifest ({publishedPaths.length})
                    </span>
                    {publicDiff.length > 0 && (
                      <span className="font-mono text-[12.5px]">
                        <span className="text-[#5bdba2]">+{diffTotals.additions}</span>{" "}
                        <span className="text-[#f27c7c]">-{diffTotals.deletions}</span>
                      </span>
                    )}
                  </div>

                  {publishedPaths.length === 0 ? (
                    <div className="rounded-xl border border-white/[0.05] bg-black/25 px-3 py-2.5 font-mono text-[12.5px] text-[#a6b5cf]">
                      {pendingFresh ? (
                        <SkelBar className="h-3 w-2/3" />
                      ) : !activePreview ? (
                        "Preview unavailable"
                      ) : (
                        "Nothing to publish"
                      )}
                    </div>
                  ) : (
                    <ul className="max-h-48 space-y-1 overflow-y-auto pr-0.5">
                      {publishedPaths.map((p) => {
                        const df = diffByPath.get(p);
                        const modeChanged =
                          !!df?.old_mode && !!df?.new_mode && df.old_mode !== df.new_mode;
                        return (
                          <li key={p}>
                            <button
                              type="button"
                              onClick={() => jumpToDiffFile(p)}
                              title={`Inspect diff for ${p}`}
                              className="flex w-full items-center justify-between gap-2 rounded-lg border border-white/[0.06] bg-black/30 px-2.5 py-1.5 text-left transition hover:border-[#5bdba2]/35 hover:bg-white/[0.04]"
                            >
                              <span className="flex min-w-0 items-center gap-1.5">
                                <IconFileNode className="h-3.5 w-3.5 text-[#5bdba2]" />
                                <span className="truncate font-mono text-[12.5px] text-[#dce4f5]">
                                  {p}
                                </span>
                              </span>
                              <span className="flex shrink-0 items-center gap-1.5 font-mono text-[12px]">
                                {modeChanged && (
                                  <span className="rounded-full border border-white/[0.11] bg-white/[0.04] px-2 py-0.5 text-[12px] text-[#9eb0cc]">
                                    mode {df.old_mode}→{df.new_mode}
                                  </span>
                                )}
                                {df?.three_way_merged && (
                                  <span className="rounded-full border border-[#7f95f8]/25 bg-[#7f95f8]/10 px-2 py-0.5 text-[12px] text-[#b8cef8]">
                                    3-way
                                  </span>
                                )}
                                {df?.is_instruction_file && (
                                  <span className="rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/14 px-2 py-0.5 text-[12px] text-[#a8c5ff]">
                                    quarantine
                                  </span>
                                )}
                                {df && <DiffKindPill kind={df.kind} />}
                                {df && !df.binary && (
                                  <span className="text-[#a6b5cf]">
                                    <span className="text-[#5bdba2]">+{df.additions}</span>/
                                    <span className="text-[#f27c7c]">-{df.deletions}</span>
                                  </span>
                                )}
                              </span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </div>

                {/* Public Commit Message Preview */}
                {proposedMessage && (
                  <div className="space-y-1.5">
                    <div className="font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Public Commit Message Preview
                    </div>
                    <pre className="max-h-36 overflow-y-auto whitespace-pre-wrap break-words rounded-xl border border-white/[0.06] bg-black/35 px-3 py-2 font-mono text-[12.5px] leading-relaxed text-[#d2dbee]">
                      {proposedMessage}
                    </pre>
                  </div>
                )}

                {publicDiff.length > 0 && (
                  <button
                    type="button"
                    onClick={jumpToDiffPanel}
                    className="pr-pill mt-auto inline-flex w-full items-center justify-center gap-1.5 rounded-xl px-3 py-1.5 font-mono text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                  >
                    <span>
                      Inspect Exact Public Diff ({plural(publicDiff.length, "file")}) ↓
                    </span>
                  </button>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Expandable Full-Width "Exact Public Diff Preview" Drawer */}
        {!isSelfTarget && activePreview && (
          <div ref={diffSectionRef} className="pr-well overflow-hidden rounded-2xl">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2.5">
              <button
                type="button"
                onClick={() => setDiffDrawerOpen((o) => !o)}
                aria-expanded={diffDrawerOpen}
                className="flex min-w-0 flex-wrap items-center gap-2 text-left"
              >
                <IconChevron
                  direction={diffDrawerOpen ? "down" : "right"}
                  className="h-4 w-4 text-[#9ec0f5]"
                />
                <span className="font-mono text-[13px] font-semibold uppercase tracking-wider text-[#f3f6fd]">
                  Exact Public Diff Preview
                </span>
                <span className="hidden text-[13px] text-[#a6b5cf] sm:inline">
                  — What <code className="text-[#5bdba2]">anonymous</code> Will Actually Clone
                </span>
              </button>

              <div className="flex shrink-0 flex-wrap items-center gap-2 font-mono text-[12.5px]">
                <span className="text-[#b6c3db]">{plural(publicDiff.length, "file")}</span>
                <span className="text-[#5bdba2]">+{diffTotals.additions}</span>
                <span className="text-[#f27c7c]">-{diffTotals.deletions}</span>
                {blocked.length + hiddenBlocked > 0 ? (
                  <span className="inline-flex items-center gap-1 rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/14 px-2 py-0.5 text-[12px] text-[#f27c7c]">
                    <IconBlock className="h-3 w-3" />
                    <span>{plural(blocked.length + hiddenBlocked, "blocked path")} excluded</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-2 py-0.5 text-[12px] text-[#5bdba2]">
                    <IconShieldCheck className="h-3 w-3" />
                    <span>0 restricted blobs</span>
                  </span>
                )}
                {activePreview.public_diff_truncated && (
                  <span className="rounded-full border border-white/[0.11] bg-white/[0.04] px-2 py-0.5 text-[12px] text-[#9eb0cc]">
                    truncated
                  </span>
                )}
                {publicDiff.length > 0 && diffDrawerOpen && (
                  <button
                    type="button"
                    onClick={() =>
                      setCollapsedDiffFiles((prev) =>
                        prev.size >= publicDiff.length
                          ? new Set()
                          : new Set(publicDiff.map((f) => f.path)),
                      )
                    }
                    title={
                      collapsedDiffFiles.size >= publicDiff.length
                        ? "Expand all files"
                        : "Collapse all files"
                    }
                    aria-label={
                      collapsedDiffFiles.size >= publicDiff.length
                        ? "Expand all files"
                        : "Collapse all files"
                    }
                    className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-lg text-[#a6b5cf] hover:text-[#f3f6fd]"
                  >
                    {collapsedDiffFiles.size >= publicDiff.length ? (
                      <IconUnfold className="h-3.5 w-3.5" />
                    ) : (
                      <IconFold className="h-3.5 w-3.5" />
                    )}
                  </button>
                )}
              </div>
            </div>

            {diffDrawerOpen && (
              <div className="space-y-3 p-3.5">
                {parsedPublicDiff.length === 0 ? (
                  <div className="py-6 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                    {publishedPaths.length === 0
                      ? "No public file changes in this landing."
                      : "Server did not return inline diff hunks for this preview."}
                  </div>
                ) : (
                  parsedPublicDiff.map((f) => {
                    const collapsed = collapsedDiffFiles.has(f.path);
                    return (
                      <div
                        id={diffElementId(f.path)}
                        key={f.path}
                        className="overflow-hidden rounded-xl border border-white/[0.06] bg-black/35"
                      >
                        <button
                          type="button"
                          onClick={() => toggleDiffFile(f.path)}
                          className="flex w-full flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.02] px-3.5 py-2 text-left hover:bg-white/[0.04]"
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <IconChevron
                              direction={collapsed ? "right" : "down"}
                              className="h-3.5 w-3.5 text-[#a6b5cf]"
                            />
                            <span className="truncate font-mono text-[13.5px] text-[#dce4f5]">
                              {f.path}
                            </span>
                            {f.old_mode && f.new_mode && f.old_mode !== f.new_mode && (
                              <span className="rounded-full border border-white/[0.11] bg-white/[0.04] px-2 py-0.5 font-mono text-[12px] text-[#9eb0cc]">
                                mode {f.old_mode} → {f.new_mode}
                              </span>
                            )}
                            <DiffKindPill kind={f.kind} />
                            {f.three_way_merged && (
                              <span className="rounded-full border border-[#7f95f8]/25 bg-[#7f95f8]/10 px-2 py-0.5 font-mono text-[12px] text-[#b8cef8]">
                                3-way merged
                              </span>
                            )}
                            {f.is_instruction_file && (
                              <span className="inline-flex items-center gap-1 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/14 px-2 py-0.5 font-mono text-[12px] text-[#a8c5ff]">
                                <IconQuarantine className="h-3 w-3" />
                                quarantine
                              </span>
                            )}
                          </span>

                          <span className="flex shrink-0 items-center gap-2 font-mono text-[12.5px]">
                            {f.binary ? (
                              <span className="text-[#b6c3db]">binary</span>
                            ) : (
                              <>
                                <span className="text-[#5bdba2]">+{f.additions}</span>
                                <span className="text-[#f27c7c]">-{f.deletions}</span>
                              </>
                            )}
                          </span>
                        </button>

                        {!collapsed && <DiffFileBody f={f} />}
                      </div>
                    );
                  })
                )}

                {activePreview.public_diff_truncated && (
                  <div className="rounded-xl border border-white/[0.12] bg-white/[0.04] px-3.5 py-2 font-mono text-[12.5px] text-[#cbd5e8]">
                    Preview truncated — all {publishedPaths.length} manifest paths still publish.
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Deliberate, High-Trust Commit Ceremony Footer */}
      {!isSelfTarget && (
        <div className="relative z-10 shrink-0 border-t border-white/[0.1] bg-[#0b0f1c] px-3.5 py-2.5 shadow-[0_-8px_20px_rgba(0,0,0,0.35)]">
          <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:gap-3">
            {/* Squash Commit Title Editor + Live Hygiene Indicator */}
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex items-center gap-2">
                <input
                  value={summaryMsg}
                  onChange={(e) => onSummaryMsgChange(e.target.value)}
                  aria-label="Public squash commit title"
                  placeholder={
                    activePreview?.clean_commit_message?.split("\n")[0] ||
                    `Squash commit title for ${target}…`
                  }
                  className="pr-well min-w-0 flex-1 rounded-xl px-3 py-1.5 font-mono text-[13.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:border-[#9ec0f5]/50 focus:outline-none"
                />
              </div>

              <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12.5px]">
                {hygieneWarnings.length === 0 ? (
                  <span className="inline-flex items-center gap-1 text-[#5bdba2]/90">
                    <IconShieldCheck className="h-3.5 w-3.5" />
                    <span>Message hygiene clear · trailer appended by server</span>
                  </span>
                ) : (
                  <span className="inline-flex flex-wrap items-center gap-1.5 text-[#a8c5ff]">
                    <IconQuarantine className="h-3.5 w-3.5" />
                    <span>
                      {plural(hygieneWarnings.length, "hygiene warning")}:{" "}
                      {hygieneWarnings
                        .slice(0, 4)
                        .map((w) => w.token)
                        .join(", ")}
                      {hygieneWarnings.length > 4 ? ` (+${hygieneWarnings.length - 4})` : ""}
                    </span>
                  </span>
                )}
              </div>

              {/* Explicit warning acknowledgement, inline with the title instead of its own row. */}
              {hasWarnings && (canPublish || (firewallBlocked && canOwnerOverride)) && (
                <label className="flex cursor-pointer items-start gap-2 text-[13px] text-[#cfe0ff]">
                  <input
                    type="checkbox"
                    checked={warningsAcked}
                    onChange={(e) => setWarningsAcked(e.target.checked)}
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-[#9ec0f5]"
                  />
                  <span className="leading-snug">
                    Verified public diff and message disclose nothing restricted.
                  </span>
                </label>
              )}
            </div>

            {/* Land CTA / Two-Step Inline Confirmation */}
            <div className="flex shrink-0 flex-col items-stretch gap-1.5 sm:items-end lg:min-w-[20rem]">
              {!confirmingLand ? (
                <button
                  type="button"
                  disabled={!canExecuteLand}
                  title={
                    publishBlocked ||
                    (hasWarnings && !warningsAcked
                      ? "Acknowledge the warnings before landing"
                      : undefined)
                  }
                  onClick={() => setConfirmingLand(true)}
                  className="pr-action-btn inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-[14px] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <IconPlay className="h-4 w-4" />
                  <span>
                    {publishing ? `Publishing to ${target}…` : `Scrub & Publish to ${target}`}
                  </span>
                </button>
              ) : (
                <div
                  role="group"
                  aria-label="Confirm publish"
                  className="flex flex-wrap items-center justify-end gap-2 rounded-xl border border-[#5bdba2]/40 bg-[#0e2320] px-3 py-1.5"
                >
                  <span className="font-mono text-[13px] text-[#e6fff4]">
                    Publish 1 clean commit to <strong>{target}</strong>?
                  </span>
                  <button
                    type="button"
                    autoFocus
                    onClick={() => setConfirmingLand(false)}
                    className={`${SECONDARY_BTN} px-2.5! py-1! text-[13px]!`}
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    disabled={!canExecuteLand}
                    onClick={() => {
                      setConfirmingLand(false);
                      onExecutePublish();
                    }}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-[#5bdba2]/50 bg-[#5bdba2] px-3 py-1 text-[13px] font-semibold text-[#061014] transition hover:brightness-105 disabled:opacity-45"
                  >
                    <IconShieldCheck className="h-3.5 w-3.5" />
                    <span>Confirm &amp; Publish</span>
                  </button>
                </div>
              )}

              <div className="flex min-h-4 flex-wrap items-center justify-end gap-x-2 gap-y-1">
                {publishBlocked ? (
                  <span
                    className={`font-mono text-[12.5px] ${
                      publishBlock?.danger ? "text-[#f27c7c]" : "text-[#b6c3db]"
                    }`}
                  >
                    {publishBlocked}
                  </span>
                ) : (
                  hasWarnings &&
                  !warningsAcked &&
                  canPublish && (
                    <span className="font-mono text-[12.5px] text-[#a8c5ff]">
                      Acknowledge the warnings to enable landing
                    </span>
                  )
                )}
                {firewallBlocked && canOwnerOverride && (
                  <button
                    type="button"
                    onClick={onOpenOverride}
                    className={`${SECONDARY_BTN} px-2.5! py-1! text-[12.5px]!`}
                  >
                    Override…
                  </button>
                )}
              </div>
            </div>
          </div>

        </div>
      )}
        </>
      )}
    </section>
  );
}
