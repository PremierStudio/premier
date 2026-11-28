import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent,
  type ReactNode,
} from "react";
import type {
  GitCommitSummary,
  IdentityPreset,
  RepoFileResponse,
  RepoTreeEntry,
} from "../api";
import { plural } from "../lib/format";
import {
  CAP_ORDER,
  clampSplitPct,
  computeCapabilityDiff,
  ghostLineWidths,
  splitLineSecretRefs,
  type LineSegment,
  type SecretRefInfo,
} from "../lib/glassWall";
import { CodeLinesSkeleton } from "./ViewSkeletons";
import { detectLanguage, tokenClassName, tokenizeLine, type SourceLanguage } from "../lib/highlight";
import {
  IconClose,
  IconEye,
  IconFileNode,
  IconFolderNode,
  IconGripVertical,
  IconLock,
  IconPanel,
  IconShield,
  IconSplitLens,
} from "./Icons";

const CAP_SHORT: Record<string, string> = {
  traverse: "T",
  list: "L",
  read: "R",
  write: "W",
  use: "U",
};

const NO_SECRETS: SecretRefInfo[] = [];

type MirrorMode = "curtain" | "side-by-side";
type PlaceholderSegment = Extract<LineSegment, { kind: "cap_placeholder" }>;

/* ── Capability pills & diff tooltip ─────────────────────────────────── */

function CapPills({
  caps,
  revoked = [],
  granted = [],
}: {
  caps: readonly string[];
  revoked?: readonly string[];
  granted?: readonly string[];
}) {
  return (
    <span className="inline-flex items-center gap-1">
      {CAP_ORDER.map((cap) => {
        const on = caps.includes(cap);
        const lost = revoked.includes(cap);
        const gained = granted.includes(cap);
        const tone = lost
          ? "border-dashed border-[#f27c7c]/55 bg-[#f27c7c]/10 text-[#f27c7c] line-through"
          : gained
            ? "border-[#9ec0f5]/45 bg-[#7f95f8]/15 text-[#a8c5ff]"
            : on
              ? "border-[#9ec0f5]/30 bg-[#7f95f8]/15 text-[#c9d6ff]"
              : "border-white/[0.06] text-[#a6b5cf]";
        const state = lost ? "revoked" : gained ? "granted" : on ? "held" : "none";
        return (
          <span
            key={cap}
            title={`${cap}: ${state}`}
            className={`inline-flex h-[18px] w-[18px] items-center justify-center rounded-md border font-mono text-[12px] font-semibold ${tone}`}
          >
            {CAP_SHORT[cap]}
          </span>
        );
      })}
    </span>
  );
}

export interface CapabilityDiffTooltipProps {
  path: string;
  ownerEntry: RepoTreeEntry | null | undefined;
  targetEntry: RepoTreeEntry | null | undefined;
  ownerLabel?: string;
  targetLabel?: string;
  className?: string;
}

/** Owner-vs-target T/L/R/W/U bitmask rows plus the winning `.access.toml` rule traces. */
export function CapabilityDiffTooltip({
  path,
  ownerEntry,
  targetEntry,
  ownerLabel = "Your reality",
  targetLabel = "Their reality",
  className = "",
}: CapabilityDiffTooltipProps) {
  const diff = computeCapabilityDiff(ownerEntry, targetEntry);
  const human = targetEntry?.human_effective;
  const agent = targetEntry?.agent_effective;
  const clipped = agent && human ? human.filter((c) => !agent.includes(c)) : [];

  return (
    <div
      className={`pr-well w-full rounded-xl p-3 text-left text-[13px] text-[#d2dbee] ${className}`}
    >
      <div className="flex items-center gap-2 text-[#e6ecf8]">
        <IconShield className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
        <span className="font-semibold">Capability diff</span>
        {diff.hasServerOverride && (
          <span className="ml-auto rounded-md border border-[#f27c7c]/50 bg-[#f27c7c]/12 px-1.5 py-px text-[12px] font-bold uppercase tracking-wider text-[#f27c7c]">
            Server override
          </span>
        )}
      </div>
      <div className="mt-1 truncate font-mono text-[12.5px] text-[#a6b5cf]" title={path}>
        {path || "/"}
      </div>

      <dl className="mt-2.5 grid grid-cols-[auto_1fr] items-center gap-x-3 gap-y-1.5">
        <dt className="text-[#a6b5cf]">{ownerLabel}</dt>
        <dd>
          <CapPills caps={diff.ownerCaps} />
        </dd>
        <dt className="text-[#a6b5cf]">{targetLabel}</dt>
        <dd className="flex flex-wrap items-center gap-2">
          <CapPills caps={diff.targetCaps} revoked={diff.revoked} granted={diff.granted} />
          {diff.identical && <span className="text-[#5bdba2]">Identical</span>}
        </dd>
        {agent && (
          <>
            <dt className="font-mono text-[#a6b5cf]">H ∩ A</dt>
            <dd className="flex flex-wrap items-center gap-2">
              <CapPills caps={targetEntry?.effective ?? []} revoked={clipped} />
              <span className={clipped.length > 0 ? "text-[#9ec0f5]" : "text-[#a6b5cf]"}>
                {clipped.length > 0
                  ? `agent profile clips ${clipped.map((c) => CAP_SHORT[c] ?? c).join(" ")}`
                  : "agent profile clips nothing"}
              </span>
            </dd>
          </>
        )}
      </dl>

      {diff.revoked.length > 0 && (
        <p className="mt-2 text-[#f27c7c]">
          Revoked: {diff.revoked.map((c) => CAP_SHORT[c] ?? c).join(" ")}
        </p>
      )}
      {targetEntry?.synthesized_traverse && (
        <p className="mt-1.5 text-[#cbd5e8]">
          Traverse is synthesized: it only lets them walk through to a deeper allowed path and
          never reveals this name or its contents.
        </p>
      )}

      <div className="mt-2.5 space-y-1.5 border-t border-white/[0.06] pt-2">
        {diff.winningRules.length === 0 ? (
          <p className="text-[#a6b5cf]">No rule trace attached (rule traces are owner-only).</p>
        ) : (
          diff.winningRules.map((rule) => (
            <div
              key={`${rule.layer}:${rule.effect}:${rule.id}`}
              className="rounded-lg border border-white/[0.06] bg-black/20 px-2 py-1.5"
            >
              <div className="flex flex-wrap items-center gap-1.5">
                {rule.layer === "server" && (
                  <span className="rounded-md border border-[#f27c7c]/50 bg-[#f27c7c]/12 px-1.5 py-px text-[12px] font-bold uppercase tracking-wider text-[#f27c7c]">
                    Server override
                  </span>
                )}
                <span
                  className={`rounded-md px-1.5 py-px text-[12px] font-semibold uppercase tracking-wider ${
                    rule.effect === "deny"
                      ? "bg-[#f27c7c]/12 text-[#f27c7c]"
                      : "bg-[#5bdba2]/12 text-[#5bdba2]"
                  }`}
                >
                  {rule.layer} {rule.effect}
                </span>
                <span className="min-w-0 truncate font-mono text-[12.5px] text-[#e6ecf8]">
                  {rule.id}
                </span>
              </div>
              <div className="mt-1 font-mono text-[12.5px] text-[#a6b5cf]">
                {rule.capabilities.join(", ")}
              </div>
              {rule.reason && <div className="mt-0.5 text-[#b6c3db]">{rule.reason}</div>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

/* ── Source rendering ────────────────────────────────────────────────── */

function CapPlaceholderPill({ seg }: { seg: PlaceholderSegment }) {
  const mode = seg.approval === "jit" ? "Just-in-time approval for each use." : "Auto-approved use.";
  const title = `use ≠ read. The value never reaches this process; it is injected host-side at the egress proxy. ${
    seg.canUse ? mode : "Denied: this reality cannot use it."
  }`;
  return (
    <span
      className={`pr-cap-shimmer font-mono ${seg.canUse ? "" : "border-[#f27c7c]/45! text-[#f6a5a5]!"}`}
      title={title}
    >
      {seg.placeholder}
      {!seg.canUse && (
        <span className="rounded bg-[#f27c7c]/15 px-1 text-[12px] font-bold uppercase tracking-wide text-[#f27c7c]">
          denied
        </span>
      )}
      {seg.canUse && seg.approval === "jit" && (
        <span className="rounded bg-[#7f95f8]/15 px-1 text-[12px] font-bold uppercase tracking-wide text-[#a8c5ff]">
          jit
        </span>
      )}
    </span>
  );
}

function renderSegments(segs: LineSegment[], lang: SourceLanguage): ReactNode {
  return segs.map((seg, si) =>
    seg.kind === "cap_placeholder" ? (
      <CapPlaceholderPill key={si} seg={seg} />
    ) : (
      tokenizeLine(seg.text, lang).map((tok, ti) => (
        <span key={`${si}-${ti}`} className={tokenClassName(tok.kind)}>
          {tok.text}
        </span>
      ))
    ),
  );
}

function CodeLines({
  path,
  content,
  truncated,
  secrets,
  nonOwner,
  wrap,
}: {
  path: string;
  content: string;
  truncated: boolean;
  secrets: SecretRefInfo[];
  nonOwner: boolean;
  wrap: boolean;
}) {
  const rows = useMemo(() => {
    const lang = detectLanguage(path);
    const lines = content.split("\n");
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
    return lines.map((line, i) => (
      <div key={i} className="flex">
        <span className="w-10 shrink-0 select-none pr-3 text-right text-[#6b7b98]">{i + 1}</span>
        <span className={`min-w-0 ${wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"}`}>
          {renderSegments(splitLineSecretRefs(line, secrets, nonOwner), lang)}
        </span>
      </div>
    ));
  }, [path, content, secrets, nonOwner, wrap]);

  return (
    <div className="px-2 py-3 font-mono text-[13.5px] leading-[1.65]">
      {rows}
      {truncated && (
        <div className="mt-2 pl-10 text-[12.5px] text-[#a8c5ff]">
          Truncated by the server: only the first part of this file is shown.
        </div>
      )}
    </div>
  );
}

function DirPanel({ entry, path }: { entry: RepoTreeEntry | null; path: string }) {
  return (
    <div className="flex flex-col items-center gap-3 px-6 py-10 text-center">
      <IconFolderNode
        className="h-9 w-9 text-[#9ec0f5]"
        traverseOnly={entry?.visibility_state === "traverse_only"}
      />
      <div className="max-w-full truncate font-mono text-[13.5px] text-[#e6ecf8]">{path || "/"}</div>
      <CapPills caps={entry?.effective ?? []} />
      <p className="text-[13px] text-[#a6b5cf]">Directory · capabilities in this reality</p>
    </div>
  );
}

/* ── Restricted glass ────────────────────────────────────────────────── */

type Reality =
  | { kind: "loading" }
  | { kind: "restricted"; why: "omitted" | "traverse_only" | "denied" | "absent"; reason: string }
  | { kind: "dir" }
  | { kind: "file"; content: string; truncated: boolean }
  | { kind: "empty" };

function resolveReality(
  side: "owner" | "target",
  entry: RepoTreeEntry | null,
  file: RepoFileResponse | null,
  loading: boolean,
): Reality {
  if (loading) return { kind: "loading" };
  const state = entry?.visibility_state;
  if (state === "omitted") {
    return {
      kind: "restricted",
      why: "omitted",
      reason: file?.reason || "Omitted: this path does not exist in this reality.",
    };
  }
  if (state === "traverse_only") {
    return {
      kind: "restricted",
      why: "traverse_only",
      reason:
        file?.reason || "Traverse-only: they can walk through this path but not list or read it.",
    };
  }
  if (file && !file.allowed) {
    return {
      kind: "restricted",
      why: "denied",
      reason: file.reason || "Read denied by policy.",
    };
  }
  if (file?.allowed && file.content !== undefined) {
    return { kind: "file", content: file.content, truncated: file.truncated };
  }
  if (entry?.kind === "dir") return { kind: "dir" };
  if (!entry && !file && side === "target") {
    return { kind: "restricted", why: "absent", reason: "This path does not appear in their reality." };
  }
  return { kind: "empty" };
}

function RestrictedGlass({
  reality,
  path,
  ownerEntry,
  targetEntry,
  ownerLabel,
  targetLabel,
  padLeftPct = 0,
  onAuthor,
}: {
  reality: Extract<Reality, { kind: "restricted" }>;
  path: string;
  ownerEntry: RepoTreeEntry | null;
  targetEntry: RepoTreeEntry | null;
  ownerLabel: string;
  targetLabel: string;
  /** Curtain mode: shifts the card into the visible (right) part of the clipped layer. */
  padLeftPct?: number;
  onAuthor?: () => void;
}) {
  return (
    <div
      className="pr-glass-frost relative flex min-h-full flex-col"
      role="status"
      aria-label="Restricted in their reality"
    >
      {/* Ghost outlines are index-derived; the restricted file's content never reaches here. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-y-0 right-0 space-y-2.5 overflow-hidden p-5 opacity-70"
        style={{ left: `${padLeftPct}%` }}
      >
        {ghostLineWidths(18).map((w, i) => (
          <div
            key={i}
            className="pr-ghost-bar"
            style={{ width: `${w}%`, marginLeft: `${[0, 4, 8, 4, 0][i % 5]}%` }}
          />
        ))}
      </div>
      <div
        className="relative flex flex-1 justify-center p-5"
        style={{ paddingLeft: `calc(${padLeftPct}% + 1.25rem)` }}
      >
        <div className="pr-elevated sticky top-4 h-fit w-full max-w-[24rem] rounded-2xl bg-[#0b0f1c]/97 p-4">
          <div className="flex items-center gap-2.5">
            <IconLock className="h-5 w-5 shrink-0 text-[#f27c7c]" />
            <div className="min-w-0">
              <div className="text-[14px] font-semibold text-[#f3f6fd]">Hidden from this viewer</div>
              <div className="truncate text-[12.5px] text-[#a6b5cf]">
                {targetLabel} cannot read this path · 0 bytes sent on clone or GitHub sync
              </div>
            </div>
          </div>
          {(
            <>
              <p className="mt-3 rounded-lg border border-[#f27c7c]/25 bg-[#f27c7c]/10 px-2.5 py-2 text-[13px] text-[#f6b3b3]">
                {reality.reason}
              </p>
              <CapabilityDiffTooltip
                className="mt-3"
                path={path}
                ownerEntry={ownerEntry}
                targetEntry={targetEntry}
                ownerLabel={ownerLabel}
                targetLabel={targetLabel}
              />
              {onAuthor && (
                <button
                  type="button"
                  onClick={onAuthor}
                  className="pr-action-btn mt-3 inline-flex w-full items-center justify-center gap-2 rounded-xl px-3 py-2 text-[13.5px]"
                >
                  <IconShield className="h-4 w-4" />
                  Edit Access Rule…
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── GlassWallMirror ─────────────────────────────────────────────────── */

export interface GlassWallMirrorProps {
  ownerIdentity: IdentityPreset;
  targetIdentity: IdentityPreset;
  targetPresets: IdentityPreset[];
  onChangeTarget: (preset: IdentityPreset) => void;
  mode: MirrorMode;
  onChangeMode: (mode: MirrorMode) => void;
  peeking?: boolean;
  selectedPath: string;
  ownerEntry: RepoTreeEntry | null;
  targetEntry: RepoTreeEntry | null;
  ownerFile: RepoFileResponse | null;
  targetFile: RepoFileResponse | null;
  ownerCommit: GitCommitSummary | null;
  targetCommit: GitCommitSummary | null;
  targetTreeStats?: { visible: number; traverseOnly: number; omitted: number };
  loadingTarget?: boolean;
  /** Owner file still resolving: left pane shows a skeleton, not a false empty state. */
  loadingOwner?: boolean;
  softWrap?: boolean;
  secretRefs?: SecretRefInfo[];
  onOpenPolicyComposer?: (target: { kind: "file" | "dir"; path: string }) => void;
  onCloseMirror: () => void;
}

function EyeChip({
  side,
  label,
  commit,
  emptyCommit = "no commit",
}: {
  side: "left" | "right";
  label: string;
  /** undefined hides the commit; null shows `emptyCommit`. */
  commit?: GitCommitSummary | null;
  emptyCommit?: string;
}) {
  return (
    <span
      className={`pr-elevated inline-flex max-w-full items-center gap-1.5 rounded-full bg-[#0b0f1c]/97 px-2 py-0.5 text-[12.5px] ${
        side === "right" ? "text-[#c9ecef]" : "text-[#e6ecf8]"
      }`}
    >
      <IconEye className={`h-3 w-3 shrink-0 ${side === "left" ? "text-[#9ec0f5]" : "text-[#67d6dc]"}`} />
      <span className="truncate">{label}</span>
      {commit !== undefined && (
        <>
          <span className="text-white/20">·</span>
          {commit ? (
            <>
              <span className="shrink-0 font-mono text-[#9ec0f5]">{commit.short_oid}</span>
              <span
                className="hidden min-w-0 max-w-[16rem] truncate text-[#b6c3db] sm:inline"
                title={commit.subject}
              >
                {commit.subject}
              </span>
              <span className="hidden shrink-0 text-[#a6b5cf] lg:inline">
                {plural(commit.files_changed, "file")}
              </span>
            </>
          ) : (
            <span className="italic text-[#a6b5cf]">{emptyCommit}</span>
          )}
        </>
      )}
    </span>
  );
}

export function GlassWallMirror({
  ownerIdentity,
  targetIdentity,
  targetPresets,
  onChangeTarget,
  mode,
  onChangeMode,
  peeking = false,
  selectedPath,
  ownerEntry,
  targetEntry,
  ownerFile,
  targetFile,
  ownerCommit,
  targetCommit,
  targetTreeStats,
  loadingTarget = false,
  loadingOwner = false,
  softWrap = false,
  secretRefs = NO_SECRETS,
  onOpenPolicyComposer,
  onCloseMirror,
}: GlassWallMirrorProps) {
  const [splitPct, setSplitPct] = useState(50);
  const [dragging, setDragging] = useState(false);
  const [syncScroll, setSyncScroll] = useState(true);
  const [showDiff, setShowDiff] = useState(false);

  const canvasRef = useRef<HTMLDivElement>(null);
  const diffWrapRef = useRef<HTMLDivElement>(null);
  const ownerPaneRef = useRef<HTMLDivElement>(null);
  const targetPaneRef = useRef<HTMLDivElement>(null);
  const activePane = useRef<"owner" | "target" | null>(null);
  const raf = useRef(0);
  useEffect(() => () => cancelAnimationFrame(raf.current), []);

  // Δ caps popover: dismiss on outside press or Escape.
  useEffect(() => {
    if (!showDiff) return;
    const onDown = (e: MouseEvent) => {
      if (!diffWrapRef.current?.contains(e.target as Node)) setShowDiff(false);
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") setShowDiff(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [showDiff]);

  const ownerLabel = `Your reality · ${ownerIdentity.label}`;
  const targetLabel = targetIdentity.label;
  const nonOwnerTarget =
    targetIdentity.principal !== ownerIdentity.principal || !!targetIdentity.agentProfile;
  const pathKind: "file" | "dir" = (targetEntry ?? ownerEntry)?.kind ?? "file";

  const ownerReality = resolveReality("owner", ownerEntry, ownerFile, loadingOwner && !ownerFile);
  const targetReality = resolveReality("target", targetEntry, targetFile, loadingTarget);
  const targetGlassed = targetReality.kind === "restricted";

  const presets = targetPresets.some((p) => p.id === targetIdentity.id)
    ? targetPresets
    : [targetIdentity, ...targetPresets];
  const agentPresets = presets.filter((p) => p.agentProfile);
  const humanPresets = presets.filter((p) => !p.agentProfile);

  const authorRule = onOpenPolicyComposer
    ? () => onOpenPolicyComposer({ kind: pathKind, path: selectedPath })
    : undefined;

  /* Glass Wall divider */
  const setFromClientX = (clientX: number) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect || rect.width <= 0) return;
    setSplitPct(clampSplitPct(((clientX - rect.left) / rect.width) * 100));
  };
  const onDividerPointerDown = (e: PointerEvent<HTMLDivElement>) => {
    e.currentTarget.setPointerCapture(e.pointerId);
    e.currentTarget.focus();
    setDragging(true);
  };
  const onDividerPointerMove = (e: PointerEvent<HTMLDivElement>) => {
    if (dragging) setFromClientX(e.clientX);
  };
  const onDividerPointerUp = (e: PointerEvent<HTMLDivElement>) => {
    if (e.currentTarget.hasPointerCapture(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
    setDragging(false);
  };
  const onDividerKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const step = e.shiftKey ? 1 : 5;
    let next: number | null = null;
    if (e.key === "ArrowLeft") next = splitPct - step;
    else if (e.key === "ArrowRight") next = splitPct + step;
    else if (e.key === "Home") next = 12;
    else if (e.key === "End") next = 88;
    else if (e.key === "Enter") next = 50;
    if (next === null) return;
    e.preventDefault();
    setSplitPct(clampSplitPct(next));
  };

  /* Side-by-side bidirectional scroll sync; the active-pane guard breaks the echo loop. */
  const onPaneScroll = (src: "owner" | "target") => {
    if (!syncScroll) return;
    if (activePane.current && activePane.current !== src) return;
    const from = (src === "owner" ? ownerPaneRef : targetPaneRef).current;
    const to = (src === "owner" ? targetPaneRef : ownerPaneRef).current;
    if (!from || !to) return;
    activePane.current = src;
    to.scrollTop = from.scrollTop;
    to.scrollLeft = from.scrollLeft;
    cancelAnimationFrame(raf.current);
    raf.current = requestAnimationFrame(() => {
      raf.current = requestAnimationFrame(() => {
        activePane.current = null;
      });
    });
  };

  const renderReality = (
    reality: Reality,
    side: "owner" | "target",
    wrap: boolean,
    padLeftPct = 0,
  ): ReactNode => {
    if (reality.kind === "loading") {
      return (
        <div
          role="status"
          aria-label="Resolving reality"
          style={padLeftPct ? { paddingLeft: `${padLeftPct}%` } : undefined}
        >
          <CodeLinesSkeleton />
        </div>
      );
    }
    if (side === "target" && reality.kind === "restricted") {
      return (
        <RestrictedGlass
          reality={reality}
          path={selectedPath}
          ownerEntry={ownerEntry}
          targetEntry={targetEntry}
          ownerLabel="Your reality"
          targetLabel={targetLabel}
          padLeftPct={padLeftPct}
          onAuthor={authorRule}
        />
      );
    }
    switch (reality.kind) {
      case "file":
        return (
          <CodeLines
            path={selectedPath}
            content={reality.content}
            truncated={reality.truncated}
            secrets={secretRefs}
            nonOwner={side === "target" && nonOwnerTarget}
            wrap={wrap}
          />
        );
      case "dir":
        return <DirPanel entry={side === "owner" ? ownerEntry : targetEntry} path={selectedPath} />;
      case "restricted":
        return <p className="p-6 text-[13.5px] text-[#a8c5ff]">{reality.reason}</p>;
      default:
        return (
          <div className="flex flex-col items-center gap-2 p-10 text-center text-[13.5px] text-[#a6b5cf]">
            <IconFileNode className="h-6 w-6 text-[#a6b5cf]" />
            {selectedPath ? "No content loaded for this path." : "Select a path to compare realities."}
          </div>
        );
    }
  };

  const modeBtn = (value: MirrorMode, label: string, icon: ReactNode) => (
    <button
      type="button"
      aria-pressed={mode === value}
      onClick={() => onChangeMode(value)}
      className={`inline-flex h-6 items-center gap-1 rounded-full px-2.5 text-[12.5px] transition ${
        mode === value ? "pr-pill-active" : "text-[#b6c3db] hover:text-[#f3f6fd]"
      }`}
    >
      {icon}
      {label}
    </button>
  );

  return (
    <section
      aria-label="Visibility Compare"
      title="Left: what you see · Right: what this viewer clones"
      className="flex h-full min-h-0 flex-col gap-1.5 p-2">
      {/* One strict single-row control row: identity picker, tree stats, mode, actions */}
      <div className="flex min-w-0 shrink-0 flex-nowrap items-center gap-1.5">
        <label className="inline-flex h-7 min-w-0 shrink items-center gap-1.5 rounded-full border border-white/[0.1] bg-[#0b0f1c] pl-2 pr-0.5 text-[12.5px] text-[#c9ecef]">
          <IconEye className="h-3 w-3 shrink-0 text-[#67d6dc]" />
          <select
            aria-label="Their reality: identity to compare"
            value={targetIdentity.id}
            onChange={(e) => {
              const preset = presets.find((p) => p.id === e.target.value);
              if (preset) onChangeTarget(preset);
            }}
            className="h-6 min-w-0 max-w-[9rem] truncate rounded-full border border-white/[0.08] bg-[#0b0f1c] px-2 text-[13px] text-[#f3f6fd] [color-scheme:dark] focus:outline-none"
          >
            {humanPresets.length > 0 && (
              <optgroup label="Humans">
                {humanPresets.map((p) => (
                  <option key={p.id} value={p.id} className="bg-[#0b0f1c] text-[#f3f6fd]">
                    {p.label}
                  </option>
                ))}
              </optgroup>
            )}
            {agentPresets.length > 0 && (
              <optgroup label="Agents">
                {agentPresets.map((p) => (
                  <option key={p.id} value={p.id} className="bg-[#0b0f1c] text-[#f3f6fd]">
                    {p.label}
                  </option>
                ))}
              </optgroup>
            )}
          </select>
        </label>
        {targetTreeStats && (
          <span
            className="hidden h-7 shrink-0 items-center gap-1.5 rounded-full border border-white/[0.08] bg-[#0b0f1c] px-2 text-[12.5px] @2xl:inline-flex"
            title="Owner-only: how much of the tree this identity cannot fully see"
          >
            <span className={targetTreeStats.omitted > 0 ? "text-[#f27c7c]" : "text-[#a6b5cf]"}>
              {targetTreeStats.omitted} omitted
            </span>
            <span className="text-[#a6b5cf]">{targetTreeStats.traverseOnly} trav</span>
            <span className="text-[#5bdba2]">{targetTreeStats.visible} visible</span>
          </span>
        )}
        <div
          className="inline-flex h-7 shrink-0 items-center rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5"
          role="group"
          aria-label="Compare layout"
        >
          {modeBtn("curtain", "Slider", <IconSplitLens className="h-3 w-3" />)}
          {modeBtn("side-by-side", "Side by side", <IconPanel className="h-3 w-3" />)}
        </div>
        {mode === "side-by-side" && (
          <button
            type="button"
            aria-pressed={syncScroll}
            onClick={() => setSyncScroll((v) => !v)}
            className={`inline-flex h-7 shrink-0 items-center rounded-full px-2.5 text-[12.5px] ${
              syncScroll ? "pr-pill-active" : "pr-pill text-[#d2dbee]"
            }`}
          >
            Sync Scroll
          </button>
        )}
        <div className="ml-auto flex shrink-0 items-center gap-1.5">
          <div ref={diffWrapRef} className="relative">
            <button
              type="button"
              aria-expanded={showDiff}
              onClick={() => setShowDiff((v) => !v)}
              title="What changes for this viewer on this path"
              className={`inline-flex h-7 items-center gap-1 rounded-full px-2.5 text-[12.5px] ${
                showDiff ? "pr-pill-active" : "pr-pill text-[#d2dbee]"
              }`}
            >
              <IconShield className="h-3 w-3" />
              Δ caps
            </button>
            {showDiff && (
              <div className="pr-elevated absolute right-0 top-full z-30 mt-1.5 max-h-[min(60vh,30rem)] w-[22rem] max-w-[calc(100vw-2rem)] overflow-y-auto rounded-xl bg-[#0b0f1c]/97 p-1.5">
                <CapabilityDiffTooltip
                  path={selectedPath}
                  ownerEntry={ownerEntry}
                  targetEntry={targetEntry}
                  targetLabel={targetLabel}
                />
              </div>
            )}
          </div>
          {authorRule && (
            <button
              type="button"
              onClick={authorRule}
              title="Edit the access rule for this path"
              aria-label="Edit access rule"
              className="pr-pill inline-flex h-7 items-center gap-1 rounded-full px-2.5 text-[12.5px] text-[#e6ecf8]"
            >
              <IconShield className="h-3 w-3 text-[#9ec0f5]" />
              <span className="hidden @2xl:inline @4xl:hidden">Edit Rule</span>
              <span className="hidden @4xl:inline">Edit Access Rule</span>
            </button>
          )}
          {peeking ? (
            <span className="pr-pill-active inline-flex h-7 items-center gap-1 rounded-full px-2.5 text-[12.5px]">
              Alt · Quick Peek
            </span>
          ) : (
            <button
              type="button"
              onClick={onCloseMirror}
              className="pr-pill inline-flex h-7 items-center gap-1 rounded-full px-2.5 text-[12.5px] text-[#e6ecf8]"
            >
              <IconClose className="h-3 w-3" />
              Exit
            </button>
          )}
        </div>
      </div>

      {/* Always reserved so toggling or switching files never shifts layout. */}
      <div
        aria-hidden="true"
        className={`h-0.5 shrink-0 rounded-full ${
          loadingTarget || loadingOwner ? "pr-shimmer" : "bg-transparent"
        }`}
      />

      {mode === "curtain" ? (
        <div className="relative min-h-[320px] flex-1">
          <div
            className="pr-well absolute inset-0 overflow-auto rounded-xl"
            aria-busy={loadingTarget}
          >
            {/* Curtain always wraps: a percent divider needs a fixed-width shared canvas. */}
            <div
              ref={canvasRef}
              className={`relative grid min-h-full ${dragging ? "select-none" : ""}`}
            >
              <div
                className="min-w-0"
                style={{
                  gridArea: "1 / 1",
                  clipPath: `inset(0 ${100 - splitPct}% 0 0)`,
                }}
              >
                <div className="sticky top-0 z-10 flex h-0 overflow-visible p-1.5">
                  <EyeChip side="left" label={ownerLabel} commit={ownerCommit} emptyCommit="no commit" />
                </div>
                <div className="pt-8">{renderReality(ownerReality, "owner", true)}</div>
              </div>
              <div
                className="min-w-0"
                style={{
                  gridArea: "1 / 1",
                  clipPath: `inset(0 0 0 ${splitPct}%)`,
                }}
              >
                <div className="sticky top-0 z-10 flex h-0 justify-end overflow-visible p-1.5">
                  <EyeChip
                    side="right"
                    label={`Their reality · ${targetLabel}`}
                    commit={targetCommit}
                    emptyCommit="no visible commits"
                  />
                </div>
                <div className={targetGlassed ? "" : "pt-8"}>
                  {renderReality(targetReality, "target", true, splitPct)}
                </div>
              </div>
              <div
                role="separator"
                tabIndex={0}
                aria-orientation="vertical"
                aria-valuemin={12}
                aria-valuemax={88}
                aria-valuenow={Math.round(splitPct)}
                aria-label="Slider position"
                title="Drag, or use arrow keys. Double-click to reset."
                onPointerDown={onDividerPointerDown}
                onPointerMove={onDividerPointerMove}
                onPointerUp={onDividerPointerUp}
                onPointerCancel={onDividerPointerUp}
                onDoubleClick={() => setSplitPct(50)}
                onKeyDown={onDividerKeyDown}
                className="absolute inset-y-0 z-20 -ml-3 flex w-6 cursor-col-resize touch-none select-none items-start justify-center focus-visible:bg-[#7f95f8]/10 focus-visible:outline-2 focus-visible:outline-[#9ec0f5]/60"
                style={{ left: `${splitPct}%` }}
              >
                <div
                  className={`pr-glass-beam pointer-events-none absolute inset-y-0 left-1/2 -translate-x-1/2 transition-[filter,opacity] ${
                    dragging ? "opacity-100 brightness-150 saturate-150" : ""
                  }`}
                />
                <div className="pr-elevated sticky top-[calc(50%-18px)] flex h-9 w-6 bg-[#0b0f1c]/97 items-center justify-center rounded-lg text-[#9ec0f5]">
                  <IconGripVertical className="h-4 w-4" />
                </div>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="grid min-h-[320px] flex-1 grid-cols-1 gap-1.5 @3xl:grid-cols-2">
          <div className="pr-well flex min-h-[260px] min-w-0 flex-col overflow-hidden rounded-xl">
            <div className="px-1.5 pb-1 pt-1.5">
              <EyeChip side="left" label={ownerLabel} commit={ownerCommit} emptyCommit="no commit" />
            </div>
            <div
              ref={ownerPaneRef}
              onScroll={() => onPaneScroll("owner")}
              className="relative min-h-0 flex-1 overflow-auto"
            >
              {renderReality(ownerReality, "owner", softWrap)}
            </div>
          </div>
          <div className="pr-well flex min-h-[260px] min-w-0 flex-col overflow-hidden rounded-xl">
            <div className="px-1.5 pb-1 pt-1.5">
              <EyeChip
                side="right"
                label={`Their reality · ${targetLabel}`}
                commit={targetCommit}
                emptyCommit="no visible commits"
              />
            </div>
            <div
              ref={targetPaneRef}
              onScroll={() => onPaneScroll("target")}
              aria-busy={loadingTarget}
              className="relative min-h-0 flex-1 overflow-auto"
            >
              {renderReality(targetReality, "target", softWrap)}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
