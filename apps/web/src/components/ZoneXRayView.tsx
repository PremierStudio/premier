import {
  Fragment,
  lazy,
  memo,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { CodeLinesSkeleton, FileTreeSkeleton, SearchResultsSkeleton } from "./ViewSkeletons";
import { getTreeTruncationInfo } from "../lib/uiHelpers";
import {
  api,
  ApiError,
  errorText,
  capMaskToNames,
  newFilePathError,
  shortOid,
  type BlameLine,
  type Directory,
  type GitCommitSummary,
  type HygieneInsight,
  type IdentityPreset,
  type PolicyIntent,
  type PolicySummaryResponse,
  type RepoFileResponse,
  type RepoSearchResponse,
  type RepoTreeEntry,
  type RepoTreeResponse,
  type WriteRepoFileResponse,
} from "../api";
import {
  detectLanguage,
  formatByteSize,
  languageLabel,
  tokenClassName,
  tokenizeLine,
  type SourceLanguage,
} from "../lib/highlight";
import { formatShortcutLabel, hasPrimaryModifier, isEditableEventTarget, useClientOS } from "../lib/platform";
import {
  monacoLanguageForPath,
  PREMIER_ACCESS_TOML_LANGUAGE,
  validateAccessToml,
} from "../lib/monaco";
import { computeCapabilityDiff, type SecretRefInfo } from "../lib/glassWall";
import { matchingZonesForPath } from "../lib/policyIntent";
import { ConfirmButton, ErrorNote, OwnerOnly } from "./forms";
import { CapabilityDiffTooltip, GlassWallMirror } from "./GlassWallMirror";
import { AmbientWhisperChip } from "./HygieneDrawer";
import { MarkdownPreview } from "./MarkdownPreview";
import {
  PolicyContextMenu,
  PolicyIntentComposer,
  type ContextMenuTarget,
} from "./PolicyIntentComposer";
import { plural } from "../lib/format";
import {
  IconAmbientPulse,
  IconBlame,
  IconCheck,
  IconChevron,
  IconClose,
  IconCopy,
  IconEdit,
  IconFileNode,
  IconFold,
  IconFolderNode,
  IconFolderOpen,
  IconIntersection,
  IconLink,
  IconLock,
  IconMenu,
  IconPanel,
  IconPlus,
  IconQuarantine,
  IconSearch,
  IconShield,
  IconSplitLens,
  IconTrash,
  IconUnfold,
  IconWrap,
} from "./Icons";

// The Monaco wrapper is only fetched (and Monaco itself only loaded) once the user edits, creates a
// file or asks for Find; read-only viewing uses the lightweight SourceViewer below.
const MonacoCodeEditor = lazy(() =>
  import("./MonacoCodeEditor").then((m) => ({ default: m.MonacoCodeEditor })),
);
const preloadMonacoWrapper = () => {
  void import("./MonacoCodeEditor");
};

const MENU_ROW =
  "flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left font-mono text-[13px] text-[#cbd5e8] transition hover:bg-white/[0.06] hover:text-[#f3f6fd] disabled:cursor-not-allowed disabled:opacity-40";

function CodeSkeleton({ className = "" }: { className?: string }) {
  return <CodeLinesSkeleton className={className} />;
}

/** Collapses identical in-flight/just-finished requests (tree, file) across effects. */
const sharedRequests = new Map<string, Promise<unknown>>();
function shared<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const hit = sharedRequests.get(key);
  if (hit) return hit as Promise<T>;
  const promise = fn();
  sharedRequests.set(key, promise);
  const drop = () => sharedRequests.delete(key);
  promise.then(() => setTimeout(drop, 1500), drop);
  return promise;
}

const identityKey = (p: IdentityPreset) => `${p.id}|${p.principal}|${p.agentProfile ?? ""}`;

/* ── Lightweight read-only source viewer (no Monaco) ─────────────────── */

const SRC_CHUNK = 400;

interface SourceRowProps {
  n: number;
  text: string;
  lang: SourceLanguage;
  selected: boolean;
  flash: boolean;
  wrap: boolean;
  showBlame: boolean;
  blame?: BlameLine;
  blockStart: boolean;
  onGutter: (n: number, shift: boolean) => void;
}

const SourceRow = memo(function SourceRow({
  n,
  text,
  lang,
  selected,
  flash,
  wrap,
  showBlame,
  blame,
  blockStart,
  onGutter,
}: SourceRowProps) {
  const tokens = useMemo(() => tokenizeLine(text, lang), [text, lang]);
  return (
    <div
      data-line={n}
      className={`flex ${
        selected
          ? "bg-[#7f95f8]/[0.14] shadow-[inset_2px_0_0_rgba(158,192,245,0.9)]"
          : flash
            ? "bg-[#9ec0f5]/[0.22] shadow-[inset_2px_0_0_rgba(158,192,245,0.95)]"
            : "hover:bg-white/[0.02]"
      }`}
    >
      {showBlame && (
        <span
          className="w-40 shrink-0 select-none truncate pl-2 pr-2 text-[12.5px] text-[#8fa6cc]"
          title={
            blame
              ? `${shortOid(blame.oid)} · ${blame.author}${blame.date ? ` · ${blame.date}` : ""}${
                  blame.summary ? `\n${blame.summary}` : ""
                }`
              : undefined
          }
        >
          {blockStart && blame ? `${shortOid(blame.oid)} · ${blame.author}` : ""}
        </span>
      )}
      <button
        type="button"
        tabIndex={-1}
        aria-label={`Select line ${n}`}
        onClick={(e) => onGutter(n, e.shiftKey)}
        className="w-12 shrink-0 select-none pr-3 text-right text-[#6b7b98] hover:text-[#9ec0f5]"
      >
        {n}
      </button>
      <span className={`min-w-0 flex-1 pr-4 ${wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"}`}>
        {tokens.map((tok, i) => (
          <span key={i} className={tokenClassName(tok.kind)}>
            {tok.text}
          </span>
        ))}
      </span>
    </div>
  );
});

function SourceViewer({
  content,
  path,
  wrap,
  selectedLines,
  onSelectLines,
  scrollTarget,
  blame,
  ariaLabel,
}: {
  content: string;
  path: string;
  wrap: boolean;
  selectedLines: [number, number] | null;
  onSelectLines: (next: [number, number] | null) => void;
  scrollTarget: { line: number; nonce: number } | null;
  blame: Map<number, BlameLine> | null;
  ariaLabel: string;
}) {
  const lang = useMemo(() => detectLanguage(path), [path]);
  const lines = useMemo(() => {
    const l = content.split(/\r?\n/);
    if (l.length > 1 && l[l.length - 1] === "") l.pop();
    return l;
  }, [content]);
  // Rows render progressively so a large file paints immediately instead of tokenizing it all.
  const [limit, setLimit] = useState(SRC_CHUNK);
  const [flashLine, setFlashLine] = useState<number | null>(null);
  const scrollerRef = useRef<HTMLDivElement>(null);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const lastNonceRef = useRef<number | null>(null);
  const selectedRef = useRef(selectedLines);
  selectedRef.current = selectedLines;
  const onSelectRef = useRef(onSelectLines);
  onSelectRef.current = onSelectLines;

  const targetLine = scrollTarget ? Math.min(lines.length, Math.max(1, scrollTarget.line)) : null;

  useEffect(() => {
    if (targetLine && targetLine > limit) setLimit(targetLine + SRC_CHUNK);
  }, [targetLine, limit]);

  useEffect(() => {
    if (!scrollTarget || !targetLine || targetLine > limit) return;
    if (lastNonceRef.current === scrollTarget.nonce) return;
    lastNonceRef.current = scrollTarget.nonce;
    scrollerRef.current
      ?.querySelector(`[data-line="${targetLine}"]`)
      ?.scrollIntoView({ block: "center" });
    setFlashLine(targetLine);
    const t = window.setTimeout(() => setFlashLine(null), 1200);
    return () => window.clearTimeout(t);
  }, [scrollTarget, targetLine, limit]);

  useEffect(() => {
    const el = sentinelRef.current;
    const root = scrollerRef.current;
    if (!el || !root || limit >= lines.length) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setLimit((l) => Math.min(lines.length, l + SRC_CHUNK * 2));
        }
      },
      { root, rootMargin: "1200px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [limit, lines.length]);

  const onGutter = useCallback((n: number, shift: boolean) => {
    const prev = selectedRef.current;
    if (shift && prev) onSelectRef.current([Math.min(prev[0], n), Math.max(prev[0], n)]);
    else if (prev && prev[0] === n && prev[1] === n) onSelectRef.current(null);
    else onSelectRef.current([n, n]);
  }, []);

  const lo = selectedLines ? Math.min(selectedLines[0], selectedLines[1]) : 0;
  const hi = selectedLines ? Math.max(selectedLines[0], selectedLines[1]) : -1;
  const shown = Math.min(limit, lines.length);
  const rows = [];
  let prevOid: string | null = null;
  for (let i = 0; i < shown; i++) {
    const n = i + 1;
    const b = blame?.get(n);
    const blockStart = b ? prevOid !== b.oid : false;
    prevOid = b ? b.oid : null;
    rows.push(
      <SourceRow
        key={n}
        n={n}
        text={lines[i]}
        lang={lang}
        selected={n >= lo && n <= hi}
        flash={flashLine === n}
        wrap={wrap}
        showBlame={Boolean(blame && blame.size > 0)}
        blame={b}
        blockStart={blockStart}
        onGutter={onGutter}
      />,
    );
  }

  return (
    <div
      ref={scrollerRef}
      role="region"
      aria-label={ariaLabel}
      tabIndex={0}
      className="min-h-0 flex-1 overflow-auto bg-[#090d18] py-2 font-mono text-[14px] leading-5 focus:outline-none"
    >
      <div className={wrap ? "" : "w-max min-w-full"}>
        {rows}
        {shown < lines.length && <div ref={sentinelRef} aria-hidden="true" className="h-8" />}
      </div>
    </div>
  );
}

const CAP_LETTERS = [
  { key: "traverse", short: "T" },
  { key: "list", short: "L" },
  { key: "read", short: "R" },
  { key: "write", short: "W" },
  { key: "use", short: "U" },
] as const;

interface TreeNode {
  name: string;
  path: string;
  entry?: RepoTreeEntry;
  isDir: boolean;
  children: TreeNode[];
}

function buildHierarchy(entries: RepoTreeEntry[]): TreeNode[] {
  const rootMap = new Map<string, TreeNode>();

  const ensureNode = (path: string, isDir: boolean, entry?: RepoTreeEntry): TreeNode => {
    const existing = rootMap.get(path);
    if (existing) {
      if (entry) existing.entry = entry;
      if (isDir) existing.isDir = true;
      return existing;
    }
    const parts = path.split("/");
    const name = parts[parts.length - 1];
    const node: TreeNode = { name, path, entry, isDir, children: [] };
    rootMap.set(path, node);

    if (parts.length > 1) {
      const parentPath = parts.slice(0, -1).join("/");
      const parent = ensureNode(parentPath, true);
      if (!parent.children.some((c) => c.path === path)) {
        parent.children.push(node);
      }
    }
    return node;
  };

  for (const e of entries) {
    ensureNode(e.path, e.kind === "dir", e);
  }

  const sortRec = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    for (const n of nodes) sortRec(n.children);
  };

  const top: TreeNode[] = [];
  for (const node of rootMap.values()) {
    if (!node.path.includes("/")) top.push(node);
  }
  sortRec(top);
  return top;
}

function collectAllDirPaths(nodes: TreeNode[], acc: string[] = []): string[] {
  for (const n of nodes) {
    if (n.isDir) {
      acc.push(n.path);
      collectAllDirPaths(n.children, acc);
    }
  }
  return acc;
}

interface Props {
  identity: IdentityPreset;
  /** False for members: the explain probe is owner-only, so it isn't offered. */
  owner?: boolean;
  /** Undefined = the repo's checked-out branch (the ref is then left off every request). */
  refName?: string;
  initialPath?: string;
  requestedPath?: string;
  requestedLines?: [number, number];
  onConsumeRequested?: () => void;
  onSelectPath?: (path: string) => void;
  onSelectLines?: (lines: [number, number] | null) => void;
  ownerIdentity?: IdentityPreset;
  presets?: IdentityPreset[];
  directory?: Directory | null;
  agentProfiles?: string[];
  mirrorEnabled?: boolean;
  onMirrorEnabledChange?: (enabled: boolean) => void;
  onOpenPolicyEditor?: (toml: string) => void;
  onPolicySaved?: () => void;
  /** Owner-only ambient hygiene insights for tree dots & contextual whisper chips. */
  hygieneInsights?: HygieneInsight[];
  onDraftPolicyRule?: (draft: {
    zoneName: string;
    pathGlob: string;
    target: string;
    tomlSnippet: string;
  }) => void;
  onAddOverlayGuard?: (path: string, suggestedScope: string) => void | Promise<void>;
  onDismissInsight?: (id: string) => void | Promise<void>;
  /** False when this tab stays mounted while hidden; pauses global hotkeys. */
  active?: boolean;
  /** Reports unsaved edits in the open file so the host can guard ref/identity switches. */
  onDirtyChange?: (dirty: boolean) => void;
}

export function ZoneXRayView({
  identity,
  owner = true,
  refName,
  initialPath,
  requestedPath,
  requestedLines,
  onConsumeRequested,
  onSelectPath,
  onSelectLines,
  ownerIdentity,
  presets = [],
  directory = null,
  agentProfiles = [],
  mirrorEnabled: mirrorEnabledProp,
  onMirrorEnabledChange,
  onOpenPolicyEditor,
  onPolicySaved,
  hygieneInsights,
  onDraftPolicyRule,
  onAddOverlayGuard,
  onDismissInsight,
  active = true,
  onDirtyChange,
}: Props) {
  const [busyInsightId, setBusyInsightId] = useState<string | null>(null);
  const [treeError, setTreeError] = useState<string | null>(null);
  const clientOS = useClientOS();
  const [xray, setXray] = useState(false);
  const [filterText, setFilterText] = useState("");
  const [tree, setTree] = useState<RepoTreeResponse | null>(null);
  const [selectedPath, setSelectedPath] = useState<string>(
    requestedPath ?? initialPath ?? "README.md",
  );
  const [expandedDirs, setExpandedDirs] = useState<Set<string>>(() => new Set(["crates", "apps"]));
  const [filesDrawerOpen, setFilesDrawerOpen] = useState(false);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [filePreview, setFilePreview] = useState<RepoFileResponse | null>(null);
  const [loadingFile, setLoadingFile] = useState(false);
  const [softWrapOverride, setSoftWrapOverride] = useState<boolean | null>(null);
  const [minimapOpen, setMinimapOpen] = useState<boolean>(() =>
    typeof window !== "undefined" ? window.innerWidth >= 1024 : true,
  );
  const [mdMode, setMdMode] = useState<"preview" | "source">("preview");

  // Line selection (click + Shift-click range)
  const [lineRange, setLineRange] = useState<[number, number] | null>(requestedLines ?? null);
  const pendingLinesRef = useRef<[number, number] | null>(requestedLines ?? null);
  const [scrollTargetLine, setScrollTargetLine] = useState<{ line: number; nonce: number } | null>(
    requestedLines ? { line: requestedLines[0], nonce: 1 } : null,
  );
  const [copiedState, setCopiedState] = useState<"path" | "source" | "link" | null>(null);

  const [explorerMode, setExplorerMode] = useState<"files" | "search">("files");
  const [repoSearchQuery, setRepoSearchQuery] = useState("");
  const repoSearchInputRef = useRef<HTMLInputElement>(null);
  const [repoSearchRes, setRepoSearchRes] = useState<RepoSearchResponse | null>(null);
  const [searchingRepo, setSearchingRepo] = useState(false);

  // Real Git Blame gutter & ACL-enforced Live File Editor
  const [blameOpen, setBlameOpen] = useState(false);
  const [blameLines, setBlameLines] = useState<Map<number, BlameLine>>(() => new Map());
  const [editMode, setEditMode] = useState(false);
  const [editDraft, setEditDraft] = useState("");
  const [savingFile, setSavingFile] = useState(false);
  const [commitMessage, setCommitMessage] = useState("");
  // Tied to the saved path so it survives the post-save refetch but not a move to another file.
  const [savedNotice, setSavedNotice] = useState<{ path: string; text: string } | null>(null);
  // A 409 on save: the branch moved under the editor. Holds the server's message.
  const [saveConflict, setSaveConflict] = useState<string | null>(null);
  // "New file": the folder it goes in, the name typed (relative to it), contents and message.
  const [newFile, setNewFile] = useState<{
    folder: string;
    name: string;
    draft: string;
    message: string;
  } | null>(null);
  const [newFileError, setNewFileError] = useState<string | null>(null);
  // Bumped to refetch the tree (and with it the open file) from the server.
  const [reloadNonce, setReloadNonce] = useState(0);
  // Bumped after a plain file save: only the file (and mirror commits) need refetching, not the tree.
  const [fileNonce, setFileNonce] = useState(0);
  // Sticky: user asked for Find, so read-only viewing uses full Monaco from then on.
  const [richView, setRichView] = useState(false);
  const [whisperOpen, setWhisperOpen] = useState(false);
  const whisperRef = useRef<HTMLDivElement>(null);

  // Monaco native Find widget trigger nonce (Cmd/Ctrl+F & Find toolbar button)
  const [findNonce, setFindNonce] = useState(0);

  // Tree reload in flight (ref/identity switch): the stale tree is dimmed and unclickable.
  const [treeLoading, setTreeLoading] = useState(false);
  // The file path whose fetch failed (so a failure shows an error state, never a blank frame).
  const [fileFailed, setFileFailed] = useState<string | null>(null);
  const [moreOpen, setMoreOpen] = useState(false);
  const moreRef = useRef<HTMLDivElement>(null);
  const hasUnsavedRef = useRef(false);
  const confirmDiscard = useCallback(
    () => !hasUnsavedRef.current || window.confirm("Discard your unsaved changes?"),
    [],
  );

  // Custom policy probe
  const [customPath, setCustomPath] = useState("");
  const [customExplain, setCustomExplain] = useState<{
    path: string;
    effective: string[];
    human: string[];
    agent?: string[];
    synthesized: boolean;
    rules: RepoTreeEntry["matched_rules"];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Owner-only "Two-Eyes" Glass Wall Mirror & Direct-Manipulation Policy Authoring state
  const [localMirrorEnabled, setLocalMirrorEnabled] = useState(false);
  const mirrorEnabled = owner ? (mirrorEnabledProp ?? localMirrorEnabled) : false;
  const setMirrorEnabled = (next: boolean | ((prev: boolean) => boolean)) => {
    const resolved = typeof next === "function" ? next(mirrorEnabled) : next;
    if (onMirrorEnabledChange) onMirrorEnabledChange(resolved);
    else setLocalMirrorEnabled(resolved);
  };
  const [mirrorMode, setMirrorMode] = useState<"curtain" | "side-by-side">("curtain");
  const [altPeeking, setAltPeeking] = useState(false);
  const [mirrorTargetId, setMirrorTargetId] = useState<string>("");
  const [hoveredTreePath, setHoveredTreePath] = useState<string | null>(null);

  const [policySummary, setPolicySummary] = useState<PolicySummaryResponse | null>(null);
  const [secretRefs, setSecretRefs] = useState<SecretRefInfo[]>([]);

  const [mirrorLeftTree, setMirrorLeftTree] = useState<RepoTreeResponse | null>(null);
  const [mirrorRightTree, setMirrorRightTree] = useState<RepoTreeResponse | null>(null);
  const [mirrorLeftFile, setMirrorLeftFile] = useState<RepoFileResponse | null>(null);
  const [mirrorRightFile, setMirrorRightFile] = useState<RepoFileResponse | null>(null);
  const [mirrorLeftCommit, setMirrorLeftCommit] = useState<GitCommitSummary | null>(null);
  const [mirrorRightCommit, setMirrorRightCommit] = useState<GitCommitSummary | null>(null);

  const [policyMenu, setPolicyMenu] = useState<{
    target: ContextMenuTarget;
    x: number;
    y: number;
  } | null>(null);
  const [composerState, setComposerState] = useState<{
    intent: PolicyIntent;
    matchingZones: string[];
  } | null>(null);

  const targetPresets = useMemo(
    () => (owner ? presets.filter((p) => p.id !== "self") : []),
    [owner, presets],
  );
  const targetIdentity = useMemo(() => {
    if (!owner || targetPresets.length === 0) return null;
    return (
      targetPresets.find((p) => p.id === mirrorTargetId) ??
      (identity.id !== "self" ? targetPresets.find((p) => p.id === identity.id) : undefined) ??
      targetPresets.find((p) => p.id === "anonymous") ??
      targetPresets[0]
    );
  }, [owner, targetPresets, mirrorTargetId, identity.id]);
  const leftIdentity = ownerIdentity ?? identity;
  const isMirrorActive = Boolean(owner && targetIdentity && (mirrorEnabled || altPeeking));

  // Owner-only Hold-Alt quick peek shortcut (automatically disabled for members or while hidden/editing)
  useEffect(() => {
    if (!active || !owner || !targetIdentity) {
      setAltPeeking(false);
      return;
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (
        e.key === "Alt" &&
        !e.ctrlKey &&
        !e.metaKey &&
        !e.shiftKey &&
        !e.repeat &&
        !isEditableEventTarget(e) &&
        !editMode &&
        !newFile &&
        !composerState &&
        !policyMenu
      ) {
        setAltPeeking(true);
      }
    };
    const releasePeek = () => setAltPeeking(false);
    const onKeyUp = (e: KeyboardEvent) => {
      if (e.key === "Alt" || !e.altKey) setAltPeeking(false);
    };
    const onVisibility = () => {
      if (document.hidden) setAltPeeking(false);
    };
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    window.addEventListener("blur", releasePeek);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
      window.removeEventListener("blur", releasePeek);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [active, owner, targetIdentity, editMode, newFile, composerState, policyMenu]);

  useEffect(() => {
    if (editMode || newFile || composerState || policyMenu) {
      setAltPeeking(false);
    }
  }, [editMode, newFile, composerState, policyMenu]);

  // Load policy zones (owner-only for direct-manipulation authoring)
  useEffect(() => {
    if (!owner) {
      setPolicySummary(null);
      return;
    }
    let active = true;
    api
      .policySummary()
      .then((s) => {
        if (active) setPolicySummary(s);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [owner, reloadNonce]);

  const openPath = (targetPath: string) => {
    setSelectedPath(targetPath);
    setCustomExplain(null);
    const parts = targetPath.split("/");
    if (parts.length > 1) {
      setExpandedDirs((prev) => {
        const next = new Set(prev);
        for (let i = 1; i < parts.length; i++) {
          next.add(parts.slice(0, i).join("/"));
        }
        return next;
      });
    }
  };

  // Moving to another file while an edit is unsaved asks first.
  const guardedOpenPath = (target: string) => {
    if (target !== selectedPath && !confirmDiscard()) return;
    openPath(target);
  };
  const selectPath = (target: string) => {
    if (target !== (selectedEntry?.path ?? selectedPath) && !confirmDiscard()) return false;
    setSelectedPath(target);
    setCustomExplain(null);
    return true;
  };

  useEffect(() => {
    if (!requestedPath) return;
    guardedOpenPath(requestedPath);
    onConsumeRequested?.();
  }, [requestedPath, onConsumeRequested]);

  useEffect(() => {
    if (!requestedLines) return;
    pendingLinesRef.current = requestedLines;
    setLineRange(requestedLines);
    setMdMode("source");
    setScrollTargetLine({ line: requestedLines[0], nonce: Date.now() });
    onConsumeRequested?.();
  }, [requestedLines, onConsumeRequested]);

  const identityId = identityKey(identity);

  useEffect(() => {
    let active = true;
    setError(null);
    setTreeError(null);
    setTreeLoading(true);
    shared(`tree|${identityId}|${owner && xray}|${refName ?? ""}|${reloadNonce}`, () =>
      api.repoTree(identity, owner && xray, refName),
    )
      .then((res) => {
        if (!active) return;
        setTree(res);
        setCustomExplain(null);
        const files = res.entries.filter((e) => e.kind === "file");
        if (files.length > 0 && !res.entries.some((e) => e.path === selectedPath)) {
          const preferred =
            files.find((f) => f.path === "README.md") ??
            files.find((f) => f.path === "Cargo.toml") ??
            files[0];
          setSelectedPath(preferred.path);
        }
      })
      .catch((err: unknown) => {
        if (!active) return;
        // Don't leave another ref's tree on screen under a 404 for this one.
        setTree(null);
        setTreeError(errorText(err));
        setError(errorText(err));
      })
      .finally(() => {
        if (active) setTreeLoading(false);
      });
    return () => {
      active = false;
    };
  }, [identityId, xray, refName, owner, reloadNonce]);

  // Search hits belong to one ref and identity; drop them when either changes.
  useEffect(() => {
    setRepoSearchRes(null);
  }, [identityId, refName]);

  const activeTree = useMemo(() => {
    if (isMirrorActive) {
      return identity.id === "self" ? tree : mirrorLeftTree ?? tree;
    }
    return tree;
  }, [isMirrorActive, identity.id, tree, mirrorLeftTree]);

  const filteredEntries = useMemo(() => {
    if (!activeTree) return [];
    const q = filterText.trim().toLowerCase();
    if (!q) return activeTree.entries;
    return activeTree.entries.filter((e) => e.path.toLowerCase().includes(q));
  }, [activeTree, filterText]);

  const hierarchy = useMemo(() => buildHierarchy(filteredEntries), [filteredEntries]);
  const allDirs = useMemo(() => collectAllDirPaths(hierarchy), [hierarchy]);

  const selectedEntry = useMemo(() => {
    if (!activeTree) return null;
    return activeTree.entries.find((e) => e.path === selectedPath) ?? activeTree.entries[0] ?? null;
  }, [activeTree, selectedPath]);

  const rightTreeMap = useMemo(() => {
    const map = new Map<string, RepoTreeEntry>();
    for (const e of mirrorRightTree?.entries ?? []) {
      map.set(e.path, e);
    }
    return map;
  }, [mirrorRightTree]);

  const leftTreeMap = useMemo(() => {
    const map = new Map<string, RepoTreeEntry>();
    for (const e of activeTree?.entries ?? []) {
      map.set(e.path, e);
    }
    return map;
  }, [activeTree]);

  const leftKey = identityKey(leftIdentity);
  const targetKey = targetIdentity ? identityKey(targetIdentity) : "";
  const mirrorNonce = `${reloadNonce}.${fileNonce}`;

  // Mirror results are cached by key: releasing Alt (quick-peek) keeps them, so peeking again at the
  // same state is instant and never flashes a loading or empty frame.
  const mirrorTreeKey = `${identity.id}|${leftKey}|${targetKey}|${refName ?? ""}|${mirrorNonce}`;
  const [mirrorTreeDone, setMirrorTreeDone] = useState("");
  const loadingMirrorTree = isMirrorActive && mirrorTreeDone !== mirrorTreeKey;

  // Truthful Mirror fetches: Left Eye (Owner) & Right Eye (Target principal / human ∩ agent)
  useEffect(() => {
    if (!isMirrorActive || !targetIdentity) return;
    if (mirrorTreeDone === mirrorTreeKey) return;
    let active = true;

    // For "self" the left tree is the main tree (activeTree ignores mirrorLeftTree), so skip the fetch.
    const fetchLeftTree: Promise<RepoTreeResponse | null> =
      identity.id === "self"
        ? Promise.resolve(null)
        : shared(`tree|${leftKey}|false|${refName ?? ""}|${reloadNonce}`, () =>
            api.repoTree(leftIdentity, false, refName),
          );
    const fetchRightTree = shared(
      `tree|${targetKey}|true|${refName ?? ""}|${reloadNonce}`,
      () => api.repoTree(targetIdentity, true, refName),
    );
    const fetchLeftCommit = api
      .commits(leftIdentity, { ref: refName, limit: 1 })
      .then((list) => list[0] ?? null)
      .catch(() => null);
    const fetchRightCommit = api
      .commits(targetIdentity, { ref: refName, limit: 1 })
      .then((list) => list[0] ?? null)
      .catch(() => null);
    const fetchSecrets = api
      .explainSecrets(targetIdentity, refName)
      .then((res) =>
        res.entries.map((e) => ({
          name: e.name,
          sensitivity: e.sensitivity,
          zone: e.zone,
          canTargetUse: e.can_use,
          hasEgress: e.has_egress,
          approval: e.approval,
        })),
      )
      .catch(() => [] as SecretRefInfo[]);

    Promise.all([fetchLeftTree, fetchRightTree, fetchLeftCommit, fetchRightCommit, fetchSecrets])
      .then(([lTree, rTree, lCommit, rCommit, secrets]) => {
        if (!active) return;
        setMirrorLeftTree(lTree);
        setMirrorRightTree(rTree);
        setMirrorLeftCommit(lCommit);
        setMirrorRightCommit(rCommit);
        setSecretRefs(secrets);
        setMirrorTreeDone(mirrorTreeKey);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setError(errorText(err));
        setMirrorTreeDone(mirrorTreeKey);
      });

    return () => {
      active = false;
    };
  }, [isMirrorActive, identity.id, leftKey, targetKey, refName, mirrorNonce, mirrorTreeDone]);

  const mirrorFilePath = selectedEntry?.kind === "file" ? selectedEntry.path : null;
  const mirrorFileKey = mirrorFilePath
    ? `${leftKey}|${targetKey}|${mirrorFilePath}|${refName ?? ""}|${mirrorNonce}`
    : "";
  const [mirrorFileDone, setMirrorFileDone] = useState("");
  const loadingMirrorFile = Boolean(
    isMirrorActive && mirrorFilePath && mirrorFileDone !== mirrorFileKey,
  );

  useEffect(() => {
    if (!isMirrorActive || !targetIdentity || !mirrorFilePath) return;
    if (mirrorFileDone === mirrorFileKey) return;
    let active = true;
    // Same request key as the main viewer's fetch, so the left eye shares it (no second round trip).
    const fetchLeftFile = shared(
      `file|${leftKey}|${mirrorFilePath}|${refName ?? ""}|${mirrorNonce}`,
      () => api.repoFile(leftIdentity, mirrorFilePath, refName),
    );
    const fetchRightFile = shared(
      `file|${targetKey}|${mirrorFilePath}|${refName ?? ""}|${mirrorNonce}`,
      () => api.repoFile(targetIdentity, mirrorFilePath, refName),
    );

    Promise.allSettled([fetchLeftFile, fetchRightFile]).then(([lRes, rRes]) => {
      if (!active) return;
      setMirrorLeftFile(lRes.status === "fulfilled" ? lRes.value : null);
      setMirrorRightFile(rRes.status === "fulfilled" ? rRes.value : null);
      setMirrorFileDone(mirrorFileKey);
    });

    return () => {
      active = false;
    };
  }, [isMirrorActive, leftKey, targetKey, mirrorFilePath, refName, mirrorNonce, mirrorFileDone]);

  // File to show: the selected file once the tree is in, or the requested path straight away so the
  // blob loads in parallel with the tree instead of after it.
  const fileTarget = selectedEntry
    ? selectedEntry.kind === "file"
      ? selectedEntry.path
      : null
    : tree
      ? null
      : selectedPath || null;

  // Only ever render a file that matches the current target: no stale content under a new header.
  const shownFile = filePreview?.path === fileTarget ? filePreview : null;
  const dirty = editMode && editDraft !== (shownFile?.content ?? "");
  const hasUnsaved = dirty || Boolean(newFile && (newFile.draft || newFile.name.trim()));
  hasUnsavedRef.current = hasUnsaved;
  useEffect(() => {
    onDirtyChange?.(hasUnsaved);
  }, [hasUnsaved, onDirtyChange]);
  useEffect(() => () => onDirtyChange?.(false), [onDirtyChange]);
  const awaitingFile =
    !shownFile && ((fileTarget ? fileFailed !== fileTarget : false) || (!tree && !error));

  // Closing the tab/window with an unsaved edit prompts.
  useEffect(() => {
    if (!hasUnsaved) return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [hasUnsaved]);

  // Per-file view state resets only when the file/identity/ref changes, never on a tree refetch.
  useEffect(() => {
    const pending = pendingLinesRef.current;
    if (pending) {
      setLineRange(pending);
      setMdMode("source");
    } else {
      setLineRange(null);
      setScrollTargetLine(null);
      setMdMode("preview");
    }
    setFindNonce(0);
    setEditMode(false);
    // Browsing stays on the lightweight viewer; Find/Edit on the new file upgrades to Monaco again.
    setRichView(false);
    setCommitMessage("");
    setSaveConflict(null);
    setBlameLines(new Map());
    if (fileTarget && selectedEntry) onSelectPath?.(fileTarget);
  }, [identityId, fileTarget, refName]);

  useEffect(() => {
    if (!fileTarget) {
      setFilePreview(null);
      setLoadingFile(false);
      setFileFailed(null);
      return;
    }
    let active = true;
    setFileFailed(null);
    // Before the tree arrives the path is a guess (e.g. README.md); don't surface its 404.
    const optimistic = !selectedEntry;
    setError(null);
    setLoadingFile(true);
    // The previous file stays on screen (dimmed, with a progress bar) until this one lands.
    shared(`file|${identityId}|${fileTarget}|${refName ?? ""}|${reloadNonce}.${fileNonce}`, () =>
      api.repoFile(identity, fileTarget, refName),
    )
      .then((res) => {
        if (!active) return;
        setFilePreview(res);
        if (pendingLinesRef.current) {
          const targetLine = pendingLinesRef.current[0];
          pendingLinesRef.current = null;
          setScrollTargetLine({ line: targetLine, nonce: Date.now() });
        }
      })
      .catch((err: unknown) => {
        if (!active) return;
        setFilePreview(null);
        setFileFailed(fileTarget);
        if (!optimistic) setError(errorText(err));
      })
      .finally(() => {
        if (active) setLoadingFile(false);
      });
    return () => {
      active = false;
    };
  }, [identityId, fileTarget, refName, reloadNonce, fileNonce]);

  useEffect(() => {
    onSelectLines?.(lineRange);
  }, [lineRange, onSelectLines]);

  // "Committed … to <branch>" describes one branch and identity; drop it when either changes.
  useEffect(() => setSavedNotice(null), [identity, refName]);

  // Fetch real `git blame` when blame gutter is enabled
  useEffect(() => {
    if (!blameOpen || !fileTarget) return;
    let active = true;
    api
      .repoBlame(identity, fileTarget, refName)
      .then((res) => {
        if (!active) return;
        const map = new Map<number, BlameLine>();
        for (const bl of res.lines) map.set(bl.line, bl);
        setBlameLines(map);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [blameOpen, identityId, fileTarget, refName, fileNonce]);

  const runRepoSearch = async (e?: React.FormEvent) => {
    e?.preventDefault();
    const q = repoSearchQuery.trim();
    if (!q) {
      setRepoSearchRes(null);
      return;
    }
    setSearchingRepo(true);
    setError(null);
    try {
      const res = await api.repoSearch(identity, q, refName);
      setRepoSearchRes(res);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSearchingRepo(false);
    }
  };

  const commitNotice = (res: WriteRepoFileResponse) =>
    res.commit
      ? `Committed ${shortOid(res.commit)}${refName ? ` to ${refName}` : ""}`
      : `Saved ${res.bytes_written} B`;

  // The folder a new file goes in: the selected folder, or the selected file's.
  const currentFolder = !selectedEntry
    ? ""
    : selectedEntry.kind === "dir"
      ? selectedEntry.path
      : selectedEntry.path.split("/").slice(0, -1).join("/");

  const handleCreateFile = async () => {
    if (!newFile) return;
    const name = newFile.name.trim();
    const full = newFile.folder ? `${newFile.folder}/${name}` : name;
    const invalid =
      newFilePathError(name) ??
      // Saving to an existing path would overwrite it.
      (tree?.entries.some((e) => e.path === full) ? `${full} already exists.` : null);
    if (invalid) {
      setNewFileError(invalid);
      return;
    }
    setSavingFile(true);
    setNewFileError(null);
    try {
      const res = await api.writeRepoFile(
        identity,
        full,
        newFile.draft,
        refName,
        newFile.message.trim() || undefined,
      );
      setSavedNotice({ path: full, text: commitNotice(res) });
      setNewFile(null);
      setSelectedPath(full);
      setExpandedDirs((prev) => {
        const next = new Set(prev);
        const parts = full.split("/");
        for (let i = 1; i < parts.length; i++) next.add(parts.slice(0, i).join("/"));
        return next;
      });
      setReloadNonce((n) => n + 1);
    } catch (err: unknown) {
      setNewFileError(errorText(err));
    } finally {
      setSavingFile(false);
    }
  };

  const handleSaveFile = async () => {
    if (!selectedEntry) return;
    setSavingFile(true);
    setError(null);
    setSaveConflict(null);
    try {
      const res = await api.writeRepoFile(
        identity,
        selectedEntry.path,
        editDraft,
        refName,
        commitMessage.trim() || undefined,
        filePreview?.tip_oid ?? undefined,
      );
      setSavedNotice({ path: selectedEntry.path, text: commitNotice(res) });
      // Shown at once; the refetch below then replaces it with what the server holds.
      setFilePreview((prev) =>
        prev ? { ...prev, content: editDraft, truncated: false } : prev,
      );
      setEditMode(false);
      // Editing a policy file changes effective capabilities, so the tree must reload too.
      if (/(^|\/)\.access\.toml$/.test(selectedEntry.path)) setReloadNonce((n) => n + 1);
      else setFileNonce((n) => n + 1);
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 409) setSaveConflict(errorText(err));
      else setError(errorText(err));
    } finally {
      setSavingFile(false);
    }
  };

  const handleDeleteFile = async () => {
    if (!selectedEntry || selectedEntry.kind !== "file") return;
    setSavingFile(true);
    setError(null);
    setSaveConflict(null);
    try {
      const targetPath = selectedEntry.path;
      const res = await api.deleteRepoFile(identity, targetPath, refName);
      setSavedNotice({ path: "", text: `Deleted ${targetPath} (${commitNotice(res)})` });
      setEditMode(false);
      setSelectedPath("");
      setFilePreview(null);
      setReloadNonce((n) => n + 1);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSavingFile(false);
    }
  };

  const lines = useMemo(() => {
    if (!shownFile?.allowed || !shownFile.content) return [];
    return shownFile.content.split(/\r?\n/);
  }, [shownFile]);

  const activeFilePath = selectedEntry?.path ?? selectedPath;

  const lang = useMemo(
    () => detectLanguage(shownFile?.path ?? ""),
    [shownFile?.path],
  );
  const isMarkdown = useMemo(
    () => /\.(md|mdx|markdown)$/i.test(shownFile?.path ?? ""),
    [shownFile?.path],
  );
  const showMarkdownPreview =
    isMarkdown && mdMode === "preview" && !editMode && !blameOpen && !lineRange;
  const softWrap = softWrapOverride ?? lang === "markdown";

  // Left pane: the mirror's own fetch, or (as "self") the main viewer's file. Never a stale path.
  const mirrorPathNow = selectedEntry?.path ?? selectedPath;
  const mirrorOwnerFile =
    mirrorLeftFile?.path === mirrorPathNow
      ? mirrorLeftFile
      : identity.id === "self" && filePreview?.path === mirrorPathNow
        ? filePreview
        : null;

  const mirrorVisible = Boolean(isMirrorActive && targetIdentity && !editMode && !newFile);

  // True when a source view (edit, new file, or read-only code) is on screen to search.
  const monacoActive =
    Boolean(newFile) ||
    (!mirrorVisible &&
      selectedEntry?.kind === "file" &&
      !loadingFile &&
      Boolean(shownFile?.allowed) &&
      !shownFile?.binary &&
      (editMode || !showMarkdownPreview));

  const openFind = () => {
    if (showMarkdownPreview) setMdMode("source");
    // Find needs Monaco's widget; the lightweight viewer upgrades to it only now.
    if (!editMode && !newFile) setRichView(true);
    setFindNonce((n) => n + 1);
  };

  // Scoped Cmd/Ctrl+F for Monaco Find widget + Escape to close mobile drawers
  useEffect(() => {
    if (!active) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (monacoActive && hasPrimaryModifier(e, clientOS) && e.key.toLowerCase() === "f") {
        e.preventDefault();
        openFind();
      } else if (e.key === "Escape") {
        if (filesDrawerOpen) {
          setFilesDrawerOpen(false);
        } else if (inspectorOpen) {
          setInspectorOpen(false);
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [active, clientOS, monacoActive, filesDrawerOpen, inspectorOpen, editMode, newFile, showMarkdownPreview]);

  const editMarkers = useMemo(() => {
    if (!editMode) return undefined;
    if (monacoLanguageForPath(activeFilePath) !== PREMIER_ACCESS_TOML_LANGUAGE) {
      return undefined;
    }
    return validateAccessToml(editDraft, error);
  }, [editMode, activeFilePath, editDraft, error]);

  const candidateNewFilePath = useMemo(() => {
    if (!newFile) return "untitled.txt";
    const trimmed = newFile.name.trim();
    if (!trimmed) return "untitled.txt";
    return newFile.folder ? `${newFile.folder}/${trimmed}` : trimmed;
  }, [newFile]);

  const newFileMarkers = useMemo(() => {
    if (!newFile) return undefined;
    if (monacoLanguageForPath(candidateNewFilePath) !== PREMIER_ACCESS_TOML_LANGUAGE) {
      return undefined;
    }
    return validateAccessToml(newFile.draft, newFileError);
  }, [newFile, candidateNewFilePath, newFileError]);

  const openPathRef = useRef(guardedOpenPath);
  openPathRef.current = guardedOpenPath;
  const openPathStable = useCallback((target: string) => openPathRef.current(target), []);

  // Dismiss the ambient-notes popover on outside press / Escape.
  useEffect(() => {
    if (!whisperOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!whisperRef.current?.contains(e.target as Node)) setWhisperOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setWhisperOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [whisperOpen]);

  // Dismiss the "⋯" actions menu on outside press / Escape.
  useEffect(() => {
    if (!moreOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!moreRef.current?.contains(e.target as Node)) setMoreOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMoreOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [moreOpen]);

  const toggleDir = (dirPath: string) => {
    setExpandedDirs((prev) => {
      const next = new Set(prev);
      if (next.has(dirPath)) next.delete(dirPath);
      else next.add(dirPath);
      return next;
    });
  };

  const runCustomExplain = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = customPath.trim();
    if (!target) return;
    try {
      const dec = await api.explain(identity, target, refName);
      setCustomExplain({
        path: dec.path,
        effective: capMaskToNames(dec.effective),
        human: capMaskToNames(dec.human_effective),
        agent: dec.agent_effective !== undefined ? capMaskToNames(dec.agent_effective) : undefined,
        synthesized: dec.synthesized_traverse,
        rules: dec.matched_rules ?? [],
      });
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const copyText = (kind: "path" | "source" | "link", text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedState(kind);
    setTimeout(() => setCopiedState(null), 1400);
  };

  const activeCaps = customExplain?.effective ?? selectedEntry?.effective ?? [];
  const humanCaps = customExplain?.human ?? selectedEntry?.human_effective ?? activeCaps;
  const agentCaps = customExplain?.agent ?? selectedEntry?.agent_effective;
  const synthesizedTraverse =
    customExplain?.synthesized ?? selectedEntry?.synthesized_traverse ?? false;
  const activeRules = customExplain?.rules ?? selectedEntry?.matched_rules ?? [];

  const breadcrumbs = (selectedEntry?.path ?? "").split("/").filter(Boolean);
  const byteSize = useMemo(
    () => (shownFile?.content ? new TextEncoder().encode(shownFile.content).length : 0),
    [shownFile?.content],
  );

  // Child entries if inspecting a directory
  const dirChildren = useMemo(() => {
    if (!activeTree || !selectedEntry || selectedEntry.kind !== "dir") return [];
    const prefix = `${selectedEntry.path}/`;
    return activeTree.entries.filter((e) => {
      if (!e.path.startsWith(prefix)) return false;
      return !e.path.slice(prefix.length).includes("/");
    });
  }, [activeTree, selectedEntry]);

  const openPolicyMenu = (target: { kind: "file" | "dir"; path: string }, x: number, y: number) => {
    if (!owner) return;
    setAltPeeking(false);
    const matchingZones = matchingZonesForPath(target.path, policySummary?.policy);
    setPolicyMenu({
      target: { kind: target.kind, path: target.path, matchingZones },
      x,
      y,
    });
  };

  const openDirectComposer = (target: { kind: "file" | "dir"; path: string }) => {
    if (!owner) return;
    setAltPeeking(false);
    const matchingZones = matchingZonesForPath(target.path, policySummary?.policy);
    const policyTarget = { kind: target.kind, path: target.path } as const;
    const initialIntent: PolicyIntent = targetIdentity?.agentProfile
      ? {
          kind: "allow_agent_access",
          target: policyTarget,
          agent_profile: targetIdentity.agentProfile,
          write: false,
        }
      : targetIdentity && targetIdentity.principal !== "anonymous"
        ? {
            kind: "restrict_to_principals",
            target: policyTarget,
            principals: [targetIdentity.principal],
            write: false,
          }
        : {
            kind: "shield_from_anonymous",
            target: policyTarget,
          };
    setComposerState({ intent: initialIntent, matchingZones });
  };

  // Owner-only active ambient insights relevant to tree nodes & selected path
  const activeTreeInsights = useMemo(() => {
    if (!owner || !hygieneInsights) return [];
    return hygieneInsights.filter(
      (i) => !i.dismissed && (i.category === "unzoned_directory" || i.category === "overlay_leak"),
    );
  }, [owner, hygieneInsights]);

  const insightsByPath = useMemo(() => {
    const map = new Map<string, HygieneInsight>();
    for (const ins of activeTreeInsights) {
      const norm = ins.target.replace(/^\/+|\/+$/g, "");
      if (!norm) continue;
      const existing = map.get(norm);
      if (!existing || (existing.severity !== "attention" && ins.severity === "attention")) {
        map.set(norm, ins);
      }
    }
    return map;
  }, [activeTreeInsights]);

  const selectedInsights = useMemo(() => {
    if (!owner || !selectedEntry || activeTreeInsights.length === 0) return [];
    const selPath = selectedEntry.path.replace(/^\/+|\/+$/g, "");
    const matched = activeTreeInsights.filter((ins) => {
      const norm = ins.target.replace(/^\/+|\/+$/g, "");
      if (!norm) return false;
      return selPath === norm || selPath.startsWith(`${norm}/`);
    });
    return matched.sort((a, b) => {
      const aExact = a.target.replace(/^\/+|\/+$/g, "") === selPath ? 0 : 1;
      const bExact = b.target.replace(/^\/+|\/+$/g, "") === selPath ? 0 : 1;
      if (aExact !== bExact) return aExact - bExact;
      return b.target.length - a.target.length;
    });
  }, [owner, selectedEntry, activeTreeInsights]);

  const renderTreeNodes = (nodes: TreeNode[], depth = 0) =>
    nodes.map((node) => {
      const entry = node.entry;
      const rightEntry = isMirrorActive ? rightTreeMap.get(node.path) : undefined;
      const isExpanded = filterText.trim().length > 0 || expandedDirs.has(node.path);
      const active = selectedEntry?.path === node.path;
      const isOmitted = isMirrorActive
        ? !rightEntry || rightEntry.visibility_state === "omitted"
        : entry?.visibility_state === "omitted";
      const isTraverse = isMirrorActive
        ? rightEntry?.visibility_state === "traverse_only"
        : entry?.visibility_state === "traverse_only";
      const mirrorDiff =
        isMirrorActive && entry ? computeCapabilityDiff(entry, rightEntry ?? null) : null;
      const nodeInsight = owner ? insightsByPath.get(node.path) : undefined;

      return (
        <div key={node.path}>
          <div
            onContextMenu={
              owner
                ? (e) => {
                    e.preventDefault();
                    openPolicyMenu(
                      { kind: node.isDir ? "dir" : "file", path: node.path },
                      e.clientX,
                      e.clientY,
                    );
                  }
                : undefined
            }
            onMouseEnter={isMirrorActive ? () => setHoveredTreePath(node.path) : undefined}
            onMouseLeave={
              isMirrorActive
                ? () => setHoveredTreePath((cur) => (cur === node.path ? null : cur))
                : undefined
            }
            className={`group flex w-full items-center gap-0.5 rounded-lg pr-1 transition ${
              active
                ? "bg-[#7f95f8]/16 text-[#f3f6fd]"
                : isOmitted
                  ? isMirrorActive
                    ? "border border-dashed border-white/[0.06] bg-white/[0.015] text-[#a6b5cf] hover:bg-white/[0.03]"
                    : "text-[#a6b5cf] hover:bg-white/[0.03]"
                  : "text-[#d2dbee] hover:bg-white/[0.045] hover:text-[#f3f6fd]"
            }`}
          >
            {/* The chevron only expands/collapses; the label selects, so opening a folder never
                navigates away from the open file. */}
            {node.isDir ? (
              <button
                type="button"
                onClick={() => toggleDir(node.path)}
                aria-expanded={isExpanded}
                aria-label={`${isExpanded ? "Collapse" : "Expand"} ${node.name}`}
                style={{ marginLeft: `${4 + depth * 14}px` }}
                className="shrink-0 rounded p-0.5 text-[#a6b5cf] transition hover:bg-white/[0.08] hover:text-[#f3f6fd]"
              >
                <IconChevron direction={isExpanded ? "down" : "right"} className="h-4 w-4" />
              </button>
            ) : (
              <span
                aria-hidden="true"
                className="shrink-0"
                style={{ marginLeft: `${4 + depth * 14}px`, width: "20px" }}
              />
            )}
            <button
              type="button"
              title={node.path}
              aria-current={active ? "true" : undefined}
              onClick={() => {
                if (!selectPath(node.path)) return;
                if (node.isDir) {
                  setExpandedDirs((prev) =>
                    prev.has(node.path) ? prev : new Set(prev).add(node.path),
                  );
                } else {
                  setFilesDrawerOpen(false);
                }
              }}
              onFocus={isMirrorActive ? () => setHoveredTreePath(node.path) : undefined}
              className="flex min-w-0 flex-1 items-center justify-between gap-1.5 py-1 pr-1 text-left"
            >
              <span className="flex min-w-0 items-center gap-1.5">
                {node.isDir ? (
                  isExpanded ? (
                    <IconFolderOpen
                      traverseOnly={isTraverse}
                      className={`h-4 w-4 ${
                        isOmitted
                          ? "text-[#f27c7c]/65"
                          : isTraverse
                            ? "text-[#a6b5cf]"
                            : "text-[#7f95f8]/90"
                      }`}
                    />
                  ) : (
                    <IconFolderNode
                      traverseOnly={isTraverse}
                      className={`h-4 w-4 ${
                        isOmitted
                          ? "text-[#f27c7c]/65"
                          : isTraverse
                            ? "text-[#a6b5cf]"
                            : "text-[#7f95f8]/80"
                      }`}
                    />
                  )
                ) : isOmitted ? (
                  <IconLock className="h-4 w-4 text-[#f27c7c]/80" />
                ) : entry?.is_instruction_file ? (
                  <IconQuarantine className="h-4 w-4 text-[#a8c5ff]" />
                ) : (
                  <IconFileNode className="h-4 w-4 text-[#7383a0] group-hover:text-[#9ec0f5]" />
                )}

                <span
                  className={`truncate font-mono text-[13.5px] ${isOmitted ? "line-through opacity-75" : ""}`}
                >
                  {node.name}
                </span>
              </span>

              <span className="flex shrink-0 items-center gap-1">
                {mirrorDiff && !mirrorDiff.identical && (
                  <span
                    className={`rounded px-1 py-px font-mono text-[12px] ${
                      isOmitted
                        ? "bg-[#f27c7c]/14 text-[#f27c7c]"
                        : isTraverse
                          ? "bg-white/[0.06] text-[#a9b7d0]"
                          : "bg-[#7f95f8]/14 text-[#b8cef8]"
                    }`}
                  >
                    {isOmitted ? "hidden" : isTraverse ? "trav" : "diff"}
                  </span>
                )}
                {nodeInsight && (
                  <span
                    title={nodeInsight.title}
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      nodeInsight.severity === "attention" ? "bg-[#7f95f8]" : "bg-[#9ec0f5]"
                    }`}
                  />
                )}
              </span>
            </button>

            {owner && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  const rect = e.currentTarget.getBoundingClientRect();
                  openPolicyMenu(
                    { kind: node.isDir ? "dir" : "file", path: node.path },
                    rect.left,
                    rect.bottom + 4,
                  );
                }}
                title={`Restrict access to ${node.path}`}
                aria-label={`Restrict access to ${node.path}`}
                className="rounded p-1 text-[#a6b5cf] opacity-60 transition hover:bg-white/[0.08] hover:text-[#9ec0f5] hover:opacity-100 group-hover:opacity-100 focus:opacity-100"
              >
                <IconShield className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {node.isDir && isExpanded && node.children.length > 0 && (
            <div>{renderTreeNodes(node.children, depth + 1)}</div>
          )}
        </div>
      );
    });

  const fileListContent = (
    <>
      <div className="flex items-center justify-between gap-1.5 border-b border-white/[0.06] px-2.5 py-1.5">
        <div className="inline-flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]">
          <button
            type="button"
            onClick={() => setExplorerMode("files")}
            className={`rounded-full px-2.5 py-0.5 transition ${
              explorerMode === "files" ? "pr-pill-active" : "text-[#a6b5cf]"
            }`}
          >
            Files
          </button>
          <button
            type="button"
            onClick={(e) => {
              const root = e.currentTarget.closest("aside");
              setExplorerMode("search");
              requestAnimationFrame(() =>
                root
                  ?.querySelector<HTMLInputElement>('input[aria-label="Search file contents"]')
                  ?.focus(),
              );
            }}
            className={`rounded-full px-2.5 py-0.5 transition ${
              explorerMode === "search" ? "pr-pill-active" : "text-[#a6b5cf]"
            }`}
          >
            Search
          </button>
        </div>
        <div className="flex items-center gap-1">
          {explorerMode === "files" && (
            <>
              <button
                type="button"
                onClick={() =>
                  setExpandedDirs((prev) =>
                    prev.size >= allDirs.length ? new Set() : new Set(allDirs),
                  )
                }
                title={expandedDirs.size >= allDirs.length ? "Collapse folders" : "Expand folders"}
                aria-label={
                  expandedDirs.size >= allDirs.length ? "Collapse folders" : "Expand folders"
                }
                className="rounded-lg p-1 text-[#a6b5cf] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
              >
                {expandedDirs.size >= allDirs.length ? (
                  <IconFold className="h-4 w-4" />
                ) : (
                  <IconUnfold className="h-4 w-4" />
                )}
              </button>
              {/* The server ignores xray for members, so the toggle is owner-only. */}
              {owner && (
                <button
                  type="button"
                  onClick={() => setXray((x) => !x)}
                  title={
                    xray
                      ? "Show hidden files greyed out (click for strict view)"
                      : "Show only files this viewer can clone (click to show hidden files greyed out)"
                  }
                  className={`shrink-0 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                    xray
                      ? "bg-[#7f95f8]/22 text-[#9ec0f5]"
                      : "bg-white/[0.045] text-[#a6b5cf] hover:text-[#f3f6fd]"
                  }`}
                >
                  {xray ? "X-Ray" : "Strict"}
                </button>
              )}
            </>
          )}
          {filesDrawerOpen && (
            <button
              type="button"
              onClick={() => setFilesDrawerOpen(false)}
              aria-label="Close files"
              className="rounded-lg p-1 text-[#a6b5cf] hover:text-white lg:hidden"
            >
              <IconClose className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Both panes stay mounted (hidden toggle) so tree scroll and search results survive a tab switch. */}
      <div className={explorerMode === "files" ? "contents" : "hidden"}>
        <div className="flex items-center gap-1.5 border-b border-white/[0.06] px-2.5 py-1.5">
          <IconSearch className="h-4 w-4 text-[#a6b5cf]" />
          <input
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            aria-label="Filter paths"
            placeholder="Filter paths…"
            className="min-w-0 flex-1 bg-transparent text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
          />
          {filterText && (
            <button
              type="button"
              onClick={() => setFilterText("")}
              aria-label="Clear filter"
              className="rounded p-0.5 text-[#a6b5cf] hover:text-white"
            >
              <IconClose className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
        {/* Reserved slot: shimmers while the tree reloads (ref/identity switch), never shifts layout. */}
        <div
          aria-hidden="true"
          className={`h-0.5 shrink-0 ${treeLoading ? "pr-shimmer" : "bg-transparent"}`}
        />
        <div
          aria-busy={treeLoading}
          className={`min-h-0 flex-1 overflow-y-auto px-1.5 py-1 transition-opacity ${
            treeLoading && tree ? "pointer-events-none opacity-50" : ""
          }`}
        >
          {!tree && treeError && !treeLoading ? (
            <div
              role="alert"
              className="flex flex-col items-center gap-2 px-3 py-10 text-center font-mono text-[13px] text-[#a6b5cf]"
            >
              <span className="text-[#dce4f5]">Couldn't load file tree</span>
              <span className="max-w-full break-words">{treeError}</span>
              <button
                type="button"
                onClick={() => setReloadNonce((n) => n + 1)}
                className="pr-pill inline-flex h-7 items-center rounded-full px-3 text-[12.5px] text-[#e6ecf8]"
              >
                Retry
              </button>
            </div>
          ) : !tree ? (
            <FileTreeSkeleton />
          ) : hierarchy.length === 0 ? (
            <div className="flex flex-col items-center gap-2 px-3 py-10 text-center font-mono text-[13px] text-[#a6b5cf]">
              {filterText.trim() ? (
                <>
                  <span>No paths match</span>
                  <button
                    type="button"
                    onClick={() => setFilterText("")}
                    className="pr-pill inline-flex h-7 items-center rounded-full px-3 text-[12.5px] text-[#e6ecf8]"
                  >
                    Clear filter
                  </button>
                </>
              ) : (
                <span>No files</span>
              )}
            </div>
          ) : (
            renderTreeNodes(hierarchy)
          )}
        </div>
      </div>

      <div className={explorerMode === "search" ? "contents" : "hidden"}>
        <form
          onSubmit={(e) => void runRepoSearch(e)}
          className="flex items-center gap-1.5 border-b border-white/[0.06] px-2.5 py-1.5"
        >
          <IconSearch className="h-4 w-4 text-[#a6b5cf]" />
          <input
            ref={repoSearchInputRef}
            value={repoSearchQuery}
            onChange={(e) => setRepoSearchQuery(e.target.value)}
            aria-label="Search file contents"
            placeholder="ACL-scoped search…"
            className="min-w-0 flex-1 bg-transparent font-mono text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
          />
          <button
            type="submit"
            disabled={searchingRepo}
            className="pr-pill shrink-0 rounded-lg px-2 py-0.5 font-mono text-[12.5px] text-[#9ec0f5]"
          >
            {searchingRepo ? "…" : "Go"}
          </button>
        </form>
        <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto">
          {searchingRepo ? (
            <SearchResultsSkeleton />
          ) : repoSearchRes ? (
            repoSearchRes.hits.length === 0 ? (
              <div className="p-4 text-center font-mono text-[13px] text-[#a6b5cf]">
                0 hits in {plural(repoSearchRes.files_scanned, "authorized file")}
              </div>
            ) : (
              repoSearchRes.hits.map((hit, idx) => (
                <button
                  key={`${hit.path}:${hit.line}:${idx}`}
                  type="button"
                  onClick={() => {
                    const switching = hit.path !== selectedEntry?.path;
                    if (switching && !confirmDiscard()) return;
                    if (switching) {
                      pendingLinesRef.current = [hit.line, hit.line];
                    }
                    setLineRange([hit.line, hit.line]);
                    setMdMode("source");
                    openPath(hit.path);
                    setScrollTargetLine({ line: hit.line, nonce: Date.now() });
                    setFilesDrawerOpen(false);
                  }}
                  className="w-full px-3 py-2 text-left transition hover:bg-white/[0.04]"
                >
                  <div className="flex items-center justify-between gap-2 font-mono text-[12.5px]">
                    <span className="truncate text-[#9ec0f5]">{hit.path}</span>
                    <span className="shrink-0 text-[#a6b5cf]">L{hit.line}</span>
                  </div>
                  <div className="mt-0.5 truncate font-mono text-[12.5px] text-[#b6c3db]">
                    {hit.text.trim()}
                  </div>
                </button>
              ))
            )
          ) : (
            <div className="p-4 text-center font-mono text-[13px] text-[#a6b5cf]">
              Press Enter to search authorized files
            </div>
          )}
        </div>
      </div>

      {owner && isMirrorActive && targetIdentity && (hoveredTreePath || selectedEntry?.path) && (
        <div className="border-t border-white/[0.06] p-2">
          {(() => {
            const probePath = hoveredTreePath ?? selectedEntry?.path ?? "";
            return (
              <CapabilityDiffTooltip
                path={probePath}
                ownerEntry={leftTreeMap.get(probePath) ?? null}
                targetEntry={rightTreeMap.get(probePath) ?? null}
                ownerLabel={leftIdentity.label}
                targetLabel={targetIdentity.label}
              />
            );
          })()}
        </div>
      )}

      {(isMirrorActive && mirrorRightTree ? mirrorRightTree : tree) && (() => {
        const statsTree = isMirrorActive && mirrorRightTree ? mirrorRightTree : tree!;
        const truncation = getTreeTruncationInfo(statsTree);
        return (
          <div className="border-t border-white/[0.06]">
            {truncation.truncated && (
              <div
                role="status"
                className="flex items-center justify-between gap-2 border-b border-white/[0.06] bg-[#7f95f8]/10 px-3 py-1.5 font-mono text-[12px] text-[#cfe0ff]"
              >
                <span className="min-w-0 truncate" title={`Tree listing capped at ${truncation.shown} of ${truncation.totalInScope} entries in scope`}>
                  Showing {truncation.shown} of {truncation.totalInScope}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setExplorerMode("search");
                    window.requestAnimationFrame(() => repoSearchInputRef.current?.focus());
                  }}
                  className="shrink-0 text-[#9ec0f5] hover:underline"
                >
                  Search all
                </button>
              </div>
            )}
            <div className="flex items-center justify-between gap-2 px-3 py-1.5 font-mono text-[12.5px] text-[#a6b5cf]">
              <span>{statsTree.visible_count} visible</span>
              {statsTree.traverse_only_count > 0 && (
                <span className="text-[#a6b5cf]">{statsTree.traverse_only_count} trav</span>
              )}
              <span className={statsTree.omitted_count > 0 ? "text-[#f27c7c]" : ""}>
                {statsTree.omitted_count} hidden
              </span>
            </div>
          </div>
        );
      })()}
    </>
  );

  const policyContent = (
    <>
      <div className="border-b border-white/[0.06] px-3 py-2.5">
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
            Capability Matrix
          </span>
          <div className="flex items-center gap-1.5">
            {customExplain && (
              <button
                type="button"
                onClick={() => setCustomExplain(null)}
                className="rounded-full bg-[#7f95f8]/18 px-2 py-0.5 font-mono text-[12px] text-[#9ec0f5]"
              >
                probe ×
              </button>
            )}
            <button
              type="button"
              onClick={() => setInspectorOpen(false)}
              aria-label="Close policy panel"
              className="rounded-lg p-1 text-[#a6b5cf] hover:text-white xl:hidden"
            >
              <IconClose className="h-4 w-4" />
            </button>
          </div>
        </div>
        <div className="mt-1.5 truncate font-mono text-[13.5px] text-[#f3f6fd]">
          {customExplain?.path ?? selectedEntry?.path ?? "—"}
        </div>

        {/* Human vs Agent vs Effective (H ∩ A) Bitmask Matrix */}
        <div className="mt-3 space-y-1.5 font-mono text-[12.5px]">
          <div className="grid grid-cols-[1fr_repeat(5,24px)] items-center gap-1 text-center text-[#a6b5cf]">
            <span className="text-left">layer</span>
            {CAP_LETTERS.map((c) => (
              <span key={c.key} title={c.key}>
                {c.short}
              </span>
            ))}
          </div>

          {/* Human row */}
          <div className="grid grid-cols-[1fr_repeat(5,24px)] items-center gap-1">
            <span className="text-[#b6c3db]">Human</span>
            {CAP_LETTERS.map((c) => {
              const on = humanCaps.includes(c.key);
              return (
                <span
                  key={c.key}
                  className={`flex h-5 items-center justify-center rounded ${
                    on ? "bg-[#5bdba2]/14 text-[#5bdba2]" : "bg-white/[0.025] text-[#a6b5cf]"
                  }`}
                >
                  {on ? c.short : "·"}
                </span>
              );
            })}
          </div>

          {/* Agent ceiling row (when delegated agent active) */}
          {agentCaps && (
            <div className="grid grid-cols-[1fr_repeat(5,24px)] items-center gap-1">
              <span className="inline-flex items-center gap-1 text-[#9ec0f5]">
                <IconIntersection className="h-4 w-4" />
                Agent
              </span>
              {CAP_LETTERS.map((c) => {
                const on = agentCaps.includes(c.key);
                const clipped = humanCaps.includes(c.key) && !on;
                return (
                  <span
                    key={c.key}
                    title={clipped ? `${c.key} clipped by agent ceiling` : c.key}
                    className={`flex h-5 items-center justify-center rounded ${
                      clipped
                        ? "bg-[#7f95f8]/18 text-[#a8c5ff]"
                        : on
                          ? "bg-[#7f95f8]/18 text-[#9ec0f5]"
                          : "bg-white/[0.025] text-[#a6b5cf]"
                    }`}
                  >
                    {clipped ? "×" : on ? c.short : "·"}
                  </span>
                );
              })}
            </div>
          )}

          {/* Effective row */}
          <div className="grid grid-cols-[1fr_repeat(5,24px)] items-center gap-1 border-t border-white/[0.06] pt-1.5">
            <span className="font-semibold text-[#f3f6fd]">
              {agentCaps ? "H ∩ A" : "Effective"}
            </span>
            {CAP_LETTERS.map((c) => {
              const on = activeCaps.includes(c.key);
              return (
                <span
                  key={c.key}
                  className={`flex h-5 items-center justify-center rounded font-semibold ${
                    on ? "bg-[#5bdba2]/20 text-[#5bdba2]" : "bg-white/[0.03] text-[#a6b5cf]"
                  }`}
                >
                  {on ? c.short : "·"}
                </span>
              );
            })}
          </div>
        </div>

        {synthesizedTraverse && (
          <div className="mt-2.5 rounded-lg border border-white/[0.12] bg-white/[0.045] px-2.5 py-1.5 font-mono text-[12.5px] text-[#cbd5e8]">
            Synthesized traverse — ancestor only
          </div>
        )}
      </div>

      {/* Rule traces are owner-only; members keep the spacer so the footer stays at the bottom. */}
      <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
        {!owner ? null : activeRules.length === 0 ? (
          <div className="px-1 py-4 font-mono text-[13px] text-[#a6b5cf]">Default policy</div>
        ) : (
          activeRules.map((rule) => (
            <div key={`${rule.layer}-${rule.id}`} className="pr-well rounded-xl p-3">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-[13px] text-[#e6ecf8]">{rule.id}</span>
                <span
                  className={`shrink-0 rounded-full px-2 py-0.5 font-mono text-[12px] uppercase ${
                    rule.effect === "deny"
                      ? "bg-[#f27c7c]/15 text-[#f27c7c]"
                      : "bg-[#5bdba2]/15 text-[#5bdba2]"
                  }`}
                >
                  {rule.layer} · {rule.effect}
                </span>
              </div>
              <div className="mt-1.5 font-mono text-[12.5px] text-[#a6b5cf]">
                {(rule.capabilities ?? []).join(", ")}
              </div>
              {rule.reason && (
                <div className="mt-1 text-[12.5px] text-[#b6c3db]">{rule.reason}</div>
              )}
            </div>
          ))
        )}
      </div>

      {owner ? (
        <form
          onSubmit={runCustomExplain}
          className="flex items-center gap-2 border-t border-white/[0.06] p-3"
        >
          <input
            value={customPath}
            onChange={(e) => setCustomPath(e.target.value)}
            aria-label="Path to explain"
            placeholder="Explain path…"
            className="pr-well min-w-0 flex-1 rounded-xl px-3 py-1.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
          />
          <button
            type="submit"
            className="pr-pill shrink-0 rounded-xl px-3 py-1.5 font-mono text-[13px] text-[#e6ecf8]"
          >
            Eval
          </button>
        </form>
      ) : (
        <OwnerOnly className="border-t border-white/[0.06]" />
      )}
    </>
  );

  return (
    <div className="relative flex min-h-0 flex-1 gap-2.5 p-2 sm:p-2.5">
      {/* Desktop File Explorer (>= 1024px) */}
      <aside className="pr-surface hidden w-[248px] shrink-0 flex-col overflow-hidden rounded-2xl lg:flex xl:w-[268px]">
        {fileListContent}
      </aside>

      {/* Slide-over File Explorer (< 1024px) */}
      {filesDrawerOpen && (
        <div
          className="fixed inset-0 z-40 flex bg-[#04060d]/65 backdrop-blur-sm lg:hidden"
          onClick={() => setFilesDrawerOpen(false)}
        >
          <aside
            role="dialog"
            aria-modal="true"
            aria-label="File explorer"
            className="pr-elevated flex h-full w-[300px] max-w-[85vw] flex-col overflow-hidden rounded-r-2xl bg-[#0b0f1c]/97"
            onClick={(e) => e.stopPropagation()}
          >
            {fileListContent}
          </aside>
        </div>
      )}

      {/* Center: Source Canvas. One header row (breadcrumb, file facts, notices, actions) so the code
          gets the vertical space. Layout follows the pane's own width (container queries): the core
          actions stay visible and secondary tools fold into a "⋯" menu below @3xl. */}
      <section className="@container pr-surface flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl">
        <div className="relative flex h-10 shrink-0 items-center gap-2 border-b border-white/[0.06] px-2 @2xl:px-3">
          <div className="flex min-w-0 flex-1 items-center gap-1.5">
            <button
              type="button"
              onClick={() => setFilesDrawerOpen(true)}
              aria-label="Open file tree"
              className="pr-pill inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[#d2dbee] lg:hidden"
            >
              <IconMenu className="h-4 w-4" />
            </button>

            {/* Clickable Breadcrumbs: middle segments collapse to "…", the last never shrinks */}
            <nav
              aria-label="Breadcrumb"
              className="flex min-w-0 shrink items-center gap-0.5 overflow-hidden font-mono text-[13.5px]"
            >
              {breadcrumbs.map((seg, i) => {
                const segPath = breadcrumbs.slice(0, i + 1).join("/");
                const isLast = i === breadcrumbs.length - 1;
                const isMiddle = breadcrumbs.length > 2 && i > 0 && !isLast;
                return (
                  <Fragment key={segPath}>
                    {isMiddle && i === 1 && (
                      <span
                        className="flex shrink-0 items-center gap-0.5 @3xl:hidden"
                        title={breadcrumbs.slice(1, -1).join("/")}
                      >
                        <span className="text-white/20">/</span>
                        <span className="px-1 text-[#a6b5cf]">…</span>
                      </span>
                    )}
                    <span
                      className={`group items-center gap-0.5 ${
                        isMiddle ? "hidden min-w-0 @3xl:flex" : "flex"
                      } ${isLast ? "max-w-full shrink-0" : "min-w-0"}`}
                    >
                      {i > 0 && <span className="text-white/20">/</span>}
                      <button
                        type="button"
                        onClick={() => {
                          if (!selectPath(segPath)) return;
                          if (!isLast) {
                            setExpandedDirs((prev) => new Set(prev).add(segPath));
                          }
                        }}
                        aria-current={isLast ? "page" : undefined}
                        className={`truncate rounded px-1 py-0.5 transition ${
                          isLast
                            ? "font-medium text-[#f3f6fd]"
                            : "text-[#a6b5cf] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
                        }`}
                      >
                        {seg}
                      </button>
                      {isLast && selectedEntry && (
                        <button
                          type="button"
                          onClick={() => copyText("path", selectedEntry.path)}
                          title="Copy path"
                          aria-label="Copy path"
                          className="shrink-0 rounded p-0.5 text-[#a6b5cf] opacity-0 transition hover:bg-white/[0.06] hover:text-[#f3f6fd] focus:opacity-100 group-hover:opacity-100"
                        >
                          {copiedState === "path" ? (
                            <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                          ) : (
                            <IconCopy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      )}
                    </span>
                  </Fragment>
                );
              })}
            </nav>

            {dirty && (
              <span
                role="status"
                className="inline-flex h-5 shrink-0 items-center rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/14 px-2 font-mono text-[12.5px] text-[#cfe0ff]"
              >
                • Unsaved
              </span>
            )}

            {selectedEntry?.is_instruction_file && (
              <span
                title="Quarantined instruction file"
                className="inline-flex shrink-0 items-center gap-1 rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-1.5 py-0.5 font-mono text-[12.5px] text-[#a8c5ff]"
              >
                <IconQuarantine className="h-3.5 w-3.5" />
                <span className="hidden @4xl:inline">Quarantined</span>
              </span>
            )}

            {/* File facts + capability letters, inline when there is room (else the footer strip) */}
            {selectedEntry?.kind === "file" && shownFile?.allowed && !editMode && (
              <>
                <span className="hidden shrink-0 items-center gap-2 font-mono text-[12.5px] text-[#a6b5cf] @3xl:flex">
                  <span className="text-[#9ec0f5]">{languageLabel(lang)}</span>
                  <span>{plural(lines.length, "line")}</span>
                  <span>{formatByteSize(byteSize)}</span>
                  {shownFile.binary && <span className="text-[#cbd5e8]">binary</span>}
                </span>
                <span className="hidden shrink-0 items-center gap-0.5 @4xl:flex">
                  {CAP_LETTERS.map((c) => {
                    const on = activeCaps.includes(c.key);
                    return (
                      <span
                        key={c.key}
                        title={c.key}
                        className={`flex h-[18px] w-[18px] items-center justify-center rounded font-mono text-[12px] ${
                          on ? "bg-[#5bdba2]/14 text-[#5bdba2]" : "bg-white/[0.03] text-[#a6b5cf]"
                        }`}
                      >
                        {c.short}
                      </span>
                    );
                  })}
                </span>
              </>
            )}
          </div>

          <div className="flex shrink-0 items-center gap-1">
            {lineRange && selectedEntry && (
              <button
                type="button"
                onClick={() => {
                  copyText("link", window.location.href);
                }}
                title="Copy deep link to selected lines"
                className="pr-pill hidden h-7 items-center gap-1.5 rounded-full px-2.5 font-mono text-[12.5px] text-[#9ec0f5] @3xl:inline-flex"
              >
                {copiedState === "link" ? (
                  <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                ) : (
                  <IconLink className="h-3.5 w-3.5" />
                )}
                <span>
                  L{lineRange[0]}
                  {lineRange[1] !== lineRange[0] ? `–${lineRange[1]}` : ""}
                </span>
              </button>
            )}

            {savedNotice &&
              !editMode &&
              (savedNotice.path === "" || savedNotice.path === selectedEntry?.path) && (
                <span
                  role="status"
                  className="inline-flex h-7 max-w-[8rem] items-center gap-1 rounded-full border border-[#5bdba2]/25 bg-[#5bdba2]/10 pl-2 pr-0.5 font-mono text-[12.5px] text-[#5bdba2] @3xl:max-w-[18rem]"
                >
                  <IconCheck className="h-3.5 w-3.5 shrink-0" />
                  <span className="truncate">{savedNotice.text}</span>
                  <button
                    type="button"
                    onClick={() => setSavedNotice(null)}
                    aria-label="Dismiss notice"
                    className="shrink-0 rounded-full p-1 text-[#5bdba2]/80 hover:bg-white/[0.06] hover:text-white"
                  >
                    <IconClose className="h-3 w-3" />
                  </button>
                </span>
              )}

            {!newFile &&
              !editMode &&
              shownFile?.allowed &&
              shownFile.truncated &&
              !shownFile.binary && (
                <span
                  role="status"
                  title="Truncated preview: file exceeds the browser edit limit; edit via Git."
                  className="inline-flex h-7 shrink-0 items-center rounded-full border border-white/[0.12] bg-white/[0.045] px-2 font-mono text-[12.5px] text-[#cbd5e8]"
                >
                  Truncated
                  <span className="hidden @4xl:inline">&nbsp;· edit via Git</span>
                </span>
              )}

            {/* Owner-only ambient hygiene whispers, folded into one pill + opaque popover */}
            {owner && !newFile && selectedInsights.length > 0 && (
              <div ref={whisperRef} className="relative">
                <button
                  type="button"
                  onClick={() => setWhisperOpen((o) => !o)}
                  aria-expanded={whisperOpen}
                  aria-label={`${plural(selectedInsights.length, "ambient note")} for this path`}
                  title="Ambient observations for this path"
                  className={`inline-flex h-7 items-center gap-1 rounded-full border px-2 font-mono text-[12.5px] transition ${
                    selectedInsights.some((i) => i.severity === "attention")
                      ? "border-[#9ec0f5]/30 bg-[#7f95f8]/10 text-[#cfe0ff]"
                      : "border-[#9ec0f5]/30 bg-[#7f95f8]/10 text-[#cfe0ff]"
                  }`}
                >
                  <IconAmbientPulse className="h-3.5 w-3.5" />
                  <span>{selectedInsights.length}</span>
                </button>
                {whisperOpen && (
                  <div className="pr-elevated absolute right-0 top-full z-30 mt-1.5 max-h-[min(60vh,28rem)] w-[min(30rem,calc(100vw-2rem))] space-y-1.5 overflow-y-auto rounded-xl bg-[#0b0f1c]/97 p-2">
                    {selectedInsights.map((insight) => {
                      const action = insight.action;
                      let actionLabel: string | undefined;
                      let onAction: (() => void) | undefined;
                      if (action?.kind === "draft_policy_rule" && onDraftPolicyRule) {
                        actionLabel = "Restrict access…";
                        onAction = () => {
                          setWhisperOpen(false);
                          onDraftPolicyRule({
                            zoneName: action.zone_name,
                            pathGlob: action.path_glob,
                            target: insight.target,
                            tomlSnippet: action.toml_snippet,
                          });
                        };
                      } else if (action?.kind === "add_overlay_guard" && onAddOverlayGuard) {
                        actionLabel = "Add to Overlay Guard";
                        onAction = () => {
                          setBusyInsightId(insight.id);
                          Promise.resolve(
                            onAddOverlayGuard(action.path, action.suggested_scope),
                          ).finally(() =>
                            setBusyInsightId((cur) => (cur === insight.id ? null : cur)),
                          );
                        };
                      }
                      return (
                        <AmbientWhisperChip
                          key={insight.id}
                          compact
                          severity={insight.severity}
                          title={insight.title}
                          detail={insight.detail}
                          actionLabel={actionLabel}
                          onAction={onAction}
                          busy={busyInsightId === insight.id}
                          onDismiss={
                            onDismissInsight
                              ? () => {
                                  setBusyInsightId(insight.id);
                                  Promise.resolve(onDismissInsight(insight.id)).finally(() =>
                                    setBusyInsightId((cur) => (cur === insight.id ? null : cur)),
                                  );
                                }
                              : undefined
                          }
                        />
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {selectedEntry?.kind === "file" && shownFile?.allowed && !editMode && (
              <>
                {isMarkdown && (
                  <div
                    role="group"
                    aria-label="Markdown view mode"
                    className="inline-flex h-7 items-center rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]"
                  >
                    <button
                      type="button"
                      onClick={() => {
                        setFindNonce(0);
                        setBlameOpen(false);
                        setLineRange(null);
                        setMdMode("preview");
                      }}
                      className={`h-6 rounded-full px-2.5 transition ${
                        showMarkdownPreview
                          ? "pr-pill-active"
                          : "text-[#a6b5cf] hover:text-[#f3f6fd]"
                      }`}
                    >
                      Preview
                    </button>
                    <button
                      type="button"
                      onClick={() => setMdMode("source")}
                      className={`h-6 rounded-full px-2.5 transition ${
                        !showMarkdownPreview
                          ? "pr-pill-active"
                          : "text-[#a6b5cf] hover:text-[#f3f6fd]"
                      }`}
                    >
                      Source
                    </button>
                  </div>
                )}
                <button
                  type="button"
                  onClick={openFind}
                  onPointerEnter={preloadMonacoWrapper}
                  title={`Find in file (${formatShortcutLabel("f", clientOS)}). Opens the full editor view.`}
                  aria-label="Find in file"
                  className="pr-pill inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[#a6b5cf] transition hover:text-[#f3f6fd]"
                >
                  <IconSearch className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  disabled={
                    !activeCaps.includes("write") ||
                    Boolean(shownFile.truncated) ||
                    Boolean(shownFile.binary)
                  }
                  onClick={() => {
                    setEditDraft(shownFile.content ?? "");
                    setFindNonce(0);
                    // Sticky rich view keeps one Monaco instance alive across Edit toggles.
                    setRichView(true);
                    setEditMode(true);
                  }}
                  onPointerEnter={preloadMonacoWrapper}
                  onFocus={preloadMonacoWrapper}
                  title={
                    shownFile.truncated || shownFile.binary
                      ? "File is too large or binary to edit in the browser; edit via Git"
                      : activeCaps.includes("write")
                        ? "Edit file (saving creates a commit)"
                        : `WRITE denied for ${identity.label}`
                  }
                  aria-label="Edit file"
                  className="pr-pill inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[#a6b5cf] hover:text-[#f3f6fd] disabled:cursor-not-allowed disabled:opacity-35"
                >
                  <IconEdit className="h-4 w-4" />
                </button>
              </>
            )}

            {tree && !editMode && !newFile && (
              <button
                type="button"
                onClick={() => {
                  setNewFileError(null);
                  setFindNonce(0);
                  setNewFile({ folder: currentFolder, name: "", draft: "", message: "" });
                }}
                onPointerEnter={preloadMonacoWrapper}
                onFocus={preloadMonacoWrapper}
                title="New file (saving creates a commit)"
                aria-label="New file"
                className="pr-pill inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[#a6b5cf] hover:text-[#f3f6fd]"
              >
                <IconPlus className="h-4 w-4" />
              </button>
            )}

            {/* Secondary tools: inline when the pane is wide, folded into "⋯" below @3xl */}
            {selectedEntry?.kind === "file" && shownFile?.allowed && !editMode && (
              <div className="hidden items-center gap-1 @3xl:flex">
                <button
                  type="button"
                  onClick={() => setBlameOpen((b) => !b)}
                  title="Toggle git blame gutter"
                  aria-label="Toggle git blame"
                  aria-pressed={blameOpen}
                  className={`inline-flex h-7 w-7 items-center justify-center rounded-lg transition ${
                    blameOpen ? "pr-pill-active" : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                  }`}
                >
                  <IconBlame className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  onClick={() => setSoftWrapOverride(!softWrap)}
                  title="Toggle soft wrap"
                  aria-label="Toggle soft wrap"
                  aria-pressed={softWrap}
                  className={`inline-flex h-7 w-7 items-center justify-center rounded-lg transition ${
                    softWrap ? "pr-pill-active" : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                  }`}
                >
                  <IconWrap className="h-4 w-4" />
                </button>
                {richView && (
                  <button
                    type="button"
                    onClick={() => setMinimapOpen((m) => !m)}
                    title={minimapOpen ? "Hide minimap" : "Show minimap"}
                    aria-label="Toggle minimap"
                    aria-pressed={minimapOpen}
                    className={`inline-flex h-7 items-center justify-center rounded-lg px-2 font-mono text-[12.5px] transition ${
                      minimapOpen ? "pr-pill-active" : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                    }`}
                  >
                    Map
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => copyText("source", shownFile.content ?? "")}
                  title="Copy source"
                  aria-label="Copy source"
                  className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-lg text-[#a6b5cf] hover:text-[#f3f6fd]"
                >
                  {copiedState === "source" ? (
                    <IconCheck className="h-4 w-4 text-[#5bdba2]" />
                  ) : (
                    <IconCopy className="h-4 w-4" />
                  )}
                </button>
                <span aria-hidden="true" className="mx-0.5 h-4 w-px bg-white/[0.1]" />
                <ConfirmButton
                  disabled={!activeCaps.includes("write") || savingFile}
                  confirmLabel="Delete"
                  question={`Delete ${selectedEntry.path}?`}
                  onConfirm={() => void handleDeleteFile()}
                  title={
                    activeCaps.includes("write")
                      ? "Delete file (creates a commit)"
                      : `WRITE denied for ${identity.label}`
                  }
                  aria-label="Delete file"
                  className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-lg text-[#a6b5cf] hover:text-[#f27c7c] disabled:opacity-35"
                >
                  <IconTrash className="h-4 w-4" />
                </ConfirmButton>
              </div>
            )}

            {!editMode &&
              !newFile &&
              ((selectedEntry?.kind === "file" && shownFile?.allowed) || (owner && selectedEntry)) && (
                <div ref={moreRef} className="relative @3xl:hidden">
                  <button
                    type="button"
                    onClick={() => setMoreOpen((o) => !o)}
                    aria-expanded={moreOpen}
                    aria-haspopup="menu"
                    aria-label="More file actions"
                    title="More actions"
                    className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg font-mono text-[14px] leading-none transition ${
                      moreOpen ? "pr-pill-active" : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                    }`}
                  >
                    ⋯
                  </button>
                  {moreOpen && (
                    <div
                      role="menu"
                      className="pr-elevated absolute right-0 top-full z-30 mt-1.5 w-56 rounded-xl bg-[#0b0f1c] p-1"
                    >
                      {selectedEntry?.kind === "file" && shownFile?.allowed && (
                        <>
                          <button
                            type="button"
                            role="menuitemcheckbox"
                            aria-checked={blameOpen}
                            onClick={() => {
                              setBlameOpen((b) => !b);
                              setMoreOpen(false);
                            }}
                            className={MENU_ROW}
                          >
                            <IconBlame className="h-4 w-4" />
                            <span className="flex-1">Git blame</span>
                            {blameOpen && <IconCheck className="h-3.5 w-3.5 text-[#9ec0f5]" />}
                          </button>
                          <button
                            type="button"
                            role="menuitemcheckbox"
                            aria-checked={softWrap}
                            onClick={() => {
                              setSoftWrapOverride(!softWrap);
                              setMoreOpen(false);
                            }}
                            className={MENU_ROW}
                          >
                            <IconWrap className="h-4 w-4" />
                            <span className="flex-1">Soft wrap</span>
                            {softWrap && <IconCheck className="h-3.5 w-3.5 text-[#9ec0f5]" />}
                          </button>
                          {richView && (
                            <button
                              type="button"
                              role="menuitemcheckbox"
                              aria-checked={minimapOpen}
                              onClick={() => {
                                setMinimapOpen((m) => !m);
                                setMoreOpen(false);
                              }}
                              className={MENU_ROW}
                            >
                              <IconPanel className="h-4 w-4" />
                              <span className="flex-1">Minimap</span>
                              {minimapOpen && <IconCheck className="h-3.5 w-3.5 text-[#9ec0f5]" />}
                            </button>
                          )}
                          <button
                            type="button"
                            role="menuitem"
                            onClick={() => {
                              copyText("source", shownFile.content ?? "");
                              setMoreOpen(false);
                            }}
                            className={MENU_ROW}
                          >
                            <IconCopy className="h-4 w-4" />
                            <span className="flex-1">Copy source</span>
                          </button>
                          {lineRange && (
                            <button
                              type="button"
                              role="menuitem"
                              onClick={() => {
                                copyText("link", window.location.href);
                                setMoreOpen(false);
                              }}
                              className={MENU_ROW}
                            >
                              <IconLink className="h-4 w-4" />
                              <span className="flex-1">
                                Copy link to L{lineRange[0]}
                                {lineRange[1] !== lineRange[0] ? `–${lineRange[1]}` : ""}
                              </span>
                            </button>
                          )}
                        </>
                      )}
                      {owner && selectedEntry && (
                        <button
                          type="button"
                          role="menuitem"
                          onClick={(e) => {
                            const rect = e.currentTarget.getBoundingClientRect();
                            setMoreOpen(false);
                            openPolicyMenu(
                              {
                                kind: selectedEntry.kind === "dir" ? "dir" : "file",
                                path: selectedEntry.path,
                              },
                              rect.left,
                              rect.bottom + 4,
                            );
                          }}
                          className={MENU_ROW}
                        >
                          <IconShield className="h-4 w-4" />
                          <span className="flex-1">Restrict access…</span>
                        </button>
                      )}
                      {selectedEntry?.kind === "file" && shownFile?.allowed && (
                        <>
                          <div role="separator" className="my-1 h-px bg-white/[0.08]" />
                          <ConfirmButton
                            disabled={!activeCaps.includes("write") || savingFile}
                            confirmLabel="Delete"
                            question={`Delete ${selectedEntry.path}?`}
                            onConfirm={() => {
                              setMoreOpen(false);
                              void handleDeleteFile();
                            }}
                            title={
                              activeCaps.includes("write")
                                ? "Delete file (creates a commit)"
                                : `WRITE denied for ${identity.label}`
                            }
                            aria-label="Delete file"
                            className={`${MENU_ROW} hover:text-[#f27c7c]!`}
                          >
                            <IconTrash className="h-4 w-4" />
                            <span className="flex-1">Delete file</span>
                          </ConfirmButton>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}

            {owner && selectedEntry && !editMode && !newFile && (
              <button
                type="button"
                onClick={(e) => {
                  const rect = e.currentTarget.getBoundingClientRect();
                  openPolicyMenu(
                    {
                      kind: selectedEntry.kind === "dir" ? "dir" : "file",
                      path: selectedEntry.path,
                    },
                    rect.left,
                    rect.bottom + 6,
                  );
                }}
                title={`Restrict access to ${selectedEntry.path}`}
                aria-label="Restrict access"
                className="pr-pill hidden h-7 shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[13px] text-[#9ec0f5] hover:text-[#f3f6fd] @3xl:inline-flex"
              >
                <IconShield className="h-3.5 w-3.5" />
                <span>Restrict</span>
              </button>
            )}

            {owner && targetIdentity && !editMode && !newFile && (
              <button
                type="button"
                onClick={() => setMirrorEnabled((m) => !m)}
                aria-pressed={isMirrorActive}
                title="Compare what you see vs what a contractor, GitHub, or AI agent receives (hold Alt to quick-peek)"
                aria-label="Compare views"
                className={`inline-flex h-7 shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[13px] transition ${
                  isMirrorActive
                    ? "pr-pill-active text-[#67d6dc]"
                    : "pr-pill text-[#b2c0d8] hover:text-[#f3f6fd]"
                }`}
              >
                <IconSplitLens className="h-3.5 w-3.5" />
                <span className="hidden @2xl:inline @3xl:hidden">Compare</span>
                <span className="hidden @3xl:inline">Compare Views</span>
              </button>
            )}

            <button
              type="button"
              onClick={() => setInspectorOpen((o) => !o)}
              aria-label="Access panel"
              aria-expanded={inspectorOpen}
              title="Inspect folder access rules and permissions for this path"
              className={`inline-flex h-7 shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[13px] transition ${
                inspectorOpen
                  ? "pr-pill-active"
                  : "pr-pill text-[#b2c0d8] hover:text-[#f3f6fd]"
              }`}
            >
              <IconPanel className="h-3.5 w-3.5" />
              <span className="hidden @2xl:inline">Access</span>
            </button>
          </div>
        </div>

        {error && (
          <div
            role="alert"
            className="shrink-0 border-b border-[#f27c7c]/25 bg-[#f27c7c]/10 px-3 py-1 font-mono text-[13px] text-[#f27c7c]"
          >
            {error}
          </div>
        )}

        {saveConflict && (
          <div
            role="alert"
            className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[#9ec0f5]/25 bg-[#7f95f8]/10 px-3 py-1 font-mono text-[13px] text-[#a8c5ff]"
          >
            <span className="min-w-0 break-words">{saveConflict}</span>
            <button
              type="button"
              title="Load the branch's current version of this file. Your unsaved edit is discarded."
              onClick={() => {
                setSaveConflict(null);
                setEditMode(false);
                setReloadNonce((n) => n + 1);
              }}
              className="pr-pill shrink-0 rounded-full px-3 py-0.5 text-[12.5px] text-[#f3f6fd]"
            >
              Reload
            </button>
          </div>
        )}

        {/* Source or Directory Body (or Two-Eyes Glass Wall Mirror for owners) */}
        <div
          aria-busy={loadingFile}
          className="relative flex min-h-0 flex-1 flex-col overflow-y-auto lg:overflow-hidden"
        >
          {loadingFile && shownFile && (
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-x-0 top-0 z-10 h-0.5 animate-pulse bg-[#7f95f8]/80"
            />
          )}
          {mirrorVisible && targetIdentity ? (
            <GlassWallMirror
              ownerIdentity={leftIdentity}
              targetIdentity={targetIdentity}
              targetPresets={targetPresets}
              onChangeTarget={(preset) => setMirrorTargetId(preset.id)}
              mode={mirrorMode}
              onChangeMode={setMirrorMode}
              peeking={altPeeking}
              selectedPath={selectedEntry?.path ?? selectedPath}
              ownerEntry={selectedEntry}
              targetEntry={
                selectedEntry ? rightTreeMap.get(selectedEntry.path) ?? null : null
              }
              ownerFile={mirrorOwnerFile}
              targetFile={
                mirrorRightFile?.path === (selectedEntry?.path ?? selectedPath)
                  ? mirrorRightFile
                  : null
              }
              ownerCommit={mirrorLeftCommit}
              targetCommit={mirrorRightCommit}
              targetTreeStats={
                mirrorRightTree
                  ? {
                      visible: mirrorRightTree.visible_count,
                      traverseOnly: mirrorRightTree.traverse_only_count,
                      omitted: mirrorRightTree.omitted_count,
                    }
                  : undefined
              }
              loadingTarget={loadingMirrorTree || loadingMirrorFile}
              loadingOwner={loadingMirrorFile && !mirrorOwnerFile}
              softWrap={softWrap}
              secretRefs={secretRefs}
              onOpenPolicyComposer={(t) => openDirectComposer(t)}
              onCloseMirror={() => {
                setMirrorEnabled(false);
                setAltPeeking(false);
              }}
            />
          ) : newFile ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleCreateFile();
              }}
              className="flex min-h-0 flex-1 flex-col gap-2 p-2"
            >
              <div className="flex shrink-0 flex-wrap items-center gap-2">
                <label className="flex min-w-[220px] flex-1 items-center gap-1 font-mono text-[13.5px]">
                  {newFile.folder && (
                    <span className="shrink-0 text-[#a6b5cf]">{newFile.folder}/</span>
                  )}
                  <input
                    autoFocus
                    value={newFile.name}
                    onChange={(e) => setNewFile({ ...newFile, name: e.target.value })}
                    aria-label="New file path, relative to the current folder"
                    placeholder="new-file.md"
                    className="pr-well h-7 min-w-0 flex-1 rounded-full px-3 text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                  />
                </label>
                <input
                  value={newFile.message}
                  onChange={(e) => setNewFile({ ...newFile, message: e.target.value })}
                  aria-label="Commit message"
                  placeholder={`Add ${newFile.name.trim() || "file"}`}
                  className="pr-well h-7 w-48 min-w-0 rounded-full px-3 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none lg:w-56"
                />
                <button
                  type="submit"
                  disabled={savingFile}
                  title={`Create & commit (${formatShortcutLabel("s", clientOS)})`}
                  className="pr-action-btn inline-flex h-7 items-center gap-1 rounded-full px-3 text-[13px] disabled:opacity-50"
                >
                  <IconCheck className="h-3.5 w-3.5" />
                  <span>{savingFile ? "Creating…" : "Create"}</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNewFile(null);
                    setNewFileError(null);
                    setFindNonce(0);
                  }}
                  className="pr-pill inline-flex h-7 items-center rounded-full px-2.5 font-mono text-[12.5px] text-[#b6c3db]"
                >
                  Cancel
                </button>
              </div>
              <ErrorNote message={newFileError} />
              <div className="flex min-h-[320px] flex-1 flex-col overflow-hidden rounded-xl border border-white/[0.08] lg:min-h-0">
                <Suspense fallback={<CodeSkeleton />}>
                  <MonacoCodeEditor
                    value={newFile.draft}
                    onChange={(next) =>
                      setNewFile((prev) => (prev ? { ...prev, draft: next } : prev))
                    }
                    path={candidateNewFilePath}
                    readOnly={false}
                    wordWrap={softWrap}
                    minimap={minimapOpen}
                    stickyScroll={true}
                    markers={newFileMarkers}
                    onSave={() => {
                      if (!savingFile) void handleCreateFile();
                    }}
                    findTriggerNonce={findNonce}
                    minHeight={0}
                    className="min-h-[320px] flex-1 lg:min-h-0"
                    ariaLabel="Contents of the new file"
                  />
                </Suspense>
              </div>
            </form>
          ) : selectedEntry?.kind === "dir" ? (
            <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto p-2">
              {dirChildren.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
                  <IconFolderNode
                    traverseOnly={selectedEntry.visibility_state === "traverse_only"}
                    className="h-8 w-8 text-[#7f95f8]/80"
                  />
                  <div className="font-mono text-[14px] text-[#dce4f5]">{selectedEntry.path}/</div>
                  <div className="font-mono text-[13px] text-[#a6b5cf]">
                    {selectedEntry.visibility_state === "visible"
                      ? "Empty folder"
                      : selectedEntry.visibility_state.replace("_", " ")}
                  </div>
                </div>
              ) : (
                dirChildren.map((child) => (
                  <button
                    key={child.path}
                    type="button"
                    onClick={() => selectPath(child.path)}
                    onContextMenu={
                      owner
                        ? (e) => {
                            e.preventDefault();
                            openPolicyMenu(
                              { kind: child.kind === "dir" ? "dir" : "file", path: child.path },
                              e.clientX,
                              e.clientY,
                            );
                          }
                        : undefined
                    }
                    className="flex w-full items-center justify-between gap-3 rounded-xl px-3 py-1.5 text-left transition hover:bg-white/[0.04]"
                  >
                    <span className="flex min-w-0 items-center gap-2.5">
                      {child.kind === "dir" ? (
                        <IconFolderNode className="h-4 w-4 text-[#7f95f8]" />
                      ) : (
                        <IconFileNode className="h-4 w-4 text-[#a6b5cf]" />
                      )}
                      <span className="truncate font-mono text-[14px] text-[#e6ecf8]">
                        {child.path.split("/").pop()}
                      </span>
                    </span>
                    <span className="flex shrink-0 items-center gap-1">
                      {CAP_LETTERS.map((c) => {
                        const on = child.effective.includes(c.key);
                        return (
                          <span
                            key={c.key}
                            className={`flex h-5 w-5 items-center justify-center rounded font-mono text-[12px] ${
                              on ? "bg-[#5bdba2]/14 text-[#5bdba2]" : "bg-white/[0.025] text-[#a6b5cf]"
                            }`}
                          >
                            {c.short}
                          </span>
                        );
                      })}
                    </span>
                  </button>
                ))
              )}
            </div>
          ) : awaitingFile ? (
            <CodeSkeleton />
          ) : shownFile?.allowed && shownFile.binary ? (
            <div
              className={`flex min-h-0 flex-1 flex-col items-center justify-center overflow-y-auto p-8 text-center transition-opacity ${
                loadingFile ? "opacity-60" : ""
              }`}
            >
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white/[0.1] bg-white/[0.04]">
                <IconFileNode className="h-6 w-6 text-[#9ec0f5]" />
              </div>
              <div className="mt-4 font-mono text-[14.5px] font-medium text-[#f3f6fd]">
                {selectedEntry?.path}
              </div>
              <div className="mt-1.5 max-w-md font-mono text-[13.5px] text-[#a6b5cf]">
                Binary file — cannot be viewed or edited in the browser; edit via Git.
              </div>
            </div>
          ) : shownFile?.allowed && !editMode && (shownFile.content ?? "") === "" ? (
            <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
              <IconFileNode className="h-6 w-6 text-[#a6b5cf]" />
              <div className="font-mono text-[14px] text-[#cbd5e8]">Empty file · 0 bytes</div>
            </div>
          ) : shownFile?.allowed && (editMode || (richView && !showMarkdownPreview)) ? (
            // One wrapper + one Monaco instance for read-only and edit, so toggling Edit
            // never remounts the editor or loses scroll/cursor.
            <div
              className={`flex min-h-0 flex-1 flex-col transition-opacity ${
                loadingFile && !editMode ? "opacity-60" : ""
              }`}
            >
              <Suspense fallback={<CodeSkeleton />}>
                <MonacoCodeEditor
                  value={editMode ? editDraft : (shownFile.content ?? "")}
                  onChange={editMode ? setEditDraft : undefined}
                  path={shownFile.path || activeFilePath}
                  readOnly={!editMode || savingFile}
                  wordWrap={softWrap}
                  minimap={minimapOpen}
                  stickyScroll={true}
                  markers={editMode ? editMarkers : undefined}
                  onSave={
                    editMode
                      ? () => {
                          if (dirty && !savingFile) void handleSaveFile();
                        }
                      : undefined
                  }
                  selectedLines={editMode ? null : lineRange}
                  onSelectLines={
                    editMode
                      ? undefined
                      : (next) => {
                          setLineRange(next);
                          onSelectLines?.(next);
                        }
                  }
                  scrollToLine={editMode ? null : scrollTargetLine}
                  blameLines={!editMode && blameOpen ? blameLines : null}
                  findTriggerNonce={findNonce}
                  minHeight={0}
                  className="min-h-[320px] flex-1 lg:min-h-0"
                  ariaLabel={`${editMode ? "Contents" : "Source"} of ${activeFilePath || "file"}`}
                />
              </Suspense>
            </div>
          ) : shownFile?.allowed && showMarkdownPreview ? (
            <div
              className={`min-h-0 flex-1 overflow-y-auto transition-opacity ${
                loadingFile ? "opacity-60" : ""
              }`}
            >
              <MarkdownPreview
                content={shownFile.content ?? ""}
                currentPath={shownFile.path}
                onOpenFile={openPathStable}
              />
            </div>
          ) : shownFile?.allowed ? (
            <div
              className={`flex min-h-0 flex-1 flex-col transition-opacity ${
                loadingFile ? "opacity-60" : ""
              }`}
            >
              <SourceViewer
                key={shownFile.path}
                content={shownFile.content ?? ""}
                path={shownFile.path || activeFilePath}
                wrap={softWrap}
                selectedLines={lineRange}
                onSelectLines={(next) => {
                  setLineRange(next);
                  onSelectLines?.(next);
                }}
                scrollTarget={scrollTargetLine}
                blame={blameOpen ? blameLines : null}
                ariaLabel={`Source of ${activeFilePath || "file"}`}
              />
            </div>
          ) : shownFile ? (
            <div className="flex min-h-0 flex-1 flex-col items-center justify-center overflow-y-auto p-8 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-[#f27c7c]/25 bg-[#f27c7c]/10">
                <IconLock className="h-6 w-6 text-[#f27c7c]" />
              </div>
              <div className="mt-4 font-mono text-[14.5px] font-medium text-[#f3f6fd]">
                {selectedEntry?.path}
              </div>
              <div className="mt-1.5 max-w-md font-mono text-[13.5px] text-[#a6b5cf]">
                {shownFile.reason}
              </div>
            </div>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col items-center justify-center gap-2 p-8 text-center">
              <IconFileNode className="h-6 w-6 text-[#a6b5cf]" />
              <div className="font-mono text-[14px] text-[#cbd5e8]">
                {fileTarget ? `Couldn't load ${fileTarget}` : "No file selected"}
              </div>
              {fileTarget && (
                <button
                  type="button"
                  onClick={() => setReloadNonce((n) => n + 1)}
                  className="pr-pill inline-flex h-7 items-center rounded-full px-3 font-mono text-[13px] text-[#e6ecf8]"
                >
                  Retry
                </button>
              )}
            </div>
          )}
        </div>

        {/* Editor footer: commit message, dirty state, shortcut hint, Cancel + Save */}
        {editMode && shownFile?.allowed && (
          <div className="flex shrink-0 flex-wrap items-center gap-2 border-t border-white/[0.06] px-2.5 py-1.5">
            <input
              value={commitMessage}
              onChange={(e) => setCommitMessage(e.target.value)}
              aria-label="Commit message"
              placeholder={`Update ${selectedEntry?.path ?? activeFilePath}`}
              className="pr-well h-7 min-w-[10rem] flex-1 rounded-full px-3 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
            <span
              className={`shrink-0 font-mono text-[12.5px] ${dirty ? "text-[#cfe0ff]" : "text-[#a6b5cf]"}`}
            >
              {dirty ? "• Unsaved changes" : "No changes"}
            </span>
            <span className="hidden shrink-0 font-mono text-[12.5px] text-[#a6b5cf] @2xl:inline">
              {formatShortcutLabel("s", clientOS)} to save
            </span>
            {dirty ? (
              <ConfirmButton
                confirmLabel="Discard"
                question="Discard changes?"
                onConfirm={() => {
                  setEditMode(false);
                  setFindNonce(0);
                }}
                className="pr-pill inline-flex h-7 shrink-0 items-center rounded-full px-2.5 font-mono text-[12.5px] text-[#b6c3db]"
              >
                Cancel
              </ConfirmButton>
            ) : (
              <button
                type="button"
                onClick={() => {
                  setEditMode(false);
                  setFindNonce(0);
                }}
                className="pr-pill inline-flex h-7 shrink-0 items-center rounded-full px-2.5 font-mono text-[12.5px] text-[#b6c3db]"
              >
                Cancel
              </button>
            )}
            <button
              type="button"
              disabled={!dirty || savingFile}
              onClick={() => void handleSaveFile()}
              title={`Save & commit (${formatShortcutLabel("s", clientOS)})`}
              className="pr-action-btn inline-flex h-7 shrink-0 items-center gap-1 rounded-full px-3 text-[13px] disabled:opacity-50"
            >
              <IconCheck className="h-3.5 w-3.5" />
              <span>{savingFile ? "Saving…" : "Save"}</span>
            </button>
          </div>
        )}

        {/* Compact facts strip, only when the header is too narrow to carry them inline */}
        {selectedEntry?.kind === "file" && shownFile?.allowed && !editMode && (
          <div className="flex shrink-0 items-center justify-between gap-3 border-t border-white/[0.06] px-3 py-1 font-mono text-[12.5px] text-[#a6b5cf] @3xl:hidden">
            <div className="flex items-center gap-3">
              <span className="text-[#9ec0f5]">{languageLabel(lang)}</span>
              <span>{plural(lines.length, "line")}</span>
              <span>{formatByteSize(byteSize)}</span>
              {shownFile.binary && <span className="text-[#cbd5e8]">binary</span>}
              {shownFile.truncated && <span className="text-[#cbd5e8]">truncated</span>}
            </div>
            <div className="hidden items-center gap-1 sm:flex">
              {CAP_LETTERS.map((c) => {
                const on = activeCaps.includes(c.key);
                return (
                  <span
                    key={c.key}
                    title={c.key}
                    className={`flex h-[18px] w-[18px] items-center justify-center rounded text-[12px] ${
                      on ? "bg-[#5bdba2]/14 text-[#5bdba2]" : "bg-white/[0.03] text-[#a6b5cf]"
                    }`}
                  >
                    {c.short}
                  </span>
                );
              })}
            </div>
          </div>
        )}
      </section>

      {/* Inline Policy Drawer (>= 1280px) */}
      {inspectorOpen && (
        <aside className="pr-surface hidden w-[300px] shrink-0 flex-col overflow-hidden rounded-2xl xl:flex 2xl:w-[336px]">
          {policyContent}
        </aside>
      )}

      {/* Slide-over Policy Drawer (< 1280px) */}
      {inspectorOpen && (
        <div
          className="fixed inset-0 z-40 flex justify-end bg-[#04060d]/60 backdrop-blur-sm xl:hidden"
          onClick={() => setInspectorOpen(false)}
        >
          <aside
            role="dialog"
            aria-modal="true"
            aria-label="Policy capability inspector"
            className="pr-elevated flex h-full w-[328px] max-w-[88vw] flex-col overflow-hidden rounded-l-2xl bg-[#0b0f1c]/97"
            onClick={(e) => e.stopPropagation()}
          >
            {policyContent}
          </aside>
        </div>
      )}

      {owner && policyMenu && (
        <PolicyContextMenu
          target={policyMenu.target}
          x={policyMenu.x}
          y={policyMenu.y}
          agentProfiles={agentProfiles}
          onSelectIntent={(intent) => {
            const matchingZones =
              policyMenu.target.kind === "secret" ? [] : policyMenu.target.matchingZones;
            setPolicyMenu(null);
            setComposerState({ intent, matchingZones });
          }}
          onClose={() => setPolicyMenu(null)}
        />
      )}

      {owner && composerState && (
        <PolicyIntentComposer
          initialIntent={composerState.intent}
          matchingZones={composerState.matchingZones}
          identity={leftIdentity}
          owner={owner}
          refName={refName}
          directory={directory}
          agentProfiles={agentProfiles}
          client={api}
          onClose={() => setComposerState(null)}
          onOpenInPolicyEditor={onOpenPolicyEditor}
          onApplied={(res) => {
            setSavedNotice({
              path: selectedEntry?.path ?? "",
              text: res.commit
                ? `Policy ${shortOid(res.commit)} committed`
                : `Policy updated (${plural(res.rule_count, "rule")})`,
            });
            setReloadNonce((n) => n + 1);
            onPolicySaved?.();
          }}
        />
      )}
    </div>
  );
}
