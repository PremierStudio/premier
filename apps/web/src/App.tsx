import {
  Fragment,
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from "react";
import {
  agentProfileNames,
  api,
  authApi,
  errorText,
  lensPresets,
  onUnauthorized,
  invalidateApiCache,
  repoPath,
  setCurrentRepo,
  type AgentLane,
  suggestionForApproval,
  type AgentSessionRecord,
  type AuditEvent,
  type AuthStatus,
  type BranchRecord,
  type BudgetAlert,
  type Directory,
  type GitCommitSummary,
  type HealthResponse,
  type HygieneInsight,
  type HygieneInsightsResponse,
  type IdentityPreset,
  type McpDriftAlert,
  type PendingApproval,
  type PolicySuggestion,
  type Repo,
  type SessionInsight,
  type User,
} from "./api";
import type { PolicyDraftRule } from "./components/AccessDiffView";
import { AuthLoadingScreen, SetupScreen, SignInScreen } from "./components/AuthScreens";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { HygieneDrawer } from "./components/HygieneDrawer";
import {
  IconBranches,
  IconBranchRef,
  IconCage,
  IconChanges,
  IconCheck,
  IconChevron,
  IconClose,
  IconCode,
  IconFileNode,
  IconGear,
  IconIntersection,
  IconLens,
  IconLock,
  IconOSBadge,
  IconPlus,
  IconPolicy,
  IconQuarantine,
  IconRefresh,
  IconSearch,
  IconTimeline,
  IconUser,
  IconVault,
  IconWorktable,
  PremierMark,
} from "./components/Icons";
import { OwnerOnly, SECONDARY_BTN } from "./components/forms";
import { AgentConnectModal } from "./components/AgentConnectModal";
import { BrandIcon } from "./components/BrandIcons";
import { GithubCompanionModal, GithubTopbarPill } from "./components/GithubCompanionPanel";
import { KnockApprovalCard, type KnockCardHandle } from "./components/KnockApprovalCard";
import { McpApprovalCard } from "./components/McpApprovalCard";
import { PolicyGraduationModal } from "./components/PolicyGraduationModal";
import { EmptyRepoPanel, NewRepoDialog } from "./components/RepoDialogs";
import {
  filterApprovalsForLens,
  filterSessionsForLens,
  sessionHasUncommittedChanges,
  type FocusTarget,
} from "./components/worktable/types";
import {
  WorktableView,
  parseFocusParam,
  serializeFocusParam,
} from "./components/worktable/WorktableView";
import type { SecretFocusTarget } from "./components/SecretsOverlaysView";
import {
  formatShortcut,
  formatShortcutLabel,
  getOSLabel,
  isEditableEventTarget,
  isMac,
  useClientOS,
} from "./lib/platform";
import { notifyPendingApproval } from "./lib/notify";
import {
  canCycleIdentityLens,
  canHandleApprovalHotkey,
  canToggleCommandPalette,
  getSandboxBadge,
  getTreeTruncationInfo,
  hasActiveModalDialog,
  hasOtherModalDialog,
  type TreeTruncationInfo,
} from "./lib/uiHelpers";
import { useModalDialog } from "./lib/useModalDialog";
import { ViewSkeleton } from "./components/ViewSkeletons";

const loadZoneXRayView = () =>
  import("./components/ZoneXRayView").then((m) => ({ default: m.ZoneXRayView }));
const loadReviewRoundsView = () =>
  import("./components/ReviewRoundsView").then((m) => ({ default: m.ReviewRoundsView }));
const loadBranchesView = () =>
  import("./components/BranchesView").then((m) => ({ default: m.BranchesView }));
const loadAgentMissionControl = () =>
  import("./components/AgentMissionControl").then((m) => ({ default: m.AgentMissionControl }));
const loadAgentTraceView = () =>
  import("./components/AgentTraceView").then((m) => ({ default: m.AgentTraceView }));
const loadSecretsOverlaysView = () =>
  import("./components/SecretsOverlaysView").then((m) => ({ default: m.SecretsOverlaysView }));
const loadAccessDiffView = () =>
  import("./components/AccessDiffView").then((m) => ({ default: m.AccessDiffView }));
const loadSettingsView = () =>
  import("./components/SettingsView").then((m) => ({ default: m.SettingsView }));

const ZoneXRayView = lazy(loadZoneXRayView);
const ReviewRoundsView = lazy(loadReviewRoundsView);
const BranchesView = lazy(loadBranchesView);
const AgentMissionControl = lazy(loadAgentMissionControl);
const AgentTraceView = lazy(loadAgentTraceView);
const SecretsOverlaysView = lazy(loadSecretsOverlaysView);
const AccessDiffView = lazy(loadAccessDiffView);
const SettingsView = lazy(loadSettingsView);

const TAB_PRELOADERS: Partial<Record<TabId, () => Promise<unknown>>> = {
  code: loadZoneXRayView,
  changes: loadReviewRoundsView,
  branches: loadBranchesView,
  agents: loadAgentMissionControl,
  traces: loadAgentTraceView,
  secrets: loadSecretsOverlaysView,
  policy: loadAccessDiffView,
  settings: loadSettingsView,
};

const preloadedTabs = new Set<TabId>();
function preloadTab(id: TabId) {
  if (preloadedTabs.has(id)) return;
  const loader = TAB_PRELOADERS[id];
  if (!loader) return;
  preloadedTabs.add(id);
  void loader().catch(() => {
    preloadedTabs.delete(id);
  });
}

type TabId =
  | "worktable"
  | "code"
  | "changes"
  | "branches"
  | "agents"
  | "traces"
  | "secrets"
  | "policy"
  | "settings";

const TAB_ORDER: TabId[] = [
  "worktable",
  "code",
  "changes",
  "branches",
  "agents",
  "traces",
  "secrets",
  "policy",
  "settings",
];

interface HashState {
  tab: TabId | null;
  repo?: string;
  ref?: string;
  path?: string;
  lines?: [number, number];
  oid?: string;
  change?: string;
  section?: string;
  focus?: string;
}

/** Parses `#<tab>?repo=&ref=&path=&lines=L1-L2&oid=&change=&section=&focus=` (compatible with legacy `#branches`). */
function parseHash(): HashState {
  const raw = window.location.hash.replace(/^#/, "");
  if (!raw) return { tab: "worktable" };
  const qIdx = raw.indexOf("?");
  const tabPart = qIdx === -1 ? raw : raw.slice(0, qIdx);
  const queryPart = qIdx === -1 ? "" : raw.slice(qIdx + 1);
  const tab = (TAB_ORDER as string[]).includes(tabPart) ? (tabPart as TabId) : null;
  const params = new URLSearchParams(queryPart);
  const repo = params.get("repo") || undefined;
  const ref = params.get("ref") || undefined;
  const path = params.get("path") || undefined;
  const oid = params.get("oid") || undefined;
  const change = params.get("change") || undefined;
  const section = params.get("section") || undefined;
  const focus = params.get("focus") || undefined;
  let lines: [number, number] | undefined;
  const linesRaw = params.get("lines");
  if (linesRaw) {
    const m = linesRaw.match(/^L?(\d+)(?:-L?(\d+))?$/i);
    if (m) {
      const a = Number(m[1]);
      const b = m[2] ? Number(m[2]) : a;
      if (a > 0 && b > 0) lines = [Math.min(a, b), Math.max(a, b)];
    }
  }
  return { tab, repo, ref, path, lines, oid, change, section, focus };
}

function buildHash(state: {
  tab: TabId;
  repo?: string;
  isDefaultRepo?: boolean;
  ref?: string;
  defaultBranch?: string | null;
  path?: string;
  lines?: [number, number] | null;
  oid?: string;
  change?: string;
  section?: string;
  focus?: string;
}): string {
  const params = new URLSearchParams();
  if (state.repo && !state.isDefaultRepo) params.set("repo", state.repo);
  if (state.ref && state.ref !== state.defaultBranch) params.set("ref", state.ref);
  if (state.tab === "worktable") {
    if (state.focus) params.set("focus", state.focus);
  } else if (state.tab === "code") {
    if (state.path) params.set("path", state.path);
    if (state.lines) {
      const [a, b] = state.lines;
      params.set("lines", a === b ? `L${a}` : `L${a}-L${b}`);
    }
  } else if (state.tab === "changes") {
    if (state.change) params.set("change", state.change);
    else if (state.oid) params.set("oid", state.oid);
  } else if (state.tab === "settings") {
    if (state.section) params.set("section", state.section);
  }
  const qs = params.toString();
  return qs ? `#${state.tab}?${qs}` : `#${state.tab}`;
}

const LENS_KEY = "premier.lens";
const NOOP = () => {};

/** Tab named by location.hash: "worktable" for no hash, null for a hash that isn't a tab. */
function hashTab(): TabId | null {
  return parseHash().tab;
}

/** Floating "Knock on the Door" popover (outside the Agents tab): one knock at a time, keyboard-driven. */
function FloatingApprovalPopover({
  approvals,
  owner,
  suggestions,
  keysEnabled,
  onDecided,
  onOpenAgents,
  onOpenSession,
  onDismiss,
  onPreviewSuggestion,
  onDismissSuggestion,
}: {
  approvals: PendingApproval[];
  owner: boolean;
  suggestions: PolicySuggestion[];
  /** False while a modal or the palette is open, so the knock keys stay quiet behind it. */
  keysEnabled: boolean;
  onDecided: () => void;
  onOpenAgents: () => void;
  onOpenSession: (sessionId: string) => void;
  onDismiss: (id: string) => void;
  onPreviewSuggestion: (s: PolicySuggestion) => void;
  onDismissSuggestion: (s: PolicySuggestion) => void;
}) {
  // Tracked by id so a knock arriving at the front doesn't swap the card under the user's cursor.
  const [activeId, setActiveId] = useState<string | null>(null);
  const cardRef = useRef<KnockCardHandle>(null);
  const found = approvals.findIndex((a) => a.id === activeId);
  const index = found === -1 ? 0 : found;
  const active = approvals[index];

  const step = useCallback(
    (delta: number) => {
      if (approvals.length === 0) return;
      const next = (index + delta + approvals.length) % approvals.length;
      setActiveId(approvals[next].id);
    },
    [approvals, index],
  );

  useEffect(() => {
    if (!keysEnabled) return;
    const onKey = (e: KeyboardEvent) => {
      if (
        !canHandleApprovalHotkey({
          keysEnabled,
          hasModal: hasActiveModalDialog(),
          metaKey: e.metaKey,
          ctrlKey: e.ctrlKey,
          altKey: e.altKey,
          isEditable: isEditableEventTarget(e),
        })
      ) {
        return;
      }
      switch (e.key) {
        case "y":
          e.preventDefault();
          cardRef.current?.approve();
          break;
        case "n":
          e.preventDefault();
          cardRef.current?.openDeny();
          break;
        case "i":
          e.preventDefault();
          cardRef.current?.toggleProof();
          break;
        case "[":
          e.preventDefault();
          step(-1);
          break;
        case "]":
          e.preventDefault();
          step(1);
          break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [keysEnabled, step]);

  if (!active) return null;

  return (
    <div
      role="dialog"
      aria-label="Pending JIT approval"
      className="relative flex max-h-[calc(100dvh-6rem)] w-full flex-col gap-1.5"
    >
      <div className="min-h-0 overflow-y-auto rounded-2xl">
        {active.kind === "mcp_tool" ? (
          <>
            <McpApprovalCard
              key={active.id}
              approval={active}
              owner={owner}
              onDecided={onDecided}
              onDismiss={() => onDismiss(active.id)}
            />
            <div className="mt-1.5 flex items-center justify-between px-1 font-mono text-[12.5px] text-[#98a8c4]">
              {approvals.length > 1 ? (
                <span>
                  {index + 1} of {approvals.length} · <kbd className="pr-kbd">[</kbd>{" "}
                  <kbd className="pr-kbd">]</kbd> switch
                </span>
              ) : (
                <span />
              )}
              <button type="button" onClick={onOpenAgents} className="text-[#9ec0f5] hover:underline">
                Open Agents
              </button>
            </div>
          </>
        ) : (
          <KnockApprovalCard
            key={active.id}
            ref={cardRef}
            approval={active}
            owner={owner}
            variant="floating"
            matchingSuggestion={suggestionForApproval(suggestions, active)}
            index={index}
            total={approvals.length}
            onPrev={() => step(-1)}
            onNext={() => step(1)}
            onDecided={onDecided}
            onOpenAgents={onOpenAgents}
            onOpenSession={onOpenSession}
            onDismiss={() => onDismiss(active.id)}
            onPreviewSuggestion={onPreviewSuggestion}
            onDismissSuggestion={onDismissSuggestion}
          />
        )}
      </div>
      {active.kind !== "mcp_tool" && (
        <div
          aria-hidden="true"
          className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 rounded-full border border-white/[0.08] bg-[#0b0f1c]/97 px-3 py-1 font-mono text-[12px] text-[#a6b5cf]"
        >
          <span><kbd className="pr-kbd">y</kbd> approve</span>
          <span><kbd className="pr-kbd">n</kbd> deny</span>
          <span><kbd className="pr-kbd">i</kbd> inspect</span>
          <span><kbd className="pr-kbd">[</kbd> <kbd className="pr-kbd">]</kbd> switch</span>
        </div>
      )}
    </div>
  );
}

function budgetAlertKey(alert: BudgetAlert): string {
  return `${alert.session_id}:${alert.metric}:${alert.timestamp}`;
}

/** Compact floating Obsidian Glassmorphic Autonomy Budget Alert Popover visible outside Agents tab. */
function FloatingBudgetAlertPopover({
  alerts,
  onOpenAgents,
  onDismiss,
}: {
  alerts: BudgetAlert[];
  onOpenAgents: (sessionId: string) => void;
  onDismiss: (key: string) => void;
}) {
  const top = alerts[0];
  if (!top) return null;

  const isTerminate = top.action === "terminate";
  const key = budgetAlertKey(top);

  return (
    <div
      role="alert"
      aria-label="Autonomy budget alert"
      className={`w-full pr-elevated rounded-2xl border p-3.5 shadow-2xl ${
        isTerminate ? "border-[#f27c7c]/40" : "border-[#9ec0f5]/40"
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2 font-mono text-[12.5px]">
          <span
            className={`h-2 w-2 shrink-0 animate-pulse rounded-full ${
              isTerminate ? "bg-[#f27c7c]" : "bg-[#7f95f8]"
            }`}
          />
          <IconQuarantine
            className={`h-3.5 w-3.5 shrink-0 ${
              isTerminate ? "text-[#f27c7c]" : "text-[#a8c5ff]"
            }`}
          />
          <span
            className={`truncate font-semibold uppercase tracking-wider ${
              isTerminate ? "text-[#f27c7c]" : "text-[#a8c5ff]"
            }`}
          >
            {isTerminate ? "Budget Terminated" : "Session Paused"}
          </span>
          {alerts.length > 1 && (
            <span
              className={`shrink-0 rounded-full px-2 py-0.5 text-[12px] ${
                isTerminate
                  ? "bg-[#f27c7c]/18 text-[#f27c7c]"
                  : "bg-[#7f95f8]/18 text-[#a8c5ff]"
              }`}
            >
              +{alerts.length - 1} more
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={() => onDismiss(key)}
          aria-label="Dismiss budget alert"
          className="rounded-lg p-1 text-[#98a8c4] hover:bg-white/[0.06] hover:text-white"
        >
          <IconClose className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="mt-2.5 space-y-1 font-mono text-[13px]">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate font-semibold text-[#f3f6fd]" title={top.session_id}>
            {top.session_id}
          </span>
          <span
            className={`shrink-0 rounded-md px-1.5 py-0.5 text-[12px] ${
              isTerminate
                ? "bg-[#f27c7c]/16 text-[#f27c7c]"
                : "bg-[#7f95f8]/16 text-[#a8c5ff]"
            }`}
          >
            {top.metric}: {top.current} &gt; {top.limit}
          </span>
        </div>
        <div className="truncate text-[12.5px] text-[#98a8c4]">
          {top.principal}
          {top.agent_profile ? ` ∩ ${top.agent_profile}` : ""}
        </div>
        <div className="line-clamp-2 font-sans text-[13px] leading-snug text-[#dce4f5]">
          {top.message}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          onClick={() => onOpenAgents(top.session_id)}
          className="pr-action-btn inline-flex items-center gap-1 rounded-full px-3 py-1 text-[12.5px]"
        >
          <span>Open Agents</span>
        </button>
        <button
          type="button"
          onClick={() => onDismiss(key)}
          className="pr-pill ml-auto rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee] hover:text-white"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}

interface WorkspaceProps {
  user: User;
  onUserChange: (user: User) => void;
  onSignOut: () => void;
  onSessionExpired: () => void;
}

const PALETTE_GROUP_CAP: Record<string, number> = { Views: 9, Files: 8, Commits: 5, Repositories: 5 };

/** 0 = no match. Substring beats subsequence; earlier and word-start matches rank higher. */
function fuzzyScore(q: string, text: string, subsequence = true): number {
  const t = text.toLowerCase();
  const boundary = (idx: number) => idx === 0 || /[\s/._:-]/.test(t[idx - 1]);
  const at = t.indexOf(q);
  if (at >= 0) return 1000 - Math.min(at, 500) + (boundary(at) ? 200 : 0);
  if (!subsequence || q.length < 2) return 0;
  let from = 0;
  let last = -2;
  let score = 1;
  for (const ch of q) {
    const f = t.indexOf(ch, from);
    if (f < 0) return 0;
    score += (f === last + 1 ? 8 : 2) + (boundary(f) ? 6 : 0);
    last = f;
    from = f + 1;
  }
  return score;
}

const MENU_ITEM_SEL = '[role="menuitem"],[role="menuitemradio"]';

/** ArrowUp/Down/Home/End move focus between a menu's items; Escape returns focus to its trigger. */
function menuKeyDown(e: ReactKeyboardEvent<HTMLElement>) {
  if (e.key === "Escape") {
    e.currentTarget.parentElement?.querySelector<HTMLElement>("button")?.focus();
    return;
  }
  const items = Array.from(e.currentTarget.querySelectorAll<HTMLElement>(MENU_ITEM_SEL));
  if (items.length === 0) return;
  const i = items.indexOf(document.activeElement as HTMLElement);
  let next: number;
  if (e.key === "ArrowDown") next = (i + 1) % items.length;
  else if (e.key === "ArrowUp") next = (i <= 0 ? items.length : i) - 1;
  else if (e.key === "Home") next = 0;
  else if (e.key === "End") next = items.length - 1;
  else return;
  e.preventDefault();
  items[next].focus();
}

/** ArrowDown on a closed menu's trigger opens it and focuses the first item. */
function menuTriggerKeyDown(e: ReactKeyboardEvent<HTMLElement>, open: boolean, openMenu: () => void) {
  if (e.key !== "ArrowDown" || open) return;
  e.preventDefault();
  openMenu();
  const root = e.currentTarget.parentElement;
  requestAnimationFrame(() => root?.querySelector<HTMLElement>(MENU_ITEM_SEL)?.focus());
}

function userInitials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  const letters = parts.length > 1 ? parts[0][0] + parts[parts.length - 1][0] : (parts[0] ?? "?").slice(0, 2);
  return letters.toUpperCase();
}

/** Signed-in account menu: who you are, then Settings and Sign out. The caller owns `open`. */
function AccountMenu({
  user,
  open,
  setOpen,
  menuRef,
  onSettings,
  onSignOut,
  children,
}: {
  user: User;
  open: boolean;
  setOpen: (open: boolean) => void;
  menuRef: RefObject<HTMLDivElement | null>;
  onSettings: () => void;
  onSignOut: () => void;
  /** Extra menu sections, shown between the name and Settings. */
  children?: ReactNode;
}) {
  return (
    <div ref={menuRef} className="relative shrink-0">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        onKeyDown={(e) => menuTriggerKeyDown(e, open, () => setOpen(true))}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Account: ${user.display_name}`}
        title={`Signed in as ${user.display_name}`}
        className="pr-pill inline-flex h-9 min-w-9 shrink-0 items-center justify-center gap-1.5 rounded-full px-1.5 text-[14px] text-[#e6ecf8] 2xl:px-3"
      >
        <span
          aria-hidden="true"
          className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-[#7f95f8]/25 text-[12.5px] font-semibold text-[#d6e2ff] 2xl:hidden"
        >
          {userInitials(user.display_name)}
        </span>
        <IconUser className="hidden h-[18px] w-[18px] text-[#9ec0f5] 2xl:block" />
        <span className="hidden max-w-[128px] truncate 2xl:inline">{user.display_name}</span>
      </button>

      {open && (
        <div
          role="menu"
          onKeyDown={menuKeyDown}
          className="pr-elevated absolute right-0 mt-2 max-h-[calc(100dvh-4.5rem)] w-60 overflow-y-auto rounded-2xl p-1.5"
        >
          <div className="px-3 pt-1.5 pb-2">
            <div className="truncate text-[14px] font-medium text-[#f3f6fd]">{user.display_name}</div>
            <div className="truncate font-mono text-[12.5px] text-[#98a8c4]">{user.username}</div>
          </div>
          {children}
          <div className="border-t border-white/[0.06] pt-1">
            <button
              type="button"
              role="menuitem"
              onClick={() => {
                onSettings();
                setOpen(false);
              }}
              className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-[14px] text-[#d2dbee] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
            >
              <IconGear className="h-4 w-4 text-[#a6b5cf]" />
              <span>Settings</span>
            </button>
            <button
              type="button"
              role="menuitem"
              onClick={onSignOut}
              className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-[14px] text-[#d2dbee] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
            >
              <IconLock className="h-4 w-4 text-[#a6b5cf]" />
              <span>Sign out</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * App shell for a member who has been granted no repository: the account menu and Settings still
 * work, so they can manage their account or sign out while they wait for access.
 */
function NoRepoAccess({
  user,
  onUserChange,
  onSignOut,
  onReposReload,
}: WorkspaceProps & { onReposReload: () => Promise<void> }) {
  const [settings, setSettings] = useState(() => hashTab() === "settings");
  const [settingsSection, setSettingsSection] = useState<string | undefined>(
    () => parseHash().section,
  );
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const retryHealth = useCallback(() => {
    setHealthError(false);
    api
      .health()
      .then((h) => {
        setHealth(h);
        setHealthError(false);
      })
      .catch(() => setHealthError(true));
  }, []);
  const [userOpen, setUserOpen] = useState(false);
  const userRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const nextHash = settings
      ? buildHash({ tab: "settings", section: settingsSection })
      : "#worktable";
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, "", nextHash);
    }
  }, [settings, settingsSection]);

  useEffect(() => {
    retryHealth();
    const onHash = () => {
      const parsed = parseHash();
      setSettings(parsed.tab === "settings");
      setSettingsSection(parsed.section);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setUserOpen(false);
    };
    const onClickOutside = (e: MouseEvent) => {
      if (userRef.current && !userRef.current.contains(e.target as Node)) setUserOpen(false);
    };
    window.addEventListener("hashchange", onHash);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("mousedown", onClickOutside);
    return () => {
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("mousedown", onClickOutside);
    };
  }, [retryHealth]);

  return (
    <div className="flex h-[100dvh] flex-col overflow-hidden text-[#f3f6fd]">
      <header className="pr-topbar z-[45] flex h-14 shrink-0 items-center justify-between gap-2 px-3.5 lg:px-4 xl:px-5">
        <button
          type="button"
          onClick={() => setSettings(false)}
          className="flex shrink-0 items-center gap-2 whitespace-nowrap text-left transition hover:opacity-90"
        >
          <PremierMark className="h-7 w-7" />
          <span className="text-[15px] font-semibold tracking-[-0.02em] text-[#f3f6fd]">Premier</span>
        </button>
        <div className="flex min-w-0 items-center justify-end gap-1.5 xl:gap-2">
          <button
            type="button"
            title="Settings"
            aria-label="Settings"
            aria-current={settings ? "page" : undefined}
            onMouseEnter={() => preloadTab("settings")}
            onClick={() => setSettings((s) => !s)}
            className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${
              settings ? "pr-pill-active" : "pr-pill"
            }`}
          >
            <IconGear className="h-[18px] w-[18px] text-[#9ec0f5]" />
          </button>
          <AccountMenu
            user={user}
            open={userOpen}
            setOpen={setUserOpen}
            menuRef={userRef}
            onSettings={() => setSettings(true)}
            onSignOut={onSignOut}
          />
        </div>
      </header>
      <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {settings ? (
          <Suspense fallback={<ViewSkeleton tab="settings" />}>
            <SettingsView
              user={user}
              health={health}
              healthError={healthError}
              onRetryHealth={retryHealth}
              repos={[]}
              onReposReload={onReposReload}
              onUserChange={onUserChange}
              onDirectoryChange={NOOP}
              requestedSection={settingsSection}
              onSelectSection={setSettingsSection}
            />
          </Suspense>
        ) : (
          <div className="pr-stage-backdrop flex min-h-0 flex-1 items-center justify-center overflow-y-auto px-4 py-10 sm:px-6">
            <section className="w-full max-w-md space-y-6">
              <div className="flex flex-col items-center space-y-3 text-center">
                <div className="pr-icon-tile flex h-12 w-12 items-center justify-center rounded-2xl">
                  <PremierMark className="h-7 w-7" />
                </div>
                <div className="space-y-1.5">
                  <h1 className="bg-gradient-to-b from-white via-[#eef3fc] to-[#a7b6d2] bg-clip-text text-[22px] font-semibold tracking-[-0.03em] text-transparent sm:text-[26px]">
                    You don&apos;t have access to any repository yet
                  </h1>
                  <p className="mx-auto max-w-sm text-[14px] leading-relaxed text-[#a8b7d1]">
                    Ask an owner to grant you access.
                  </p>
                </div>
              </div>

              <div className="pr-elevated relative flex flex-col items-center gap-4 overflow-hidden rounded-2xl p-5 text-center sm:p-6">
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-[#cfe0ff]/25 to-transparent"
                />
                <p className="text-[14px] leading-relaxed text-[#b6c3db]">
                  Once an owner shares a repository with{" "}
                  <code className="text-[#dce4f5]">{user.username}</code>, it will appear here.
                </p>
                <button type="button" onClick={() => void onReposReload()} className={SECONDARY_BTN}>
                  <IconRefresh className="h-4 w-4 text-[#a6b5cf]" />
                  <span>Check again</span>
                </button>
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}

/** Repo-scoped nav shown on the owner welcome shell; Traces stays unlocked even with 0 repos. */
const WELCOME_NAV: { id: TabId; label: string; icon: typeof IconCode; standalone?: boolean }[] = [
  { id: "worktable", label: "Overview", icon: IconWorktable },
  { id: "code", label: "Files", icon: IconCode },
  { id: "changes", label: "Changes", icon: IconChanges },
  { id: "branches", label: "Branches", icon: IconBranches },
  { id: "agents", label: "AI Agents", icon: IconCage },
  { id: "traces", label: "Traces", icon: IconTimeline, standalone: true },
  { id: "secrets", label: "Secrets", icon: IconVault },
  { id: "policy", label: "Access Rules", icon: IconPolicy },
];

/**
 * App shell for an owner whose server has no repositories yet. Repo-scoped navigation stays
 * locked; Traces, Settings, and the account menu work immediately.
 */
function OwnerWelcome({
  user,
  onUserChange,
  onSignOut,
  onRepoCreated,
  onReposReload,
}: WorkspaceProps & {
  onRepoCreated: (repo: Repo & { imported_policy?: boolean }) => void;
  onReposReload: () => Promise<void>;
}) {
  const [view, setView] = useState<"welcome" | "traces" | "settings">(() => {
    const t = hashTab();
    if (t === "settings") return "settings";
    if (t === "traces") return "traces";
    return "welcome";
  });
  const [settingsSection, setSettingsSection] = useState<string | undefined>(
    () => parseHash().section,
  );
  const [dialog, setDialog] = useState<"import" | "new" | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const [traceRevision, setTraceRevision] = useState(0);
  const [traceSseConnected, setTraceSseConnected] = useState(false);
  const selfIdentity = useMemo<IdentityPreset>(
    () => ({
      id: `user:${user.username}`,
      label: user.display_name || user.username,
      subtitle: "Owner",
      principal: user.principal,
      groups: [],
      badgeColor: "emerald",
    }),
    [user.display_name, user.principal, user.username],
  );
  const retryHealth = useCallback(() => {
    setHealthError(false);
    api
      .health()
      .then((h) => {
        setHealth(h);
        setHealthError(false);
      })
      .catch(() => setHealthError(true));
  }, []);
  const [userOpen, setUserOpen] = useState(false);
  const userRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const nextHash =
      view === "settings"
        ? buildHash({ tab: "settings", section: settingsSection })
        : view === "traces"
          ? window.location.hash.startsWith("#traces")
            ? window.location.hash
            : "#traces"
          : "#worktable";
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, "", nextHash);
    }
  }, [view, settingsSection]);

  useEffect(() => {
    if (view !== "traces") {
      setTraceSseConnected(false);
      return;
    }
    const es = new EventSource("/v1/events/stream");
    es.addEventListener("ready", () => setTraceSseConnected(true));
    es.addEventListener("trace", () => setTraceRevision((n) => n + 1));
    es.onerror = () => setTraceSseConnected(false);
    return () => es.close();
  }, [view]);

  useEffect(() => {
    retryHealth();
    const onHash = () => {
      const parsed = parseHash();
      setView(
        parsed.tab === "settings" ? "settings" : parsed.tab === "traces" ? "traces" : "welcome",
      );
      setSettingsSection(parsed.section);
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") setUserOpen(false);
    };
    const onClickOutside = (e: MouseEvent) => {
      if (userRef.current && !userRef.current.contains(e.target as Node)) setUserOpen(false);
    };
    window.addEventListener("hashchange", onHash);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("mousedown", onClickOutside);
    return () => {
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("mousedown", onClickOutside);
    };
  }, [retryHealth]);

  return (
    <div className="flex h-[100dvh] flex-col overflow-hidden text-[#f3f6fd]">
      <header className="pr-topbar relative z-[45] flex h-14 shrink-0 items-center justify-between gap-2 px-3.5 lg:px-4 xl:gap-3 xl:px-5">
        <div className="flex shrink-0 items-center gap-2.5">
          <button
            type="button"
            onClick={() => setView("welcome")}
            className="flex shrink-0 items-center gap-2 whitespace-nowrap text-left transition hover:opacity-90"
          >
            <PremierMark className="h-7 w-7" />
            <span className="hidden text-[15px] font-semibold tracking-[-0.02em] text-[#f3f6fd] sm:inline">
              Premier
            </span>
          </button>
          <span className="hidden rounded-full border border-white/[0.08] bg-white/[0.025] px-2.5 py-0.5 text-[13px] text-[#98a8c4] sm:inline">
            No repository
          </span>
          <button
            type="button"
            onClick={() => setDialog("import")}
            className="pr-pill inline-flex h-8 shrink-0 items-center gap-1.5 rounded-full px-3 text-[13.5px] font-medium text-[#cfe0ff] hover:text-[#f3f6fd]"
          >
            <IconPlus className="h-3.5 w-3.5" />
            <span>Add Repo</span>
          </button>
        </div>

        <nav aria-label="Primary" className="hidden shrink-0 items-center gap-0.5 xl:gap-1 md:flex">
          {WELCOME_NAV.map((item) => {
            const Icon = item.icon;
            const active = item.id === "traces" && view === "traces";
            if (item.standalone) {
              return (
                <button
                  key={item.id}
                  type="button"
                  title={item.label}
                  aria-label={item.label}
                  aria-current={active ? "page" : undefined}
                  onMouseEnter={() => preloadTab("traces")}
                  onClick={() => setView((v) => (v === "traces" ? "welcome" : "traces"))}
                  className={`inline-flex h-9 shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 text-[13.5px] font-medium transition xl:gap-2 xl:px-3 xl:text-[14px] ${
                    active
                      ? "pr-pill-active text-[#f5f7fd]"
                      : "border-transparent text-[#c4d0e6] hover:bg-white/[0.05] hover:text-[#f5f7fd]"
                  }`}
                >
                  <Icon className="h-[18px] w-[18px]" />
                  <span>{item.label}</span>
                </button>
              );
            }
            return (
              <Fragment key={item.id}>
                {item.id === "secrets" && (
                  <span aria-hidden="true" className="mx-0.5 h-5 w-px shrink-0 bg-white/[0.10]" />
                )}
                <button
                  type="button"
                  disabled
                  title="Add a repository to unlock"
                  aria-label={item.label}
                  className="inline-flex h-9 shrink-0 cursor-not-allowed items-center gap-1 whitespace-nowrap rounded-full border border-transparent px-2 text-[13.5px] font-medium text-[#b2c0d8] opacity-35 xl:gap-2 xl:px-2.5 xl:text-[14px] 2xl:px-3"
                >
                  <Icon className="h-[18px] w-[18px] opacity-85" />
                  <span className="hidden 2xl:inline">{item.label}</span>
                </button>
              </Fragment>
            );
          })}
        </nav>

        <div className="flex min-w-0 items-center justify-end gap-1.5 xl:gap-2">
          <button
            type="button"
            title="Traces"
            aria-label="Traces"
            aria-current={view === "traces" ? "page" : undefined}
            onMouseEnter={() => preloadTab("traces")}
            onClick={() => setView((v) => (v === "traces" ? "welcome" : "traces"))}
            className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full md:hidden ${
              view === "traces" ? "pr-pill-active" : "pr-pill"
            }`}
          >
            <IconTimeline className="h-[18px] w-[18px] text-[#9ec0f5]" />
          </button>
          <button
            type="button"
            title="Settings"
            aria-label="Settings"
            aria-current={view === "settings" ? "page" : undefined}
            onMouseEnter={() => preloadTab("settings")}
            onClick={() => setView((v) => (v === "settings" ? "welcome" : "settings"))}
            className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${
              view === "settings" ? "pr-pill-active" : "pr-pill"
            }`}
          >
            <IconGear className="h-[18px] w-[18px] text-[#9ec0f5]" />
          </button>
          <AccountMenu
            user={user}
            open={userOpen}
            setOpen={setUserOpen}
            menuRef={userRef}
            onSettings={() => setView("settings")}
            onSignOut={onSignOut}
          />
        </div>
      </header>

      <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {view === "settings" ? (
          <Suspense fallback={<ViewSkeleton tab="settings" />}>
            <SettingsView
              user={user}
              health={health}
              healthError={healthError}
              onRetryHealth={retryHealth}
              repos={[]}
              onReposReload={onReposReload}
              onUserChange={onUserChange}
              onDirectoryChange={NOOP}
              onAddRepo={() => setDialog("import")}
              requestedSection={settingsSection}
              onSelectSection={setSettingsSection}
            />
          </Suspense>
        ) : view === "traces" ? (
          <Suspense fallback={<ViewSkeleton tab="traces" />}>
            <AgentTraceView
              identity={selfIdentity}
              owner
              sseConnected={traceSseConnected}
              traceRevision={traceRevision}
            />
          </Suspense>
        ) : (
          <div className="pr-stage-backdrop flex min-h-0 flex-1 items-center justify-center overflow-y-auto px-4 py-10 sm:px-6">
            <section className="w-full max-w-[680px] space-y-8">
              <div className="flex flex-col items-center space-y-3 text-center">
                <div className="pr-icon-tile flex h-12 w-12 items-center justify-center rounded-2xl">
                  <PremierMark className="h-7 w-7" />
                </div>
                <div className="space-y-1.5">
                  <h1 className="bg-gradient-to-b from-white via-[#eef3fc] to-[#a7b6d2] bg-clip-text text-[26px] font-semibold tracking-[-0.03em] text-transparent sm:text-[32px]">
                    Add your first repository
                  </h1>
                  <p className="mx-auto max-w-md text-[14.5px] leading-relaxed text-[#a8b7d1]">
                    Import an existing repository or initialize a new one to get started.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => setDialog("import")}
                  className="pr-action-card group flex flex-col justify-between gap-5 rounded-2xl p-5 text-left focus-visible:outline-2 focus-visible:outline-[#9ec0f5] sm:p-6"
                >
                  <div className="flex w-full items-start justify-between gap-3">
                    <div className="pr-icon-tile flex h-11 w-11 items-center justify-center rounded-xl">
                      <BrandIcon name="github" className="h-6 w-6" />
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="inline-flex h-6 w-6 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03]">
                        <BrandIcon name="gitlab" className="h-3.5 w-3.5 opacity-90" />
                      </span>
                      <span className="inline-flex h-6 w-6 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03]">
                        <BrandIcon name="bitbucket" className="h-3.5 w-3.5 opacity-90" />
                      </span>
                      <span className="inline-flex h-6 w-6 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03]">
                        <BrandIcon name="git" className="h-3.5 w-3.5 opacity-90" />
                      </span>
                      <span
                        aria-hidden="true"
                        className="ml-1 text-[15px] text-[#98a8c4] transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-[#cfe0ff]"
                      >
                        →
                      </span>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <div className="text-[15px] font-semibold tracking-[-0.015em] text-[#f3f6fd]">
                      Import repository
                    </div>
                    <p className="text-[14px] leading-relaxed text-[#a8b7d1]">
                      Clone from GitHub, GitLab, Bitbucket, or any HTTPS Git URL.
                    </p>
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => setDialog("new")}
                  className="pr-action-card group flex flex-col justify-between gap-5 rounded-2xl p-5 text-left focus-visible:outline-2 focus-visible:outline-[#9ec0f5] sm:p-6"
                >
                  <div className="flex w-full items-start justify-between gap-3">
                    <div className="pr-icon-tile flex h-11 w-11 items-center justify-center rounded-xl">
                      <BrandIcon name="git" className="h-6 w-6" />
                    </div>
                    <span
                      aria-hidden="true"
                      className="text-[15px] text-[#98a8c4] transition-transform duration-200 group-hover:translate-x-0.5 group-hover:text-[#cfe0ff]"
                    >
                      →
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    <div className="text-[15px] font-semibold tracking-[-0.015em] text-[#f3f6fd]">
                      Create new repository
                    </div>
                    <p className="text-[14px] leading-relaxed text-[#a8b7d1]">
                      Initialize an empty Git repository ready for your first push.
                    </p>
                  </div>
                </button>
              </div>
            </section>
          </div>
        )}
      </main>

      {dialog && (
        <NewRepoDialog
          existing={[]}
          initialMode={dialog}
          onClose={() => setDialog(null)}
          onCreated={onRepoCreated}
        />
      )}
    </div>
  );
}

interface StudioProps extends WorkspaceProps {
  repos: Repo[];
  /** The repository this mount is scoped to; switching remounts the Studio. */
  repo: Repo;
  onSwitchRepo: (name: string) => void;
  onRepoCreated: (repo: Repo & { imported_policy?: boolean }) => void;
  onReposReload: () => Promise<void>;
  /** True right after importing this repo with an in-repo policy the server left inactive. */
  importedPolicy: boolean;
  onDismissImportedPolicy: () => void;
}

/** The signed-in app for one repository. Keyed on the repo, so a switch reopens SSE and refetches. */
function Studio({
  user,
  onUserChange,
  onSignOut,
  onSessionExpired,
  repos,
  repo,
  onSwitchRepo,
  onRepoCreated,
  onReposReload,
  importedPolicy,
  onDismissImportedPolicy,
}: StudioProps) {
  const clientOS = useClientOS();
  const cmdShortcut = useMemo(() => formatShortcut("k", clientOS), [clientOS]);
  const macOS = isMac(clientOS);

  // Deep-linkable hash state: `#<tab>?repo=&ref=&path=&lines=&oid=&change=&focus=`
  const initialHash = useMemo(() => parseHash(), []);
  const [rawTab, setTab] = useState<TabId>(() => initialHash.tab ?? "worktable");
  // A repository with no commits has nothing to browse, diff or branch, so those tabs stay locked.
  const repoEmpty = !repo.head_oid;
  const isTabDisabled = (id: TabId) =>
    repoEmpty && (id === "code" || id === "changes" || id === "branches");
  // Derived, so every setTab caller (hash links, palette, menus) lands on Overview while locked.
  const tab: TabId = isTabDisabled(rawTab) ? "worktable" : rawTab;
  // Normalize locked tabs to Overview so pushing the first commit never teleports away from Overview.
  useEffect(() => {
    if (repoEmpty && (rawTab === "code" || rawTab === "changes" || rawTab === "branches")) {
      setTab("worktable");
    }
  }, [repoEmpty, rawTab]);
  // "View as" lens: yourself first, then the directory's principals, then anonymous.
  const [directory, setDirectory] = useState<Directory | null>(null);
  // Members always act as themselves (the server ignores any other principal), so they get no lens.
  const owner = user.role !== "member";
  // Agent profiles the policy declares; refetched after a policy save (not on every tab switch).
  const [agentProfiles, setAgentProfiles] = useState<string[]>([]);
  const refreshAgentProfiles = () => {
    // Members get no policy text, so they have no profiles to pick from.
    if (!owner) return;
    api
      .policySummary()
      .then((s) => {
        const names = agentProfileNames(s);
        // Same list: keep the old array so the lens presets (and every view) don't refetch.
        setAgentProfiles((prev) => (prev.join("|") === names.join("|") ? prev : names));
      })
      .catch(() => {});
  };
  useEffect(refreshAgentProfiles, [owner]);
  // Tabs stay mounted once visited, so switching back is instant and keeps scroll/filters/state.
  const [visitedTabs, setVisitedTabs] = useState<Set<TabId>>(() => new Set([tab]));
  useEffect(() => {
    setVisitedTabs((prev) => (prev.has(tab) ? prev : new Set(prev).add(tab)));
  }, [tab]);
  const presets = useMemo(() => {
    const all = lensPresets(user, directory, agentProfiles);
    return owner ? all : all.slice(0, 1);
  }, [user.principal, owner, directory, agentProfiles]);
  // The "View as" lens survives repo switches (Studio remounts per repo) via sessionStorage.
  const [identityId, setIdentityId] = useState<string>(() => {
    try {
      return sessionStorage.getItem(LENS_KEY) ?? "self";
    } catch {
      return "self";
    }
  });
  useEffect(() => {
    try {
      sessionStorage.setItem(LENS_KEY, identityId);
    } catch {
      // storage unavailable: the lens just resets on the next repo switch
    }
  }, [identityId]);
  const [policyDraftToml, setPolicyDraftToml] = useState<string | null>(null);
  const [mirrorEnabled, setMirrorEnabled] = useState(false);
  const [githubModalOpen, setGithubModalOpen] = useState(false);
  const [agentConnectOpen, setAgentConnectOpen] = useState(false);
  const openPolicyEditorWithDraft = useCallback((toml: string) => {
    setPolicyDraftToml(toml);
    setTab("policy");
  }, []);
  const ownerIdentity = presets[0];
  // Falls back to yourself if the selected principal is removed from the directory.
  const lens = presets.find((p) => p.id === identityId) ?? presets[0];
  // Keyed on content, so a directory reload doesn't refetch every view through a new object.
  const identity = useMemo<IdentityPreset>(() => lens, [lens.id, lens.groups.join(",")]);
  // Unsaved Code-tab edits (reported by ZoneXRayView) must be confirmed before a ref/identity switch discards them.
  const codeDirtyRef = useRef(false);
  const confirmLeaveDirtyCode = () =>
    !codeDirtyRef.current ||
    window.confirm("You have unsaved file edits in Code. Discard them and switch?");
  const setIdentity = (preset: IdentityPreset) => {
    if (preset.id !== identityId && !confirmLeaveDirtyCode()) return;
    setIdentityId(preset.id);
  };
  const viewingAs = identity.id !== "self";
  // Undefined until known: API calls then omit the ref and the server uses the checked-out branch.
  const [activeRef, setActiveRef] = useState<string | undefined>(
    initialHash.ref ?? repo.default_branch ?? undefined,
  );
  const [requestedPath, setRequestedPath] = useState<string | undefined>(initialHash.path);
  const [requestedLines, setRequestedLines] = useState<[number, number] | undefined>(
    initialHash.lines,
  );
  const [requestedOid, setRequestedOid] = useState<string | undefined>(initialHash.oid);
  const [requestedChangeId, setRequestedChangeId] = useState<string | undefined>(
    initialHash.change,
  );
  const [requestedBranch, setRequestedBranch] = useState<string | undefined>(undefined);
  const [requestedSessionId, setRequestedSessionId] = useState<string | undefined>(undefined);
  const [delegateFocusNonce, setDelegateFocusNonce] = useState(0);
  const [worktableJudgmentCount, setWorktableJudgmentCount] = useState<number | null>(null);

  useEffect(() => {
    if (tab !== "agents" && requestedSessionId) setRequestedSessionId(undefined);
  }, [tab, requestedSessionId]);

  // Mirrors active deep-linkable view state back into location.hash.
  const [currentPath, setCurrentPath] = useState<string | undefined>(initialHash.path);
  const [currentLines, setCurrentLines] = useState<[number, number] | null>(
    initialHash.lines ?? null,
  );
  const [currentOid, setCurrentOid] = useState<string | undefined>(initialHash.oid);
  const [currentChangeId, setCurrentChangeId] = useState<string | undefined>(initialHash.change);
  const [settingsSection, setSettingsSection] = useState<string | undefined>(initialHash.section);
  const [dismissedApprovalIds, setDismissedApprovalIds] = useState<Set<string>>(() => new Set());

  const consumeCodeRequest = useCallback(() => {
    setRequestedPath(undefined);
    setRequestedLines(undefined);
  }, []);

  const consumeChangesRequest = useCallback(() => {
    setRequestedOid(undefined);
    setRequestedChangeId(undefined);
  }, []);

  // Clear one-shot branch target when leaving the Branches tab so revisiting never clobbers selection.
  useEffect(() => {
    if (tab !== "branches") setRequestedBranch(undefined);
  }, [tab]);
  const [dismissedBudgetKeys, setDismissedBudgetKeys] = useState<Set<string>>(() => new Set());
  const [requestedFocus, setRequestedFocus] = useState<FocusTarget | null>(() =>
    parseFocusParam(initialHash.focus),
  );
  const [currentFocus, setCurrentFocus] = useState<FocusTarget | null>(() =>
    parseFocusParam(initialHash.focus),
  );
  const [graduationTarget, setGraduationTarget] = useState<PolicySuggestion | null>(null);

  const prevTabRef = useRef<TabId>(tab);
  useEffect(() => {
    const nextHash = buildHash({
      tab,
      repo: repo.name,
      isDefaultRepo: repo.is_default,
      ref: activeRef,
      defaultBranch: repo.default_branch,
      path: currentPath,
      lines: currentLines,
      oid: currentOid,
      change: currentChangeId,
      section: settingsSection,
      focus: serializeFocusParam(currentFocus),
    });
    const isTraceDeepLink = tab === "traces" && window.location.hash.startsWith("#traces?");
    if (!isTraceDeepLink && window.location.hash !== nextHash) {
      if (prevTabRef.current !== tab) {
        window.location.hash = nextHash;
      } else {
        window.history.replaceState(null, "", nextHash);
      }
    }
    prevTabRef.current = tab;
  }, [
    tab,
    repo.name,
    repo.is_default,
    repo.default_branch,
    activeRef,
    currentPath,
    currentLines,
    currentOid,
    currentChangeId,
    settingsSection,
    currentFocus,
  ]);

  const defaultBranchRef = useRef(repo.default_branch);
  defaultBranchRef.current = repo.default_branch;

  // Quietly warm lazy view chunks once the initial tab settles so tab switches skip Suspense.
  useEffect(() => {
    const warm = () => {
      for (const id of TAB_ORDER) {
        if (id !== tab) preloadTab(id);
      }
    };
    const w = window as Window & {
      requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => number;
      cancelIdleCallback?: (id: number) => void;
    };
    if (w.requestIdleCallback) {
      const id = w.requestIdleCallback(warm, { timeout: 2200 });
      return () => w.cancelIdleCallback?.(id);
    }
    const timer = window.setTimeout(warm, 1400);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const onHash = () => {
      const parsed = parseHash();
      if (parsed.tab) setTab(parsed.tab);
      // A link without `ref` means the default branch, not whichever branch this tab was on.
      setActiveRef(parsed.ref ?? defaultBranchRef.current ?? undefined);
      setRequestedPath(parsed.path);
      setCurrentPath(parsed.path);
      setRequestedLines(parsed.lines);
      setCurrentLines(parsed.lines ?? null);
      setSettingsSection(parsed.section);
      if (parsed.change !== undefined) {
        setRequestedChangeId(parsed.change);
        setCurrentChangeId(parsed.change);
        setRequestedOid(undefined);
        setCurrentOid(undefined);
      } else if (parsed.oid !== undefined) {
        setRequestedOid(parsed.oid);
        setCurrentOid(parsed.oid);
        setRequestedChangeId(undefined);
        setCurrentChangeId(undefined);
      } else {
        setRequestedOid(undefined);
        setCurrentOid(undefined);
        setRequestedChangeId(undefined);
        setCurrentChangeId(undefined);
      }
      if (parsed.focus !== undefined) {
        const nextFocus = parseFocusParam(parsed.focus);
        setRequestedFocus(nextFocus);
        setCurrentFocus(nextFocus);
      } else if (parsed.tab === "worktable") {
        setRequestedFocus(null);
        setCurrentFocus(null);
      }
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [repo.default_branch]);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthError, setHealthError] = useState(false);
  const retryHealth = useCallback(() => {
    setHealthError(false);
    api
      .health()
      .then((h) => {
        setHealth(h);
        setHealthError(false);
      })
      .catch(() => setHealthError(true));
  }, []);
  const [branches, setBranches] = useState<BranchRecord[]>([]);
  const [paletteFiles, setPaletteFiles] = useState<string[]>([]);
  const [paletteTreeTruncation, setPaletteTreeTruncation] = useState<TreeTruncationInfo | null>(null);
  const [paletteCommits, setPaletteCommits] = useState<GitCommitSummary[]>([]);

  const [sseConnected, setSseConnected] = useState(false);
  const [sseNonce, setSseNonce] = useState(0);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [suggestions, setSuggestions] = useState<PolicySuggestion[]>([]);
  const [sessions, setSessions] = useState<AgentSessionRecord[]>([]);
  const [mcpAlerts, setMcpAlerts] = useState<McpDriftAlert[]>([]);
  const [budgetAlerts, setBudgetAlerts] = useState<BudgetAlert[]>([]);
  const [lanes, setLanes] = useState<AgentLane[]>([]);
  // Bumped by each "review" SSE frame so an open review reloads without polling.
  const [reviewRevision, setReviewRevision] = useState(0);
  const [traceRevision, setTraceRevision] = useState(0);

  // Owner-only ambient security hygiene & cross-tab ambient action handoffs
  const [hygiene, setHygiene] = useState<HygieneInsightsResponse | null>(null);
  const [hygieneLoading, setHygieneLoading] = useState(false);
  const [hygieneError, setHygieneError] = useState<string | null>(null);
  const hygieneReqIdRef = useRef(0);
  const [showDismissedHygiene, setShowDismissedHygiene] = useState(false);
  const [busyHygieneId, setBusyHygieneId] = useState<string | null>(null);
  const [pendingPolicyDraft, setPendingPolicyDraft] = useState<PolicyDraftRule | null>(null);
  const [pendingSecretFocus, setPendingSecretFocus] = useState<SecretFocusTarget | null>(null);

  const [lensOpen, setLensOpen] = useState(false);
  const [refOpen, setRefOpen] = useState(false);
  const [statusOpen, setStatusOpen] = useState(false);
  const [userOpen, setUserOpen] = useState(false);
  const [repoOpen, setRepoOpen] = useState(false);
  const [newRepoOpen, setNewRepoOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [paletteQuery, setPaletteQuery] = useState("");
  const [paletteIndex, setPaletteIndex] = useState(0);

  const lensRef = useRef<HTMLDivElement>(null);
  const refMenuRef = useRef<HTMLDivElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);
  const userRef = useRef<HTMLDivElement>(null);
  const repoMenuRef = useRef<HTMLDivElement>(null);
  const chordPrefixRef = useRef<number>(0);

  // Living-policy proposals are owner-only; a member would just get a 403.
  const refreshSuggestions = useCallback(() => {
    if (!owner) {
      setSuggestions([]);
      return;
    }
    api
      .approvalSuggestions()
      .then(setSuggestions)
      .catch(() => {});
  }, [owner]);

  const refreshApprovals = useCallback(() => {
    api
      .approvalsList()
      .then(setApprovals)
      .catch(() => {});
    refreshSuggestions();
  }, [refreshSuggestions]);

  const dismissSuggestion = useCallback(
    (s: PolicySuggestion) => {
      api
        .dismissApprovalSuggestion(s.id)
        .catch(() => {})
        .finally(refreshSuggestions);
    },
    [refreshSuggestions],
  );

  const refreshMcpAlerts = useCallback(() => {
    if (!owner) return;
    api
      .mcpAlerts()
      .then(setMcpAlerts)
      .catch(() => {});
  }, [owner]);

  const refreshHygiene = useCallback(
    (includeDismissed?: boolean) => {
      // Strictly owner-only: never query /v1/hygiene/* for members.
      if (!owner) {
        hygieneReqIdRef.current += 1;
        setHygiene(null);
        setHygieneError(null);
        setHygieneLoading(false);
        return;
      }
      const reqId = ++hygieneReqIdRef.current;
      const inc = includeDismissed ?? showDismissedHygiene;
      setHygieneLoading(true);
      api
        .hygieneInsights(activeRef, inc)
        .then((res) => {
          if (reqId !== hygieneReqIdRef.current) return;
          setHygiene(res);
          setHygieneError(null);
        })
        .catch((err: unknown) => {
          if (reqId !== hygieneReqIdRef.current) return;
          setHygieneError(errorText(err));
        })
        .finally(() => {
          if (reqId === hygieneReqIdRef.current) setHygieneLoading(false);
        });
    },
    [owner, activeRef, showDismissedHygiene],
  );

  // First load waits briefly so the active tab's own data gets the connections; later changes are immediate.
  const hygieneBootedRef = useRef(false);
  useEffect(() => {
    if (hygieneBootedRef.current) {
      refreshHygiene();
      return;
    }
    const t = setTimeout(() => {
      hygieneBootedRef.current = true;
      refreshHygiene();
    }, 700);
    return () => clearTimeout(t);
  }, [refreshHygiene]);

  const handleDismissHygiene = useCallback(
    async (id: string) => {
      if (!owner) return;
      setBusyHygieneId(id);
      setHygieneError(null);
      try {
        await api.dismissHygieneInsight(id);
        refreshHygiene();
      } catch (err: unknown) {
        setHygieneError(errorText(err));
      } finally {
        setBusyHygieneId((cur) => (cur === id ? null : cur));
      }
    },
    [owner, refreshHygiene],
  );

  const handleRestoreHygiene = useCallback(
    async (id: string) => {
      if (!owner) return;
      setBusyHygieneId(id);
      setHygieneError(null);
      try {
        await api.restoreHygieneInsight(id);
        refreshHygiene();
      } catch (err: unknown) {
        setHygieneError(errorText(err));
      } finally {
        setBusyHygieneId((cur) => (cur === id ? null : cur));
      }
    },
    [owner, refreshHygiene],
  );

  const handleAddOverlayGuard = useCallback(
    async (path: string, suggestedScope: string, insightId?: string) => {
      if (!owner) return;
      if (insightId) setBusyHygieneId(insightId);
      setHygieneError(null);
      try {
        await api.mountOverlay({
          path,
          scope: suggestedScope || "personal",
          encrypted: true,
          create_file: false,
        });
        refreshHygiene();
      } catch (err: unknown) {
        setHygieneError(errorText(err));
      } finally {
        if (insightId) setBusyHygieneId((cur) => (cur === insightId ? null : cur));
      }
    },
    [owner, refreshHygiene],
  );

  const handleHygieneAction = useCallback(
    (insight: HygieneInsight) => {
      if (!owner || !insight.action) return;
      const act = insight.action;
      switch (act.kind) {
        case "draft_policy_rule":
          setPendingPolicyDraft({
            zoneName: act.zone_name,
            pathGlob: act.path_glob,
            target: insight.target,
            tomlSnippet: act.toml_snippet,
          });
          setStatusOpen(false);
          setTab("policy");
          break;
        case "add_overlay_guard":
          void handleAddOverlayGuard(act.path, act.suggested_scope, insight.id);
          break;
        case "configure_secret":
          setPendingSecretFocus({ env: act.env, varName: act.var_name, tab: "contract" });
          setStatusOpen(false);
          setTab("secrets");
          break;
        case "inspect_branch":
          setRequestedBranch(act.branch);
          setStatusOpen(false);
          setTab("branches");
          break;
        case "review_agent_egress":
          setPendingSecretFocus({ tab: "contract" });
          setStatusOpen(false);
          setTab("secrets");
          break;
      }
    },
    [owner, handleAddOverlayGuard],
  );

  // Desktop notification for each newly seen pending approval (SSE frame or list refresh).
  const seenApprovals = useRef(new Set<string>());
  useEffect(() => {
    for (const ap of approvals) {
      if (ap.status !== "pending" || seenApprovals.current.has(ap.id)) continue;
      seenApprovals.current.add(ap.id);
      notifyPendingApproval(ap);
    }
  }, [approvals]);

  // Critical: what the shell and the active tab need to paint. Independent, so fired in parallel.
  const refreshCritical = useCallback(() => {
    void Promise.allSettled([
      api
        .health()
        .then((h) => {
          setHealth(h);
          setHealthError(false);
        })
        .catch((e) => {
          setHealthError(true);
          throw e;
        }),
      api.directory().then(setDirectory),
      api.branches().then((list) => {
        setBranches(list);
        // A ref this identity can't see (or a deleted one) would 404, so fall back to the current one.
        const cur = list.find((b) => b.is_current)?.name;
        setActiveRef((prev) => (prev && list.some((b) => b.name === prev) ? prev : cur));
      }),
      api.approvalsList().then(setApprovals),
    ]);
  }, []);

  // Secondary: badges and side panels. The audit log and MCP drift alerts are owner-only (403 for members).
  const refreshSecondary = useCallback(() => {
    void Promise.allSettled([
      owner ? api.auditList().then(setAuditEvents) : undefined,
      api.listSessions().then(setSessions),
      api.listLanes().then(setLanes),
    ]);
    refreshMcpAlerts();
    refreshSuggestions();
  }, [refreshMcpAlerts, refreshSuggestions, owner]);

  const refreshMetadata = useCallback(() => {
    invalidateApiCache();
    refreshCritical();
    refreshSecondary();
  }, [refreshCritical, refreshSecondary]);

  const sseAuthProbeRef = useRef<number>(0);

  useEffect(() => {
    refreshCritical();
    // Defer background panels so ~10 concurrent boot requests never starve the active tab's data.
    const secondaryTimer = setTimeout(refreshSecondary, 350);
    const es = new EventSource(repoPath("/v1/events/stream"));
    let hadDisconnect = false;
    const handleConnected = () => {
      setSseConnected(true);
      if (hadDisconnect) {
        hadDisconnect = false;
        refreshMetadata();
        setReviewRevision((n) => n + 1);
        setTraceRevision((n) => n + 1);
      }
    };
    es.onopen = handleConnected;
    es.onerror = () => {
      hadDisconnect = true;
      setSseConnected(false);
      // Debounced auth probe so an expired/revoked session transitions cleanly to sign-in
      // instead of looping "Reconnecting" forever on 401 SSE errors.
      const now = Date.now();
      if (now - sseAuthProbeRef.current >= 5000) {
        sseAuthProbeRef.current = now;
        authApi
          .status()
          .then((status) => {
            if (!status.authenticated) {
              es.close();
              onSessionExpired();
            }
          })
          .catch(() => {});
      }
    };
    es.addEventListener("ready", handleConnected);
    es.addEventListener("audit", (evt) => {
      try {
        const parsed = JSON.parse((evt as MessageEvent).data) as AuditEvent;
        setAuditEvents((prev) => [parsed, ...prev].slice(0, 200));
      } catch {
        // ignore malformed frames
      }
    });
    es.addEventListener("approval", (evt) => {
      try {
        const parsed = JSON.parse((evt as MessageEvent).data) as PendingApproval;
        setApprovals((prev) => [parsed, ...prev.filter((p) => p.id !== parsed.id)]);
        invalidateApiCache();
        // A decision can graduate a proposal, so re-read them on every approval event.
        refreshSuggestions();
      } catch {
        // ignore malformed frames
      }
    });
    es.addEventListener("session", (evt) => {
      try {
        const parsed = JSON.parse((evt as MessageEvent).data) as AgentSessionRecord;
        setSessions((prev) => {
          const existing = prev.find((s) => s.id === parsed.id);
          const merged =
            parsed.insights === undefined && existing?.insights
              ? { ...parsed, insights: existing.insights }
              : parsed;
          return [merged, ...prev.filter((s) => s.id !== parsed.id)].slice(0, 30);
        });
        if (
          parsed.status !== "paused" &&
          parsed.status !== "budget_exceeded" &&
          !parsed.budget?.paused
        ) {
          setBudgetAlerts((prev) => prev.filter((a) => a.session_id !== parsed.id));
        }
      } catch {
        // ignore malformed frames
      }
    });
    es.addEventListener("budget_alert", (evt) => {
      try {
        const parsed = JSON.parse((evt as MessageEvent).data) as BudgetAlert;
        setBudgetAlerts((prev) =>
          [
            parsed,
            ...prev.filter(
              (a) => !(a.session_id === parsed.session_id && a.metric === parsed.metric),
            ),
          ].slice(0, 30),
        );
      } catch {
        // ignore malformed frames
      }
    });
    es.addEventListener("mcp_alert", (evt) => {
      try {
        const parsed = JSON.parse((evt as MessageEvent).data) as McpDriftAlert;
        setMcpAlerts((prev) => [parsed, ...prev.filter((a) => a.id !== parsed.id)]);
        invalidateApiCache();
      } catch {
        // ignore malformed frames
      }
    });
    es.addEventListener("lane", (evt) => {
      try {
        const parsed = JSON.parse((evt as MessageEvent).data) as AgentLane;
        invalidateApiCache();
        // A deleted lane arrives once more as "discarded": drop it instead of keeping a ghost.
        setLanes((prev) => {
          const rest = prev.filter((l) => l.lane_id !== parsed.lane_id);
          return parsed.status === "discarded" ? rest : [parsed, ...rest];
        });
      } catch {
        // ignore malformed frames
      }
    });
    es.addEventListener("review", () => {
      invalidateApiCache();
      setReviewRevision((n) => n + 1);
    });
    es.addEventListener("trace", () => {
      setTraceRevision((n) => n + 1);
    });
    if (owner) {
      es.addEventListener("session_insight", (evt) => {
        try {
          const insight = JSON.parse((evt as MessageEvent).data) as SessionInsight;
          setSessions((prev) =>
            prev.map((s) => {
              if (s.id !== insight.session_id) return s;
              const current = s.insights ?? [];
              const merged = current.some((x) => x.id === insight.id)
                ? current.map((x) => (x.id === insight.id ? insight : x))
                : [...current, insight];
              return { ...s, insights: merged };
            }),
          );
        } catch {
          // ignore malformed frames
        }
      });
    }
    return () => {
      clearTimeout(secondaryTimer);
      es.close();
    };
  }, [
    refreshCritical,
    refreshSecondary,
    refreshMetadata,
    refreshSuggestions,
    sseNonce,
    onSessionExpired,
    owner,
  ]);

  // Lazy-load files & commits when Command Palette opens
  useEffect(() => {
    if (!paletteOpen || repoEmpty) return;
    api
      .repoTree(identity, false, activeRef)
      .then((res) => {
        setPaletteFiles(res.entries.filter((e) => e.kind === "file").map((e) => e.path));
        setPaletteTreeTruncation(getTreeTruncationInfo(res));
      })
      .catch(() => {});
    api
      .commits(identity, { ref: activeRef })
      .then(setPaletteCommits)
      .catch(() => {});
  }, [paletteOpen, repoEmpty, identity, activeRef]);

  const pendingApprovals = useMemo(
    () => approvals.filter((a) => a.status === "pending"),
    [approvals],
  );
  const visiblePendingApprovals = useMemo(
    () => pendingApprovals.filter((a) => !dismissedApprovalIds.has(a.id)),
    [pendingApprovals, dismissedApprovalIds],
  );
  const pendingCount = pendingApprovals.length;
  const lensPendingCount = useMemo(
    () =>
      filterApprovalsForLens(approvals, identity, owner).filter((a) => a.status === "pending")
        .length,
    [approvals, identity, owner],
  );
  const lensUncommittedCount = useMemo(
    () => filterSessionsForLens(sessions, identity, owner).filter(sessionHasUncommittedChanges).length,
    [sessions, identity, owner],
  );
  const worktableBadge = worktableJudgmentCount ?? lensPendingCount + lensUncommittedCount;

  const pausedSessions = useMemo(
    () => sessions.filter((s) => s.status === "paused" || Boolean(s.budget?.paused)),
    [sessions],
  );
  const pausedCount = pausedSessions.length;

  const visibleBudgetAlerts = useMemo(() => {
    const byId = new Map(sessions.map((s) => [s.id, s]));
    const filtered = budgetAlerts.filter((a) => {
      if (dismissedBudgetKeys.has(budgetAlertKey(a))) return false;
      const sess = byId.get(a.session_id);
      if (!sess) return true;
      return (
        sess.status === "paused" ||
        Boolean(sess.budget?.paused) ||
        (a.action === "terminate" && sess.status === "budget_exceeded")
      );
    });
    // Also surface any already-paused session that predates this SSE connection.
    const seenIds = new Set(filtered.map((a) => a.session_id));
    for (const s of pausedSessions) {
      if (seenIds.has(s.id)) continue;
      const synthetic: BudgetAlert = {
        session_id: s.id,
        principal: s.principal,
        agent_profile: s.agent_profile || undefined,
        metric: s.budget?.breached_metric ?? "budget",
        current: 1,
        limit: 1,
        action: "pause",
        message: s.budget?.breach_reason ?? "Session paused after exceeding an autonomy budget.",
        timestamp: s.started_at,
      };
      if (!dismissedBudgetKeys.has(budgetAlertKey(synthetic))) {
        filtered.push(synthetic);
      }
    }
    return filtered;
  }, [budgetAlerts, dismissedBudgetKeys, sessions, pausedSessions]);

  const sessionsWithInsights = useMemo(
    () =>
      owner
        ? sessions.filter(
            (s) =>
              (s.status === "running" || s.status === "paused") &&
              (s.insights?.length ?? 0) > 0,
          )
        : [],
    [owner, sessions],
  );
  const thrashingRunningSessions = useMemo(
    () => sessionsWithInsights.filter((s) => s.status === "running"),
    [sessionsWithInsights],
  );
  const activeHygieneInsights = useMemo(
    () => (owner ? (hygiene?.insights ?? []).filter((i) => !i.dismissed) : []),
    [owner, hygiene],
  );
  const activeAttentionCount = useMemo(
    () => activeHygieneInsights.filter((i) => i.severity === "attention").length,
    [activeHygieneInsights],
  );
  const activeNoticeCount = useMemo(
    () => activeHygieneInsights.filter((i) => i.severity === "notice").length,
    [activeHygieneInsights],
  );
  const hasAmbientAttention =
    owner && (thrashingRunningSessions.length > 0 || activeAttentionCount > 0);
  const hasAmbientNotice = owner && !hasAmbientAttention && activeNoticeCount > 0;

  // Rendered in the header switcher (md+) and in the account menu (phones < md).
  const branchMenu = (
    <>
      <div className="max-h-60 overflow-y-auto">
        {branches.map((b) => {
          const selected = b.name === activeRef;
          return (
            <button
              key={b.name}
              type="button"
              role="menuitemradio"
              aria-checked={selected}
              onClick={() => {
                if (b.name !== activeRef && !confirmLeaveDirtyCode()) return;
                setActiveRef(b.name);
                setRefOpen(false);
                setUserOpen(false);
              }}
              className={`flex w-full items-center justify-between gap-2 rounded-xl px-3 py-2 text-left font-mono text-[13px] transition ${
                selected ? "bg-[#7f95f8]/18 text-[#f3f6fd]" : "text-[#d2dbee] hover:bg-white/[0.05]"
              }`}
            >
              <span className="flex min-w-0 items-center gap-2">
                {b.visibility.scope === "restricted" || b.visibility.scope === "personal" ? (
                  <IconLock className="h-4 w-4 text-[#a8c5ff]" />
                ) : (
                  <IconBranchRef className="h-4 w-4 text-[#7f95f8]" />
                )}
                <span className="truncate">{b.name}</span>
              </span>
              {selected && <IconCheck className="h-4 w-4 shrink-0 text-[#9ec0f5]" />}
            </button>
          );
        })}
      </div>
      <div className="mt-1 border-t border-white/[0.06] pt-1">
        <button
          type="button"
          role="menuitem"
          onClick={() => {
            setTab("branches");
            setRefOpen(false);
            setUserOpen(false);
          }}
          className="flex w-full items-center justify-between rounded-xl px-3 py-1.5 font-mono text-[12.5px] text-[#9ec0f5] hover:bg-white/[0.05]"
        >
          <span>Manage branches</span>
          <span>→</span>
        </button>
      </div>
    </>
  );

  // Rendered in the header switcher (xl+) and in the account menu (narrower screens).
  const repoMenu = (
    <>
      <div className="max-h-60 overflow-y-auto">
        {repos.map((r) => {
          const selected = r.name === repo.name;
          return (
            <button
              key={r.name}
              type="button"
              role="menuitemradio"
              aria-checked={selected}
              onClick={() => {
                setRepoOpen(false);
                setUserOpen(false);
                if (!selected) onSwitchRepo(r.name);
              }}
              className={`flex w-full items-center justify-between gap-2 rounded-xl px-3 py-2 text-left transition ${
                selected ? "bg-[#7f95f8]/18 text-[#f3f6fd]" : "text-[#d2dbee] hover:bg-white/[0.05]"
              }`}
            >
              <span className="min-w-0">
                <span className="block truncate font-mono text-[13px]">{r.name}</span>
                {r.description && (
                  <span className="mt-0.5 block truncate text-[12.5px] text-[#98a8c4]">
                    {r.description}
                  </span>
                )}
              </span>
              {selected && <IconCheck className="h-4 w-4 shrink-0 text-[#9ec0f5]" />}
            </button>
          );
        })}
      </div>
      {owner && (
        <div className="mt-1 border-t border-white/[0.06] pt-1">
          <button
            type="button"
            role="menuitem"
            onClick={() => {
              setRepoOpen(false);
              setUserOpen(false);
              setNewRepoOpen(true);
            }}
            className="flex w-full items-center gap-2 rounded-xl px-3 py-1.5 text-left font-mono text-[12.5px] text-[#9ec0f5] hover:bg-white/[0.05]"
          >
            <IconPlus className="h-4 w-4" />
            <span>New repository…</span>
          </button>
        </div>
      )}
    </>
  );

  const navItems: {
    id: TabId;
    label: string;
    shortcut: string;
    icon: typeof IconCode;
    badge?: number;
    /** Gold only when something needs a decision (approvals/quarantine); otherwise neutral indigo-ice. */
    urgent?: boolean;
  }[] = [
    {
      id: "worktable",
      label: "Overview",
      shortcut: "1",
      icon: IconWorktable,
      badge: worktableBadge,
      urgent: lensPendingCount > 0 || pausedCount > 0,
    },
    { id: "code", label: "Files", shortcut: "2", icon: IconCode },
    { id: "changes", label: "Changes", shortcut: "3", icon: IconChanges },
    { id: "branches", label: "Branches", shortcut: "4", icon: IconBranches },
    {
      id: "agents",
      label: "AI Agents",
      shortcut: "5",
      icon: IconCage,
      badge: pendingCount + pausedCount,
      urgent: true,
    },
    { id: "traces", label: "Traces", shortcut: "6", icon: IconTimeline },
    { id: "secrets", label: "Secrets", shortcut: "7", icon: IconVault },
    { id: "policy", label: "Access Rules", shortcut: "8", icon: IconPolicy },
    { id: "settings", label: "Settings", shortcut: "9", icon: IconGear },
  ];

  const paletteActions = useMemo(() => {
    const q = paletteQuery.trim().toLowerCase();
    const lensSessions = filterSessionsForLens(sessions, identity, owner);
    const lensApprovals = filterApprovalsForLens(pendingApprovals, identity, owner);
    const items: {
      id: string;
      group: string;
      label: string;
      meta?: string;
      kind: "view" | "lens" | "file" | "commit" | "action";
      run: () => void;
    }[] = [
      ...(owner && !repoEmpty
        ? [
            {
              id: "act-delegate",
              group: "Overview",
              label: "Delegate a task…",
              meta: "D",
              kind: "action" as const,
              run: () => {
                setTab("worktable");
                setDelegateFocusNonce((n) => n + 1);
              },
            },
          ]
        : []),
      ...navItems.filter((n) => !isTabDisabled(n.id)).map((n) => ({
        id: `nav-${n.id}`,
        group: "Views",
        label: n.label,
        meta: n.shortcut,
        kind: "view" as const,
        run: () => setTab(n.id),
      })),
      ...lensApprovals.slice(0, 6).map((ap) => ({
        id: `judge-${ap.id}`,
        group: "Action Required",
        label: `${ap.var_name} (${ap.method} ${ap.host})`,
        meta: `${ap.principal}${ap.agent_profile ? ` ∩ ${ap.agent_profile}` : ""}`,
        kind: "action" as const,
        run: () => {
          const matching = lensSessions.find(
            (s) =>
              s.status === "running" &&
              s.principal === ap.principal &&
              (!ap.agent_profile || s.agent_profile === ap.agent_profile),
          );
          const nextFocus: FocusTarget | null = matching
            ? { kind: "session", id: matching.id }
            : null;
          setRequestedFocus(nextFocus);
          setCurrentFocus(nextFocus);
          setTab("worktable");
        },
      })),
      ...lensSessions.slice(0, q ? 50 : 4).map((s) => ({
        id: `sess-${s.id}`,
        group: "Agents",
        label: `$ ${s.command}`,
        meta: `${s.status} · ${s.principal}${s.agent_profile ? ` ∩ ${s.agent_profile}` : ""}`,
        kind: "action" as const,
        run: () => {
          const nextFocus: FocusTarget = { kind: "session", id: s.id };
          setRequestedFocus(nextFocus);
          setCurrentFocus(nextFocus);
          setTab("worktable");
        },
      })),
      ...branches.slice(0, q ? 100 : 6).map((b) => ({
        id: `branch-${b.name}`,
        group: "Branches",
        label: b.name,
        meta: b.readiness,
        kind: "action" as const,
        run: () => {
          const nextFocus: FocusTarget = { kind: "branch", name: b.name };
          setRequestedFocus(nextFocus);
          setCurrentFocus(nextFocus);
          setTab("worktable");
        },
      })),
      ...(owner ? presets : []).map((p) => ({
        id: `id-${p.id}`,
        group: "View as",
        label: p.label,
        meta: p.groups.length > 0 ? p.groups.join(", ") : "no groups",
        kind: "lens" as const,
        run: () => setIdentity(p),
      })),
      ...(owner && !repoEmpty
        ? [
            {
              id: "act-toggle-mirror",
              group: "Compare Views",
              label: "Compare Views (Owner vs Contractor / AI Agent)",
              meta: "Alt peek",
              kind: "lens" as const,
              run: () => {
                setMirrorEnabled((m) => (tab === "code" ? !m : true));
                setTab("code");
              },
            },
          ]
        : []),
      ...(owner && !repoEmpty
        ? [
            {
              id: "act-github-companion",
              group: "Connect",
              label: "Connect GitHub (sync & safe PRs)",
              kind: "action" as const,
              run: () => setGithubModalOpen(true),
            },
          ]
        : []),
      {
        id: "act-agent-connect",
        group: "Connect",
        label: "Connect AI Agent (MCP / CLI)",
        kind: "action" as const,
        run: () => setAgentConnectOpen(true),
      },
      {
        id: "act-reconnect",
        group: "System",
        label: "Reconnect live event stream",
        meta: sseConnected ? "live" : "offline",
        kind: "action",
        run: () => setSseNonce((n) => n + 1),
      },
      ...repos.map((r) => ({
        id: `repo-${r.name}`,
        group: "Repositories",
        label: r.name,
        meta: r.name === repo.name ? "current" : r.description || undefined,
        kind: "action" as const,
        run: () => {
          if (r.name !== repo.name) onSwitchRepo(r.name);
        },
      })),
      ...paletteFiles.slice(0, q ? 5000 : 8).map((fp) => ({
        id: `file-${fp}`,
        group: "Files",
        label: fp,
        meta: activeRef,
        kind: "file" as const,
        run: () => {
          setRequestedPath(fp);
          setCurrentPath(fp);
          setRequestedLines(undefined);
          setCurrentLines(null);
          setTab("code");
        },
      })),
      ...paletteCommits.slice(0, q ? 200 : 6).map((c) => ({
        id: `commit-${c.oid}`,
        group: "Commits",
        label: c.subject,
        meta: c.short_oid,
        kind: "commit" as const,
        run: () => {
          setRequestedOid(c.oid);
          setCurrentOid(c.oid);
          setRequestedChangeId(undefined);
          setCurrentChangeId(undefined);
          setTab("changes");
        },
      })),
    ];

    // Group, then cap each group so Repositories, Files, Commits and View-as are all reachable
    // (a flat slice let the first groups crowd the rest out).
    const scored = q
      ? items
          .map((i) => ({
            i,
            s: Math.max(
              fuzzyScore(q, i.label),
              fuzzyScore(q, i.group, false) * 0.5,
              i.meta ? fuzzyScore(q, i.meta, false) * 0.5 : 0,
            ),
          }))
          .filter((x) => x.s > 0)
      : items.map((i) => ({ i, s: 0 }));
    const groups = new Map<string, typeof scored>();
    for (const x of scored) {
      const list = groups.get(x.i.group);
      if (list) list.push(x);
      else groups.set(x.i.group, [x]);
    }
    const ordered = [...groups.entries()];
    if (q) {
      for (const [, list] of ordered) list.sort((a, b) => b.s - a.s);
      ordered.sort((a, b) => b[1][0].s - a[1][0].s);
    }
    return ordered.flatMap(([group, list]) =>
      list.slice(0, PALETTE_GROUP_CAP[group] ?? (q ? 6 : 4)).map((x) => x.i),
    );
  }, [
    paletteQuery,
    paletteFiles,
    paletteCommits,
    activeRef,
    sseConnected,
    pendingCount,
    pausedCount,
    worktableBadge,
    presets,
    repos,
    owner,
    identity,
    sessions,
    pendingApprovals,
    branches,
    repo.name,
    onSwitchRepo,
    tab,
    repoEmpty,
  ]);

  useEffect(() => {
    setPaletteIndex(0);
  }, [paletteQuery, paletteOpen]);

  const paletteListRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!paletteOpen) return;
    paletteListRef.current
      ?.querySelector<HTMLElement>('[data-active="true"]')
      ?.scrollIntoView({ block: "nearest" });
  }, [paletteOpen, paletteIndex, paletteActions]);

  const paletteInputRef = useRef<HTMLInputElement>(null);
  const closePalette = useCallback(() => setPaletteOpen(false), []);
  const { panelRef: palettePanelRef, onKeyDown: paletteModalKeyDown } = useModalDialog({
    open: paletteOpen,
    onClose: closePalette,
    initialFocusRef: paletteInputRef,
  });

  // Global keyboard shortcuts (Cmd/Ctrl+K in capture phase to beat Monaco's chord prefix,
  // plus 1-7, g+letter chords, Shift+L "View as" cycle, Esc)
  useEffect(() => {
    const onCaptureKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === "k") {
        if (!canToggleCommandPalette(hasOtherModalDialog())) return;
        e.preventDefault();
        e.stopPropagation();
        setPaletteOpen((open) => !open);
        setPaletteQuery("");
        setLensOpen(false);
        setRefOpen(false);
        setStatusOpen(false);
      }
    };

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setPaletteOpen(false);
        setLensOpen(false);
        setRefOpen(false);
        setStatusOpen(false);
        setUserOpen(false);
        setRepoOpen(false);
        return;
      }

      if (githubModalOpen || agentConnectOpen) return;

      if (paletteOpen) {
        // Ignore keys that are confirming an IME composition (e.g. Enter picking a candidate).
        if (e.isComposing || e.keyCode === 229) return;
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setPaletteIndex((idx) =>
            paletteActions.length === 0 ? 0 : (idx + 1) % paletteActions.length,
          );
        } else if (e.key === "ArrowUp") {
          e.preventDefault();
          setPaletteIndex((idx) =>
            paletteActions.length === 0
              ? 0
              : (idx - 1 + paletteActions.length) % paletteActions.length,
          );
        } else if (e.key === "Enter") {
          const item = paletteActions[paletteIndex];
          if (item) {
            e.preventDefault();
            item.run();
            setPaletteOpen(false);
          }
        }
        return;
      }

      if (hasActiveModalDialog()) return;

      if (isEditableEventTarget(e) || e.metaKey || e.ctrlKey || e.altKey) {
        return;
      }

      // 1-9 direct tab jump (1-4 stay on Traces to switch Span Inspector tabs)
      if (e.key >= "1" && e.key <= "9") {
        if (tab === "traces" && e.key >= "1" && e.key <= "4") {
          return;
        }
        const idx = Number(e.key) - 1;
        if (TAB_ORDER[idx]) {
          e.preventDefault();
          if (!isTabDisabled(TAB_ORDER[idx])) setTab(TAB_ORDER[idx]);
        }
        return;
      }

      // Shift+L cycles identity lens
      if (e.shiftKey && e.key.toLowerCase() === "l") {
        if (!canCycleIdentityLens(owner, presets.length)) return;
        e.preventDefault();
        if (!confirmLeaveDirtyCode()) return;
        setIdentityId((cur) => {
          const idx = presets.findIndex((p) => p.id === cur);
          return presets[(idx + 1) % presets.length].id;
        });
        return;
      }

      // g + key chords (g w, g c, g h, g b, g a, g s, g p)
      const now = Date.now();
      const lower = e.key.toLowerCase();
      if (lower === "g" && !e.shiftKey) {
        chordPrefixRef.current = now;
        return;
      }
      if (now - chordPrefixRef.current < 800) {
        chordPrefixRef.current = 0;
        const map: Record<string, TabId> = {
          w: "worktable",
          c: "code",
          h: "changes",
          b: "branches",
          a: "agents",
          t: "traces",
          s: "secrets",
          p: "policy",
        };
        if (map[lower]) {
          e.preventDefault();
          if (!isTabDisabled(map[lower])) setTab(map[lower]);
        }
      }
    };

    const onClickOutside = (e: MouseEvent) => {
      const target = e.target as Node;
      if (lensRef.current && !lensRef.current.contains(target)) setLensOpen(false);
      if (refMenuRef.current && !refMenuRef.current.contains(target)) setRefOpen(false);
      if (statusRef.current && !statusRef.current.contains(target)) setStatusOpen(false);
      if (userRef.current && !userRef.current.contains(target)) setUserOpen(false);
      if (repoMenuRef.current && !repoMenuRef.current.contains(target)) setRepoOpen(false);
    };

    window.addEventListener("keydown", onCaptureKeyDown, true);
    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("mousedown", onClickOutside);
    return () => {
      window.removeEventListener("keydown", onCaptureKeyDown, true);
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("mousedown", onClickOutside);
    };
  }, [
    tab,
    paletteOpen,
    paletteActions,
    paletteIndex,
    presets,
    githubModalOpen,
    agentConnectOpen,
    repoEmpty,
  ]);

  // A tab mounts on first visit and then stays mounted (hidden) so switching back is instant.
  const pane = (id: TabId, render: () => ReactNode) => {
    const scope = navItems.find((item) => item.id === id)?.label ?? id;
    return tab === id || visitedTabs.has(id) ? (
      <div
        key={id}
        className={tab === id ? "flex min-h-0 flex-1 flex-col overflow-hidden" : "hidden"}
        aria-hidden={tab === id ? undefined : true}
      >
        <ErrorBoundary scope={scope} resetKey={`${repo.name}:${id}`}>
          <Suspense fallback={<ViewSkeleton tab={id} />}>{render()}</Suspense>
        </ErrorBoundary>
      </div>
    ) : null;
  };

  return (
    <div className="flex h-[100dvh] flex-col overflow-hidden text-[#f3f6fd]">
      {/* Full-bleed header; z-[45] keeps status/hygiene popovers above the z-40 floating approval cards */}
      <header
        data-premier-header
        className="pr-topbar relative z-[45] flex h-14 shrink-0 items-center justify-between gap-2 px-3.5 lg:px-4 xl:gap-3 xl:px-5"
      >
        {/* Left: Brand + xl repo switcher + md+ branch ref (strictly shrink-0 so it never collides) */}
        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={() => setTab("worktable")}
            className="flex shrink-0 items-center gap-2 whitespace-nowrap text-left transition hover:opacity-90"
          >
            <PremierMark className="h-7 w-7" />
            <span className="hidden text-[15px] font-semibold tracking-[-0.02em] text-[#f3f6fd] sm:inline">
              Premier
            </span>
          </button>

          <div className="hidden shrink-0 items-center gap-2 xl:flex">
            <span className="hidden text-white/15 2xl:inline">/</span>
            <div ref={repoMenuRef} className="relative shrink-0">
              <button
                type="button"
                onClick={() => setRepoOpen((o) => !o)}
                onKeyDown={(e) => menuTriggerKeyDown(e, repoOpen, () => setRepoOpen(true))}
                aria-haspopup="menu"
                aria-expanded={repoOpen}
                aria-label={`Repository: ${repo.name}`}
                title={repo.description ? `${repo.name} · ${repo.description}` : repo.name}
                className="pr-pill inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[13px] leading-none text-[#b4c2dc] hover:text-[#f3f6fd]"
              >
                <span className="max-w-[88px] truncate 2xl:max-w-[128px]">{repo.name}</span>
                <IconChevron className="h-4 w-4 text-[#98a8c4]" />
              </button>
              {repoOpen && (
                <div
                  role="menu"
                  onKeyDown={menuKeyDown}
                  className="pr-elevated absolute left-0 mt-2 w-64 overflow-hidden rounded-2xl p-1.5"
                >
                  {repoMenu}
                </div>
              )}
            </div>
          </div>

          {/* Nothing to switch until a first commit exists. */}
          {!repoEmpty && (
          <div ref={refMenuRef} className="relative hidden shrink-0 md:block">
            <button
              type="button"
              onClick={() => {
                setRefOpen((o) => !o);
                setLensOpen(false);
                setStatusOpen(false);
              }}
              onKeyDown={(e) => menuTriggerKeyDown(e, refOpen, () => setRefOpen(true))}
              aria-haspopup="menu"
              aria-expanded={refOpen}
              aria-label={`Branch: ${activeRef ?? repo.default_branch ?? "no branches yet"}`}
              // Nothing to pick in an empty repository (or one with no branch you can see).
              disabled={branches.length === 0}
              className="pr-pill inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[13px] leading-none text-[#b4c2dc] hover:text-[#f3f6fd] disabled:cursor-default disabled:opacity-60 disabled:hover:text-[#b4c2dc]"
            >
              <IconBranchRef className="h-4 w-4 text-[#7f95f8]" />
              <span className="max-w-[72px] truncate lg:max-w-[88px] xl:max-w-[104px]">
                {activeRef ?? repo.default_branch ?? "no branches yet"}
              </span>
              <IconChevron className="h-4 w-4 text-[#a6b5cf]" />
            </button>

            {refOpen && (
              <div
                role="menu"
                onKeyDown={menuKeyDown}
                className="pr-elevated absolute left-0 mt-2 w-64 overflow-hidden rounded-2xl p-1.5"
              >
                {branchMenu}
              </div>
            )}
          </div>
          )}
        </div>

        {/* Center: Primary navigation (zero overflow at md=768px and lg=1024px) */}
        <nav aria-label="Primary" className="hidden shrink-0 items-center gap-0.5 xl:gap-1 md:flex">
          {navItems
            .filter((item) => item.id !== "settings")
            .map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            const locked = isTabDisabled(item.id);
            return (
              <Fragment key={item.id}>
                {/* Core workflow tabs | governance tabs */}
                {item.id === "secrets" && (
                  <span aria-hidden="true" className="mx-0.5 h-5 w-px shrink-0 bg-white/[0.10]" />
                )}
              <button
                type="button"
                title={locked ? "Push your first commit to unlock" : `${item.label} (${item.shortcut})`}
                aria-label={item.label}
                aria-current={active ? "page" : undefined}
                disabled={locked}
                onMouseEnter={() => preloadTab(item.id)}
                onFocus={() => preloadTab(item.id)}
                onClick={() => setTab(item.id)}
                className={`inline-flex h-9 shrink-0 items-center gap-1 whitespace-nowrap rounded-full px-2 text-[13.5px] font-medium transition xl:gap-2 xl:px-2.5 2xl:px-3 xl:text-[14px] ${
                  locked
                    ? "cursor-not-allowed border border-transparent text-[#b2c0d8] opacity-35"
                    : active
                    ? "pr-pill-active"
                    : "border border-transparent text-[#b2c0d8] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
                }`}
              >
                <Icon className={`h-[18px] w-[18px] ${active ? "text-[#9ec0f5]" : "opacity-85"}`} />
                <span className={active ? "inline" : "hidden 2xl:inline"}>{item.label}</span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span
                    className={`rounded-full px-1.5 py-0.5 font-mono text-[12.5px] leading-none ${
                      item.urgent
                        ? "bg-[#7f95f8]/22 text-[#a8c5ff]"
                        : "bg-[#7f95f8]/20 text-[#9ec0f5]"
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
              </Fragment>
            );
          })}
        </nav>

        {/* Right: "View as" lens + OS-aware shortcut + live host status + account menu.
            The lens is the one shrinkable item, so the bar never overflows. */}
        <div className="flex min-w-0 items-center justify-end gap-1.5 xl:gap-2">
          {!owner ? (
            <span
              title={`You act as ${user.principal}. "View as" is owner only.`}
              className="pr-pill inline-flex h-9 min-w-0 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 font-mono text-[13.5px] text-[#e6ecf8] xl:px-3"
            >
              <IconUser className="h-[18px] w-[18px] shrink-0 text-[#7f95f8]" />
              <span className="max-w-[76px] min-w-0 truncate lg:max-w-[104px] xl:max-w-[152px]">
                {user.principal}
              </span>
            </span>
          ) : // Progressive disclosure: the lens appears once you view as someone else or have configured more than self + anonymous.
          viewingAs || presets.length > 2 ? (
          <div ref={lensRef} className="relative min-w-0">
            <button
              type="button"
              onClick={() => {
                setLensOpen((o) => !o);
                setRefOpen(false);
                setStatusOpen(false);
              }}
              onKeyDown={(e) => menuTriggerKeyDown(e, lensOpen, () => setLensOpen(true))}
              aria-haspopup="menu"
              aria-expanded={lensOpen}
              aria-label={`View as ${identity.label} (policy simulator)`}
              title={`View as ${identity.label} (${identity.subtitle}) · policy simulator, not your sign-in · Shift+L to cycle`}
              className={`inline-flex h-9 max-w-full min-w-0 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 font-mono text-[13.5px] text-[#e6ecf8] transition xl:gap-2 xl:px-3 ${
                viewingAs
                  ? "border border-[#9ec0f5]/35 bg-[#7f95f8]/15 hover:bg-[#7f95f8]/22"
                  : "pr-pill"
              }`}
            >
              {identity.agentProfile ? (
                <IconIntersection className="h-[18px] w-[18px] text-[#9ec0f5]" />
              ) : (
                <IconLens className={`h-[18px] w-[18px] ${viewingAs ? "text-[#9ec0f5]" : "text-[#7f95f8]"}`} />
              )}
              <span className="hidden shrink-0 font-sans text-[12.5px] text-[#a6b5cf] 2xl:inline">
                View as
              </span>
              <span className="max-w-[76px] min-w-0 truncate lg:max-w-[104px] xl:max-w-[152px]">
                {identity.label}
              </span>
              <IconChevron className="h-4 w-4 text-[#a6b5cf]" />
            </button>

            {lensOpen && (
              <div
                role="menu"
                onKeyDown={menuKeyDown}
                className="pr-elevated fixed inset-x-3 top-14 mt-2 max-h-[70vh] overflow-y-auto rounded-2xl p-1.5 sm:absolute sm:inset-x-auto sm:top-auto sm:right-0 sm:w-68"
              >
                <div className="px-3 pt-1.5 pb-2 text-[12.5px] leading-snug text-[#98a8c4]">
                  <span className="font-medium text-[#d2dbee]">View as</span> · owner-only policy
                  simulator. Previews what another identity can see; you stay signed in as{" "}
                  {user.display_name}.
                </div>
                {(
                  [
                    ["People", presets.filter((p) => !p.agentProfile)],
                    ["Agents ∩ profile", presets.filter((p) => p.agentProfile)],
                  ] as const
                ).map(([heading, group]) =>
                  group.length === 0 ? null : (
                    <div key={heading} role="group" aria-label={heading}>
                      <div className="px-3 pt-2 pb-1 text-[12.5px] font-semibold tracking-wide text-[#a6b5cf] uppercase">
                        {heading}
                      </div>
                      {group.map((preset) => {
                        const active = preset.id === identity.id;
                        return (
                          <button
                            key={preset.id}
                            type="button"
                            role="menuitemradio"
                            aria-checked={active}
                            onClick={() => {
                              setIdentity(preset);
                              setLensOpen(false);
                            }}
                            className={`flex w-full items-center justify-between rounded-xl px-3 py-2 text-left transition ${
                              active
                                ? "bg-[#7f95f8]/18 text-[#f3f6fd]"
                                : "text-[#d2dbee] hover:bg-white/[0.05]"
                            }`}
                          >
                            <div className="min-w-0">
                              <div className="flex items-center gap-2 font-mono text-[13.5px] font-medium">
                                {preset.agentProfile ? (
                                  <IconIntersection className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
                                ) : (
                                  <IconLens className="h-4 w-4 shrink-0 text-[#a6b5cf]" />
                                )}
                                <span className="truncate">{preset.label}</span>
                              </div>
                              <div className="mt-0.5 truncate pl-6 text-[12.5px] text-[#98a8c4]">
                                {preset.id === "self"
                                  ? "you"
                                  : preset.groups.length > 0
                                    ? preset.groups.join(", ")
                                    : "no groups"}
                              </div>
                            </div>
                            {active && <IconCheck className="h-4 w-4 shrink-0 text-[#9ec0f5]" />}
                          </button>
                        );
                      })}
                    </div>
                  ),
                )}
              </div>
            )}
          </div>
          ) : null}

          {/* GitHub Companion: first-class, owner-only entry point (renders nothing otherwise).
              Nothing to sync until a first commit exists. */}
          {!repoEmpty && <GithubTopbarPill user={user} onOpen={() => setGithubModalOpen(true)} />}

          {/* OS-aware Command Palette Trigger (no duplicate clover on macOS!) */}
          <button
            type="button"
            onClick={() => {
              setPaletteOpen(true);
              setPaletteQuery("");
            }}
            title={`Command palette (${formatShortcutLabel("k", clientOS)} · ${getOSLabel(clientOS)})`}
            aria-label={`Command palette (${formatShortcutLabel("k", clientOS)})`}
            className="pr-pill inline-flex h-9 shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-full px-2.5 font-mono text-[13px] text-[#b6c3db] hover:text-[#f3f6fd]"
          >
            <IconSearch className="h-4 w-4 text-[#a6b5cf] xl:hidden" />
            <IconOSBadge os={clientOS} className="hidden h-4 w-4 text-[#a6b5cf] xl:block" />
            <span className="hidden items-center gap-1 2xl:inline-flex">
              {!macOS && <kbd className="pr-kbd">{cmdShortcut.modifier}</kbd>}
              <kbd className="pr-kbd">{cmdShortcut.key}</kbd>
            </span>
          </button>

          {/* Interactive Live Connection & Host Capabilities Popover */}
          <div ref={statusRef} className="relative shrink-0">
            <button
              type="button"
              onClick={() => {
                setStatusOpen((o) => !o);
                setLensOpen(false);
                setRefOpen(false);
              }}
              aria-label="Runtime status"
              title={
                hasAmbientAttention
                  ? `${sseConnected ? "Connected" : "Reconnecting"} · ambient hygiene needs attention`
                  : hasAmbientNotice
                    ? `${sseConnected ? "Connected" : "Reconnecting"} · ambient hygiene notice`
                    : sseConnected
                      ? "Connected"
                      : "Reconnecting"
              }
              className={`pr-pill relative inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full ${
                hasAmbientAttention
                  ? "border-[#9ec0f5]/45! ring-1 ring-[#9ec0f5]/28"
                  : hasAmbientNotice
                    ? "border-[#9ec0f5]/45! ring-1 ring-[#9ec0f5]/24"
                    : ""
              }`}
            >
              <span
                className={`h-2.5 w-2.5 rounded-full ${
                  sseConnected
                    ? "bg-[#5bdba2] shadow-[0_0_10px_rgba(91,219,162,0.8)]"
                    : "bg-[#7f95f8] shadow-[0_0_8px_rgba(240,185,101,0.65)]"
                }`}
              />
              {hasAmbientAttention && (
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-[#7f95f8] ring-2 ring-[#070912]" />
              )}
              {hasAmbientNotice && (
                <span className="absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full bg-[#9ec0f5] ring-2 ring-[#070912]" />
              )}
            </button>

            {statusOpen && (
              <div
                className={`pr-elevated absolute right-0 mt-2 rounded-2xl p-3.5 font-mono text-[13px] ${
                  owner
                    ? "w-[340px] max-w-[calc(100vw-1.5rem)] max-h-[82vh] overflow-y-auto sm:w-[384px]"
                    : "w-72 max-w-[calc(100vw-1.5rem)] overflow-hidden"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="flex items-center gap-2 text-[#f3f6fd]">
                    <span
                      className={`h-2 w-2 rounded-full ${sseConnected ? "bg-[#5bdba2]" : "bg-[#7f95f8]"}`}
                    />
                    {sseConnected ? "Live SSE" : "Reconnecting"}
                  </span>
                  <button
                    type="button"
                    onClick={() => setSseNonce((n) => n + 1)}
                    className="pr-pill inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[12.5px] text-[#9ec0f5]"
                  >
                    <IconRefresh className="h-4 w-4" />
                    <span>Reconnect</span>
                  </button>
                </div>

                {health && (
                  <div className="mt-3 space-y-1.5 border-t border-white/[0.06] pt-2.5 text-[12.5px]">
                    <div className="flex justify-between text-[#a6b5cf]">
                      <span>server</span>
                      <span className="text-[#dce4f5]">v{health.version}</span>
                    </div>
                    {health.host_capabilities && (
                      <div className="flex justify-between text-[#a6b5cf]">
                        <span>host</span>
                        <span className="text-[#dce4f5]">
                          {health.host_capabilities.os}/{health.host_capabilities.arch}
                        </span>
                      </div>
                    )}
                    <div className="flex justify-between text-[#a6b5cf]">
                      <span>client</span>
                      <span className="text-[#dce4f5]">{getOSLabel(clientOS)}</span>
                    </div>
                    {health.agent_sandbox && (
                      <div className="flex justify-between text-[#a6b5cf]">
                        <span>sandbox</span>
                        <span className="text-[#dce4f5]">{health.agent_sandbox}</span>
                      </div>
                    )}
                    {(typeof health.server_policy_loaded === "boolean" ||
                      typeof health.schema_loaded === "boolean" ||
                      health.agent_sandbox !== undefined ||
                      health.host_capabilities !== undefined) && (
                      <div className="flex flex-wrap gap-1.5 pt-2">
                        {typeof health.server_policy_loaded === "boolean" && (
                          <span
                            className={`rounded-full px-2 py-0.5 text-[12px] ${
                              health.server_policy_loaded
                                ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                                : "bg-white/[0.05] text-[#a6b5cf]"
                            }`}
                          >
                            server-policy
                          </span>
                        )}
                        {typeof health.schema_loaded === "boolean" && (
                          <span
                            className={`rounded-full px-2 py-0.5 text-[12px] ${
                              health.schema_loaded
                                ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                                : "bg-white/[0.05] text-[#a6b5cf]"
                            }`}
                          >
                            .env.schema
                          </span>
                        )}
                        {(health.agent_sandbox !== undefined || health.host_capabilities !== undefined) && (() => {
                          const badge = getSandboxBadge(health);
                          return (
                            <span
                              title={badge.title}
                              className={`rounded-full px-2 py-0.5 text-[12px] ${badge.className}`}
                            >
                              {badge.label}
                            </span>
                          );
                        })()}
                      </div>
                    )}
                  </div>
                )}

                {owner && (
                  <HygieneDrawer
                    hygiene={hygiene}
                    loading={hygieneLoading}
                    error={hygieneError}
                    showDismissed={showDismissedHygiene}
                    onToggleShowDismissed={() => {
                      setShowDismissedHygiene((prev) => !prev);
                    }}
                    onRefresh={() => refreshHygiene()}
                    sessionsWithInsights={sessionsWithInsights}
                    onStepInSession={(sessionId) => {
                      setRequestedSessionId(sessionId);
                      setStatusOpen(false);
                      setTab("agents");
                    }}
                    onAction={handleHygieneAction}
                    onDismiss={(id) => void handleDismissHygiene(id)}
                    onRestore={(id) => void handleRestoreHygiene(id)}
                    busyInsightId={busyHygieneId}
                  />
                )}
              </div>
            )}
          </div>

          <button
            type="button"
            title="Settings (9)"
            aria-label="Settings"
            aria-current={tab === "settings" ? "page" : undefined}
            onMouseEnter={() => preloadTab("settings")}
            onFocus={() => preloadTab("settings")}
            onClick={() => setTab("settings")}
            className={`hidden h-9 w-9 shrink-0 items-center justify-center rounded-full md:inline-flex ${
              tab === "settings" ? "pr-pill-active" : "pr-pill"
            }`}
          >
            <IconGear className="h-[18px] w-[18px] text-[#9ec0f5]" />
          </button>

          <AccountMenu
            user={user}
            open={userOpen}
            setOpen={setUserOpen}
            menuRef={userRef}
            onSettings={() => setTab("settings")}
            onSignOut={onSignOut}
          >
            {/* The header branch switcher is hidden below md, so branches live here on phones. */}
            {branches.length > 0 && !repoEmpty && (
              <div className="border-t border-white/[0.06] py-1 md:hidden">
                <div className="px-3 pt-1 pb-1.5 text-[12.5px] text-[#98a8c4]">Branch</div>
                {branchMenu}
              </div>
            )}
            {/* The header switcher is hidden below xl, so the repositories live here too. */}
            <div className="border-t border-white/[0.06] py-1 xl:hidden">
              <div className="px-3 pt-1 pb-1.5 text-[12.5px] text-[#98a8c4]">Repository</div>
              {repoMenu}
            </div>
            {/* Secondary views omitted from the 5-item mobile bottom dock (< md) live here. */}
            <div className="border-t border-white/[0.06] py-1 md:hidden">
              <button
                type="button"
                role="menuitem"
                disabled={isTabDisabled("traces")}
                aria-current={tab === "traces" ? "page" : undefined}
                onClick={() => {
                  setTab("traces");
                  setUserOpen(false);
                }}
                className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-[14px] text-[#d2dbee] hover:bg-white/[0.05] hover:text-[#f3f6fd] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <IconTimeline className="h-4 w-4 text-[#a6b5cf]" />
                <span>Traces</span>
              </button>
              <button
                type="button"
                role="menuitem"
                disabled={isTabDisabled("secrets")}
                aria-current={tab === "secrets" ? "page" : undefined}
                onClick={() => {
                  setTab("secrets");
                  setUserOpen(false);
                }}
                className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-[14px] text-[#d2dbee] hover:bg-white/[0.05] hover:text-[#f3f6fd] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <IconVault className="h-4 w-4 text-[#a6b5cf]" />
                <span>Secrets</span>
              </button>
              {owner && (
                <button
                  type="button"
                  role="menuitem"
                  disabled={isTabDisabled("policy")}
                  aria-current={tab === "policy" ? "page" : undefined}
                  onClick={() => {
                    setTab("policy");
                    setUserOpen(false);
                  }}
                  className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-[14px] text-[#d2dbee] hover:bg-white/[0.05] hover:text-[#f3f6fd] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <IconPolicy className="h-4 w-4 text-[#a6b5cf]" />
                  <span>Policy</span>
                </button>
              )}
            </div>
          </AccountMenu>
        </div>
      </header>

      <GithubCompanionModal
        open={githubModalOpen}
        onClose={() => setGithubModalOpen(false)}
        user={user}
      />
      <AgentConnectModal
        open={agentConnectOpen}
        onClose={() => setAgentConnectOpen(false)}
        repoName={repo.name}
        isDefaultRepo={repo.is_default}
      />

      {viewingAs && (
        <div
          role="status"
          className="flex h-8 shrink-0 items-center justify-center gap-2 border-b border-[#9ec0f5]/20 bg-[#7f95f8]/12 px-3 text-[13.5px] text-[#c9d8f5]"
        >
          <IconLens className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
          <span className="min-w-0 truncate">
            Viewing as <span className="font-mono font-medium text-[#f3f6fd]">{identity.label}</span>
          </span>
          <span aria-hidden="true">·</span>
          <button
            type="button"
            onClick={() => {
              if (confirmLeaveDirtyCode()) setIdentityId("self");
            }}
            title="Return to your own identity (Shift+L cycles lenses)"
            className="shrink-0 font-medium text-[#9ec0f5] underline-offset-2 hover:text-[#f3f6fd] hover:underline"
          >
            Reset <span className="hidden font-mono text-[12.5px] text-[#a6b5cf] sm:inline">· Shift+L cycles</span>
          </button>
        </div>
      )}

      {/* Full-bleed workspace canvas */}
      {importedPolicy && (
        <div
          role="status"
          className="mx-3 mt-3 flex shrink-0 flex-wrap items-center justify-between gap-2 rounded-xl border border-[#9ec0f5]/30 bg-[#7f95f8]/8 px-4 py-2.5 text-[14px] leading-relaxed text-[#a8c5ff] sm:mx-4 xl:mx-5"
        >
          <span className="min-w-0 flex-1">
            The imported repository contained its own access policy, which has NOT been activated.
            Review it under Policy and save to apply.
          </span>
          <span className="flex shrink-0 gap-2">
            <button type="button" onClick={() => setTab("policy")} className={SECONDARY_BTN}>
              Open Policy
            </button>
            <button type="button" onClick={onDismissImportedPolicy} className={SECONDARY_BTN}>
              Dismiss
            </button>
          </span>
        </div>
      )}
      <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {pane("worktable", () => (
            <WorktableView
              active={tab === "worktable"}
              user={user}
              repo={repo}
              identity={identity}
              owner={owner}
              sseConnected={sseConnected}
              health={health}
              healthError={healthError}
              onRetryHealth={retryHealth}
              onOpenSettings={() => setTab("settings")}
              onOpenGlassWall={() => {
                setMirrorEnabled(true);
                setTab("code");
              }}
              onOpenGithub={() => setGithubModalOpen(true)}
              onOpenAgentConnect={() => setAgentConnectOpen(true)}
              onOpenSecrets={() => setTab("secrets")}
              sessions={sessions}
              approvals={approvals}
              auditEvents={owner ? auditEvents : []}
              paletteOpen={paletteOpen || githubModalOpen || agentConnectOpen}
              requestedFocus={requestedFocus}
              delegateFocusNonce={delegateFocusNonce}
              onFocusChange={(target) => {
                setCurrentFocus(target);
                setRequestedFocus(target);
              }}
              onSessionChange={(rec) =>
                setSessions((prev) => prev.map((s) => (s.id === rec.id ? rec : s)))
              }
              onSessionCreated={(rec) =>
                setSessions((prev) => [rec, ...prev.filter((s) => s.id !== rec.id)].slice(0, 30))
              }
              onDecided={refreshApprovals}
              onBranchesChanged={refreshMetadata}
              onReposReload={onReposReload}
              onOpenCode={(branch, path) => {
                if (branch && branch !== activeRef) {
                  if (!confirmLeaveDirtyCode()) return;
                  setActiveRef(branch);
                }
                if (path) {
                  setRequestedPath(path);
                  setCurrentPath(path);
                }
                setRequestedLines(undefined);
                setCurrentLines(null);
                setTab("code");
              }}
              onOpenChanges={(oid) => {
                if (oid) {
                  setRequestedOid(oid);
                  setCurrentOid(oid);
                  setRequestedChangeId(undefined);
                  setCurrentChangeId(undefined);
                }
                setTab("changes");
              }}
              onOpenReview={(changeId) => {
                setRequestedChangeId(changeId);
                setCurrentChangeId(changeId);
                setRequestedOid(undefined);
                setCurrentOid(undefined);
                setTab("changes");
              }}
              onOpenBranches={(branchName) => {
                if (branchName) setRequestedBranch(branchName);
                setTab("branches");
              }}
              onOpenAgents={(sessionId) => {
                if (sessionId) setRequestedSessionId(sessionId);
                setTab("agents");
              }}
              onOpenPolicy={() => setTab("policy")}
              onJudgmentCountChange={setWorktableJudgmentCount}
            />
          ))}
          {pane("code", () =>
            repo.head_oid ? (
              <ZoneXRayView
                active={tab === "code"}
                onDirtyChange={(dirty) => {
                  codeDirtyRef.current = dirty;
                }}
                identity={identity}
                owner={owner}
                refName={activeRef}
                initialPath={currentPath}
                requestedPath={requestedPath}
                requestedLines={requestedLines}
                onConsumeRequested={consumeCodeRequest}
                onSelectPath={setCurrentPath}
                onSelectLines={setCurrentLines}
                hygieneInsights={owner ? hygiene?.insights : undefined}
                onDraftPolicyRule={
                  owner
                    ? (draft) => {
                        setPendingPolicyDraft(draft);
                        setTab("policy");
                      }
                    : undefined
                }
                onAddOverlayGuard={
                  owner ? (path, scope) => handleAddOverlayGuard(path, scope) : undefined
                }
                onDismissInsight={owner ? handleDismissHygiene : undefined}
                ownerIdentity={owner ? ownerIdentity : undefined}
                presets={owner ? presets : undefined}
                directory={owner ? directory : null}
                agentProfiles={owner ? agentProfiles : undefined}
                mirrorEnabled={owner ? mirrorEnabled : false}
                onMirrorEnabledChange={owner ? setMirrorEnabled : undefined}
                onOpenPolicyEditor={owner ? openPolicyEditorWithDraft : undefined}
                onPolicySaved={refreshAgentProfiles}
              />
            ) : (
              <EmptyRepoPanel user={user} repo={repo} onRefresh={() => void onReposReload()} />
            ))}
          {pane("changes", () =>
            repo.head_oid ? (
              <ReviewRoundsView
                active={tab === "changes"}
                identity={identity}
                refName={activeRef}
                initialOid={currentOid}
                initialChangeId={currentChangeId}
                requestedOid={requestedOid}
                requestedChangeId={requestedChangeId}
                onConsumeRequested={consumeChangesRequest}
                owner={owner}
                branches={branches}
                sessions={sessions}
                lanes={lanes}
                agentProfiles={agentProfiles}
                agentSandbox={health?.agent_sandbox}
                auditEvents={auditEvents}
                viewerPrincipal={user.principal}
                onOpenAgents={() => setTab("agents")}
                reviewRevision={reviewRevision}
                onLanesChanged={refreshMetadata}
                onSelectOid={(oid) => {
                  setCurrentOid(oid);
                  setCurrentChangeId(undefined);
                }}
                onSelectChange={(changeId) => {
                  setCurrentChangeId(changeId);
                  setCurrentOid(undefined);
                }}
                onPublishBranch={(branchName) => {
                  setRequestedBranch(branchName);
                  setTab("branches");
                }}
              />
            ) : (
              <EmptyRepoPanel
                title="No commits yet"
                user={user}
                repo={repo}
                onRefresh={() => void onReposReload()}
              />
            ))}
          {pane("branches", () => (
            <BranchesView
              active={tab === "branches"}
              user={user}
              identity={identity}
              initialBranch={requestedBranch}
              repoName={repo.name}
              isDefaultRepo={repo.is_default}
              defaultBranch={repo.default_branch}
              onBranchesChanged={() => {
                refreshMetadata();
                refreshHygiene();
              }}
              onOpenCommit={(oid, targetRefName) => {
                if (targetRefName && targetRefName !== activeRef) {
                  if (!confirmLeaveDirtyCode()) return;
                  setActiveRef(targetRefName);
                }
                setRequestedOid(oid);
                setCurrentOid(oid);
                setRequestedChangeId(undefined);
                setCurrentChangeId(undefined);
                setTab("changes");
              }}
            />
          ))}
          {pane("agents", () => (
            <AgentMissionControl
              identity={identity}
              userPrincipal={user.principal}
              owner={owner}
              agentProfiles={agentProfiles}
              agentSandbox={health?.agent_sandbox}
              agentSandboxDetail={health?.agent_sandbox_detail}
              branchNames={branches.map((b) => b.name)}
              activeRef={activeRef}
              onSessionChange={(rec) => {
                setSessions((prev) =>
                  prev.some((s) => s.id === rec.id)
                    ? prev.map((s) => (s.id === rec.id ? rec : s))
                    : [rec, ...prev].slice(0, 30),
                );
                if (
                  rec.status !== "paused" &&
                  rec.status !== "budget_exceeded" &&
                  !rec.budget?.paused
                ) {
                  setBudgetAlerts((prev) => prev.filter((a) => a.session_id !== rec.id));
                }
              }}
              onOpenReview={(changeId) => {
                setRequestedChangeId(changeId);
                setCurrentChangeId(changeId);
                setRequestedOid(undefined);
                setCurrentOid(undefined);
                setTab("changes");
              }}
              onBranchesChanged={() => {
                refreshMetadata();
                refreshHygiene();
              }}
              lanes={lanes}
              onLanesChanged={refreshMetadata}
              auditEvents={auditEvents}
              approvals={approvals}
              sessions={sessions}
              mcpAlerts={mcpAlerts}
              onMcpAlertsChanged={refreshMcpAlerts}
              budgetAlerts={visibleBudgetAlerts}
              requestedSessionId={requestedSessionId}
              onClearRequestedSession={() => setRequestedSessionId(undefined)}
              onConsumeRequestedSession={() => setRequestedSessionId(undefined)}
              onHygieneChanged={owner ? () => refreshHygiene() : undefined}
              onDecided={refreshApprovals}
              suggestions={suggestions}
              onSuggestionsChanged={refreshSuggestions}
              onPreviewSuggestion={setGraduationTarget}
            />
          ))}
          {pane("traces", () => (
            <AgentTraceView
              active={tab === "traces"}
              identity={identity}
              owner={owner}
              activeRef={activeRef}
              repoName={repo.name}
              isDefaultRepo={repo.is_default}
              sseConnected={sseConnected}
              traceRevision={traceRevision}
              identityPresets={owner ? presets : undefined}
              onSelectIdentity={owner ? setIdentity : undefined}
              onOpenReview={(changeId) => {
                setRequestedChangeId(changeId);
                setCurrentChangeId(changeId);
                setRequestedOid(undefined);
                setCurrentOid(undefined);
                setTab("changes");
              }}
              onOpenFile={(path) => {
                setRequestedPath(path);
                setCurrentPath(path);
                setTab("code");
              }}
              onOpenCommit={(oid) => {
                setRequestedOid(oid);
                setCurrentOid(oid);
                setRequestedChangeId(undefined);
                setCurrentChangeId(undefined);
                setTab("changes");
              }}
              onOpenBranch={(branch) => {
                setRequestedBranch(branch);
                setTab("branches");
              }}
            />
          ))}
          {pane("secrets", () => (
            <SecretsOverlaysView
              identity={identity}
              owner={owner}
              directory={owner ? directory : null}
              agentProfiles={owner ? agentProfiles : undefined}
              refName={activeRef}
              onOpenPolicyEditor={owner ? openPolicyEditorWithDraft : undefined}
              onPolicySaved={refreshAgentProfiles}
              hygieneInsights={owner ? hygiene?.insights : undefined}
              focusTarget={pendingSecretFocus}
              onConsumeFocus={() => setPendingSecretFocus(null)}
              onDismissInsight={owner ? handleDismissHygiene : undefined}
              onHygieneChanged={owner ? () => refreshHygiene() : undefined}
            />
          ))}
          {pane("policy", () =>
            owner ? (
              <AccessDiffView
                identity={identity}
                owner={owner}
                draftToml={policyDraftToml}
                onClearDraftToml={() => setPolicyDraftToml(null)}
                draftRule={pendingPolicyDraft}
                onConsumeDraft={() => setPendingPolicyDraft(null)}
                onPolicySaved={() => {
                  refreshAgentProfiles();
                  refreshHygiene();
                }}
              />
            ) : (
              // Members get no policy text and a 403 from the diff, so nothing is fetched.
              <div className="flex min-h-0 flex-1 p-3 sm:p-4 xl:p-5">
                <OwnerOnly className="pr-surface flex-1 rounded-2xl" />
              </div>
            ))}
          {pane("settings", () => (
            <SettingsView
              user={user}
              health={health}
              healthError={healthError}
              onRetryHealth={retryHealth}
              repos={repos}
              onReposReload={onReposReload}
              onUserChange={onUserChange}
              onDirectoryChange={setDirectory}
              requestedSection={settingsSection}
              onSelectSection={setSettingsSection}
            />
          ))}
      </main>

      {/* Mobile native frosted bottom dock (< 768px) */}
      <nav
        aria-label="Mobile Navigation"
        className="pr-topbar z-30 flex min-h-16 shrink-0 items-center justify-around border-t border-b-0 border-white/[0.08] px-1 pb-[env(safe-area-inset-bottom)] md:hidden"
      >
        {navItems
          .filter((item) =>
            ["worktable", "code", "changes", "branches", "agents"].includes(item.id),
          )
          .map((item) => {
            const Icon = item.icon;
            const active = tab === item.id;
            const locked = isTabDisabled(item.id);
            return (
              <button
                key={item.id}
                type="button"
                aria-current={active ? "page" : undefined}
                disabled={locked}
                title={locked ? "Push your first commit to unlock" : undefined}
                onClick={() => setTab(item.id)}
                className={`relative flex min-w-0 flex-1 flex-col items-center justify-center gap-1 rounded-xl py-1.5 transition ${
                  locked
                    ? "cursor-not-allowed text-[#a6b5cf] opacity-35"
                    : active
                      ? "text-[#9ec0f5]"
                      : "text-[#a6b5cf]"
                }`}
              >
                <Icon className="h-5 w-5" />
                <span className="max-w-full truncate px-0.5 text-[12.5px] font-medium leading-[1.35]">
                  {item.label}
                </span>
                {item.badge !== undefined && item.badge > 0 && (
                  <>
                    <span
                      aria-hidden="true"
                      className={`absolute top-1 right-2 h-2 w-2 rounded-full ${
                        item.urgent ? "bg-[#7f95f8]" : "bg-[#7f95f8]"
                      }`}
                    />
                    <span className="sr-only"> ({item.badge} pending)</span>
                  </>
                )}
              </button>
            );
          })}
      </nav>

      {tab !== "agents" &&
        ((owner && tab !== "worktable" && visiblePendingApprovals.length > 0) || visibleBudgetAlerts.length > 0) && (
          <div className="fixed right-4 bottom-20 z-40 flex w-[360px] max-w-[calc(100vw-2rem)] flex-col gap-2.5 md:bottom-5">
            {visibleBudgetAlerts.length > 0 && (
              <FloatingBudgetAlertPopover
                alerts={visibleBudgetAlerts}
                onOpenAgents={(sessionId) => {
                  setRequestedSessionId(sessionId);
                  setTab("agents");
                }}
                onDismiss={(key) => setDismissedBudgetKeys((prev) => new Set(prev).add(key))}
              />
            )}
            {owner && tab !== "worktable" && visiblePendingApprovals.length > 0 && (
              <FloatingApprovalPopover
                approvals={visiblePendingApprovals}
                owner={owner}
                suggestions={suggestions}
                keysEnabled={
                  !paletteOpen &&
                  !newRepoOpen &&
                  !graduationTarget &&
                  !githubModalOpen &&
                  !agentConnectOpen
                }
                onDecided={refreshApprovals}
                onOpenAgents={() => setTab("agents")}
                onOpenSession={(sid) => {
                  setRequestedSessionId(sid);
                  setTab("agents");
                }}
                onPreviewSuggestion={setGraduationTarget}
                onDismissSuggestion={dismissSuggestion}
                onDismiss={(id) =>
                  setDismissedApprovalIds((prev) => {
                    const next = new Set(prev);
                    next.add(id);
                    return next;
                  })
                }
              />
            )}
          </div>
        )}

      {graduationTarget && (
        <PolicyGraduationModal
          suggestion={graduationTarget}
          onClose={() => setGraduationTarget(null)}
          onApplied={refreshSuggestions}
        />
      )}

      {newRepoOpen && (
        <NewRepoDialog
          existing={repos}
          onClose={() => setNewRepoOpen(false)}
          onCreated={onRepoCreated}
        />
      )}

      {/* Power Command Palette (Views, Lenses, Files, Commits, Actions + full keyboard nav) */}
      {paletteOpen && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-[#04060d]/80 px-4 pt-16 backdrop-blur-sm sm:pt-24"
          onClick={() => setPaletteOpen(false)}
        >
          <div
            ref={palettePanelRef}
            role="dialog"
            aria-modal="true"
            aria-label="Command palette"
            data-command-palette="true"
            tabIndex={-1}
            className="pr-elevated w-full max-w-lg overflow-hidden rounded-2xl focus:outline-none"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (!e.nativeEvent.isComposing && e.keyCode !== 229) {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  e.stopPropagation();
                  e.nativeEvent.stopPropagation();
                  setPaletteIndex((idx) =>
                    paletteActions.length === 0 ? 0 : (idx + 1) % paletteActions.length,
                  );
                  return;
                }
                if (e.key === "ArrowUp") {
                  e.preventDefault();
                  e.stopPropagation();
                  e.nativeEvent.stopPropagation();
                  setPaletteIndex((idx) =>
                    paletteActions.length === 0
                      ? 0
                      : (idx - 1 + paletteActions.length) % paletteActions.length,
                  );
                  return;
                }
                if (e.key === "Enter") {
                  const item = paletteActions[paletteIndex];
                  if (item) {
                    e.preventDefault();
                    e.stopPropagation();
                    e.nativeEvent.stopPropagation();
                    item.run();
                    setPaletteOpen(false);
                    return;
                  }
                }
              }
              paletteModalKeyDown(e);
            }}
          >
            <div className="flex items-center gap-2.5 border-b border-white/[0.08] px-4 py-3">
              <IconSearch className="h-[18px] w-[18px] text-[#a6b5cf]" />
              <input
                ref={paletteInputRef}
                autoFocus
                value={paletteQuery}
                onChange={(e) => setPaletteQuery(e.target.value)}
                aria-label="Command palette search"
                placeholder="Jump to file, commit, view, or view-as identity…"
                className="flex-1 bg-transparent text-[14.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setPaletteOpen(false)}
                aria-label="Close"
                className="rounded-lg p-1.5 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white"
              >
                <IconClose className="h-4 w-4" />
              </button>
            </div>

            <div ref={paletteListRef} className="max-h-80 overflow-y-auto p-1.5">
              {paletteActions.length === 0 ? (
                <div className="py-8 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                  No matches
                </div>
              ) : (
                paletteActions.map((act, idx) => {
                  const selected = idx === paletteIndex;
                  const newGroup = idx === 0 || paletteActions[idx - 1].group !== act.group;
                  return (
                    <div key={act.id}>
                      {newGroup && (
                        <div
                          aria-hidden="true"
                          className={`px-3 pb-1 text-[12.5px] font-semibold tracking-wide text-[#a6b5cf] uppercase ${
                            idx === 0 ? "pt-1" : "pt-2.5"
                          }`}
                        >
                          {act.group}
                        </div>
                      )}
                      <button
                        type="button"
                        data-active={selected}
                        // mousemove, not mouseenter: a stationary pointer must not hijack keyboard scrolling.
                        onMouseMove={() => selected || setPaletteIndex(idx)}
                        onClick={() => {
                          act.run();
                          setPaletteOpen(false);
                        }}
                        className={`flex w-full items-center justify-between gap-3 rounded-xl px-3 py-2 text-left text-[14px] transition ${
                          selected
                            ? "bg-[#7f95f8]/20 text-[#f3f6fd]"
                            : "text-[#d2dbee] hover:bg-white/[0.05]"
                        }`}
                      >
                        <span className="flex min-w-0 items-center gap-2.5">
                          {act.kind === "file" ? (
                            <IconFileNode className="h-4 w-4 shrink-0 text-[#7f95f8]" />
                          ) : act.kind === "commit" ? (
                            <IconChanges className="h-4 w-4 shrink-0 text-[#5bdba2]" />
                          ) : act.kind === "lens" ? (
                            <IconLens className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
                          ) : (
                            <IconCode className="h-4 w-4 shrink-0 text-[#98a8c4]" />
                          )}
                          <span className="truncate font-mono">{act.label}</span>
                        </span>
                        {act.meta && (
                          <span className="max-w-[40%] shrink-0 truncate font-mono text-[12.5px] text-[#a6b5cf]">
                            {act.meta}
                          </span>
                        )}
                      </button>
                    </div>
                  );
                })
              )}
            </div>

            {paletteTreeTruncation?.truncated && (
              <div className="flex items-center justify-between gap-2 border-t border-white/[0.06] bg-[#7f95f8]/8 px-4 py-1.5 font-mono text-[12px] text-[#cfe0ff]">
                <span>
                  File list capped at {paletteTreeTruncation.shown} of{" "}
                  {paletteTreeTruncation.totalInScope} in-scope entries
                </span>
                {!isTabDisabled("code") && (
                  <button
                    type="button"
                    onClick={() => {
                      setTab("code");
                      setPaletteOpen(false);
                    }}
                    className="shrink-0 text-[#9ec0f5] hover:underline"
                  >
                    Open Code Search
                  </button>
                )}
              </div>
            )}

            <div className="flex items-center justify-between border-t border-white/[0.06] px-4 py-2 font-mono text-[12.5px] text-[#a6b5cf]">
              <span className="flex items-center gap-2">
                <kbd className="pr-kbd">↑↓</kbd>
                <kbd className="pr-kbd">↵</kbd>
                <kbd className="pr-kbd">esc</kbd>
              </span>
              <span>1–9 views · g w home · Shift+L view as</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const REPO_KEY = "premier.repo";

/** Studio-shaped placeholder shown only if repo loading takes longer than the smooth boot grace window. */
function BootShell() {
  const initialTab = hashTab() ?? "worktable";
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const id = window.setTimeout(() => setVisible(true), 150);
    return () => window.clearTimeout(id);
  }, []);
  if (!visible) return <div className="h-[100dvh]" aria-hidden="true" />;
  return (
    <div className="pr-page-enter flex h-[100dvh] flex-col overflow-hidden text-[#f3f6fd]">
      <header className="pr-topbar z-[45] flex h-14 shrink-0 items-center gap-2 px-3.5 lg:px-4 xl:px-5">
        <PremierMark className="h-7 w-7" />
        <span className="text-[15px] font-semibold tracking-[-0.02em] text-[#f3f6fd]">Premier</span>
      </header>
      <main className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <ViewSkeleton tab={initialTab} />
      </main>
    </div>
  );
}

function resolveWantedRepoName(): string | null {
  const hashRepo = parseHash().repo;
  if (hashRepo) return hashRepo;
  try {
    return localStorage.getItem(REPO_KEY);
  } catch {
    return null;
  }
}

function pickInitialRepo(list: Repo[], name: string | null): Repo | null {
  return list.find((r) => r.name === name) ?? list.find((r) => r.is_default) ?? list[0] ?? null;
}

/** Loads the repository list, owns the current-repo choice, and mounts one Studio per repo. */
function Workspace(props: WorkspaceProps & { initialRepos?: Repo[] | null }) {
  const wanted = useRef<string | null>(resolveWantedRepoName());
  const [repos, setRepos] = useState<Repo[] | null>(() => {
    if (!props.initialRepos) return null;
    const next = pickInitialRepo(props.initialRepos, wanted.current);
    setCurrentRepo(next);
    wanted.current = next?.name ?? null;
    return props.initialRepos;
  });
  const [repoName, setRepoName] = useState<string | null>(() => {
    if (!props.initialRepos) return null;
    return pickInitialRepo(props.initialRepos, wanted.current)?.name ?? null;
  });
  const [error, setError] = useState<string | null>(null);
  // Name of a just-imported repo whose in-repo policy the server left inactive.
  const [importedPolicyRepo, setImportedPolicyRepo] = useState<string | null>(null);
  const hadInitialRepos = useRef(props.initialRepos !== undefined && props.initialRepos !== null);

  // Picks `name` if it still exists, else the default repo, and points the API layer at it.
  const apply = useCallback((list: Repo[], name: string | null) => {
    const next = pickInitialRepo(list, name);
    setCurrentRepo(next);
    wanted.current = next?.name ?? null;
    try {
      if (next) localStorage.setItem(REPO_KEY, next.name);
      else window.localStorage.removeItem(REPO_KEY);
    } catch {
      // storage unavailable: the choice just isn't remembered
    }
    if (list.length === 0) {
      const parsed = parseHash();
      if (
        (parsed.tab === "settings" && parsed.section === "repositories") ||
        parsed.repo !== undefined
      ) {
        if (window.location.hash !== "#worktable") {
          window.history.replaceState(null, "", "#worktable");
        }
      }
    }
    setRepos(list);
    setRepoName(next?.name ?? null);
  }, []);

  const reload = useCallback(
    () =>
      api
        .repos()
        .then((list) => {
          setError(null);
          apply(list, wanted.current);
        })
        .catch((err: unknown) => setError(errorText(err))),
    [apply],
  );

  useEffect(() => {
    wanted.current = resolveWantedRepoName();
    if (hadInitialRepos.current) {
      hadInitialRepos.current = false;
      // Sync localStorage/hash cleanup for the already-prefetched list without a second flash.
      if (props.initialRepos) apply(props.initialRepos, wanted.current);
    } else {
      void reload();
    }
    // Scope is module state in api.ts; clear it so the next sign-in starts unprefixed.
    return () => setCurrentRepo(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reload]);

  useEffect(() => {
    if (!repos) return;
    const onHash = () => {
      const hashRepo = parseHash().repo;
      const defaultRepo = repos.find((r) => r.is_default) ?? repos[0];
      const target = hashRepo ? repos.find((r) => r.name === hashRepo) : defaultRepo;
      if (target && target.name !== repoName) {
        apply(repos, target.name);
      }
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [repos, repoName, apply]);

  const switchRepoWithCleanHash = useCallback(
    (list: Repo[], name: string, forcedTab?: TabId) => {
      const target = list.find((r) => r.name === name) ?? list.find((r) => r.is_default) ?? list[0];
      if (target) {
        const parsed = parseHash();
        const nextTab = forcedTab ?? parsed.tab ?? "worktable";
        // Clear repo-scoped params (ref, path, lines, oid, change) BEFORE remounting Studio.
        const cleanHash = buildHash({
          tab: nextTab,
          repo: target.name,
          isDefaultRepo: target.is_default,
          section: nextTab === "settings" ? parsed.section : undefined,
        });
        if (window.location.hash !== cleanHash) {
          window.history.replaceState(null, "", cleanHash);
        }
      }
      apply(list, name);
    },
    [apply],
  );

  const repo = repos?.find((r) => r.name === repoName);
  // A 200 with an empty list: a member who has been granted nothing yet. Not a failure, so they
  // get the app shell.
  if (repos?.length === 0 && !error && props.user.role === "member") {
    return (
      <div className="pr-page-enter">
        <NoRepoAccess {...props} onReposReload={reload} />
      </div>
    );
  }
  // An owner with no repositories yet gets the welcome shell instead of an error.
  if (repos?.length === 0 && !error && props.user.role === "owner") {
    return (
      <div className="pr-page-enter">
        <OwnerWelcome
          {...props}
          onReposReload={reload}
          onRepoCreated={(created) => {
            switchRepoWithCleanHash([created], created.name, "worktable");
            if (created.imported_policy) setImportedPolicyRepo(created.name);
          }}
        />
      </div>
    );
  }
  const loadError = error ?? (repos && !repo ? "The server returned no repositories." : null);
  if ((!repos || !repo) && !loadError) return <BootShell />;
  if (!repos || !repo) {
    return (
      <AuthLoadingScreen
        error={loadError}
        onRetry={() => void reload()}
      />
    );
  }

  return (
    <div className="pr-page-enter">
      <Studio
        key={repo.name}
        {...props}
        repos={repos}
        repo={repo}
        onSwitchRepo={(name) => switchRepoWithCleanHash(repos, name)}
        onRepoCreated={(created) => {
          switchRepoWithCleanHash([...repos, created], created.name);
          if (created.imported_policy) setImportedPolicyRepo(created.name);
        }}
        onReposReload={reload}
        importedPolicy={importedPolicyRepo === repo.name}
        onDismissImportedPolicy={() => setImportedPolicyRepo(null)}
      />
    </div>
  );
}

/**
 * Fetch `/v1/repos` speculatively during initial boot without tripping global 401 session-expired
 * handlers when the visitor is not yet signed in.
 */
async function prefetchReposQuietly(): Promise<Repo[] | null> {
  try {
    const res = await fetch("/v1/repos", { credentials: "same-origin" });
    if (!res.ok) return null;
    const data = (await res.json()) as unknown;
    return Array.isArray(data) ? (data as Repo[]) : null;
  } catch {
    return null;
  }
}

/** Auth gate: first-run owner setup, sign-in, or the app. */
export function App() {
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [bootRepos, setBootRepos] = useState<Repo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expired, setExpired] = useState(false);
  const [showSlowBoot, setShowSlowBoot] = useState(false);

  const handleSessionExpired = useCallback(() => {
    setExpired(true);
    setBootRepos(null);
    setAuth({ setup_required: false, authenticated: false, user: null });
  }, []);

  const loadStatus = useCallback(() => {
    setError(null);
    // Warm the lazy view chunk for the current hash tab in parallel with auth + repos so
    // refreshing `#settings` or any other route resolves in a single smooth paint.
    const initialTab = hashTab();
    if (initialTab && initialTab !== "worktable") preloadTab(initialTab);
    Promise.all([authApi.status(), prefetchReposQuietly()])
      .then(([status, prefetchedRepos]) => {
        setBootRepos(status.authenticated ? prefetchedRepos : null);
        setAuth(status);
      })
      .catch((err: unknown) => setError(errorText(err)));
  }, []);

  useEffect(() => {
    loadStatus();
    const id = window.setTimeout(() => setShowSlowBoot(true), 150);
    // Any 401 from a session-protected call (expired or revoked session) drops back to sign-in.
    const unsub = onUnauthorized(handleSessionExpired);
    return () => {
      window.clearTimeout(id);
      unsub();
    };
  }, [loadStatus, handleSessionExpired]);

  if (!auth) {
    // Fast local/LAN/Tailscale reloads resolve in <40ms: avoid flashing a "Connecting…" card
    // unless the request actually stalls past 150ms or fails.
    if (!error && !showSlowBoot) return <div className="h-[100dvh]" aria-hidden="true" />;
    return (
      <div className="pr-page-enter">
        <AuthLoadingScreen error={error} onRetry={loadStatus} />
      </div>
    );
  }
  if (auth.setup_required) {
    return (
      <div className="pr-page-enter">
        <SetupScreen onDone={setAuth} />
      </div>
    );
  }
  if (!auth.authenticated || !auth.user) {
    return (
      <div className="pr-page-enter">
        <SignInScreen
          reason={expired ? "expired" : undefined}
          onDone={(status) => {
            setExpired(false);
            setBootRepos(null);
            setAuth(status);
          }}
        />
      </div>
    );
  }

  return (
    <Workspace
      key={auth.user.username}
      user={auth.user}
      initialRepos={bootRepos}
      onUserChange={(user) => setAuth({ ...auth, user })}
      onSessionExpired={handleSessionExpired}
      // Re-read status rather than assuming, so a failed logout never shows a fake signed-out state.
      onSignOut={() => void authApi.logout().catch(() => {}).finally(loadStatus)}
    />
  );
}
