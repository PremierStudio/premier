import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  errorText,
  type AgentSessionRecord,
  type AuditEvent,
  type HealthResponse,
  type IdentityPreset,
  type PendingApproval,
  type Repo,
  type User,
  type WorktableResponse,
} from "../../api";
import { isEditableEventTarget } from "../../lib/platform";
import { ErrorNote } from "../forms";
import { EmptyRepoPanel } from "../RepoDialogs";
import { CommandCenterHero } from "./CommandCenterHero";
import { JudgmentRail } from "./JudgmentRail";
import { buildPresenceCards, PresenceCanvas } from "./PresenceCanvas";
import { QuickDelegateBar } from "./QuickDelegateBar";
import {
  filterApprovalsForLens,
  filterSessionsForLens,
  sessionHasUncommittedChanges,
  type FocusTarget,
  type PresenceFilter,
} from "./types";
import { WorkstreamFocusDrawer } from "./WorkstreamFocusDrawer";

export interface WorktableViewProps {
  user: User;
  repo: Repo;
  identity: IdentityPreset;
  owner: boolean;
  sseConnected: boolean;
  health: HealthResponse | null;
  sessions: AgentSessionRecord[];
  approvals: PendingApproval[];
  auditEvents: AuditEvent[];
  paletteOpen: boolean;
  requestedFocus?: FocusTarget | null;
  delegateFocusNonce?: number;
  onFocusChange?: (target: FocusTarget | null) => void;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onSessionCreated: (rec: AgentSessionRecord) => void;
  onDecided: () => void;
  onBranchesChanged: () => void;
  onReposReload: () => Promise<void>;
  onOpenCode: (branch?: string, path?: string) => void;
  onOpenChanges: (oid?: string) => void;
  onOpenReview: (changeId: string) => void;
  onOpenBranches: (branchName?: string) => void;
  onOpenAgents: (sessionId?: string) => void;
  onOpenPolicy: () => void;
  onJudgmentCountChange?: (count: number | null) => void;
  /** True when the /health request failed and no health snapshot exists. */
  healthError?: boolean;
  onRetryHealth?: () => void;
  onOpenSettings?: () => void;
  onOpenGlassWall?: () => void;
  onOpenGithub?: () => void;
  onOpenAgentConnect?: () => void;
  onOpenSecrets?: () => void;
  /** False when this tab stays mounted while hidden; pauses timers and global hotkeys. */
  active?: boolean;
}

/** Parses URL query/hash focus token (`session:<id>`, `branch:<name>`, `review:<changeId>`). */
export function parseFocusParam(raw: string | undefined): FocusTarget | null {
  if (!raw) return null;
  const idx = raw.indexOf(":");
  if (idx <= 0) return null;
  const kind = raw.slice(0, idx);
  const value = raw.slice(idx + 1).trim();
  if (!value) return null;
  if (kind === "session") return { kind: "session", id: value };
  if (kind === "branch") return { kind: "branch", name: value };
  if (kind === "review") return { kind: "review", changeId: value };
  return null;
}

/** Serializes a `FocusTarget` into a stable URL token (`<kind>:<value>`). */
export function serializeFocusParam(target: FocusTarget | null): string | undefined {
  if (!target) return undefined;
  switch (target.kind) {
    case "session":
      return `session:${target.id}`;
    case "branch":
      return `branch:${target.name}`;
    case "review":
      return `review:${target.changeId}`;
  }
}

interface SessionSnapshot {
  status: string;
  committed: boolean;
  discarded: boolean;
}

// Module-level stale-while-revalidate cache: re-entering the tab paints the last snapshot instantly
// while a fresh fetch runs, and fetches started within COALESCE_MS share one in-flight request.
const COALESCE_MS = 400;
const worktableCache = new Map<string, WorktableResponse>();
const worktableInflight = new Map<string, { startedAt: number; promise: Promise<WorktableResponse> }>();

function fetchWorktable(scopeKey: string, identity: IdentityPreset): Promise<WorktableResponse> {
  const existing = worktableInflight.get(scopeKey);
  if (existing && Date.now() - existing.startedAt < COALESCE_MS) return existing.promise;
  const entry = {
    startedAt: Date.now(),
    promise: api.worktable(identity).then((res) => {
      worktableCache.set(scopeKey, res);
      return res;
    }),
  };
  worktableInflight.set(scopeKey, entry);
  const clear = () => {
    if (worktableInflight.get(scopeKey) === entry) worktableInflight.delete(scopeKey);
  };
  entry.promise.then(clear, clear);
  return entry.promise;
}

/** Living Studio Worktable container: Quick-Delegate + Presence Canvas + Judgment Rail + Focus Drawer. */
export function WorktableView({
  user,
  repo,
  identity,
  owner,
  sseConnected,
  health,
  sessions,
  approvals,
  auditEvents,
  paletteOpen,
  requestedFocus,
  delegateFocusNonce,
  onFocusChange,
  onSessionChange,
  onSessionCreated,
  onDecided,
  onBranchesChanged,
  onReposReload,
  onOpenCode,
  onOpenChanges,
  onOpenReview,
  onOpenBranches,
  onOpenAgents,
  onOpenPolicy,
  onJudgmentCountChange,
  healthError,
  onRetryHealth,
  onOpenSettings,
  onOpenGlassWall,
  onOpenGithub,
  onOpenAgentConnect,
  onOpenSecrets,
  active = true,
}: WorktableViewProps) {
  const scopeKey = `${repo.name}|${identity.id}|${identity.principal}|${identity.agentProfile ?? ""}`;
  const [worktable, setWorktable] = useState<WorktableResponse | null>(
    () => worktableCache.get(scopeKey) ?? null,
  );
  const [loaded, setLoaded] = useState(() => worktableCache.has(scopeKey));
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshNonce, setRefreshNonce] = useState(0);

  const [filter, setFilter] = useState<PresenceFilter>("all");
  const [search, setSearch] = useState("");
  const [showSettled, setShowSettled] = useState<boolean | null>(null);
  const [selectedCardKey, setSelectedCardKey] = useState<string | null>(null);
  const [focused, setFocused] = useState<FocusTarget | null>(requestedFocus ?? null);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [railExpanded, setRailExpanded] = useState(false);

  const delegateInputRef = useRef<HTMLInputElement | null>(null);
  const railRef = useRef<HTMLElement | null>(null);
  const prevSessionsRef = useRef<Map<string, SessionSnapshot>>(new Map());
  const prevScopeRef = useRef<string>("");
  const lastDelegateNonceRef = useRef<number>(0);

  const triggerRefresh = useCallback(() => {
    setRefreshNonce((n) => n + 1);
  }, []);

  // Fetch /v1/worktable on mount, lens change, repo change, or explicit refreshNonce bump (NO polling).
  useEffect(() => {
    let active = true;
    if (prevScopeRef.current && prevScopeRef.current !== scopeKey) {
      // Lens/repo changed: never show another scope's data; use this scope's cached snapshot if any.
      const cached = worktableCache.get(scopeKey) ?? null;
      setWorktable(cached);
      setLoaded(cached !== null);
    }
    prevScopeRef.current = scopeKey;
    if (!repo.head_oid) {
      setWorktable(null);
      setLoaded(false);
      setError(null);
      setRefreshing(false);
      return;
    }
    setError(null);
    setRefreshing(true);
    fetchWorktable(scopeKey, identity)
      .then((res) => {
        if (!active) return;
        setWorktable(res);
        setLoaded(true);
        setRefreshing(false);
      })
      .catch((err: unknown) => {
        if (!active) return;
        // Keep `loaded` honest: a failed first fetch must not read as an empty/all-clear worktable.
        setError(errorText(err));
        setRefreshing(false);
      });
    return () => {
      active = false;
    };
    // `identity` itself is covered by its id/principal/agentProfile fields (scopeKey).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeKey, repo.head_oid, refreshNonce]);

  // Sync external requestedFocus (e.g. URL deep-link or command palette jump) into drawer state.
  const requestedKey = serializeFocusParam(requestedFocus ?? null);
  useEffect(() => {
    if (requestedFocus === undefined) return;
    setFocused((curr) =>
      serializeFocusParam(curr) === requestedKey ? curr : requestedFocus,
    );
    if (requestedKey) {
      setSelectedCardKey(requestedKey);
    }
  }, [requestedKey, requestedFocus]);

  // Tab stays mounted while hidden: drop the drawer so returning never pops a stale one over the screen.
  useEffect(() => {
    if (!active) setFocused(null);
  }, [active]);

  // Jump actions navigate to another tab: close the drawer first.
  const leaving =
    <A extends unknown[]>(fn: (...args: A) => void) =>
    (...args: A) => {
      setFocused(null);
      fn(...args);
    };

  // Focus Quick-Delegate input when triggered via external nonce (e.g. command palette).
  useEffect(() => {
    if (
      delegateFocusNonce !== undefined &&
      delegateFocusNonce > 0 &&
      delegateFocusNonce !== lastDelegateNonceRef.current
    ) {
      lastDelegateNonceRef.current = delegateFocusNonce;
      delegateInputRef.current?.focus();
    }
  }, [delegateFocusNonce]);

  // Refresh worktable summary ONCE whenever an SSE session finishes, commits, or is discarded.
  useEffect(() => {
    const prev = prevSessionsRef.current;
    let transitioned = false;
    const next = new Map<string, SessionSnapshot>();

    for (const s of sessions) {
      const snap: SessionSnapshot = {
        status: s.status,
        committed: Boolean(s.commit),
        discarded: Boolean(s.discarded),
      };
      next.set(s.id, snap);

      const old = prev.get(s.id);
      if (old) {
        if (
          (old.status === "running" && snap.status !== "running") ||
          (!old.committed && snap.committed) ||
          (!old.discarded && snap.discarded)
        ) {
          transitioned = true;
        }
      }
    }

    prevSessionsRef.current = next;
    if (transitioned) {
      setRefreshNonce((n) => n + 1);
    }
  }, [sessions]);

  // Lens-filtered SSE collections
  const visibleSessions = useMemo(
    () => filterSessionsForLens(sessions, identity, owner),
    [sessions, identity, owner],
  );
  const visiblePendingApprovals = useMemo(
    () => filterApprovalsForLens(approvals, identity, owner).filter((a) => a.status === "pending"),
    [approvals, identity, owner],
  );

  const runningSessions = useMemo(
    () => visibleSessions.filter((s) => s.status === "running"),
    [visibleSessions],
  );
  const uncommittedSessions = useMemo(
    () => visibleSessions.filter(sessionHasUncommittedChanges),
    [visibleSessions],
  );

  // Stable references so downstream memoization isn't busted by fresh `[]` each render.
  const branches = useMemo(() => worktable?.branches ?? [], [worktable]);
  const reviews = useMemo(() => worktable?.reviews ?? [], [worktable]);
  const quarantineItems = useMemo(() => worktable?.quarantine_items ?? [], [worktable]);
  const agentProfiles = useMemo(
    () => (owner ? (worktable?.agent_profiles ?? []) : []),
    [owner, worktable],
  );
  const defaultBranch = worktable?.default_branch ?? repo.default_branch ?? "main";
  const agentBlocked = health?.agent_sandbox === "none";

  const readyBranches = useMemo(
    () => branches.filter((b) => b.publish_candidate),
    [branches],
  );

  // Local 1s tick ONLY while active and at least one running session or pending approval needs live timers.
  const needsLiveTick = active && (runningSessions.length > 0 || visiblePendingApprovals.length > 0);
  useEffect(() => {
    if (!needsLiveTick) return;
    setNowMs(Date.now());
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [needsLiveTick]);

  const judgmentCount =
    visiblePendingApprovals.length +
    quarantineItems.length +
    uncommittedSessions.length +
    readyBranches.length;

  const worktableReady = worktable !== null;
  useEffect(() => {
    onJudgmentCountChange?.(worktableReady ? judgmentCount : null);
  }, [judgmentCount, worktableReady, onJudgmentCountChange]);

  useEffect(() => () => onJudgmentCountChange?.(null), [onJudgmentCountChange]);

  const openFocus = useCallback(
    (target: FocusTarget | null) => {
      setFocused(target);
      const serialized = serializeFocusParam(target);
      if (serialized) setSelectedCardKey(serialized);
      onFocusChange?.(target);
    },
    [onFocusChange],
  );

  // Ordered visible cards for j/k/Enter navigation matching PresenceCanvas exactly.
  // Built ONCE here (deferred search keeps typing snappy) and shared with PresenceCanvas.
  const deferredSearch = useDeferredValue(search);
  const built = useMemo(
    () =>
      buildPresenceCards({
        sessions: visibleSessions,
        branches,
        reviews,
        pendingApprovals: visiblePendingApprovals,
        defaultBranch,
        filter,
        query: deferredSearch,
        showSettled,
      }),
    [
      visibleSessions,
      branches,
      reviews,
      visiblePendingApprovals,
      defaultBranch,
      filter,
      deferredSearch,
      showSettled,
    ],
  );
  const visibleCards = built.visibleCards;

  // Global Worktable keyboard shortcuts: d, n, j/k, Enter, Escape.
  useEffect(() => {
    if (!active) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (paletteOpen) return;

      if (e.key === "Escape" && focused !== null) {
        if (e.defaultPrevented) return; // a child (e.g. ConfirmButton cancel) already consumed it
        e.preventDefault();
        if (isEditableEventTarget(e) && document.activeElement instanceof HTMLElement) {
          document.activeElement.blur();
        } else {
          openFocus(null);
        }
        return;
      }

      if (e.metaKey || e.ctrlKey || e.altKey || isEditableEventTarget(e)) return;
      if (focused !== null) return;

      const lower = e.key.toLowerCase();
      if (lower === "d" && !e.shiftKey && !agentBlocked) {
        if (delegateInputRef.current) {
          e.preventDefault();
          delegateInputRef.current.focus();
        }
        return;
      }

      if (lower === "n" && !e.shiftKey) {
        if (!railRef.current) {
          // Rail is collapsed (nothing pending): `n` peeks at it.
          e.preventDefault();
          setRailExpanded(true);
        } else {
          e.preventDefault();
          railRef.current.scrollIntoView({ behavior: "smooth", block: "nearest" });
          const target =
            railRef.current.querySelector<HTMLElement>("[data-judgment-item] button:not([disabled])") ??
            railRef.current.querySelector<HTMLElement>(
              "button:not([disabled]), input:not([disabled]), select:not([disabled])",
            );
          target?.focus();
        }
        return;
      }

      if (e.key === "j" || e.key === "k") {
        if (visibleCards.length === 0) return;
        e.preventDefault();
        const currIdx = selectedCardKey
          ? visibleCards.findIndex((c) => c.cardKey === selectedCardKey)
          : -1;
        let nextIdx: number;
        if (e.key === "j") {
          nextIdx = currIdx < 0 ? 0 : Math.min(visibleCards.length - 1, currIdx + 1);
        } else {
          nextIdx = currIdx <= 0 ? 0 : currIdx - 1;
        }
        const nextKey = visibleCards[nextIdx].cardKey;
        setSelectedCardKey(nextKey);
        const cardEl = document.querySelector<HTMLElement>(
          `[data-card-key="${CSS.escape(nextKey)}"]`,
        );
        cardEl?.scrollIntoView({ behavior: "smooth", block: "nearest" });
        cardEl?.focus({ preventScroll: true });
        return;
      }

      if (e.key === "Enter" && selectedCardKey) {
        const matched = visibleCards.find((c) => c.cardKey === selectedCardKey);
        if (matched) {
          e.preventDefault();
          openFocus(matched.focus);
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [active, paletteOpen, focused, visibleCards, selectedCardKey, openFocus, agentBlocked]);

  // Never let an active filter/search hide the session the user just launched.
  const handleSessionLaunched = (rec: AgentSessionRecord) => {
    onSessionCreated(rec);
    setFilter("all");
    setSearch("");
    openFocus({ kind: "session", id: rec.id });
  };

  const hasCommits = Boolean(repo.head_oid);
  // Progressive disclosure: the Action Required rail only takes space when something needs action
  // (or the user peeks via the "0 pending" pill / `n` key, or the worktable failed to load).
  const showJudgmentRail = judgmentCount > 0 || Boolean(error) || railExpanded;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2.5 overflow-y-auto p-3 sm:p-3.5 lg:overflow-hidden xl:gap-3 xl:p-4 2xl:p-5">
      {hasCommits && (
        <CommandCenterHero
          repo={repo}
          owner={owner}
          identity={identity}
          worktable={worktable}
          agentSandbox={health ? (health.agent_sandbox ?? "bwrap") : undefined}
          activeSessions={runningSessions.length}
          refreshing={refreshing && loaded}
          onRefresh={triggerRefresh}
          // Members have no Compare Views picker: browsing code is their wall preview.
          onOpenGlassWall={onOpenGlassWall ?? (() => onOpenCode(defaultBranch))}
          onOpenGithub={onOpenGithub}
          onOpenAgentConnect={onOpenAgentConnect}
          onOpenBranches={onOpenBranches}
          onOpenPolicy={onOpenPolicy}
          onOpenSecrets={onOpenSecrets}
        />
      )}

      <ErrorNote message={error} />

      {/* Owners only; on Windows (no sandbox) the hero's Connect Claude / Cursor card replaces this bar. */}
      {hasCommits && owner && (healthError || (health !== null && health.agent_sandbox !== "none")) && (
        <QuickDelegateBar
          userPrincipal={user.principal}
          identity={identity}
          branches={branches}
          profiles={agentProfiles}
          activeRef={defaultBranch}
          // Health answered but older servers omit the field: treat that as available, not as loading.
          agentSandbox={health ? (health.agent_sandbox ?? "bwrap") : undefined}
          agentSandboxDetail={health?.agent_sandbox_detail}
          healthError={healthError}
          inputRef={delegateInputRef}
          onSessionLaunched={handleSessionLaunched}
          onOpenPolicy={onOpenPolicy}
          onRetryHealth={onRetryHealth}
          onOpenSettings={onOpenSettings}
          onOpenAgents={onOpenAgents}
          onOpenAgentConnect={onOpenAgentConnect}
        />
      )}

      {!hasCommits ? (
        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          <div className="mx-auto my-auto w-full max-w-4xl">
            <EmptyRepoPanel
              title="Push your first commit to get started"
              user={user}
              repo={repo}
              onRefresh={() => {
                void onReposReload().then(triggerRefresh);
              }}
            />
          </div>
        </div>
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row xl:gap-4">
          {/* Left / Main: Presence Canvas */}
          <div className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
            <PresenceCanvas
              built={built}
              owner={owner}
              identity={identity}
              sseConnected={sseConnected}
              nowMs={nowMs}
              defaultBranch={defaultBranch}
              agentProfiles={agentProfiles}
              filter={filter}
              onFilterChange={setFilter}
              search={search}
              onSearchChange={setSearch}
              showSettled={showSettled}
              onShowSettledChange={setShowSettled}
              selectedCardKey={selectedCardKey}
              onSelectCard={setSelectedCardKey}
              onFocus={(target) => openFocus(target)}
              onSessionChange={onSessionChange}
              loaded={loaded}
              error={error}
              onRetry={triggerRefresh}
              agentBlocked={agentBlocked}
              onOpenGlassWall={onOpenGlassWall}
              onOpenAgentConnect={onOpenAgentConnect}
              onOpenBranches={onOpenBranches}
              pendingJudgmentCount={worktable !== null ? judgmentCount : null}
              judgmentRailOpen={showJudgmentRail}
              onToggleJudgmentRail={() => setRailExpanded((v) => !v)}
            />
          </div>

          {/* Right Rail: Action Required — only mounted when something needs action (or the user peeks). */}
          {showJudgmentRail && (
          <div className="flex max-h-[460px] min-h-0 shrink-0 flex-col lg:max-h-none lg:w-[320px] xl:w-[360px] 2xl:w-[400px] [&>section]:min-h-0 [&>section]:flex-1">
            <JudgmentRail
              owner={owner}
              identity={identity}
              nowMs={nowMs}
              pendingApprovals={visiblePendingApprovals}
              quarantineItems={quarantineItems}
              uncommittedSessions={uncommittedSessions}
              readyBranches={readyBranches}
              defaultBranch={defaultBranch}
              railRef={railRef}
              loaded={worktable !== null}
              error={error}
              onRetry={triggerRefresh}
              onApprovalDecided={() => {
                onDecided();
                triggerRefresh();
              }}
              onSessionChange={onSessionChange}
              onRefreshWorktable={triggerRefresh}
              onFocus={(target) => openFocus(target)}
              onOpenCode={leaving((branch?: string, path?: string) => onOpenCode(branch, path))}
              onOpenReview={leaving(onOpenReview)}
              onOpenBranches={leaving((branchName?: string) => onOpenBranches(branchName))}
            />
          </div>
          )}
        </div>
      )}

      {/* Slide-over Workstream Focus Drawer */}
      <WorkstreamFocusDrawer
        focus={focused}
        owner={owner}
        identity={identity}
        nowMs={nowMs}
        worktable={worktable}
        sessions={visibleSessions}
        pendingApprovals={visiblePendingApprovals}
        auditEvents={owner ? auditEvents : []}
        onClose={() => openFocus(null)}
        onFocus={(target) => openFocus(target)}
        onApprovalDecided={() => {
          onDecided();
          triggerRefresh();
        }}
        onSessionChange={onSessionChange}
        onRefreshWorktable={triggerRefresh}
        onBranchesChanged={onBranchesChanged}
        onOpenCode={leaving((branch?: string, path?: string) => onOpenCode(branch, path))}
        onOpenChanges={leaving(onOpenChanges)}
        onOpenReview={leaving(onOpenReview)}
        onOpenBranches={leaving((branchName?: string) => onOpenBranches(branchName))}
        onOpenAgents={leaving(onOpenAgents)}
      />
    </div>
  );
}
