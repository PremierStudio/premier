import { useEffect, useMemo, useRef, useState } from "react";
import { AirlockSkeleton, BranchListSkeleton } from "./ViewSkeletons";
import {
  api,
  ApiError,
  branchNameError,
  cloneUrls,
  errorText,
  type BranchRecord,
  type DeclassificationReport,
  type FirewallFinding,
  type FirewallSeverity,
  type IdentityPreset,
  type PublishBranchResponse,
  type SquashPreviewResponse,
  type User,
  type Visibility,
} from "../api";
import {
  DeclassificationAirlock,
  isPrivateScope,
  visibilityLabel,
  visibilityPillTone,
} from "./DeclassificationAirlock";
import { ConfirmButton } from "./forms";
import {
  IconBlock,
  IconDeclassify,
  IconPlay,
  IconShieldCheck,
  IconBranches,
  IconCheck,
  IconChevron,
  IconClose,
  IconCopy,
  IconLens,
  IconLock,
  IconPlus,
  IconQuarantine,
  IconSearch,
  IconTerminal,
  IconTrash,
} from "./Icons";
import {
  GithubCompanionBranchPanel,
  GithubCompanionPill,
  useGithubCompanionStatus,
} from "./GithubCompanionPanel";
import { plural } from "../lib/format";

const VIS_FILTERS = ["all", "public", "org", "restricted", "personal"] as const;
type VisFilter = (typeof VIS_FILTERS)[number];

function matchesVisibilitySelector(entry: string, identity: IdentityPreset): boolean {
  if (entry === "*") return true;
  const isAnon = identity.principal === "anonymous";
  if (entry === "authenticated") return !isAnon;
  if (entry === identity.principal) return true;
  const bare = identity.principal.replace(/^@/, "");
  if (!isAnon && (entry === `user:${bare}` || entry === `user:${identity.principal}`)) {
    return true;
  }
  for (const g of identity.groups) {
    if (entry === `group:${g}` || entry === `team:${g}`) return true;
  }
  return false;
}

/** Evaluates whether `identity` can see `branch` under its visibility scope. */
function canIdentitySeeBranch(branch: BranchRecord, identity: IdentityPreset): boolean {
  const vis = branch.visibility;
  if (vis.scope === "public") return true;
  if (identity.groups.includes("owners")) return true;
  if (vis.scope === "org") return identity.principal !== "anonymous";
  if (vis.scope === "restricted") {
    return (vis.allow ?? []).some((entry) => matchesVisibilitySelector(entry, identity));
  }
  if (vis.scope === "personal") {
    const rawAllow = vis.allow as string[] | string | undefined;
    const allowList = Array.isArray(rawAllow) ? rawAllow : rawAllow ? [rawAllow] : [];
    return allowList.some((entry) => matchesVisibilitySelector(entry, identity));
  }
  return false;
}

const stringList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];

function parseDeclassificationReport(raw: unknown): DeclassificationReport | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  if (
    typeof r.passed !== "boolean" ||
    typeof r.blocking_count !== "number" ||
    typeof r.warning_count !== "number" ||
    typeof r.report_digest !== "string" ||
    !Array.isArray(r.findings)
  ) {
    return null;
  }
  return r as unknown as DeclassificationReport;
}

function severityPillClass(severity: FirewallSeverity): string {
  switch (severity) {
    case "critical":
      return "border border-[#f27c7c]/45 bg-[#f27c7c]/20 text-[#f27c7c]";
    case "high":
      return "border border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f7a49c]";
    case "warning":
      return "border border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#a8c5ff]";
    case "info":
      return "border border-[#9ec0f5]/30 bg-[#9ec0f5]/12 text-[#9ec0f5]";
  }
}

function FirewallFindingItem({ finding }: { finding: FirewallFinding }) {
  const loc = finding.line != null ? `${finding.location}:${finding.line}` : finding.location;
  return (
    <li className="pr-well space-y-1.5 rounded-lg px-3 py-2">
      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12px]">
        <span className={`rounded-full px-2 py-0.5 uppercase ${severityPillClass(finding.severity)}`}>
          {finding.severity}
        </span>
        <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2 py-0.5 text-[#b6c3db]">
          {finding.category}
        </span>
        {finding.blocking && (
          <span className="rounded-full bg-[#f27c7c]/16 px-2 py-0.5 text-[#f27c7c]">blocking</span>
        )}
      </div>
      <div title={loc} className="truncate font-mono text-[12.5px] text-[#dce4f5]">
        {loc}
      </div>
      <p className="text-[13px] leading-snug text-[#d2dbee]">{finding.summary}</p>
      {finding.owner_detail && (
        <div className="rounded-md border border-white/[0.06] bg-black/25 px-2.5 py-1.5 font-mono text-[12.5px] leading-snug text-[#b6c3db]">
          {finding.owner_detail}
        </div>
      )}
    </li>
  );
}

interface Props {
  user: User;
  identity: IdentityPreset;
  initialBranch?: string;
  onBranchesChanged?: () => void;
  onOpenCommit?: (oid: string, refName?: string) => void;
  repoName?: string;
  isDefaultRepo?: boolean;
  defaultBranch?: string | null;
  /** False while the tab is hidden-but-mounted; keyboard handlers must stay inert. */
  active?: boolean;
}

export function BranchesView({
  user,
  identity,
  initialBranch,
  onBranchesChanged,
  onOpenCommit,
  repoName,
  isDefaultRepo,
  defaultBranch,
  active = true,
}: Props) {
  const [branches, setBranches] = useState<BranchRecord[]>([]);
  // False until the first list arrives, so the empty state never flashes while loading.
  const [loaded, setLoaded] = useState(false);
  const [search, setSearch] = useState("");
  const [visFilter, setVisFilter] = useState<VisFilter>("all");
  // Empty until the list loads, then the requested or repo's default branch.
  const [selected, setSelected] = useState<string>(initialBranch ?? "");
  const [targetBranch, setTargetBranch] = useState<string>("");
  const [wideAirlock, setWideAirlock] = useState(false);
  const [preview, setPreview] = useState<SquashPreviewResponse | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  // The last preview request failed (or answered for another branch/target).
  const [previewFailed, setPreviewFailed] = useState(false);
  const [summaryMsg, setSummaryMsg] = useState("");
  const [newPrincipal, setNewPrincipal] = useState("");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [newBranchName, setNewBranchName] = useState("");
  const [newBranchScope, setNewBranchScope] = useState<"restricted" | "org" | "public">(
    "restricted",
  );
  const [newBranchAllow, setNewBranchAllow] = useState(user.principal);
  const [creating, setCreating] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [publishReceipt, setPublishReceipt] = useState<PublishBranchResponse | null>(null);
  // Paths from a publish refused with 409; shown like the preview's until the next preview.
  const [refused, setRefused] = useState<{
    conflicts: string[];
    hidden: number;
    blocked: string[];
    hiddenBlocked: number;
  } | null>(null);
  // Scoped by branch+target so a switch never shows the previous branch's report for even one frame.
  const [refusedReport, setRefusedReport] = useState<{
    branch: string;
    target: string;
    report: DeclassificationReport;
  } | null>(null);
  const [overrideOpen, setOverrideOpen] = useState(false);
  const [overrideReason, setOverrideReason] = useState("");
  const [overrideAck, setOverrideAck] = useState(false);
  // Unacknowledged commit-message hygiene warnings in the airlock also gate the override.
  const [warningsPending, setWarningsPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const previewReqIdRef = useRef(0);
  // Last previews by "source→target": revisiting a branch paints instantly, then revalidates.
  const previewCacheRef = useRef(new Map<string, SquashPreviewResponse>());
  // null = follow the content: auto-open (from xl up) once a firewall block or a connected GitHub
  // companion needs the rail, then stay open so branch switches never bounce it.
  const [railPref, setRailPref] = useState<boolean | null>(null);
  const [railLatched, setRailLatched] = useState(false);
  const [isXl, setIsXl] = useState(
    () => typeof window !== "undefined" && !!window.matchMedia?.("(min-width: 1280px)").matches,
  );
  useEffect(() => {
    const mq = window.matchMedia?.("(min-width: 1280px)");
    if (!mq) return;
    const onChange = () => setIsXl(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  const member = user.role === "member";
  const simulatingOther = !member && identity.id !== "self";
  // Same cache as the pill and branch panel, so this adds no request.
  const { status: ghStatus } = useGithubCompanionStatus(!member);
  const ghConnected = ghStatus?.connected === true;

  const cachePreview = (src: string, tgt: string, res: SquashPreviewResponse) => {
    const cache = previewCacheRef.current;
    const key = `${src}→${tgt}`;
    cache.delete(key);
    cache.set(key, res);
    if (cache.size > 16) cache.delete(cache.keys().next().value as string);
  };

  useEffect(() => {
    if (initialBranch) setSelected(initialBranch);
  }, [initialBranch]);

  // The view remounts on a repo switch, so reading the current repo once is enough.
  const clone = useMemo(() => cloneUrls(user.username), [user.username]);

  const loadBranches = () => {
    api
      .branches()
      .then((list) => {
        setBranches(list);
        setLoaded(true);
        if (list.length > 0) {
          setSelected((prev) =>
            prev && list.some((b) => b.name === prev)
              ? prev
              : (
                  list.find((b) => !b.is_current && b.ahead_commits > 0) ??
                  list.find((b) => !b.is_current) ??
                  list.find((b) => b.is_current) ??
                  list[0]
                ).name,
          );
        }
      })
      .catch((err: unknown) => setError(errorText(err)));
  };

  useEffect(() => {
    loadBranches();
  }, []);

  const filteredBranches = useMemo(() => {
    const q = search.trim().toLowerCase();
    return branches.filter((b) => {
      if (visFilter !== "all" && b.visibility.scope !== visFilter) return false;
      if (!q) return true;
      return (
        b.name.toLowerCase().includes(q) ||
        b.subject.toLowerCase().includes(q) ||
        b.head_oid.toLowerCase().includes(q)
      );
    });
  }, [branches, search, visFilter]);

  const visCounts = useMemo(() => {
    const counts: Record<string, number> = { all: branches.length };
    for (const b of branches) counts[b.visibility.scope] = (counts[b.visibility.scope] ?? 0) + 1;
    return counts;
  }, [branches]);

  const currentBranch = branches.find((b) => b.name === selected) ?? branches[0] ?? null;
  // The repo's default branch; undefined (empty repo) lets the server pick.
  const baseBranch = branches.find((b) => b.is_current)?.name ?? defaultBranch ?? undefined;

  // Keep targetBranch valid when branch list or source branch changes
  const resolvedTargetBranch = useMemo(() => {
    if (
      targetBranch &&
      branches.some((b) => b.name === targetBranch) &&
      targetBranch !== currentBranch?.name
    ) {
      return targetBranch;
    }
    return baseBranch ?? "";
  }, [targetBranch, branches, currentBranch?.name, baseBranch]);

  useEffect(() => {
    if (targetBranch && (!branches.some((b) => b.name === targetBranch) || targetBranch === currentBranch?.name)) {
      setTargetBranch(baseBranch ?? "");
    }
  }, [branches, currentBranch?.name, targetBranch, baseBranch]);

  // Fetch squash preview with request-id guard against out-of-order responses. The previous
  // preview stays in state while the next one loads (the airlock shows it dimmed, never blank).
  useEffect(() => {
    const reqId = ++previewReqIdRef.current;
    setSummaryMsg("");
    setRefused(null);
    setRefusedReport(null);
    setOverrideOpen(false);
    setOverrideReason("");
    setOverrideAck(false);
    setPublishReceipt(null);
    setPreviewFailed(false);
    setError(null);
    // Squash-declassify is owner-only; a member would just get a 403.
    if (!currentBranch || member) {
      setPreview(null);
      setLoadingPreview(false);
      return;
    }
    if (resolvedTargetBranch && currentBranch.name === resolvedTargetBranch) {
      setPreview(null);
      setLoadingPreview(false);
      return;
    }
    const sourceName = currentBranch.name;
    const cached = previewCacheRef.current.get(`${sourceName}→${resolvedTargetBranch}`);
    if (cached) setPreview(cached);
    setLoadingPreview(true);
    api
      .squashPreview(sourceName, resolvedTargetBranch || undefined)
      .then((res) => {
        if (previewReqIdRef.current !== reqId) return;
        setPreview(res);
        // An answer for another branch/target would never match the airlock: settle as unavailable.
        setPreviewFailed(
          res.source_branch !== sourceName ||
            (!!resolvedTargetBranch && res.target_branch !== resolvedTargetBranch),
        );
        cachePreview(res.source_branch ?? sourceName, res.target_branch ?? resolvedTargetBranch, res);
      })
      .catch((err: unknown) => {
        if (previewReqIdRef.current === reqId) {
          setPreview(null);
          setPreviewFailed(true);
          setError(errorText(err));
        }
      })
      .finally(() => {
        if (previewReqIdRef.current === reqId) setLoadingPreview(false);
      });
  }, [currentBranch?.name, resolvedTargetBranch, member]);

  const updateVis = async (
    branch: BranchRecord,
    visibility: Visibility,
    readiness = branch.readiness,
  ) => {
    try {
      await api.updateBranchVisibility(branch.name, visibility, readiness);
      loadBranches();
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const setVisibilityScope = (branch: BranchRecord, scope: Visibility["scope"]) => {
    const existingAllow =
      branch.visibility.scope === "restricted" && branch.visibility.allow.length > 0
        ? branch.visibility.allow
        : [user.principal];
    const nextVis: Visibility =
      scope === "public"
        ? { scope: "public" }
        : scope === "org"
          ? { scope: "org" }
          : scope === "personal"
            ? { scope: "personal", allow: [user.principal] }
            : { scope: "restricted", allow: existingAllow };
    void updateVis(branch, nextVis);
  };

  const addAllowedPrincipal = (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentBranch || currentBranch.visibility.scope !== "restricted") return;
    const p = newPrincipal.trim();
    if (!p) return;
    const nextAllow = Array.from(new Set([...currentBranch.visibility.allow, p]));
    setNewPrincipal("");
    void updateVis(currentBranch, { scope: "restricted", allow: nextAllow });
  };

  const removeAllowedPrincipal = (target: string) => {
    if (!currentBranch || currentBranch.visibility.scope !== "restricted") return;
    const nextAllow = currentBranch.visibility.allow.filter((a) => a !== target);
    void updateVis(currentBranch, { scope: "restricted", allow: nextAllow });
  };

  const refreshPreview = async (message = summaryMsg) => {
    if (!currentBranch || member) return;
    if (resolvedTargetBranch && currentBranch.name === resolvedTargetBranch) return;
    const reqId = ++previewReqIdRef.current;
    setLoadingPreview(true);
    setPreviewFailed(false);
    try {
      const res = await api.squashPreview(
        currentBranch.name,
        resolvedTargetBranch || undefined,
        message || undefined,
      );
      if (previewReqIdRef.current !== reqId) return;
      setPreview(res);
      if (!message) cachePreview(currentBranch.name, resolvedTargetBranch, res);
      setRefused(null);
      setRefusedReport(null);
      setOverrideOpen(false);
      setOverrideAck(false);
    } catch (err: unknown) {
      if (previewReqIdRef.current !== reqId) return;
      setError(errorText(err));
    } finally {
      if (previewReqIdRef.current === reqId) setLoadingPreview(false);
    }
  };

  const handleCreateBranch = async (e: React.FormEvent) => {
    e.preventDefault();
    const name = newBranchName.trim();
    if (!name) return;
    const nameError = branchNameError(name);
    if (nameError) {
      setError(nameError);
      return;
    }
    setCreating(true);
    setError(null);
    const allow = newBranchAllow
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const vis: Visibility =
      newBranchScope === "public"
        ? { scope: "public" }
        : newBranchScope === "org"
          ? { scope: "org" }
          : { scope: "restricted", allow: allow.length > 0 ? allow : [user.principal] };
    try {
      // Members send no visibility (the server 403s on one that differs from the source branch).
      const created = await api.createBranch(name, member ? undefined : vis, baseBranch, "wip");
      setSelected(created.name);
      setCreateOpen(false);
      loadBranches();
      onBranchesChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setCreating(false);
    }
  };

  const handleDeleteBranch = async (branchName: string) => {
    setError(null);
    try {
      await api.deleteBranch(branchName);
      if (selected === branchName && baseBranch) setSelected(baseBranch);
      loadBranches();
      onBranchesChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const handleExecutePublish = async (override?: {
    override_reason: string;
    override_ack_digest: string;
  }) => {
    if (!currentBranch || currentBranch.name === resolvedTargetBranch) return;
    setPublishing(true);
    setError(null);
    setPublishReceipt(null);
    setRefused(null);
    setRefusedReport(null);
    try {
      const res = await api.publishBranch(
        currentBranch.name,
        resolvedTargetBranch || undefined,
        summaryMsg.trim() || undefined,
        {
          expected_source_oid: preview?.source_oid ?? preview?.source_commit_oid ?? undefined,
          expected_target_oid: preview?.target_oid ?? preview?.target_commit_oid ?? undefined,
        },
        override,
      );
      setPublishReceipt(res);
      // The title went into the commit; refresh preview without clearing publishReceipt.
      setSummaryMsg("");
      setOverrideOpen(false);
      setOverrideReason("");
      setOverrideAck(false);
      loadBranches();
      onBranchesChanged?.();
      await refreshPreview("");
    } catch (err: unknown) {
      const body = err instanceof ApiError && err.status === 409 ? err.body : null;
      const conflicts = stringList(body?.conflicts);
      const hidden = typeof body?.hidden_conflicts === "number" ? body.hidden_conflicts : 0;
      const blocked = stringList(body?.blocked);
      const hiddenBlocked = typeof body?.hidden_blocked === "number" ? body.hidden_blocked : 0;
      const report = parseDeclassificationReport(body?.declassification_report);
      if (report) {
        setRefusedReport({
          branch: currentBranch.name,
          target: resolvedTargetBranch,
          report,
        });
      }
      // A 409 without paths is "the target moved": that one stays a plain error.
      if (conflicts.length + hidden + blocked.length + hiddenBlocked > 0) {
        setRefused({ conflicts, hidden, blocked, hiddenBlocked });
      }
      setError(errorText(err));
    } finally {
      setPublishing(false);
    }
  };

  const copyCommand = (key: string, cmd: string) => {
    navigator.clipboard?.writeText(cmd).catch(() => {});
    setCopiedKey(key);
    window.setTimeout(() => setCopiedKey(null), 1600);
  };

  const cloneCommands = [
    { key: "auth", short: `clone as ${user.username}`, cmd: `git clone ${clone.auth}` },
    { key: "anon", short: "clone public", cmd: `git clone ${clone.anon}` },
  ];

  const createCmd = `premier branch create ${newBranchName.trim() || "private-branch"} --private --allow ${
    newBranchAllow.trim() || user.principal
  } --from ${baseBranch ?? "main"}`;

  const conflicts = refused?.conflicts ?? preview?.conflicts ?? [];
  const hiddenConflicts = refused?.hidden ?? preview?.hidden_conflicts ?? 0;
  const blocked = refused?.blocked ?? preview?.blocked ?? [];
  const hiddenBlocked = refused?.hiddenBlocked ?? preview?.hidden_blocked ?? 0;
  // A report only counts for the branch and target on screen, never the previous branch's.
  const previewFresh =
    !!preview &&
    preview.source_branch === currentBranch?.name &&
    preview.target_branch === resolvedTargetBranch;
  const scopedRefusedReport =
    refusedReport &&
    refusedReport.branch === currentBranch?.name &&
    refusedReport.target === resolvedTargetBranch
      ? refusedReport.report
      : null;
  const activeReport =
    scopedRefusedReport ?? (previewFresh ? preview?.declassification_report : null) ?? null;
  const firewallBlocked =
    !!activeReport && !activeReport.passed && activeReport.blocking_count > 0;
  const canOwnerOverride =
    !member &&
    !loadingPreview &&
    previewFresh &&
    !!currentBranch &&
    currentBranch.name !== resolvedTargetBranch &&
    conflicts.length + hiddenConflicts === 0 &&
    blocked.length + hiddenBlocked === 0 &&
    (preview?.published_paths ?? []).length > 0 &&
    firewallBlocked &&
    !activeReport.redacted;

  // A member who has been granted no branch has nothing to act on: only the clone URLs are shown.
  const nothingVisible = member && loaded && branches.length === 0;

  // The right rail only earns its width for a firewall block or a connected GitHub companion;
  // below xl it is a slide-over drawer that only opens on request.
  const railAvailable = !member && (firewallBlocked || ghConnected);
  useEffect(() => {
    if (railAvailable) setRailLatched(true);
  }, [railAvailable]);
  const railOpen = !member && (railPref ?? (isXl && (railLatched || railAvailable)));
  const drawerOpen = railOpen && !isXl;
  const openOverride = () => {
    setRailPref(true);
    setOverrideOpen(true);
  };

  useEffect(() => {
    if (!drawerOpen || !active) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !e.defaultPrevented) setRailPref(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drawerOpen, active]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3 sm:p-4 lg:overflow-hidden xl:p-4">
      {error && (
        <div
          role="alert"
          className="rounded-xl border border-[#f27c7c]/25 bg-[#f27c7c]/10 px-4 py-2 font-mono text-[13px] text-[#f27c7c]"
        >
          {error}
        </div>
      )}

      {/* Viewing As Lens Indicator */}
      {simulatingOther && (
        <div
          role="status"
          className="flex shrink-0 flex-wrap items-center justify-between gap-2 rounded-xl border border-[#9ec0f5]/25 bg-[#7f95f8]/10 px-4 py-2 font-mono text-[13px] text-[#cfe0ff]"
        >
          <span className="inline-flex items-center gap-2">
            <IconLens className="h-4 w-4 text-[#9ec0f5]" />
            <span>
              Viewing as <strong className="text-[#f3f6fd]">{identity.label}</strong>
            </span>
          </span>
          <span className="text-[#b6c3db]">
            {branches.filter((b) => canIdentitySeeBranch(b, identity)).length} visible ·{" "}
            {branches.filter((b) => !canIdentitySeeBranch(b, identity)).length} hidden
          </span>
        </div>
      )}

      {/* Compact Projected Smart HTTP v2 Clone Strip + New Branch Trigger */}
      <div className="pr-surface flex shrink-0 flex-wrap items-center justify-between gap-2 rounded-2xl px-3.5 py-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span
            title="Password: an access token from Settings. The public clone is the anonymous projection."
            className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]"
          >
            Smart HTTP v2
          </span>
          {cloneCommands.map((c) => (
            <button
              key={c.key}
              type="button"
              onClick={() => copyCommand(c.key, c.cmd)}
              title={c.cmd}
              className="pr-pill inline-flex max-w-full items-center gap-2 rounded-full px-3 py-1 font-mono text-[13px] text-[#dce4f5]"
            >
              <span className="shrink-0 text-[#9ec0f5]">{c.short}</span>
              <span className="hidden max-w-[260px] min-w-0 truncate text-[#a6b5cf] 2xl:inline">
                {c.cmd}
              </span>
              {copiedKey === c.key ? (
                <IconCheck className="h-4 w-4 text-[#5bdba2]" />
              ) : (
                <IconCopy className="h-4 w-4 text-[#a6b5cf]" />
              )}
            </button>
          ))}
          <GithubCompanionPill user={user} />
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          {!nothingVisible && (
            <button
              type="button"
              onClick={() => setCreateOpen((o) => !o)}
              aria-expanded={createOpen}
              className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[13.5px]"
            >
              <IconPlus className="h-4 w-4" />
              <span>New branch</span>
            </button>
          )}
        </div>
      </div>

      {nothingVisible && (
        <section className="pr-surface mx-auto max-w-md space-y-1.5 rounded-2xl p-5 text-center">
          <h2 className="text-[14px] font-semibold text-[#f3f6fd]">No branches to show</h2>
          <p className="text-[14px] leading-relaxed text-[#b6c3db]">
            You can&apos;t see any branch in this repository yet. Ask an owner to grant you access.
          </p>
        </section>
      )}

      {/* Inline Create Private/Embargo Branch Drawer */}
      {createOpen && !nothingVisible && (
        <form
          onSubmit={(e) => void handleCreateBranch(e)}
          onKeyDown={(e) => {
            if (e.key === "Escape") setCreateOpen(false);
          }}
          className="pr-elevated flex shrink-0 flex-wrap items-center justify-between gap-2.5 rounded-2xl px-4 py-3"
        >
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">
            <input
              value={newBranchName}
              onChange={(e) => setNewBranchName(e.target.value)}
              autoFocus
              aria-label="Branch name"
              placeholder="branch-name"
              className="pr-well w-44 rounded-xl px-3 py-1.5 font-mono text-[13.5px] text-[#f3f6fd] focus:outline-none"
            />
            <span
              title={`The new branch starts from ${baseBranch ?? "the default branch"}`}
              className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2 py-0.5 font-mono text-[12.5px] text-[#b6c3db]"
            >
              from {baseBranch ?? "default"}
            </span>
            {member ? (
              <span className="text-[13px] text-[#a6b5cf]">
                This branch will be private to you.
              </span>
            ) : (
              <div
                role="group"
                aria-label="New branch visibility"
                className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 font-mono text-[12.5px]"
              >
                {(["restricted", "org", "public"] as const).map((sc) => (
                  <button
                    key={sc}
                    type="button"
                    aria-pressed={newBranchScope === sc}
                    onClick={() => setNewBranchScope(sc)}
                    className={`rounded-full px-2.5 py-1 transition ${
                      newBranchScope === sc
                        ? sc === "restricted"
                          ? "bg-white/[0.12] text-[#f3f6fd]"
                          : "bg-[#7f95f8]/24 text-[#f3f6fd]"
                        : "text-[#a6b5cf] hover:text-white"
                    }`}
                  >
                    {sc}
                  </button>
                ))}
              </div>
            )}
            {!member && newBranchScope === "restricted" && (
              <input
                value={newBranchAllow}
                onChange={(e) => setNewBranchAllow(e.target.value)}
                aria-label="Who may see the branch, comma separated"
                placeholder={`e.g. ${user.principal},group:security`}
                className="pr-well w-48 rounded-xl px-3 py-1.5 font-mono text-[13.5px] text-[#f3f6fd] focus:outline-none"
              />
            )}
            {!member && newBranchScope === "public" && (
              <span role="note" className="font-mono text-[12.5px] text-[#a8c5ff]">
                Public: anyone, including anonymous visitors, can read this branch.
              </span>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              type="submit"
              disabled={creating || !newBranchName.trim()}
              className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-[13.5px] disabled:opacity-50"
            >
              <IconPlus className="h-4 w-4" />
              <span>{creating ? "Creating…" : "Create"}</span>
            </button>
            <button
              type="button"
              onClick={() => copyCommand("create-cli", createCmd)}
              title={createCmd}
              // The CLI line sets a visibility, which a member may not.
              hidden={member}
              className="pr-pill inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 font-mono text-[12.5px] text-[#d2dbee]"
            >
              {copiedKey === "create-cli" ? (
                <IconCheck className="h-4 w-4 text-[#5bdba2]" />
              ) : (
                <IconTerminal className="h-4 w-4 text-[#9ec0f5]" />
              )}
              <span className="hidden sm:inline">CLI</span>
            </button>
            <button
              type="button"
              onClick={() => setCreateOpen(false)}
              aria-label="Close"
              className="rounded-lg p-1.5 text-[#a6b5cf] hover:text-white"
            >
              <IconClose className="h-4 w-4" />
            </button>
          </div>
        </form>
      )}

      {/* Main Split: Collapsible Branches Rail + Full Declassification Airlock */}
      <div className={nothingVisible ? "hidden" : "flex min-h-0 flex-1 flex-col gap-3 lg:flex-row"}>
        {!wideAirlock && (
          <aside className="pr-surface flex max-h-[300px] min-h-[220px] shrink-0 flex-col overflow-hidden rounded-2xl lg:max-h-none lg:min-h-0 lg:w-[280px] xl:w-[320px]">
            {/* Search + Visibility Filter Chips */}
            <div className="space-y-1.5 border-b border-white/[0.06] px-3 py-2">
              <div className="flex items-center gap-2">
                <IconSearch className="h-4 w-4 text-[#a6b5cf]" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  aria-label="Filter branches"
                  placeholder="Filter branches…"
                  className="min-w-0 flex-1 bg-transparent text-[14px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
                />
              </div>
              <div className="flex flex-nowrap items-center gap-0.5 overflow-x-auto">
                {VIS_FILTERS.filter(
                  (vf) => vf === "all" || visFilter === vf || (visCounts[vf] ?? 0) > 0,
                ).map((vf) => {
                  const count = visCounts[vf] ?? 0;
                  return (
                    <button
                      key={vf}
                      type="button"
                      onClick={() => setVisFilter(vf)}
                      aria-pressed={visFilter === vf}
                      className={`shrink-0 rounded-full px-1.5 py-0.5 font-mono text-[12.5px] capitalize transition ${
                        visFilter === vf
                          ? "pr-pill-active"
                          : "text-[#a6b5cf] hover:bg-white/[0.04] hover:text-[#f3f6fd]"
                      }`}
                    >
                      {vf} {count}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto">
              {!loaded && filteredBranches.length === 0 && <BranchListSkeleton />}
              {loaded && filteredBranches.length === 0 && (
                <div className="flex h-full min-h-[140px] items-center justify-center p-4 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                  {branches.length === 0
                    ? "No branches yet. Push a commit to create the first one."
                    : "No branches match"}
                </div>
              )}
              {filteredBranches.map((b) => {
                const active = currentBranch?.name === b.name;
                const visibleToIdentity = !simulatingOther || canIdentitySeeBranch(b, identity);
                return (
                  <div
                    key={b.name}
                    onClick={() => setSelected(b.name)}
                    className={`group flex cursor-pointer flex-col gap-1.5 px-3 py-2 transition ${
                      active ? "bg-[#7f95f8]/12" : "hover:bg-white/[0.03]"
                    } ${!visibleToIdentity ? "opacity-55" : ""}`}
                  >
                    <button
                      type="button"
                      onClick={() => setSelected(b.name)}
                      aria-current={active ? "true" : undefined}
                      className="min-w-0 rounded-lg text-left focus-visible:outline-offset-[-2px]"
                    >
                      <div className="flex items-center gap-1.5">
                        {isPrivateScope(b.visibility) ? (
                          <IconLock className="h-4 w-4 shrink-0 text-[#a8c5ff]" />
                        ) : (
                          <IconBranches className="h-4 w-4 shrink-0 text-[#7f95f8]" />
                        )}
                        <span className="min-w-0 truncate font-mono text-[14px] font-medium text-[#f3f6fd]">
                          {b.name}
                        </span>
                        {b.is_current && (
                          <span className="shrink-0 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-2 py-0.5 font-mono text-[12px] leading-4 text-[#5bdba2]">
                            HEAD
                          </span>
                        )}
                        <span className="ml-auto shrink-0 whitespace-nowrap font-mono text-[12.5px] text-[#a6b5cf]">
                          {b.head_oid}
                          {b.ahead_commits > 0 && (
                            <>
                              {" · "}
                              <span className="text-[#9ec0f5]">+{b.ahead_commits}</span>
                            </>
                          )}
                          {b.private_paths_touched.length > 0 && ` · ${b.private_paths_touched.length} priv`}
                        </span>
                      </div>

                      {/* Visibility chip and subject share one line. */}
                      <div className="mt-1 flex items-center gap-1.5">
                        <span
                          className={`max-w-[55%] shrink-0 truncate rounded-full border px-2 py-0.5 font-mono text-[12px] leading-4 ${visibilityPillTone(b.visibility)}`}
                        >
                          {visibilityLabel(b.visibility)}
                        </span>
                        {simulatingOther && !visibleToIdentity && (
                          <span
                            title={`Hidden from ${identity.label}`}
                            className="shrink-0 rounded-full border border-[#f27c7c]/30 bg-[#f27c7c]/12 px-2 py-0.5 font-mono text-[12px] leading-4 text-[#f27c7c]"
                          >
                            hidden
                          </span>
                        )}
                        <span className="min-w-0 truncate text-[13px] text-[#a6b5cf]" title={b.subject}>
                          {b.subject}
                        </span>
                      </div>
                    </button>

                    {/* Compact Scope Pills + Orthogonal Readiness + Delete */}
                    <div
                      className={`flex-wrap items-center justify-between gap-1.5 ${
                        active ? "flex" : "hidden group-focus-within:flex group-hover:flex"
                      }`}
                      onClick={(e) => e.stopPropagation()}
                    >
                      {!member && (
                        <div
                          role="group"
                          aria-label={`${b.name} visibility`}
                          className="inline-flex items-center rounded-full border border-white/[0.08] bg-black/30 p-0.5 font-mono text-[12px]"
                        >
                          {(["public", "org", "restricted"] as const).map((sc) => (
                            <button
                              key={sc}
                              type="button"
                              aria-pressed={b.visibility.scope === sc}
                              onClick={() => setVisibilityScope(b, sc)}
                              className={`rounded-full px-2 py-0.5 transition ${
                                b.visibility.scope === sc
                                  ? sc === "restricted"
                                    ? "bg-white/[0.12] text-[#f3f6fd]"
                                    : "bg-[#7f95f8]/24 text-[#f3f6fd]"
                                  : "text-[#a6b5cf] hover:text-[#e6ecf8]"
                              }`}
                            >
                              {sc}
                            </button>
                          ))}
                        </div>
                      )}

                      <div className="flex items-center gap-1.5">
                        <button
                          type="button"
                          // Readiness is saved through the visibility endpoint, which is owner-only.
                          disabled={member}
                          title={member ? "Owner only" : "Toggle readiness"}
                          aria-label={`${b.name} readiness: ${b.readiness}`}
                          onClick={() =>
                            void updateVis(
                              b,
                              b.visibility,
                              b.readiness === "ready" ? "wip" : "ready",
                            )
                          }
                          className={`rounded-full px-2 py-0.5 font-mono text-[12px] leading-4 uppercase transition disabled:cursor-not-allowed disabled:opacity-60 ${
                            b.readiness === "ready"
                              ? "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                              : "border border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
                          }`}
                        >
                          {b.readiness}
                        </button>

                        {!b.is_current && (
                          <ConfirmButton
                            disabled={member}
                            confirmLabel="Delete"
                            question={`Delete ${b.name}?`}
                            onConfirm={() => void handleDeleteBranch(b.name)}
                            title={member ? "Owner only" : `Delete ${b.name}`}
                            aria-label={`Delete ${b.name}`}
                            className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-full text-[#a6b5cf] hover:text-[#f27c7c] disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:text-[#8b99b2]"
                          >
                            <IconTrash className="h-3.5 w-3.5" />
                          </ConfirmButton>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </aside>
        )}

        {/* Airlock + right rail: side by side from xl; below xl the rail is a slide-over drawer. */}
        <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-3 xl:flex-row">
        <div className="flex min-h-[420px] min-w-0 flex-1 flex-col lg:min-h-0">
        {!loaded && !currentBranch ? (
          <section className="pr-surface flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl">
            <AirlockSkeleton />
          </section>
        ) : (
        <DeclassificationAirlock
          branch={currentBranch}
          branches={branches}
          baseBranch={baseBranch}
          targetBranch={resolvedTargetBranch}
          onSelectTargetBranch={setTargetBranch}
          member={member}
          preview={preview}
          loadingPreview={loadingPreview}
          previewFailed={previewFailed}
          firewallBlocked={firewallBlocked}
          firewallBlockingCount={activeReport?.blocking_count ?? 0}
          canOwnerOverride={canOwnerOverride}
          onOpenOverride={openOverride}
          railOpen={railOpen}
          onToggleRail={() => setRailPref(!railOpen)}
          ghConnected={ghConnected}
          onSelectBranch={setSelected}
          onWarningsPendingChange={setWarningsPending}
          refused={refused}
          summaryMsg={summaryMsg}
          onSummaryMsgChange={setSummaryMsg}
          onRefreshPreview={() => void refreshPreview()}
          onExecutePublish={() => {
            if (firewallBlocked) {
              // The firewall gate holds the publish; only the audited override in the rail lifts it.
              if (canOwnerOverride) openOverride();
              setError(
                `Blocked by leak & secret scanner (${plural(activeReport?.blocking_count ?? 0, "blocking finding")})`,
              );
              return;
            }
            void handleExecutePublish();
          }}
          publishing={publishing}
          publishReceipt={publishReceipt}
          onDismissReceipt={() => setPublishReceipt(null)}
          wideMode={wideAirlock}
          onToggleWideMode={() => setWideAirlock((w) => !w)}
          newPrincipal={newPrincipal}
          onNewPrincipalChange={setNewPrincipal}
          onAddPrincipal={addAllowedPrincipal}
          onRemovePrincipal={removeAllowedPrincipal}
          repoName={repoName}
          isDefaultRepo={isDefaultRepo}
          defaultBranch={defaultBranch}
          onOpenCommit={onOpenCommit}
          active={active}
        />
        )}
        </div>
        {/* Right rail: declassification firewall report, audited owner override, GitHub Companion */}
        {drawerOpen && (
          <button
            type="button"
            aria-label="Close leak scanner and GitHub rail"
            onClick={() => setRailPref(false)}
            className="fixed inset-0 z-30 cursor-default bg-black/55 xl:hidden"
          />
        )}
        {railOpen && (
        <aside
          aria-label="Leak scanner and GitHub"
          role={drawerOpen ? "dialog" : undefined}
          aria-modal={drawerOpen ? true : undefined}
          className="pr-surface fixed inset-y-3 right-3 z-40 flex w-[min(360px,calc(100vw-1.5rem))] flex-col overflow-hidden rounded-2xl shadow-2xl max-xl:bg-[#0b0f1c] xl:static xl:inset-auto xl:z-auto xl:max-h-none xl:w-[300px] xl:shrink-0 xl:shadow-none"
        >
          <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-2">
            <span className="inline-flex items-center gap-2 font-mono text-[13px] uppercase tracking-wider text-[#9ec0f5]">
              <IconDeclassify className="h-[18px] w-[18px]" />
              <span>Leak Scanner &amp; GitHub</span>
            </span>
            <button
              type="button"
              onClick={() => setRailPref(false)}
              aria-label="Hide leak scanner and GitHub rail"
              className="rounded-lg p-1 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white"
            >
              <IconClose className="h-4 w-4" />
            </button>
          </div>
          <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3.5">
            {!activeReport && !ghConnected && (
              <p className="text-[13px] leading-relaxed text-[#a6b5cf]">
                The leak & secret scanner report appears here once the branch has a publish preview.
              </p>
            )}
            {/* Declassification Firewall Report */}
            {activeReport && (
              <div className="space-y-2 rounded-xl border border-white/[0.07] bg-black/20 p-2.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                    Leak &amp; Secret Scanner
                  </span>
                  <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12.5px]">
                    {activeReport.passed ? (
                      <span className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/14 px-2 py-0.5 text-[#5bdba2]">
                        <IconShieldCheck className="h-3.5 w-3.5" />
                        <span>Scanner Passed</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/16 px-2 py-0.5 text-[#f27c7c]">
                        <IconBlock className="h-3.5 w-3.5" />
                        <span>{plural(activeReport.blocking_count, "blocker")}</span>
                      </span>
                    )}
                    {activeReport.warning_count > 0 && (
                      <span className="rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/12 px-2 py-0.5 text-[#a8c5ff]">
                        {plural(activeReport.warning_count, "warning")}
                      </span>
                    )}
                  </div>
                </div>

                {activeReport.report_digest && (
                  <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px] text-[#a6b5cf]">
                    <span>digest {activeReport.report_digest.slice(0, 12)}</span>
                    {activeReport.redacted && (
                      <span className="rounded-full border border-white/[0.12] bg-white/[0.045] px-2 py-0.5 text-[12px] leading-4 text-[#cbd5e8]">
                        redacted
                      </span>
                    )}
                  </div>
                )}

                {activeReport.findings.length > 0 && (
                  <ul className="max-h-60 space-y-1.5 overflow-y-auto">
                    {activeReport.findings.map((finding) => (
                      <FirewallFindingItem key={finding.id} finding={finding} />
                    ))}
                  </ul>
                )}

                {canOwnerOverride && (
                  <div className="rounded-xl border border-[#9ec0f5]/40 bg-[#171208] p-2.5 shadow-[0_6px_18px_rgba(0,0,0,0.4)]">
                    <button
                      type="button"
                      onClick={() => setOverrideOpen((o) => !o)}
                      aria-expanded={overrideOpen}
                      className="flex w-full items-center justify-between gap-2 font-mono text-[12.5px] font-medium text-[#a8c5ff]"
                    >
                      <span className="inline-flex items-center gap-1.5">
                        <IconQuarantine className="h-4 w-4" />
                        <span>Owner Override (Audited)</span>
                      </span>
                      <IconChevron
                        direction={overrideOpen ? "up" : "down"}
                        className="h-4 w-4 text-[#a8c5ff]"
                      />
                    </button>

                    {overrideOpen && (
                      <div className="mt-2.5 space-y-2.5 border-t border-[#9ec0f5]/20 pt-2.5">
                        <div className="font-mono text-[12.5px] text-[#b6c3db]">
                          onto <span className="text-[#f3f6fd]">{resolvedTargetBranch}</span> · 1 squashed
                          commit
                        </div>
                        <div className="space-y-1">
                          <input
                            value={overrideReason}
                            onChange={(e) => setOverrideReason(e.target.value)}
                            aria-label="Audit reason for scanner override"
                            placeholder="Mandatory audit reason (min 8 chars)…"
                            className="pr-well w-full rounded-lg px-2.5 py-1.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
                          />
                          <div
                            className={`text-right font-mono text-[12px] ${
                              overrideReason.trim().length >= 8 ? "text-[#5bdba2]" : "text-[#b6c3db]"
                            }`}
                          >
                            {Math.min(overrideReason.trim().length, 8)}/8 chars
                          </div>
                        </div>

                        <label className="flex cursor-pointer items-start gap-2 text-[12.5px] leading-snug text-[#d6e2f8]">
                          <input
                            type="checkbox"
                            checked={overrideAck}
                            onChange={(e) => setOverrideAck(e.target.checked)}
                            className="mt-0.5 accent-[#9ec0f5]"
                          />
                          <span>
                            I acknowledge digest{" "}
                            <code className="font-mono text-[#f3f6fd]">
                              {activeReport.report_digest.slice(0, 12)}
                            </code>{" "}
                            and accept audit responsibility
                          </span>
                        </label>

                        {warningsPending && (
                          <div role="note" className="font-mono text-[12.5px] text-[#a8c5ff]">
                            Acknowledge the commit-message hygiene warnings in the airlock first.
                          </div>
                        )}

                        <ConfirmButton
                          disabled={
                            publishing ||
                            overrideReason.trim().length < 8 ||
                            !overrideAck ||
                            warningsPending
                          }
                          question="Override the scanner and publish?"
                          confirmLabel="Publish"
                          onConfirm={() =>
                            void handleExecutePublish({
                              override_reason: overrideReason.trim(),
                              override_ack_digest: activeReport.report_digest,
                            })
                          }
                          className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-[#9ec0f5]/40 bg-[#7f95f8]/18 px-3 py-1.5 font-mono text-[13px] font-medium text-[#a8c5ff] transition hover:bg-[#7f95f8]/26 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <IconPlay className="h-3.5 w-3.5" />
                          <span>{publishing ? "Publishing…" : "Override & Publish"}</span>
                        </ConfirmButton>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {currentBranch && (
              <GithubCompanionBranchPanel
                user={user}
                branchName={currentBranch.name}
                baseBranch={baseBranch}
                first={!activeReport}
                onPublished={() => {
                  loadBranches();
                  onBranchesChanged?.();
                }}
              />
            )}
          </div>
        </aside>
        )}
        </div>
      </div>
    </div>
  );
}
