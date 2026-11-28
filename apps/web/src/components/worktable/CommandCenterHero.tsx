import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  api,
  type HealthResponse,
  type IdentityPreset,
  type PolicySummaryResponse,
  type RepoTreeResponse,
  type Repo,
  type SchemaDashboardResponse,
  type WorktableResponse,
} from "../../api";
import { SkelBar } from "../ViewSkeletons";
import { AiHarnessCluster, BrandIcon } from "../BrandIcons";
import { useGithubCompanionStatus } from "../GithubCompanionPanel";
import {
  IconCheck,
  IconClose,
  IconEye,
  IconLock,
  IconQuarantine,
  IconRefresh,
} from "../Icons";

export interface CommandCenterHeroProps {
  repo: Repo;
  owner: boolean;
  identity: IdentityPreset;
  worktable: WorktableResponse | null;
  agentSandbox?: HealthResponse["agent_sandbox"];
  /** Live agent sessions currently running (feeds the "Connect MCP Agent" step). */
  activeSessions?: number;
  refreshing?: boolean;
  onRefresh?: () => void;
  onOpenGlassWall?: () => void;
  onOpenGithub?: () => void;
  onOpenAgentConnect?: () => void;
  onOpenBranches: (branchName?: string) => void;
  onOpenPolicy: () => void;
  onOpenSecrets?: () => void;
}

const DISMISS_KEY = "premier.quickstart.dismissed.v1";

function readDismissed(): boolean {
  try {
    return window.localStorage.getItem(DISMISS_KEY) === "1";
  } catch {
    return false;
  }
}

function zoneCount(summary: PolicySummaryResponse | null): number {
  const zones = (summary?.policy as { zones?: unknown } | null | undefined)?.zones;
  if (Array.isArray(zones)) return zones.length;
  if (zones && typeof zones === "object") return Object.keys(zones).length;
  return 0;
}

const CTA =
  "pr-pill inline-flex w-fit items-center gap-1 rounded-full px-2.5 py-1 text-[13px] text-[#dce4f5] hover:text-[#f3f6fd] disabled:opacity-50";
const CTA_PRIMARY =
  "pr-action-btn inline-flex w-fit items-center gap-1 rounded-full px-3 py-1 text-[13px] disabled:opacity-50";
const CHIP =
  "inline-flex min-w-0 max-w-[150px] items-center gap-1 rounded-md border border-white/[0.08] bg-white/[0.04] px-1.5 py-0.5 font-mono text-[12.5px] text-[#dce4f5]";

/** Same anonymous lens the "Compare Views" public side uses; hits api.ts's cache. */
const PUBLIC_LENS: IdentityPreset = {
  id: "anonymous",
  label: "Public / GitHub",
  subtitle: "Public projection",
  principal: "anonymous",
  groups: [],
  badgeColor: "zinc",
};

function Pillar({
  icon,
  kicker,
  stat,
  proof,
  children,
}: {
  icon: ReactNode;
  kicker: string;
  stat: ReactNode;
  proof: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="pr-surface pr-card-interactive flex min-h-[132px] min-w-0 flex-col justify-between gap-2.5 rounded-xl p-3">
      <div className="min-w-0 space-y-1">
        <div className="flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wide text-[#a6b5cf]">
          {icon}
          <span className="truncate">{kicker}</span>
        </div>
        <div className="flex min-h-5 items-center truncate text-[14px] font-semibold leading-5 text-[#f3f6fd]">
          {stat}
        </div>
        <div className="flex min-h-[22px] min-w-0 items-center gap-1 overflow-hidden text-[12.5px] text-[#a6b5cf]">
          {proof}
        </div>
      </div>
      <div className="flex min-w-0 flex-wrap items-center gap-1.5">{children}</div>
    </section>
  );
}

function StepPill({
  n,
  done,
  label,
  onClick,
}: {
  n: number;
  done: boolean;
  label: string;
  onClick?: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!onClick}
      className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[13px] text-[#dce4f5] hover:text-[#f3f6fd] disabled:opacity-50"
    >
      {done ? (
        <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
      ) : (
        <span className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-[#9ec0f5]/40 font-mono text-[12px] text-[#9ec0f5]">
          {n}
        </span>
      )}
      <span className={done ? "text-[#a6b5cf]" : undefined}>{label}</span>
    </button>
  );
}

/** Home hero: what Premier protects in this repo right now, with a one-click action per superpower. */
export function CommandCenterHero({
  owner,
  identity,
  worktable,
  activeSessions = 0,
  refreshing,
  onRefresh,
  onOpenGlassWall,
  onOpenGithub,
  onOpenAgentConnect,
  onOpenBranches,
  onOpenPolicy,
  onOpenSecrets,
}: CommandCenterHeroProps) {
  const { status: ghStatus } = useGithubCompanionStatus(owner);
  const [policy, setPolicy] = useState<PolicySummaryResponse | null>(null);
  const [env, setEnv] = useState<SchemaDashboardResponse | null>(null);
  const [publicTree, setPublicTree] = useState<RepoTreeResponse | null>(null);
  const [mcpServers, setMcpServers] = useState(0);
  const [dismissed, setDismissed] = useState(readDismissed);
  const lens = `${identity.id}|${identity.principal}|${identity.agentProfile ?? ""}`;

  // Both calls hit api.ts's short-TTL cache + in-flight dedupe, so tab re-entry is free.
  useEffect(() => {
    let alive = true;
    if (owner) {
      api
        .policySummary()
        .then((r) => alive && setPolicy(r))
        .catch(() => {});
      api
        .repoTree(PUBLIC_LENS, true)
        .then((r) => alive && setPublicTree(r))
        .catch(() => {});
    }
    api
      .envDashboard(identity)
      .then((r) => alive && setEnv(r))
      .catch(() => {});
    if (owner && !readDismissed()) {
      api
        .mcpGateways(identity)
        .then((r) => alive && setMcpServers(r.total_servers))
        .catch(() => {});
    }
    return () => {
      alive = false;
    };
    // `identity` is covered by `lens`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [owner, lens]);

  const zones = zoneCount(policy);
  const secretKeys = Object.keys(env?.schema?.vars ?? {});
  const secrets = secretKeys.length;
  const unlanded = useMemo(
    () =>
      (worktable?.branches ?? []).filter(
        (b) => b.name !== worktable?.default_branch && b.ahead_commits > 0,
      ),
    [worktable],
  );
  const quarantined = worktable?.quarantine_items.length ?? 0;
  const gh = ghStatus?.connected && ghStatus.config ? ghStatus : null;
  const ghDetail = gh
    ? (gh.sync_state?.last_sync_summary ??
      (gh.receipts.length > 0 ? `${gh.receipts.length} PRs` : gh.config?.sync_direction))
    : null;
  const hiddenPaths = (publicTree?.entries ?? [])
    .filter((e) => e.visibility_state === "omitted")
    .map((e) => e.path);
  const hiddenCount = Math.max(publicTree?.omitted_count ?? 0, hiddenPaths.length);
  const visibleCount =
    publicTree?.visible_count ??
    (publicTree?.entries ?? []).filter((e) => e.visibility_state === "visible").length;

  const steps = [
    { label: "Connect GitHub", done: Boolean(gh), go: onOpenGithub },
    { label: "Compare Views as AI Agent", done: zones > 0, go: onOpenGlassWall },
    {
      label: "Connect AI Agent",
      done: mcpServers > 0 || activeSessions > 0,
      go: onOpenAgentConnect,
    },
    { label: "Set Access Rules", done: zones > 0, go: onOpenPolicy },
  ];
  const showQuickStart = owner && !dismissed && steps.some((s) => !s.done);

  const dismiss = () => {
    setDismissed(true);
    try {
      window.localStorage.setItem(DISMISS_KEY, "1");
    } catch {
      /* private mode: dismissal lasts for this view only */
    }
  };

  return (
    <div className="shrink-0 space-y-2">
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Pillar
          icon={<IconLock className="h-3.5 w-3.5 text-[#a8c5ff]" />}
          kicker="Private Folders"
          stat={
            !owner ? (
              "Your view follows Access Rules"
            ) : !publicTree ? (
              <SkelBar className="inline-block h-4 w-32 align-middle" />
            ) : hiddenCount > 0 ? (
              `${hiddenCount} hidden · ${visibleCount} public`
            ) : (
              "No folders locked yet"
            )
          }
          proof={
            !owner || !publicTree ? null : hiddenPaths.length > 0 ? (
              <>
                {hiddenPaths.slice(0, 2).map((path) => (
                  <span key={path} className={CHIP} title={path}>
                    <IconLock className="h-3 w-3 shrink-0 text-[#a8c5ff]" />
                    <span className="truncate">{path}</span>
                  </span>
                ))}
                {hiddenCount > 2 && <span className="shrink-0">+{hiddenCount - 2} more</span>}
              </>
            ) : (
              <span className="truncate">
                Private folders send 0 bytes to other clones &amp; GitHub.
              </span>
            )
          }
        >
          <button
            type="button"
            onClick={onOpenGlassWall}
            disabled={!onOpenGlassWall}
            title="Compare your view against a contractor or AI agent"
            className={CTA_PRIMARY}
          >
            <IconEye className="h-3.5 w-3.5" />
            Compare Views →
          </button>
          <button type="button" onClick={onOpenPolicy} className={CTA}>
            Access Rules
          </button>
        </Pillar>

        <Pillar
          icon={<BrandIcon name="github" className="h-3.5 w-3.5" />}
          kicker="GitHub Sync & Safe PRs"
          stat={
            gh?.config ? (
              <span className="inline-flex max-w-full items-center gap-1.5" title={ghDetail ?? undefined}>
                <span className="h-2 w-2 shrink-0 rounded-full bg-[#5bdba2]" aria-label="connected" />
                <span className="truncate">{gh.config.full_name}</span>
                <span className="shrink-0 font-mono text-[12.5px] font-normal text-[#a6b5cf]">
                  {gh.config.sync_direction}
                </span>
              </span>
            ) : owner ? (
              "Not connected"
            ) : (
              "Owner-managed"
            )
          }
          proof={
            unlanded.length > 0 ? (
              <>
                <span className="truncate">
                  {unlanded.length} branch{unlanded.length === 1 ? "" : "es"} ready to scrub &amp; publish
                </span>
                {quarantined > 0 && (
                  <span className="inline-flex shrink-0 items-center gap-1 text-[#a8c5ff]">
                    <IconQuarantine className="h-3.5 w-3.5" />
                    {quarantined} held
                  </span>
                )}
              </>
            ) : (
              <span className="truncate">Public folders sync; private folders stay local.</span>
            )
          }
        >
          {owner && (
            <button
              type="button"
              onClick={onOpenGithub}
              disabled={!onOpenGithub}
              className={gh ? CTA : CTA_PRIMARY}
            >
              {gh ? "Sync & Manage →" : "Connect GitHub →"}
            </button>
          )}
          <button type="button" onClick={() => onOpenBranches(unlanded[0]?.name)} className={CTA}>
            Safe Publish
          </button>
        </Pillar>

        <Pillar
          icon={<AiHarnessCluster compact />}
          kicker="AI Agent Secret Protection"
          stat={
            secrets > 0 ? (
              `${secrets} secret${secrets === 1 ? "" : "s"} protected · ${mcpServers} MCP`
            ) : env ? (
              "No secrets configured yet"
            ) : (
              <SkelBar className="inline-block h-4 w-32 align-middle" />
            )
          }
          proof={
            secrets > 0 ? (
              <>
                {secretKeys.slice(0, 3).map((k) => (
                  <span key={k} className={CHIP} title={k}>
                    <span className="truncate">{k}</span>
                  </span>
                ))}
                <span className="shrink-0 text-[12px] uppercase tracking-wide">masked</span>
              </>
            ) : (
              <span className="truncate">
                Works with any MCP or CLI coding agent.
              </span>
            )
          }
        >
          <button
            type="button"
            onClick={onOpenAgentConnect}
            disabled={!onOpenAgentConnect}
            className={CTA_PRIMARY}
          >
            Connect AI Agent →
          </button>
          <button type="button" onClick={onOpenSecrets} disabled={!onOpenSecrets} className={CTA}>
            Secrets
          </button>
        </Pillar>
      </div>

      <div className="flex min-h-[42px] flex-wrap items-center gap-2">
        {showQuickStart ? (
          <div className="pr-well flex min-h-[40px] min-w-0 flex-1 flex-wrap items-center gap-2 rounded-xl px-3 py-2">
            <span className="text-[13px] font-semibold text-[#f3f6fd]">Get started in 60 seconds</span>
            {steps.map((s, i) => (
              <StepPill key={s.label} n={i + 1} done={s.done} label={s.label} onClick={s.go} />
            ))}
            <button
              type="button"
              onClick={dismiss}
              aria-label="Dismiss quick start"
              title="Dismiss"
              className="ml-auto rounded-full p-1 text-[#a6b5cf] hover:text-[#f3f6fd]"
            >
              <IconClose className="h-3 w-3" />
            </button>
          </div>
        ) : (
          <span className="flex-1" />
        )}
        {onRefresh && (
          <button
            type="button"
            onClick={onRefresh}
            aria-label="Refresh overview"
            title="Refresh overview"
            aria-busy={refreshing}
            className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee] hover:text-[#f3f6fd]"
          >
            <IconRefresh className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </button>
        )}
      </div>
    </div>
  );
}
