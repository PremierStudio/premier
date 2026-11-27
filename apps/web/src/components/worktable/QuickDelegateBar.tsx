import { useState, type ReactNode, type RefObject } from "react";
import {
  api,
  type AgentSessionRecord,
  type HealthResponse,
  type IdentityPreset,
  type WorktableAgentProfile,
  type WorktableBranch,
} from "../../api";
import { ErrorNote, useAction } from "../forms";
import {
  IconCheck,
  IconCage,
  IconClock,
  IconCopy,
  IconIntersection,
  IconLock,
  IconPlay,
  IconQuarantine,
  IconVault,
} from "../Icons";

interface Props {
  userPrincipal: string;
  identity: IdentityPreset;
  branches: WorktableBranch[];
  profiles: WorktableAgentProfile[];
  activeRef?: string;
  agentSandbox?: HealthResponse["agent_sandbox"];
  agentSandboxDetail?: string;
  healthError?: boolean;
  inputRef?: RefObject<HTMLInputElement | null>;
  onSessionLaunched: (rec: AgentSessionRecord) => void;
  onOpenPolicy: () => void;
  onRetryHealth?: () => void;
  onOpenSettings?: () => void;
  onOpenAgents?: (sessionId?: string) => void;
  onOpenAgentConnect?: () => void;
}

const ENVS = ["dev", "preview", "staging", "prod"] as const;
const TTLS = [
  { label: "5m", secs: 300 },
  { label: "30m", secs: 1800 },
  { label: "2h", secs: 7200 },
] as const;

const SERVE_FLAG = "premier serve --allow-unsandboxed-agents";

const SELECT_CLASS =
  "pr-well h-8 rounded-xl px-2.5 text-[13.5px] text-[#dce4f5] focus:border-[#9ec0f5]/45 focus:outline-none disabled:opacity-60 [&>option]:bg-[#0b0f1c] [&>option]:text-[#dce4f5]";

function Chip({
  tone,
  title,
  children,
}: {
  tone: "ice" | "coral" | "muted";
  title?: string;
  children: ReactNode;
}) {
  const toneClass = {
    ice: "border-[#9ec0f5]/20 bg-[#7f95f8]/10 text-[#b9cdf8]",
    coral: "border-[#f27c7c]/25 bg-[#f27c7c]/10 text-[#f4a0a0]",
    muted: "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf]",
  }[tone];
  return (
    <span
      title={title}
      className={`inline-flex max-w-full items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[12.5px] ${toneClass}`}
    >
      {children}
    </span>
  );
}

function ProfileChips({ profile }: { profile: WorktableAgentProfile }) {
  const hasAny =
    profile.allow_paths.length +
      profile.deny_paths.length +
      profile.allow_secret_use.length +
      profile.allow_egress_hosts.length >
    0;
  return (
    <div className="flex flex-wrap items-center gap-1.5" aria-label={`Boundaries of ${profile.name}`}>
      {profile.allow_paths.map((p) => (
        <Chip key={`a:${p}`} tone="ice" title="Allowed path">
          <span className="truncate">{p}</span>
        </Chip>
      ))}
      {profile.deny_paths.map((p) => (
        <Chip key={`d:${p}`} tone="coral" title="Denied path">
          <IconLock className="h-3 w-3" />
          <span className="truncate">{p}</span>
        </Chip>
      ))}
      {profile.allow_secret_use.map((s) => {
        const tone = s.approval === "jit" ? "ice" : "muted";
        return (
          <Chip
            key={`s:${s.name}`}
            tone={tone}
            title={`use ≠ read · ${s.approval}${s.hosts.length ? ` · ${s.hosts.join(", ")}` : ""}`}
          >
            <IconVault className="h-3 w-3" />
            <span>{s.name}</span>
            <span className="opacity-70">use ≠ read</span>
            {s.approval === "jit" && <IconClock className="h-3 w-3" />}
          </Chip>
        );
      })}
      {profile.allow_egress_hosts.map((h) => (
        <Chip key={`e:${h}`} tone="muted" title="Egress host">
          <span className="truncate">{h}</span>
        </Chip>
      ))}
      {!hasAny && <span className="text-[12.5px] text-[#a6b5cf]">No extra boundaries declared.</span>}
    </div>
  );
}

/** Top-of-worktable command bar for owners to delegate a caged task (members never see it). */
export function QuickDelegateBar({
  userPrincipal,
  identity,
  branches,
  profiles,
  activeRef,
  agentSandbox,
  agentSandboxDetail,
  healthError,
  inputRef,
  onSessionLaunched,
  onOpenPolicy,
  onRetryHealth,
  onOpenAgentConnect,
}: Props) {
  const [command, setCommand] = useState("");
  const [branchSel, setBranchSel] = useState<string | null>(null);
  const [profileSel, setProfileSel] = useState<string | null>(null);
  const [env, setEnv] = useState<(typeof ENVS)[number]>("dev");
  const [ttlSecs, setTtlSecs] = useState<number>(TTLS[0].secs);
  const { pending, error, run } = useAction();
  const [copied, setCopied] = useState(false);

  // Health has not answered yet: hold a quiet placeholder instead of flashing a live form that flips disabled.
  if (agentSandbox === undefined && healthError) {
    return (
      <div
        role="status"
        className="pr-well flex h-10 shrink-0 items-center gap-2.5 rounded-2xl px-3.5 py-2"
      >
        <IconLock className="h-4 w-4 shrink-0 text-[#a6b5cf]" />
        <span className="text-[14px] text-[#dce4f5]">Couldn't check host sandbox</span>
        {onRetryHealth && (
          <button
            type="button"
            onClick={onRetryHealth}
            className="pr-pill ml-auto rounded-full px-2.5 py-0.5 text-[13px] text-[#dce4f5]"
          >
            Retry
          </button>
        )}
      </div>
    );
  }

  if (agentSandbox === undefined) {
    return (
      <div
        role="status"
        aria-label="Checking agent sandbox"
        className="pr-well flex min-h-[44px] shrink-0 items-center gap-2.5 rounded-2xl px-3.5 py-2"
      >
        <div className="pr-shimmer h-4 w-4 shrink-0 rounded" />
        <div className="pr-shimmer h-3.5 w-64 max-w-[50%] rounded" />
        <div className="ml-auto flex items-center gap-1.5">
          <div className="pr-shimmer h-7 w-7 rounded-full" />
          <div className="pr-shimmer h-7 w-44 rounded-full" />
        </div>
      </div>
    );
  }

  if (agentSandbox === "none") {
    const copy = () => {
      navigator.clipboard?.writeText(SERVE_FLAG).catch(() => {});
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    };
    return (
      <div
        role="status"
        className="pr-well flex min-h-[44px] shrink-0 flex-wrap items-center gap-x-2.5 gap-y-1.5 rounded-2xl px-3.5 py-2"
      >
        <IconCage className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
        <span className="text-[14px] text-[#dce4f5]">MCP & CLI Secret Proxy ready on this host</span>
        <span
          className="rounded-full border border-white/[0.08] px-2 py-0.5 font-mono text-[12.5px] text-[#a6b5cf]"
          title={agentSandboxDetail}
        >
          in-browser Linux cage unavailable
        </span>
        <span className="ml-auto inline-flex items-center gap-1.5">
          <button
            type="button"
            onClick={copy}
            title="Enable unsandboxed local runs"
            aria-label={`Copy ${SERVE_FLAG}`}
            className="pr-pill inline-flex items-center rounded-full p-1.5 text-[#d2dbee] hover:text-[#f3f6fd]"
          >
            {copied ? (
              <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
            ) : (
              <IconCopy className="h-3.5 w-3.5" />
            )}
          </button>
          {onOpenAgentConnect && (
            <button
              type="button"
              onClick={onOpenAgentConnect}
              className="pr-action-btn inline-flex items-center rounded-full px-3 py-1 text-[13px]"
            >
              Connect AI Agent (MCP)
            </button>
          )}
        </span>
      </div>
    );
  }

  const effectivePrincipal = identity.principal === "anonymous" ? userPrincipal : identity.principal;
  const branch =
    branchSel !== null && branches.some((b) => b.name === branchSel)
      ? branchSel
      : activeRef && branches.some((b) => b.name === activeRef)
        ? activeRef
        : (branches[0]?.name ?? "");
  const profile =
    profileSel !== null && (profileSel === "" || profiles.some((p) => p.name === profileSel))
      ? profileSel
      : identity.agentProfile && profiles.some((p) => p.name === identity.agentProfile)
        ? identity.agentProfile
        : (profiles[0]?.name ?? "");
  const activeProfileObj = profiles.find((p) => p.name === profile);
  const selectedBranch = branches.find((b) => b.name === branch);
  const canSubmit = command.trim() !== "" && !pending;

  const submit = () => {
    if (!canSubmit) return;
    void run(async () => {
      const rec = await api.spawnSession({
        command: command.trim(),
        principal: effectivePrincipal,
        agent_profile: profile || undefined,
        env,
        max_secs: ttlSecs,
        branch: branch || undefined,
      });
      setCommand("");
      onSessionLaunched(rec);
    });
  };

  return (
    <form
      className="pr-surface shrink-0 space-y-2 rounded-2xl px-3.5 py-2.5"
      onSubmit={(e) => {
        e.preventDefault();
        submit();
      }}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span
          title={
            activeProfileObj
              ? "Effective authority: human ∩ agent task"
              : "Effective authority: human ∩ agent task · private workspace copy · human permissions · zero raw secrets in process.env"
          }
          className="pr-well inline-flex h-8 max-w-[220px] shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[12.5px] text-[#d2dbee]"
        >
          <IconIntersection className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
          <span className="truncate">
            {effectivePrincipal}
            {profile ? ` ∩ ${profile}` : ""}
          </span>
        </span>
        {agentSandbox === "unsandboxed-allowed" && (
          <span
            title={`No sandbox on this host: sessions run as a plain process of the server user.${
              agentSandboxDetail ? ` ${agentSandboxDetail}` : ""
            }`}
            className="inline-flex h-8 shrink-0 items-center gap-1 rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-2.5 font-mono text-[12.5px] text-[#a8c5ff]"
          >
            <IconQuarantine className="h-3 w-3" />
            unsandboxed
          </span>
        )}
        <div className="relative min-w-[220px] flex-1">
          <input
            ref={inputRef}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            aria-label="Delegate a task"
            placeholder="Delegate a task in a caged workspace… (e.g. git status -sb)"
            className="pr-well h-8 w-full rounded-xl pl-3 pr-9 font-mono text-[14px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none disabled:opacity-60"
          />
          <kbd className="pr-kbd pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 font-mono">
            D
          </kbd>
        </div>
        <select
          value={branch}
          onChange={(e) => setBranchSel(e.target.value)}
          aria-label="Branch to copy"
          className={`${SELECT_CLASS} max-w-[170px]`}
        >
          {branches.length === 0 && <option value="">default branch</option>}
          {branches.map((b) => (
            <option key={b.name} value={b.name}>
              {b.name}
            </option>
          ))}
        </select>
        <select
          value={profile}
          onChange={(e) => setProfileSel(e.target.value)}
          aria-label="Agent profile"
          className={`${SELECT_CLASS} max-w-[200px]`}
        >
          <option value="">No profile (human permissions)</option>
          {profiles.map((p) => (
            <option key={p.name} value={p.name}>
              {p.name}
            </option>
          ))}
        </select>
        <select
          value={env}
          onChange={(e) => setEnv(e.target.value as (typeof ENVS)[number])}
          aria-label="Environment"
          className={SELECT_CLASS}
        >
          {ENVS.map((e) => (
            <option key={e} value={e}>
              {e}
            </option>
          ))}
        </select>
        <select
          value={ttlSecs}
          onChange={(e) => setTtlSecs(Number(e.target.value))}
          aria-label="Time limit"
          className={SELECT_CLASS}
        >
          {TTLS.map((t) => (
            <option key={t.secs} value={t.secs}>
              {t.label}
            </option>
          ))}
        </select>
        <button
          type="submit"
          disabled={!canSubmit}
          className="pr-action-btn inline-flex h-8 items-center justify-center gap-1.5 rounded-xl px-4 text-[14px] disabled:cursor-not-allowed disabled:opacity-40"
        >
          <IconPlay className="h-3.5 w-3.5" />
          {pending ? "Launching…" : "Delegate"}
        </button>
      </div>

      {/* Boundary row only when it carries information; the generic copy lives in the authority chip tooltip. */}
      {activeProfileObj ? (
        <ProfileChips profile={activeProfileObj} />
      ) : (
        profiles.length === 0 && (
          <div className="flex flex-wrap items-center gap-2 text-[13px] text-[#a6b5cf]">
            <span>Private workspace copy · human permissions · zero raw secrets in process.env</span>
            <button
              type="button"
              onClick={onOpenPolicy}
              className="pr-pill rounded-full px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
            >
              Define [[agent_profiles]] in Policy →
            </button>
          </div>
        )
      )}

      {selectedBranch && selectedBranch.quarantine_paths.length > 0 && (
        <div
          role="status"
          className="flex items-start gap-2 rounded-xl border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-3 py-2 text-[13.5px] text-[#a8c5ff]"
        >
          <IconQuarantine className="mt-px h-4 w-4 shrink-0" />
          <span className="min-w-0 break-words">
            Selected branch modifies instruction files (
            <span className="font-mono">{selectedBranch.quarantine_paths.join(", ")}</span>) —
            review before delegating.
          </span>
        </div>
      )}
      <ErrorNote message={error} />
    </form>
  );
}
