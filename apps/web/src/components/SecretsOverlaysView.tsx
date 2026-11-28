import { useEffect, useMemo, useRef, useState } from "react";
import { SecretsListSkeleton, SettingsRowsSkeleton } from "./ViewSkeletons";
import {
  api,
  ApiError,
  errorText,
  shortOid,
  type Directory,
  type HygieneInsight,
  type IdentityPreset,
  type KmsStatus,
  type OverlayCheckResponse,
  type OverlayEntry,
  type OverlayManifest,
  type PolicyIntent,
  type SchemaDashboardResponse,
  type SecretStatusResponse,
  type VarSpec,
} from "../api";
import {
  IconAmbientPulse,
  IconBlock,
  IconCheck,
  IconClose,
  IconCopy,
  IconLens,
  IconLock,
  IconPlus,
  IconQuarantine,
  IconSearch,
  IconShield,
  IconTerminal,
  IconTrash,
  IconVault,
} from "./Icons";
import { AmbientWhisperChip } from "./HygieneDrawer";
import { ConfirmButton, OwnerOnly } from "./forms";
import { SecretLifecyclePanel } from "./SecretLifecyclePanel";
import { plural } from "../lib/format";
import { formatVaultHeader, formatVaultStoredNotice } from "../lib/uiHelpers";
import {
  PolicyContextMenu,
  PolicyIntentComposer,
  type ContextMenuTarget,
} from "./PolicyIntentComposer";

type EnvName = "dev" | "preview" | "staging" | "prod";
type SensitivityFilter = "all" | VarSpec["sensitivity"];

const ENVS: EnvName[] = ["dev", "preview", "staging", "prod"];
const SENS_FILTERS: SensitivityFilter[] = ["all", "restricted", "secret", "internal", "public"];

interface UseAccessBadge {
  canUse: boolean;
  label: string;
  tone: "mint" | "amber" | "coral" | "muted";
  reason: string;
}

/** Evaluates whether `identity` may `use` a variable using truthful server-computed `can_use`. */
/** Where overlay payloads live. Never the canonical working tree, never pushed. */
export const OVERLAY_STORAGE_COPY =
  "Overlay payloads are stored per user in the Premier state directory, never written into the canonical working tree or pushed.";

/** "Personal · @user" or "Team · name" from the server's ownership fields. */
export function overlayOwnerLabel(entry: OverlayEntry): string {
  if (entry.kind.kind === "team") {
    return `Team · ${entry.team_group || entry.kind.name}`;
  }
  const owner = entry.owner_principal?.replace(/^@/, "");
  return owner ? `Personal · @${owner}` : "Personal";
}

/** Real at-rest state of an overlay payload: AES-256-GCM, or plaintext in the state dir. */
export function overlayEncryptionLabel(entry: OverlayEntry): string {
  return entry.encrypted ? "AES-256-GCM" : "Plaintext (state dir)";
}

/** Whether a payload is stored; empty when the server did not say. */
export function overlayPayloadLabel(entry: OverlayEntry): string {
  if (entry.has_payload === undefined || entry.has_payload === null) return "";
  return entry.has_payload ? "payload stored" : "no payload yet";
}

function evaluateVarUseAccess(
  spec: VarSpec,
  identity: IdentityPreset,
  serverCanUse?: boolean,
): UseAccessBadge {
  if (serverCanUse !== undefined) {
    if (!serverCanUse) {
      return {
        canUse: false,
        label: "no use",
        tone: "coral",
        reason: `Server policy denies access for ${identity.label}`,
      };
    }
    if (spec.egress?.approval === "jit") {
      return {
        canUse: true,
        label: "use · JIT",
        tone: "amber",
        reason: "Allowed via egress proxy with JIT owner approval (use ≠ read)",
      };
    }
    if (spec.egress) {
      return {
        canUse: true,
        label: "can use",
        tone: "mint",
        reason: "Allowed via egress proxy (use ≠ read)",
      };
    }
    if (spec.sensitivity === "public") {
      return {
        canUse: true,
        label: "public",
        tone: "muted",
        reason: "Public configuration variable",
      };
    }
    return {
      canUse: true,
      label: "can use",
      tone: "mint",
      reason: `Authorized for ${identity.label} by server policy`,
    };
  }

  // Fallback for older servers that do not return `can_use`.
  const isAnon = identity.principal === "anonymous";
  const isOwnerGroup = identity.groups.includes("owners");
  const isAgent = Boolean(identity.agentProfile);

  if (isAnon) {
    if (spec.sensitivity === "public") {
      return {
        canUse: true,
        label: "public",
        tone: "muted",
        reason: "Public configuration variable",
      };
    }
    return {
      canUse: false,
      label: "no use",
      tone: "coral",
      reason: "Anonymous visitors cannot use non-public variables",
    };
  }

  if (spec.egress) {
    if (spec.egress.approval === "jit") {
      return {
        canUse: true,
        label: "use · JIT",
        tone: "amber",
        reason: "Brokered via egress proxy with JIT approval (use ≠ read)",
      };
    }
    return {
      canUse: true,
      label: "can use",
      tone: "mint",
      reason: "Brokered via egress proxy (use ≠ read)",
    };
  }

  if (spec.sensitivity === "secret" || spec.sensitivity === "restricted") {
    if (isAgent) {
      return {
        canUse: false,
        label: "no use",
        tone: "coral",
        reason: "Agents cannot receive raw secrets without an egress capability",
      };
    }
    if (spec.sensitivity === "restricted" && !isOwnerGroup) {
      return {
        canUse: false,
        label: "no use",
        tone: "coral",
        reason: "Restricted variable requires owner or explicit policy grant",
      };
    }
    return {
      canUse: true,
      label: "can use",
      tone: "mint",
      reason: "Authorized human principal",
    };
  }

  return {
    canUse: true,
    label: "can use",
    tone: "mint",
    reason: "Non-secret variable",
  };
}

const USE_BADGE_CLASS: Record<UseAccessBadge["tone"], string> = {
  mint: "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]",
  amber: "border border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#a8c5ff]",
  coral: "border border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f27c7c]",
  muted: "border border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]",
};

export interface SecretFocusTarget {
  env?: string;
  varName?: string;
  tab?: "contract" | "overlays";
}

interface Props {
  identity: IdentityPreset;
  /** False for members: owner-only actions are disabled rather than left to 403. */
  owner: boolean;
  directory?: Directory | null;
  agentProfiles?: string[];
  refName?: string;
  onOpenPolicyEditor?: (toml: string) => void;
  onPolicySaved?: () => void;
  /** Owner-only ambient hygiene insights for vault/egress/overlay nudges. */
  hygieneInsights?: HygieneInsight[];
  focusTarget?: SecretFocusTarget | null;
  onConsumeFocus?: () => void;
  onDismissInsight?: (id: string) => void | Promise<void>;
  onHygieneChanged?: () => void;
}

export function SecretsOverlaysView({
  identity,
  owner,
  directory = null,
  agentProfiles = [],
  refName,
  onOpenPolicyEditor,
  onPolicySaved,
  hygieneInsights,
  focusTarget,
  onConsumeFocus,
  onDismissInsight,
  onHygieneChanged,
}: Props) {
  const [dashboard, setDashboard] = useState<SchemaDashboardResponse | null>(null);
  const [secretStatus, setSecretStatus] = useState<SecretStatusResponse | null>(null);
  const [kmsStatus, setKmsStatus] = useState<KmsStatus | null>(null);
  // A failed status check must not leave Store / Update value disabled forever.
  const [secretStatusError, setSecretStatusError] = useState<string | null>(null);
  const [overlays, setOverlays] = useState<OverlayManifest | null>(null);
  const [activeEnv, setActiveEnv] = useState<EnvName>("dev");
  const [search, setSearch] = useState("");
  const [sensFilter, setSensFilter] = useState<SensitivityFilter>("all");
  const [filterOpen, setFilterOpen] = useState(false);
  const filterRef = useRef<HTMLDivElement>(null);
  const [selectedVarName, setSelectedVarName] = useState<string | null>(null);
  const [asideTab, setAsideTab] = useState<"contract" | "overlays" | "lifecycle">("contract");
  const [busyInsightId, setBusyInsightId] = useState<string | null>(null);
  const [secretInput, setSecretInput] = useState("");
  const [secretBusy, setSecretBusy] = useState(false);
  const [secretNotice, setSecretNotice] = useState<string | null>(null);
  const [mountPath, setMountPath] = useState("");
  const [mountScope, setMountScope] = useState("personal");
  const [mountEncrypted, setMountEncrypted] = useState(true);
  const [mountCreateFile, setMountCreateFile] = useState(false);
  const [mountInitialContent, setMountInitialContent] = useState("");
  const [showInitialContent, setShowInitialContent] = useState(false);
  const [testPaths, setTestPaths] = useState("");
  // Team overlay scopes offered in the mount form: the directory's groups.
  const [groups, setGroups] = useState<string[]>([]);
  const [checkResult, setCheckResult] = useState<OverlayCheckResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [policyMenu, setPolicyMenu] = useState<{
    target: ContextMenuTarget;
    x: number;
    y: number;
  } | null>(null);
  const [composerIntent, setComposerIntent] = useState<PolicyIntent | null>(null);
  const [policyAppliedNotice, setPolicyAppliedNotice] = useState<string | null>(null);

  const openSecretMenuAt = (varName: string, zone: string | undefined, x: number, y: number) => {
    if (!owner) return;
    setPolicyMenu({
      target: { kind: "secret", varName, zone },
      x,
      y,
    });
  };

  // The repository has no .env.schema (a 200 with no schema, or a 404 from older servers):
  // an empty state, not an error.
  const [noSchema, setNoSchema] = useState(false);

  const refreshVaultAndOverlays = () => {
    // Vault status and overlays are owner-only; a member would just get a 403.
    if (!owner) return;
    api
      .secretsStatus()
      .then((res) => {
        setSecretStatus(res);
        setSecretStatusError(null);
      })
      .catch((err: unknown) => setSecretStatusError(errorText(err)));
    api
      .kmsStatus()
      .then(setKmsStatus)
      .catch(() => {});
    // Overlays are only fetched once the Overlays tab has been opened; then kept fresh.
    if (overlays) {
      api
        .overlays(identity.principal)
        .then(setOverlays)
        .catch(() => {});
    }
  };

  useEffect(() => {
    let active = true;
    api
      .envDashboard(identity)
      .then((d) => {
        if (!active) return;
        if (!d?.schema) {
          setNoSchema(true);
          return;
        }
        setNoSchema(false);
        setDashboard(d);
        const entries = Object.entries(d.schema.vars);
        const preferred =
          entries.find(([, v]) => Boolean(v.egress))?.[0] ?? entries[0]?.[0];
        if (preferred) setSelectedVarName((cur) => cur ?? preferred);
      })
      .catch((err: unknown) => {
        if (!active) return;
        if (err instanceof ApiError && err.status === 404) setNoSchema(true);
        else setError(errorText(err));
      });
    return () => {
      active = false;
    };
  }, [identity]);

  useEffect(() => {
    // Vault status feeds the table badges; overlays/groups wait for the Overlays tab.
    refreshVaultAndOverlays();
  }, [owner]);

  useEffect(() => {
    if (!owner || asideTab !== "overlays") return;
    let active = true;
    api
      .overlays(identity.principal)
      .then((res) => {
        if (active) setOverlays(res);
      })
      .catch((err: unknown) => {
        if (active) setError(errorText(err));
      });
    api
      .directory()
      .then((d) => {
        if (active) setGroups(d.groups);
      })
      .catch(() => {});
    return () => {
      active = false;
    };
  }, [owner, asideTab, identity.principal]);

  // Compact (<xl) sensitivity filter popover: outside-click + Esc dismissal.
  useEffect(() => {
    if (!filterOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!filterRef.current?.contains(e.target as Node)) setFilterOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFilterOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [filterOpen]);

  const activeReport = dashboard?.reports[activeEnv];

  useEffect(() => {
    if (!focusTarget) return;
    if (focusTarget.env && (ENVS as string[]).includes(focusTarget.env)) {
      setActiveEnv(focusTarget.env as EnvName);
    }
    if (focusTarget.varName) {
      setSelectedVarName(focusTarget.varName);
    }
    setAsideTab(focusTarget.tab ?? "contract");
    onConsumeFocus?.();
  }, [focusTarget, onConsumeFocus]);

  const activeHygieneInsights = useMemo(
    () => (owner ? (hygieneInsights ?? []).filter((i) => !i.dismissed) : []),
    [owner, hygieneInsights],
  );
  const missingSecretInsights = useMemo(
    () => activeHygieneInsights.filter((i) => i.category === "missing_vault_secret"),
    [activeHygieneInsights],
  );
  const broadEgressInsights = useMemo(
    () => activeHygieneInsights.filter((i) => i.category === "broad_egress_host"),
    [activeHygieneInsights],
  );
  const overlayLeakInsights = useMemo(
    () => activeHygieneInsights.filter((i) => i.category === "overlay_leak"),
    [activeHygieneInsights],
  );
  const missingVarsForActiveEnv = useMemo(() => {
    const set = new Set<string>();
    for (const ins of missingSecretInsights) {
      if (ins.action?.kind === "configure_secret") {
        if (!ins.action.env || ins.action.env === activeEnv) set.add(ins.action.var_name);
      } else if (ins.target.startsWith(`${activeEnv}:`)) {
        set.add(ins.target.slice(activeEnv.length + 1));
      } else {
        set.add(ins.target);
      }
    }
    return set;
  }, [missingSecretInsights, activeEnv]);
  const issueVars = useMemo(
    () => new Set(activeReport?.issues.map((i) => i.var_name) ?? []),
    [activeReport],
  );

  const filteredVars = useMemo(() => {
    if (!dashboard?.schema) return [];
    const q = search.trim().toLowerCase();
    return Object.entries(dashboard.schema.vars).filter(([name, spec]) => {
      if (sensFilter !== "all" && spec.sensitivity !== sensFilter) return false;
      if (!q) return true;
      return (
        name.toLowerCase().includes(q) ||
        spec.type.toLowerCase().includes(q) ||
        (spec.zone?.toLowerCase().includes(q) ?? false) ||
        (spec.egress?.hosts.some((h) => h.toLowerCase().includes(q)) ?? false) ||
        (spec.mcp_servers?.some((s) => s.toLowerCase().includes(q)) ?? false)
      );
    });
  }, [dashboard, search, sensFilter]);

  const selectedEntry = useMemo(() => {
    if (!dashboard?.schema) return null;
    if (selectedVarName && dashboard.schema.vars[selectedVarName]) {
      return [selectedVarName, dashboard.schema.vars[selectedVarName]] as const;
    }
    return filteredVars[0] ?? null;
  }, [dashboard, selectedVarName, filteredVars]);

  const runGuardCheck = async () => {
    const paths = testPaths
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    try {
      const res = await api.checkOverlays(paths);
      setCheckResult(res);
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const handleSetSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedEntry || !secretInput) return;
    const key = selectedEntry[0];
    setSecretBusy(true);
    setError(null);
    setSecretNotice(null);
    try {
      const meta = await api.setSecret(key, secretInput, activeEnv, identity.principal);
      setSecretInput("");
      // Stays visible until the next input change (see the value field's onChange).
      setSecretNotice(formatVaultStoredNotice(kmsStatus, meta.rotated_count));
      refreshVaultAndOverlays();
      onHygieneChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSecretBusy(false);
    }
  };

  const handleRevokeSecret = async (key: string) => {
    setSecretBusy(true);
    setError(null);
    setSecretNotice(null);
    try {
      await api.deleteSecret(key, activeEnv, identity.principal);
      setSecretNotice(`Revoked ${key} from vault`);
      refreshVaultAndOverlays();
      onHygieneChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSecretBusy(false);
    }
  };

  const canSupplyInitialContent =
    !mountPath.match(/[*?[\]{}]/) && (mountCreateFile || mountEncrypted);

  const handleMountOverlay = async (e: React.FormEvent) => {
    e.preventDefault();
    const p = mountPath.trim();
    if (!p) return;
    setError(null);
    try {
      const updated = await api.mountOverlay({
        path: p,
        scope: mountScope,
        encrypted: mountEncrypted,
        create_file: mountCreateFile,
        initial_content:
          canSupplyInitialContent && mountInitialContent ? mountInitialContent : undefined,
        principal: identity.principal,
      });
      setOverlays(updated);
      setMountPath("");
      setMountInitialContent("");
      setShowInitialContent(false);
      setCheckResult(null);
      onHygieneChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const handleUnmountOverlay = async (path: string) => {
    setError(null);
    try {
      const updated = await api.unmountOverlay(path, identity.principal);
      setOverlays(updated);
      setCheckResult(null);
      onHygieneChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    }
  };

  const handleQuickOverlayGuard = async (insight: HygieneInsight) => {
    if (!owner || insight.action?.kind !== "add_overlay_guard") return;
    setBusyInsightId(insight.id);
    setError(null);
    try {
      const updated = await api.mountOverlay({
        path: insight.action.path,
        scope: insight.action.suggested_scope || "personal",
        encrypted: true,
        create_file: false,
        principal: identity.principal,
      });
      setOverlays(updated);
      setCheckResult(null);
      onHygieneChanged?.();
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setBusyInsightId((cur) => (cur === insight.id ? null : cur));
    }
  };

  const copyStr = (key: string, val: string) => {
    navigator.clipboard?.writeText(val).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const premierRunCmd = `premier run --env ${activeEnv} -- npm run dev`;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-2.5 sm:p-3 lg:flex-row lg:overflow-hidden xl:p-4">
      {/* Left: Interactive .env.schema Capabilities & Env Validator */}
      <section className="pr-surface flex min-h-[280px] min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:min-h-0">
        {/* One condensed toolbar: title · env pills · search · sensitivity filter · viewing-as */}
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5 border-b border-white/[0.06] px-3 py-2 lg:flex-nowrap">
          <span className="inline-flex shrink-0 items-center gap-1.5 font-mono text-[13.5px] text-[#f3f6fd]">
            <IconVault className="h-4 w-4 text-[#9ec0f5]" />
            <span>.env.schema</span>
          </span>

          {dashboard && (
            <div className="flex shrink-0 flex-nowrap items-center gap-1 font-mono text-[12.5px]">
              {ENVS.map((env) => {
                const issues = dashboard.reports[env]?.issues.length ?? 0;
                const active = activeEnv === env;
                return (
                  <button
                    key={env}
                    type="button"
                    onClick={() => setActiveEnv(env)}
                    className={`rounded-full px-2 py-0.5 transition ${
                      active
                        ? "pr-pill-active"
                        : issues === 0
                          ? "bg-[#5bdba2]/10 text-[#5bdba2] hover:bg-[#5bdba2]/18"
                          : "bg-[#7f95f8]/10 text-[#a8c5ff] hover:bg-[#7f95f8]/18"
                    }`}
                  >
                    {env} {issues > 0 ? `(${issues})` : "✓"}
                  </button>
                );
              })}
            </div>
          )}

          <div className="flex min-w-[120px] flex-1 items-center gap-1.5 rounded-full border border-white/[0.07] bg-black/25 px-2.5 py-1">
            <IconSearch className="h-3.5 w-3.5 shrink-0 text-[#a6b5cf]" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Filter variables"
              placeholder="Filter keys, hosts, zones…"
              className="min-w-0 flex-1 bg-transparent text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
          </div>

          <div className="hidden shrink-0 items-center gap-0.5 font-mono text-[12.5px] xl:flex">
            {SENS_FILTERS.map((sf) => (
              <button
                key={sf}
                type="button"
                onClick={() => setSensFilter(sf)}
                className={`rounded-full px-2 py-0.5 capitalize transition ${
                  sensFilter === sf
                    ? "pr-pill-active"
                    : "text-[#a6b5cf] hover:bg-white/[0.04] hover:text-[#f3f6fd]"
                }`}
              >
                {sf}
              </button>
            ))}
          </div>

          <div ref={filterRef} className="relative shrink-0 xl:hidden">
            <button
              type="button"
              aria-haspopup="true"
              aria-expanded={filterOpen}
              onClick={() => setFilterOpen((o) => !o)}
              title="Filter by sensitivity"
              className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                sensFilter === "all" ? "pr-pill text-[#d2dbee]" : "pr-pill-active"
              }`}
            >
              <span>Filter</span>
              {sensFilter !== "all" && <span className="capitalize">· {sensFilter}</span>}
            </button>
            {filterOpen && (
              <div
                role="menu"
                className="absolute right-0 top-full z-20 mt-1.5 flex min-w-[130px] flex-col gap-0.5 rounded-xl border border-white/[0.1] bg-[#0b0f1c] p-1 font-mono text-[12.5px] shadow-xl"
              >
                {SENS_FILTERS.map((sf) => (
                  <button
                    key={sf}
                    type="button"
                    role="menuitemradio"
                    aria-checked={sensFilter === sf}
                    onClick={() => {
                      setSensFilter(sf);
                      setFilterOpen(false);
                    }}
                    className={`rounded-lg px-2.5 py-1 text-left capitalize transition ${
                      sensFilter === sf
                        ? "bg-[#7f95f8]/20 text-[#f3f6fd]"
                        : "text-[#d2dbee] hover:bg-white/[0.06] hover:text-[#f3f6fd]"
                    }`}
                  >
                    {sf}
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Signals strip: validation issues + ambient hygiene whispers share one wrapped row */}
        {((activeReport && activeReport.issues.length > 0) ||
          (owner && (missingSecretInsights.length > 0 || broadEgressInsights.length > 0))) && (
          <div className="flex flex-wrap items-center gap-1.5 border-b border-white/[0.06] bg-[#7f95f8]/[0.04] px-3 py-1.5 font-mono text-[12.5px]">
            {activeReport && activeReport.issues.length > 0 && (
              <>
                <span className="inline-flex items-center gap-1 text-[#a8c5ff]">
                  <IconQuarantine className="h-3.5 w-3.5" />
                  <span>
                    {activeEnv}: {plural(activeReport.issues.length, "issue")}
                  </span>
                </span>
                {activeReport.issues.map((iss, i) => (
                  <button
                    key={`${iss.var_name}-${i}`}
                    type="button"
                    title={iss.message}
                    onClick={() => {
                      setSelectedVarName(iss.var_name);
                      setAsideTab("contract");
                    }}
                    className="max-w-[320px] truncate rounded-full border border-[#9ec0f5]/25 bg-[#0b0f1c] px-2.5 py-0.5 text-left text-[#cfe0ff] hover:border-[#9ec0f5]/50"
                  >
                    <strong className="text-[#a8c5ff]">{iss.var_name}</strong>: {iss.message}
                  </button>
                ))}
              </>
            )}
            {owner &&
              missingSecretInsights.map((ins) => {
                const cfg = ins.action?.kind === "configure_secret" ? ins.action : null;
                return (
                  <span
                    key={ins.id}
                    title={ins.detail}
                    className="inline-flex items-center gap-1.5 rounded-full border border-[#9ec0f5]/28 bg-[#0b0f1c] py-0.5 pr-1.5 pl-2.5 text-[#cfe0ff]"
                  >
                    <button
                      type="button"
                      onClick={() => {
                        if (cfg?.env && (ENVS as string[]).includes(cfg.env)) {
                          setActiveEnv(cfg.env as EnvName);
                        }
                        if (cfg?.var_name) setSelectedVarName(cfg.var_name);
                        setAsideTab("contract");
                      }}
                      className="inline-flex items-center gap-1.5 text-left hover:underline"
                    >
                      <IconAmbientPulse className="h-3.5 w-3.5 text-[#9ec0f5]" />
                      <span>{ins.title}</span>
                    </button>
                    {onDismissInsight && (
                      <button
                        type="button"
                        onClick={() => void onDismissInsight(ins.id)}
                        aria-label={`Dismiss ${ins.title}`}
                        className="rounded-full p-0.5 opacity-70 hover:bg-white/[0.08] hover:opacity-100"
                      >
                        <IconClose className="h-3 w-3" />
                      </button>
                    )}
                  </span>
                );
              })}
            {owner &&
              broadEgressInsights.map((ins) => (
                <span
                  key={ins.id}
                  title={ins.detail}
                  className="inline-flex items-center gap-1.5 rounded-full border border-[#9ec0f5]/28 bg-[#0b0f1c] py-0.5 pr-1.5 pl-2.5 text-[#cfe0ff]"
                >
                  <IconAmbientPulse className="h-3.5 w-3.5 text-[#9ec0f5]" />
                  <span>{ins.title}</span>
                  {onDismissInsight && (
                    <button
                      type="button"
                      onClick={() => void onDismissInsight(ins.id)}
                      aria-label={`Dismiss ${ins.title}`}
                      className="rounded-full p-0.5 opacity-70 hover:bg-white/[0.08] hover:opacity-100"
                    >
                      <IconClose className="h-3 w-3" />
                    </button>
                  )}
                </span>
              ))}
          </div>
        )}

        {error && (
          <div role="alert" className="border-b border-[#f27c7c]/25 bg-[#f27c7c]/10 px-3 py-1.5 font-mono text-[13px] text-[#f27c7c]">
            {error}
          </div>
        )}

        {policyAppliedNotice && (
          <div
            role="status"
            className="flex items-center gap-2 border-b border-[#5bdba2]/25 bg-[#5bdba2]/10 px-3 py-1.5 font-mono text-[13px] text-[#5bdba2]"
          >
            <IconCheck className="h-4 w-4 shrink-0" />
            <span>{policyAppliedNotice}</span>
          </div>
        )}

        <div className="min-h-0 flex-1 divide-y divide-white/[0.05] overflow-y-auto">
          {!dashboard && !error && <SecretsListSkeleton />}
          {noSchema && (
            <div className="flex h-full min-h-[200px] flex-col items-center justify-center gap-1.5 p-6 text-center">
              <div className="text-[14.5px] font-medium text-[#dce4f5]">
                No .env.schema in this repository
              </div>
              <div className="max-w-sm text-[13.5px] leading-relaxed text-[#a6b5cf]">
                Declare API keys here — encrypted in Premier, masked for AI agents.
              </div>
            </div>
          )}
          {filteredVars.map(([name, spec]) => {
            const active = selectedEntry?.[0] === name;
            const hasIssue = issueVars.has(name);
            const vaultMeta =
              secretStatus?.entries[`${activeEnv}:${name}`] ?? secretStatus?.entries[name];
            const useBadge = evaluateVarUseAccess(spec, identity, dashboard?.can_use?.[name]);
            return (
              <div
                key={name}
                onContextMenu={
                  owner
                    ? (e) => {
                        e.preventDefault();
                        openSecretMenuAt(name, spec.zone, e.clientX, e.clientY);
                      }
                    : undefined
                }
                className={`group flex items-center gap-2 px-3 transition ${
                  active ? "bg-[#7f95f8]/12" : "hover:bg-white/[0.03]"
                } ${!useBadge.canUse && identity.id !== "self" ? "opacity-65" : ""}`}
              >
                <button
                  type="button"
                  onClick={() => {
                    setSelectedVarName(name);
                    setSecretInput("");
                    setSecretNotice(null);
                    setAsideTab("contract");
                  }}
                  className="min-w-0 flex-1 py-2 text-left"
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex min-w-0 flex-wrap items-center gap-2">
                      {hasIssue && <span className="h-2 w-2 shrink-0 rounded-full bg-[#7f95f8]" />}
                      <span className="truncate font-mono text-[14px] font-medium text-[#f3f6fd]">
                        {name}
                      </span>
                      <span
                        className={`rounded-full border px-2 py-0.5 font-mono text-[12px] ${
                          spec.sensitivity === "restricted" || spec.sensitivity === "secret"
                            ? "border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]"
                            : "border-white/[0.08] bg-white/[0.04] text-[#9eb0cc]"
                        }`}
                      >
                        {spec.sensitivity}
                      </span>
                      <span
                        title={useBadge.reason}
                        className={`rounded-full px-2 py-0.5 font-mono text-[12px] leading-[1.15rem] ${USE_BADGE_CLASS[useBadge.tone]}`}
                      >
                        {useBadge.label}
                      </span>
                      {vaultMeta ? (
                        <span className="rounded-full bg-[#5bdba2]/14 px-2 py-0.5 font-mono text-[12px] text-[#5bdba2]">
                          vault · r{vaultMeta.rotated_count}
                        </span>
                      ) : (
                        owner &&
                        missingVarsForActiveEnv.has(name) && (
                          <span className="rounded-full border border-[#9ec0f5]/28 bg-[#7f95f8]/8 px-2 py-0.5 font-mono text-[12px] text-[#cfe0ff]">
                            vault unset
                          </span>
                        )
                      )}
                      {spec.zone && (
                        <span className="font-mono text-[12.5px] text-[#a6b5cf]">@{spec.zone}</span>
                      )}
                      {spec.mcp_servers &&
                        spec.mcp_servers.map((srv) => (
                          <span
                            key={srv}
                            className="rounded-full bg-[#7f95f8]/15 px-2 py-0.5 font-mono text-[12px] text-[#9ec0f5]"
                          >
                            mcp: {srv}
                          </span>
                        ))}
                    </div>
                    <span className="shrink-0 font-mono text-[12.5px] text-[#a6b5cf]">{spec.type}</span>
                  </div>
                  {spec.egress && (
                    <div className="mt-1 truncate font-mono text-[12.5px] text-[#a6b5cf]">
                      {spec.egress.hosts.join(", ")} · {spec.egress.methods.join("/")} ·{" "}
                      <span className="text-[#9ec0f5]">{spec.egress.approval}</span>
                    </div>
                  )}
                </button>
                {owner && (
                  <button
                    type="button"
                    onClick={(e) => {
                      const rect = e.currentTarget.getBoundingClientRect();
                      openSecretMenuAt(name, spec.zone, rect.left, rect.bottom + 6);
                    }}
                    title={`Author USE policy for ${name} (use ≠ read)`}
                    aria-label={`Author USE policy for ${name}`}
                    className="pr-pill inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg text-[#a6b5cf] opacity-60 transition hover:text-[#9ec0f5] hover:opacity-100 group-hover:opacity-100 focus:opacity-100"
                  >
                    <IconShield className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Right: Contract Inspector & Typed Overlays + Push Guard */}
      <aside className="pr-surface flex shrink-0 flex-col overflow-hidden rounded-2xl lg:w-[376px] xl:w-[424px] 2xl:w-[480px]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-1.5">
          <div className="inline-flex flex-wrap rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]">
            <button
              type="button"
              onClick={() => setAsideTab("contract")}
              className={`rounded-full px-2.5 py-1 transition ${
                asideTab === "contract" ? "pr-pill-active" : "text-[#a6b5cf]"
              }`}
            >
              Secret Details
            </button>
            <button
              type="button"
              onClick={() => setAsideTab("overlays")}
              className={`rounded-full px-2.5 py-1 transition ${
                asideTab === "overlays" ? "pr-pill-active" : "text-[#a6b5cf]"
              }`}
            >
              Local-Only Files{overlays ? ` (${overlays.entries.length})` : ""}
            </button>
            <button
              type="button"
              onClick={() => setAsideTab("lifecycle")}
              className={`rounded-full px-2.5 py-1 transition ${
                asideTab === "lifecycle" ? "pr-pill-active" : "text-[#a6b5cf]"
              }`}
            >
              Rotation &amp; OIDC
            </button>
          </div>
          {owner && identity.id !== "self" && (
            <span
              role="status"
              title={`Viewing as ${identity.label} — ${
                identity.agentProfile
                  ? "Delegated agent · use ≠ read enforced"
                  : identity.principal === "anonymous"
                    ? "Public projection"
                    : identity.groups.length > 0
                      ? identity.groups.join(", ")
                      : "no groups"
              }`}
              className="inline-flex min-w-0 max-w-[104px] xl:max-w-[144px] items-center gap-1.5 rounded-full border border-[#9ec0f5]/22 bg-[#7f95f8]/10 px-2.5 py-0.5 font-mono text-[12.5px] text-[#cfe0ff]"
            >
              <IconLens className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
              <span className="min-w-0 truncate">
                as <strong className="text-[#f3f6fd]">{identity.label}</strong>
              </span>
            </span>
          )}
        </div>

        {asideTab === "lifecycle" ? (
          <SecretLifecyclePanel
            owner={owner}
            identity={identity}
            activeEnv={activeEnv}
            selectedVar={
              selectedEntry ? { name: selectedEntry[0], spec: selectedEntry[1] } : null
            }
            varNames={dashboard?.schema ? Object.keys(dashboard.schema.vars) : []}
            onVaultChanged={refreshVaultAndOverlays}
          />
        ) : asideTab === "contract" ? (
          selectedEntry ? (
          <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-3 font-mono text-[13px]">
            {(() => {
              const [selName, selSpec] = selectedEntry;
              const badge = evaluateVarUseAccess(selSpec, identity, dashboard?.can_use?.[selName]);
              return (
                <div>
                  <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                    <div className="flex min-w-0 items-center gap-2">
                      <span className="truncate text-[14px] font-semibold text-[#f3f6fd]">{selName}</span>
                      <span
                        title={badge.reason}
                        className={`shrink-0 rounded-full px-2 py-0.5 text-[12px] ${USE_BADGE_CLASS[badge.tone]}`}
                      >
                        {identity.label}: {badge.label}
                      </span>
                    </div>
                    {owner && (
                      <button
                        type="button"
                        onClick={(e) => {
                          const rect = e.currentTarget.getBoundingClientRect();
                          openSecretMenuAt(selName, selSpec.zone, rect.left, rect.bottom + 6);
                        }}
                        title="Allow or revoke agent USE capability (use ≠ read)"
                        className="pr-pill inline-flex shrink-0 items-center gap-1 rounded-full px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                      >
                        <IconShield className="h-3.5 w-3.5" />
                        <span>Author USE</span>
                      </button>
                    )}
                  </div>
                  <div className="mt-1 font-sans text-[13px] leading-snug text-[#a6b5cf]">
                    {selSpec.description && (
                      <span className="text-[13.5px] text-[#b6c3db]">{selSpec.description} · </span>
                    )}
                    {badge.reason}
                  </div>
                </div>
              );
            })()}

            <div className="pr-well space-y-2 rounded-xl p-3">
              <div className="flex justify-between">
                <span className="text-[#a6b5cf]">type</span>
                <span className="text-[#dce4f5]">{selectedEntry[1].type}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#a6b5cf]">sensitivity</span>
                <span
                  className={
                    selectedEntry[1].sensitivity === "restricted" ||
                    selectedEntry[1].sensitivity === "secret"
                      ? "text-[#cbd5e8]"
                      : "text-[#dce4f5]"
                  }
                >
                  {selectedEntry[1].sensitivity}
                </span>
              </div>
              {selectedEntry[1].zone && (
                <div className="flex justify-between">
                  <span className="text-[#a6b5cf]">zone</span>
                  <span className="text-[#9ec0f5]">@{selectedEntry[1].zone}</span>
                </div>
              )}
              {selectedEntry[1].default !== undefined && (
                <div className="flex justify-between">
                  <span className="text-[#a6b5cf]">default</span>
                  <span className="text-[#dce4f5]">{selectedEntry[1].default}</span>
                </div>
              )}
              {selectedEntry[1].required_in.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <span className="text-[#a6b5cf]">required_in</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedEntry[1].required_in.map((e) => (
                      <span
                        key={e}
                        className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12px] text-[#dce4f5]"
                      >
                        {e}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {selectedEntry[1].allowed_values.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <span className="text-[#a6b5cf]">allowed</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedEntry[1].allowed_values.map((v) => (
                      <span
                        key={v}
                        className="rounded-full bg-[#7f95f8]/15 px-2 py-0.5 text-[12px] text-[#9ec0f5]"
                      >
                        {v}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              {selectedEntry[1].mcp_servers && selectedEntry[1].mcp_servers.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                  <span className="text-[#a6b5cf]">mcp_servers</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedEntry[1].mcp_servers.map((srv) => (
                      <span
                        key={srv}
                        className="rounded-full bg-[#7f95f8]/15 px-2 py-0.5 text-[12px] text-[#9ec0f5]"
                      >
                        mcp: {srv}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {selectedEntry[1].egress && (
              <div className="pr-well space-y-2 rounded-xl p-3">
                <div className="text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                  Egress Capability (use ≠ read)
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">hosts</span>
                  <span className="truncate text-[#5bdba2]">
                    {selectedEntry[1].egress.hosts.join(", ")}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">methods</span>
                  <span className="text-[#dce4f5]">
                    {selectedEntry[1].egress.methods.join(", ")}
                  </span>
                </div>
                {selectedEntry[1].egress.path_prefixes.length > 0 && (
                  <div className="flex justify-between gap-2">
                    <span className="text-[#a6b5cf]">prefixes</span>
                    <span className="truncate text-[#dce4f5]">
                      {selectedEntry[1].egress.path_prefixes.join(", ")}
                    </span>
                  </div>
                )}
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">approval</span>
                  <span className="text-[#cbd5e8]">
                    {selectedEntry[1].egress.approval} · {selectedEntry[1].egress.jit_ttl_secs}s
                  </span>
                </div>
                {selectedEntry[1].egress.rate_limit_per_min !== undefined && (
                  <div className="flex justify-between gap-2">
                    <span className="text-[#a6b5cf]">rate limit</span>
                    <span className="text-[#dce4f5]">
                      {selectedEntry[1].egress.rate_limit_per_min}/min
                    </span>
                  </div>
                )}
              </div>
            )}

            {selectedEntry[1].rotation && (
              <div className="pr-well space-y-2 rounded-xl p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                    Rotation Policy
                  </span>
                  <button
                    type="button"
                    onClick={() => setAsideTab("lifecycle")}
                    className="pr-pill rounded-full px-2 py-0.5 text-[12px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                  >
                    Rotate in Key Rotation →
                  </button>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">provider</span>
                  <span className="text-[#dce4f5]">
                    {selectedEntry[1].rotation.provider || "webhook"}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">webhook</span>
                  <span
                    className="truncate text-[#9ec0f5]"
                    title={selectedEntry[1].rotation.webhook_url}
                  >
                    {selectedEntry[1].rotation.webhook_url}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">offboard</span>
                  <span
                    className={
                      selectedEntry[1].rotation.revoke_on_offboard
                        ? "text-[#f27c7c]"
                        : "text-[#a6b5cf]"
                    }
                  >
                    {selectedEntry[1].rotation.revoke_on_offboard
                      ? "auto-rotate on offboard"
                      : "manual"}
                  </span>
                </div>
              </div>
            )}

            {/* Real Encrypted Age AEAD Vault CRUD (write-only, never echoes plaintext) */}
            {(() => {
              if (!owner) return <OwnerOnly className="pr-well rounded-xl" />;
              const vaultEntry =
                secretStatus?.entries[`${activeEnv}:${selectedEntry[0]}`] ??
                secretStatus?.entries[selectedEntry[0]];
              return (
                <form
                  onSubmit={(e) => void handleSetSecret(e)}
                  className="pr-well space-y-2.5 rounded-xl p-3"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                      {formatVaultHeader(kmsStatus, activeEnv)}
                    </span>
                    {vaultEntry ? (
                      <span className="rounded-full bg-[#5bdba2]/14 px-2 py-0.5 text-[12px] text-[#5bdba2]">
                        r{vaultEntry.rotated_count} · encrypted
                      </span>
                    ) : (
                      <span className="text-[12.5px] text-[#a6b5cf]">unset</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      type="password"
                      autoComplete="new-password"
                      value={secretInput}
                      onChange={(e) => {
                        setSecretInput(e.target.value);
                        setSecretNotice(null);
                      }}
                      aria-label={`Value for ${selectedEntry[0]}`}
                      disabled={!owner}
                      title={owner ? undefined : "Owner only"}
                      placeholder={
                        !owner
                          ? "Owner only"
                          : vaultEntry
                            ? "Enter new value…"
                            : "Enter secret value…"
                      }
                      className="min-w-0 flex-1 rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                    />
                    <button
                      type="submit"
                      disabled={
                        !owner || secretBusy || !secretInput || (!secretStatus && !secretStatusError)
                      }
                      title={
                        !owner
                          ? "Owner only"
                          : !secretStatus
                            ? secretStatusError
                              ? "Vault status unavailable; the value will still be stored"
                              : "Loading vault status…"
                            : undefined
                      }
                      className="pr-action-btn shrink-0 rounded-lg px-3 py-1.5 text-[12.5px] disabled:opacity-40"
                    >
                      {vaultEntry ? "Update value" : "Store"}
                    </button>
                    {vaultEntry && (
                      <ConfirmButton
                        disabled={!owner || secretBusy}
                        confirmLabel="Revoke"
                        question="Revoke secret?"
                        onConfirm={() => void handleRevokeSecret(selectedEntry[0])}
                        title={owner ? "Revoke secret from local vault" : "Owner only"}
                        aria-label="Revoke secret"
                        className="pr-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[#f27c7c] disabled:opacity-40"
                      >
                        <IconTrash className="h-4 w-4" />
                      </ConfirmButton>
                    )}
                  </div>
                  {!secretStatus && secretStatusError && (
                    <p className="font-sans text-[12.5px] leading-snug text-[#a6b5cf]">
                      Vault status unavailable.{" "}
                      <button
                        type="button"
                        onClick={refreshVaultAndOverlays}
                        className="text-[#9ec0f5] underline-offset-2 hover:underline"
                      >
                        Retry
                      </button>
                    </p>
                  )}
                  <p className="font-sans text-[12.5px] leading-snug text-[#a6b5cf]">
                    Local vault only — rotate provider keys in Key Rotation.
                  </p>
                  {secretNotice && (
                    <div role="status" className="flex items-center gap-1.5 text-[12.5px] text-[#5bdba2]">
                      <IconCheck className="h-4 w-4" />
                      <span>{secretNotice}</span>
                    </div>
                  )}
                </form>
              );
            })()}

            {/* Ready-to-copy `premier run` command */}
            <button
              type="button"
              onClick={() => copyStr("pr-run", premierRunCmd)}
              className="pr-pill flex w-full items-center justify-between gap-2 rounded-xl px-3.5 py-2.5 text-left text-[13px] text-[#dce4f5]"
            >
              <span className="flex min-w-0 items-center gap-2">
                <IconTerminal className="h-4 w-4 text-[#9ec0f5]" />
                <span className="truncate">{premierRunCmd}</span>
              </span>
              {copiedKey === "pr-run" ? (
                <IconCheck className="h-4 w-4 text-[#5bdba2]" />
              ) : (
                <IconCopy className="h-4 w-4 text-[#a6b5cf]" />
              )}
            </button>
          </div>
          ) : (
            !dashboard && !error && !noSchema ? (
              <div className="min-h-0 flex-1 overflow-y-auto p-3">
                <SettingsRowsSkeleton rows={4} />
              </div>
            ) : (
              <div className="flex min-h-[160px] flex-1 items-center justify-center p-4 font-mono text-[13.5px] text-[#a6b5cf]">
                {noSchema ? "No .env.schema to inspect" : "Select a variable to inspect"}
              </div>
            )
          )
        ) : !owner ? (
          <OwnerOnly className="min-h-[160px] flex-1" />
        ) : (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="min-h-0 flex-1 space-y-2 overflow-y-auto p-4">
              <p className="font-sans text-[13.5px] leading-relaxed text-[#a6b5cf]">
                Local-only config files, blocked from commits and pushes. {OVERLAY_STORAGE_COPY}
              </p>
              {overlayLeakInsights.length > 0 && (
                <div className="space-y-1.5 pb-1">
                  {overlayLeakInsights.map((ins) => (
                    <AmbientWhisperChip
                      key={ins.id}
                      compact
                      severity={ins.severity}
                      title={ins.title}
                      detail={ins.detail}
                      actionLabel={
                        ins.action?.kind === "add_overlay_guard"
                          ? "Add to Overlay Guard"
                          : undefined
                      }
                      onAction={
                        ins.action?.kind === "add_overlay_guard"
                          ? () => void handleQuickOverlayGuard(ins)
                          : undefined
                      }
                      busy={busyInsightId === ins.id}
                      onDismiss={
                        onDismissInsight
                          ? () => {
                              setBusyInsightId(ins.id);
                              Promise.resolve(onDismissInsight(ins.id)).finally(() =>
                                setBusyInsightId((cur) => (cur === ins.id ? null : cur)),
                              );
                            }
                          : undefined
                      }
                    />
                  ))}
                </div>
              )}
              {!overlays && !error && <SettingsRowsSkeleton rows={2} />}
              {overlays?.entries.length === 0 && (
                <div className="py-6 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                  No local-only files yet
                </div>
              )}
              {overlays?.entries.map((entry) => (
                <div
                  key={entry.path}
                  className="pr-well flex flex-wrap items-center justify-between gap-2 rounded-xl px-3.5 py-2.5"
                >
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[13.5px] text-[#e6ecf8]">
                      {entry.path}
                    </div>
                    <div className="mt-0.5 font-mono text-[12.5px] text-[#a6b5cf]">
                      {overlayOwnerLabel(entry)}
                      {overlayPayloadLabel(entry) && ` · ${overlayPayloadLabel(entry)}`}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1.5">
                    <span
                      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[11.5px] ${
                        entry.encrypted
                          ? "border-[#5bdba2]/30 text-[#5bdba2]"
                          : "border-white/[0.1] text-[#a6b5cf]"
                      }`}
                      title={
                        entry.encrypted
                          ? "Payload sealed with AES-256-GCM in the Premier state directory"
                          : "Payload stored unencrypted in the Premier state directory"
                      }
                    >
                      {entry.encrypted && <IconLock className="h-3 w-3" />}
                      {overlayEncryptionLabel(entry)}
                    </span>
                    <ConfirmButton
                      disabled={!owner}
                      confirmLabel="Unmount"
                      question="Unmount overlay?"
                      onConfirm={() => void handleUnmountOverlay(entry.path)}
                      title={owner ? `Unmount ${entry.path}` : "Owner only"}
                      aria-label={`Unmount ${entry.path}`}
                      className="rounded-lg p-1 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-[#f27c7c] disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <IconTrash className="h-4 w-4" />
                    </ConfirmButton>
                  </div>
                </div>
              ))}

              {/* Mount New Typed Overlay */}
              <form
                onSubmit={(e) => void handleMountOverlay(e)}
                className="pr-well space-y-2 rounded-xl p-3 font-mono text-[12.5px]"
              >
                <div className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                  Mount Overlay
                </div>
                <div className="flex items-center gap-2">
                  <input
                    value={mountPath}
                    onChange={(e) => setMountPath(e.target.value)}
                    aria-label="Overlay path"
                    disabled={!owner}
                    placeholder={owner ? ".env.scratch or .vscode/local.json" : "Owner only"}
                    className="min-w-0 flex-1 rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                  />
                  <button
                    type="submit"
                    disabled={!owner || !mountPath.trim()}
                    title={owner ? undefined : "Owner only"}
                    className="pr-pill inline-flex shrink-0 items-center gap-1 rounded-lg px-2.5 py-1.5 text-[#9ec0f5] disabled:opacity-40"
                  >
                    <IconPlus className="h-4 w-4" />
                    <span>Mount</span>
                  </button>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2 text-[12.5px] text-[#a6b5cf]">
                  <div className="inline-flex flex-wrap rounded-2xl border border-white/[0.08] bg-black/30 p-0.5">
                    {["personal", ...groups.map((g) => `team:${g}`)].map((sc) => (
                      <button
                        key={sc}
                        type="button"
                        onClick={() => setMountScope(sc)}
                        className={`rounded-full px-2 py-0.5 transition ${
                          mountScope === sc ? "bg-[#7f95f8]/24 text-[#f3f6fd]" : "text-[#a6b5cf]"
                        }`}
                      >
                        {sc}
                      </button>
                    ))}
                  </div>
                  <div className="flex items-center gap-3">
                    <label
                      className="inline-flex cursor-pointer items-center gap-1"
                      title="Seal the overlay payload with AES-256-GCM in the Premier state directory"
                    >
                      <input
                        type="checkbox"
                        className="accent-[#7f95f8]"
                        checked={mountEncrypted}
                        onChange={(e) => setMountEncrypted(e.target.checked)}
                      />
                      <span>Encrypted</span>
                    </label>
                    <label
                      className="inline-flex cursor-pointer items-center gap-1"
                      title="Store an empty overlay payload in the state directory if none exists yet"
                    >
                      <input
                        type="checkbox"
                        className="accent-[#7f95f8]"
                        checked={mountCreateFile}
                        onChange={(e) => setMountCreateFile(e.target.checked)}
                      />
                      <span>Create file</span>
                    </label>
                  </div>
                </div>
                {canSupplyInitialContent && (
                  <div className="space-y-1.5 pt-1">
                    <button
                      type="button"
                      onClick={() => setShowInitialContent((v) => !v)}
                      aria-expanded={showInitialContent}
                      className="text-[12px] text-[#9ec0f5] hover:underline"
                    >
                      {showInitialContent ? "Hide initial content" : "+ Add initial content (optional)"}
                    </button>
                    {showInitialContent && (
                      <textarea
                        value={mountInitialContent}
                        onChange={(e) => setMountInitialContent(e.target.value)}
                        rows={3}
                        aria-label="Initial overlay file content"
                        placeholder="Optional initial file payload stored in the overlay state directory…"
                        className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                      />
                    )}
                  </div>
                )}
              </form>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void runGuardCheck();
              }}
              className="space-y-2.5 border-t border-white/[0.06] p-4"
            >
              <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                Push Guard
              </div>

              <div className="flex items-center gap-2">
                <input
                  value={testPaths}
                  onChange={(e) => setTestPaths(e.target.value)}
                  aria-label="Paths to check, comma separated"
                  placeholder="Paths to check, comma separated"
                  className="pr-well min-w-0 flex-1 rounded-xl px-3 py-2 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={!testPaths.trim()}
                  className="pr-action-btn shrink-0 rounded-xl px-3.5 py-2 text-[13px] disabled:opacity-40"
                >
                  Check
                </button>
              </div>

              {checkResult && (
                <div
                  className={`rounded-xl border px-3 py-2.5 font-mono text-[12.5px] ${
                    checkResult.allowed
                      ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#5bdba2]"
                      : "border-[#f27c7c]/30 bg-[#f27c7c]/10 text-[#f27c7c]"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {checkResult.allowed ? (
                      <IconCheck className="h-4 w-4" />
                    ) : (
                      <IconBlock className="h-4 w-4" />
                    )}
                    <span>
                      {checkResult.allowed
                        ? "Clean — safe to push"
                        : `Blocked ${plural(checkResult.blocked_paths.length, "overlay path")}`}
                    </span>
                  </div>
                  {checkResult.blocked_paths.length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {checkResult.blocked_paths.map((bp) => (
                        <span
                          key={bp}
                          className="rounded-md bg-black/30 px-2 py-0.5 text-[12.5px] text-[#f9b4b4]"
                        >
                          {bp}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </form>
          </div>
        )}
      </aside>

      {owner && policyMenu && (
        <PolicyContextMenu
          target={policyMenu.target}
          x={policyMenu.x}
          y={policyMenu.y}
          agentProfiles={agentProfiles}
          onSelectIntent={(intent) => {
            setPolicyMenu(null);
            setComposerIntent(intent);
          }}
          onClose={() => setPolicyMenu(null)}
        />
      )}

      {owner && composerIntent && (
        <PolicyIntentComposer
          initialIntent={composerIntent}
          identity={identity}
          owner={owner}
          refName={refName}
          directory={directory}
          agentProfiles={agentProfiles}
          client={api}
          onClose={() => setComposerIntent(null)}
          onOpenInPolicyEditor={onOpenPolicyEditor}
          onApplied={(res) => {
            setPolicyAppliedNotice(
              res.commit
                ? `Committed ${shortOid(res.commit)} · .access.toml updated`
                : `Policy updated (${plural(res.rule_count, "rule")})`,
            );
            setTimeout(() => setPolicyAppliedNotice(null), 4000);
            refreshVaultAndOverlays();
            onPolicySaved?.();
          }}
        />
      )}
    </div>
  );
}
