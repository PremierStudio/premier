import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from "react";
import {
  errorText,
  shortOid,
  type AccessImpactDiff,
  type Directory,
  type IdentityPreset,
  type UpdateRepoPolicyResponse,
} from "../api";
import { plural } from "../lib/format";
import {
  computeTomlLineDiff,
  summarizeBlastRadius,
  type PolicyIntent,
  type PolicyTarget,
  type ProposePolicyIntentResponse,
  type SecretProbeInput,
} from "../lib/policyIntent";
import { PanelRowsSkeleton } from "./ViewSkeletons";
import { ErrorNote, INPUT_CLASS, OwnerOnly, PRIMARY_BTN, SECONDARY_BTN } from "./forms";
import {
  IconBlock,
  IconCheck,
  IconChevron,
  IconClose,
  IconFileNode,
  IconFolderNode,
  IconIntersection,
  IconLock,
  IconPlus,
  IconPolicy,
  IconQuarantine,
  IconShieldCheck,
  IconUser,
  IconVault,
} from "./Icons";

export interface PolicyAuthoringClient {
  proposePolicyIntent: (payload: {
    intent: PolicyIntent;
    base_toml?: string;
    ref_name?: string;
  }) => Promise<ProposePolicyIntentResponse>;
  policyDiff: (payload: {
    base_toml: string;
    head_toml: string;
    principals?: string[];
    paths?: string[];
    ref_name?: string;
    include_agent_profiles?: boolean;
    secret_probes?: SecretProbeInput[];
    changed_files: { path: string; content?: string }[];
  }) => Promise<AccessImpactDiff>;
  updateRepoPolicy: (
    toml: string,
    principal?: string,
    expectedBaseSha256?: string,
  ) => Promise<UpdateRepoPolicyResponse>;
}

export type ContextMenuTarget =
  | { kind: "file" | "dir"; path: string; matchingZones: string[] }
  | { kind: "secret"; varName: string; zone?: string };

export interface PolicyContextMenuProps {
  target: ContextMenuTarget;
  x: number;
  y: number;
  agentProfiles: string[];
  onSelectIntent: (intent: PolicyIntent) => void;
  onClose: () => void;
}

export interface PolicyIntentComposerProps {
  initialIntent: PolicyIntent;
  matchingZones?: string[];
  identity: IdentityPreset;
  owner: boolean;
  refName?: string;
  directory: Directory | null;
  agentProfiles: string[];
  client: PolicyAuthoringClient;
  onClose: () => void;
  onApplied: (res: UpdateRepoPolicyResponse) => void;
  onOpenInPolicyEditor?: (proposedToml: string) => void;
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])';

type PathIntentKind =
  | "shield_from_anonymous"
  | "shield_from_all_agents"
  | "shield_from_agent"
  | "allow_agent_access"
  | "restrict_to_principals";

type SecretIntentKind = "allow_agent_secret_use" | "revoke_agent_secret_use";

function isSecretIntent(
  intent: PolicyIntent,
): intent is Extract<PolicyIntent, { kind: SecretIntentKind }> {
  return intent.kind === "allow_agent_secret_use" || intent.kind === "revoke_agent_secret_use";
}

function targetLabel(target: PolicyTarget): string {
  if (target.kind === "zone") return `@${target.zone}`;
  return target.kind === "dir" && !target.path.endsWith("/") ? `${target.path}/` : target.path;
}

interface MenuEntry {
  id: string;
  section?: string;
  label: string;
  sublabel?: string;
  tone: "mint" | "indigo" | "amber" | "coral" | "neutral";
  icon: ReactNode;
  intent: PolicyIntent;
}

/**
 * Anchored obsidian-glass context menu for direct-manipulation policy authoring on files,
 * directories, zones, and secrets.
 */
export function PolicyContextMenu({
  target,
  x,
  y,
  agentProfiles,
  onSelectIntent,
  onClose,
}: PolicyContextMenuProps) {
  const menuRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  const [selectedZone, setSelectedZone] = useState<string | null>(null);
  const [pos, setPos] = useState<{ left: number; top: number }>({ left: x, top: y });

  const activePathTarget: PolicyTarget | null = useMemo(() => {
    if (target.kind === "secret") return null;
    if (selectedZone) return { kind: "zone", zone: selectedZone };
    return { kind: target.kind, path: target.path };
  }, [target, selectedZone]);

  const entries = useMemo<MenuEntry[]>(() => {
    if (target.kind === "secret") {
      const list: MenuEntry[] = [];
      for (const profile of agentProfiles) {
        list.push({
          id: `allow-secret-${profile}`,
          section: "Agent secret capabilities (USE ≠ READ)",
          label: `Allow ${profile} to USE (never read) ${target.varName}`,
          sublabel: "Proxy-injected egress only · raw value stays sealed",
          tone: "indigo",
          icon: <IconVault className="h-4 w-4 text-[#67d6dc]" />,
          intent: {
            kind: "allow_agent_secret_use",
            var_name: target.varName,
            zone: target.zone,
            agent_profile: profile,
            human_principals: [],
          },
        });
        list.push({
          id: `revoke-secret-${profile}`,
          section: "Agent secret capabilities (USE ≠ READ)",
          label: `Revoke ${profile} USE of ${target.varName}`,
          sublabel: "Remove egress secret capability for this profile",
          tone: "mint",
          icon: <IconBlock className="h-4 w-4 text-[#5bdba2]" />,
          intent: {
            kind: "revoke_agent_secret_use",
            var_name: target.varName,
            zone: target.zone,
            agent_profile: profile,
          },
        });
      }
      list.push({
        id: "allow-secret-custom",
        section: agentProfiles.length > 0 ? "Custom profile" : "Secret capability",
        label: "Allow agent profile to USE (never read)…",
        sublabel: "Choose or enter a profile and authorized human principals",
        tone: "neutral",
        icon: <IconIntersection className="h-4 w-4 text-[#9ec0f5]" />,
        intent: {
          kind: "allow_agent_secret_use",
          var_name: target.varName,
          zone: target.zone,
          agent_profile: agentProfiles[0] ?? "",
          human_principals: [],
        },
      });
      return list;
    }

    const tgt = activePathTarget!;
    const list: MenuEntry[] = [
      {
        id: "shield-anon",
        section: "Restrict access",
        label: "Hide from anonymous (public)",
        sublabel: "Public visitors and GitHub sync can no longer see or read this path",
        tone: "mint",
        icon: <IconShieldCheck className="h-4 w-4 text-[#5bdba2]" />,
        intent: { kind: "shield_from_anonymous", target: tgt },
      },
      {
        id: "shield-all-agents",
        section: "Restrict access",
        label: "Lock folder from all AI agents",
        sublabel: "Block this path for every agent profile",
        tone: "mint",
        icon: <IconLock className="h-4 w-4 text-[#5bdba2]" />,
        intent: { kind: "shield_from_all_agents", target: tgt },
      },
    ];

    for (const profile of agentProfiles) {
      list.push({
        id: `allow-ro-${profile}`,
        section: "AI agent profiles",
        label: `Allow ${profile} read-only`,
        sublabel: "Grant traverse, list, read inside human ∩ agent boundary",
        tone: "indigo",
        icon: <IconIntersection className="h-4 w-4 text-[#9ec0f5]" />,
        intent: {
          kind: "allow_agent_access",
          target: tgt,
          agent_profile: profile,
          write: false,
        },
      });
      list.push({
        id: `allow-rw-${profile}`,
        section: "AI agent profiles",
        label: `Allow ${profile} read + write`,
        sublabel: "Grant read + write capability to this agent profile",
        tone: "amber",
        icon: <IconIntersection className="h-4 w-4 text-[#a8c5ff]" />,
        intent: {
          kind: "allow_agent_access",
          target: tgt,
          agent_profile: profile,
          write: true,
        },
      });
      list.push({
        id: `shield-agent-${profile}`,
        section: "AI agent profiles",
        label: `Block ${profile}`,
        sublabel: "Add an explicit deny rule for this agent profile",
        tone: "mint",
        icon: <IconBlock className="h-4 w-4 text-[#5bdba2]" />,
        intent: {
          kind: "shield_from_agent",
          target: tgt,
          agent_profile: profile,
        },
      });
    }

    list.push({
      id: "restrict-principals",
      section: "Access scope",
      label: "Restrict to group / principal…",
      sublabel: "Allow selected groups or users while preserving group:owners",
      tone: "neutral",
      icon: <IconUser className="h-4 w-4 text-[#9ec0f5]" />,
      intent: {
        kind: "restrict_to_principals",
        target: tgt,
        principals: [],
        write: false,
      },
    });

    return list;
  }, [target, activePathTarget, agentProfiles]);

  // Clamp menu position cleanly inside the viewport after render.
  useLayoutEffect(() => {
    const el = menuRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const pad = 12;
    const maxLeft = Math.max(pad, window.innerWidth - rect.width - pad);
    const maxTop = Math.max(pad, window.innerHeight - rect.height - pad);
    setPos({
      left: Math.min(Math.max(pad, x), maxLeft),
      top: Math.min(Math.max(pad, y), maxTop),
    });
  }, [x, y, entries.length, selectedZone]);

  // Focus first item on mount and dismiss on outside click / resize / Escape.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    itemRefs.current[0]?.focus();

    const onPointerDown = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onCloseRef.current();
      }
    };
    const onWindowKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onCloseRef.current();
      }
    };
    const onResize = () => onCloseRef.current();

    window.addEventListener("mousedown", onPointerDown, true);
    window.addEventListener("keydown", onWindowKey, true);
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("mousedown", onPointerDown, true);
      window.removeEventListener("keydown", onWindowKey, true);
      window.removeEventListener("resize", onResize);
      opener?.focus?.();
    };
  }, []);

  const handleKeyDown = (e: ReactKeyboardEvent) => {
    e.stopPropagation();
    const items = itemRefs.current.filter((el): el is HTMLButtonElement => el !== null);
    if (items.length === 0) return;

    const currentIdx = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = currentIdx < 0 ? 0 : (currentIdx + 1) % items.length;
      items[next]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const prev = currentIdx <= 0 ? items.length - 1 : currentIdx - 1;
      items[prev]?.focus();
    } else if (e.key === "Home") {
      e.preventDefault();
      items[0]?.focus();
    } else if (e.key === "End") {
      e.preventDefault();
      items[items.length - 1]?.focus();
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  let lastSection: string | undefined;

  return (
    <div
      ref={menuRef}
      role="menu"
      aria-label="Policy authoring actions"
      onKeyDown={handleKeyDown}
      style={{ left: `${pos.left}px`, top: `${pos.top}px` }}
      className="pr-elevated fixed z-50 flex max-h-[min(78vh,540px)] bg-[#0b0f1c]/97 w-[min(340px,calc(100vw-24px))] flex-col overflow-hidden rounded-2xl text-left"
    >
      {/* Target header */}
      <div className="shrink-0 border-b border-white/[0.08] bg-white/[0.02] px-3.5 py-2.5">
        <div className="flex items-center justify-between gap-2">
          <div className="flex min-w-0 items-center gap-2">
            {target.kind === "secret" ? (
              <IconVault className="h-4 w-4 text-[#67d6dc]" />
            ) : target.kind === "dir" ? (
              <IconFolderNode className="h-4 w-4 text-[#9ec0f5]" />
            ) : (
              <IconFileNode className="h-4 w-4 text-[#9ec0f5]" />
            )}
            <span className="truncate font-mono text-[13.5px] font-medium text-[#f3f6fd]">
              {target.kind === "secret"
                ? target.varName
                : activePathTarget
                  ? targetLabel(activePathTarget)
                  : target.path}
            </span>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close policy menu"
            className="rounded-lg p-1 text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-white"
          >
            <IconClose className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Zone quick-pills when path matches one or more zones */}
        {target.kind !== "secret" && target.matchingZones.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1.5">
            <span className="font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf]">
              Target:
            </span>
            <button
              type="button"
              onClick={() => setSelectedZone(null)}
              className={`rounded-full px-2 py-0.5 font-mono text-[12.5px] transition ${
                selectedZone === null ? "pr-pill-active" : "pr-pill text-[#a6b5cf]"
              }`}
            >
              {target.kind === "dir" ? "folder" : "file"}
            </button>
            {target.matchingZones.map((zone) => (
              <button
                key={zone}
                type="button"
                onClick={() => setSelectedZone((z) => (z === zone ? null : zone))}
                className={`rounded-full px-2 py-0.5 font-mono text-[12.5px] transition ${
                  selectedZone === zone ? "pr-pill-active" : "pr-pill text-[#9ec0f5]"
                }`}
              >
                in @{zone}
              </button>
            ))}
          </div>
        )}

        {target.kind === "secret" && target.zone && (
          <div className="mt-1.5 font-mono text-[12.5px] text-[#a6b5cf]">
            zone <span className="text-[#9ec0f5]">@{target.zone}</span>
          </div>
        )}
      </div>

      {/* Menu actions */}
      <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
        {entries.map((entry, idx) => {
          const showSection = entry.section !== lastSection;
          lastSection = entry.section;
          return (
            <div key={entry.id}>
              {showSection && entry.section && (
                <div
                  className={`px-2.5 pb-1 font-mono text-[12px] uppercase tracking-wider text-[#a6b5cf] ${
                    idx > 0 ? "mt-1.5 border-t border-white/[0.06] pt-2" : "pt-1"
                  }`}
                >
                  {entry.section}
                </div>
              )}
              <button
                ref={(el) => {
                  itemRefs.current[idx] = el;
                }}
                type="button"
                role="menuitem"
                onClick={() => {
                  onSelectIntent(entry.intent);
                  onClose();
                }}
                className="group flex w-full items-start gap-2.5 rounded-xl px-2.5 py-2 text-left transition hover:bg-white/[0.06] focus:bg-white/[0.08] focus:outline-none"
              >
                <span className="mt-0.5 shrink-0">{entry.icon}</span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[14px] font-medium leading-snug text-[#f3f6fd] group-hover:text-white">
                    {entry.label}
                  </span>
                  {entry.sublabel && (
                    <span className="mt-0.5 block text-[12.5px] leading-snug text-[#a6b5cf]">
                      {entry.sublabel}
                    </span>
                  )}
                </span>
                <IconChevron
                  direction="right"
                  className="mt-1 h-3.5 w-3.5 text-[#54627c] opacity-0 transition group-hover:opacity-100 group-focus:opacity-100"
                />
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const PATH_INTENT_OPTIONS: { kind: PathIntentKind; label: string; hint: string }[] = [
  {
    kind: "shield_from_anonymous",
    label: "Hide from anonymous",
    hint: "Deny public visibility",
  },
  {
    kind: "shield_from_all_agents",
    label: "Lock from all AI agents",
    hint: "Fence across every agent",
  },
  {
    kind: "shield_from_agent",
    label: "Block one agent",
    hint: "Deny one agent profile",
  },
  {
    kind: "allow_agent_access",
    label: "Allow agent access",
    hint: "Bounded human ∩ agent",
  },
  {
    kind: "restrict_to_principals",
    label: "Restrict to group / principal",
    hint: "Allow-list + group:owners",
  },
];

/**
 * Direct-manipulation Policy Intent Composer with live debounced blast-radius simulation,
 * Server Policy override verification, per-principal deltas, and clean `.access.toml` diff.
 */
export function PolicyIntentComposer({
  initialIntent,
  matchingZones = [],
  identity,
  owner,
  refName,
  directory,
  agentProfiles,
  client,
  onClose,
  onApplied,
  onOpenInPolicyEditor,
}: PolicyIntentComposerProps) {
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const requestSeqRef = useRef(0);

  const [intent, setIntent] = useState<PolicyIntent>(initialIntent);
  // Remember the original file/dir target so owners can switch back from a @zone scope cleanly.
  const [basePathTarget] = useState<Extract<PolicyTarget, { kind: "file" | "dir" }> | null>(() =>
    !isSecretIntent(initialIntent) && initialIntent.target.kind !== "zone"
      ? initialIntent.target
      : null,
  );
  const [customPrincipal, setCustomPrincipal] = useState("");
  const [proposal, setProposal] = useState<ProposePolicyIntentResponse | null>(null);
  const [diff, setDiff] = useState<AccessImpactDiff | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [applying, setApplying] = useState(false);
  const [applyError, setApplyError] = useState<string | null>(null);
  const [appliedMessage, setAppliedMessage] = useState<string | null>(null);

  const zoneOptions = useMemo(() => {
    const set = new Set<string>(matchingZones);
    if (!isSecretIntent(initialIntent) && initialIntent.target.kind === "zone") {
      set.add(initialIntent.target.zone);
    }
    return Array.from(set).sort();
  }, [matchingZones, initialIntent]);

  const directoryGroups = useMemo(
    () => (directory?.groups ?? []).map((g) => (g.startsWith("group:") ? g : `group:${g}`)),
    [directory],
  );
  const directoryPrincipals = useMemo(
    () => (directory?.principals ?? []).map((p) => p.principal),
    [directory],
  );

  // Determine whether required inputs are currently blank.
  const needsAgentProfile = useMemo(() => {
    switch (intent.kind) {
      case "shield_from_agent":
      case "allow_agent_access":
      case "allow_agent_secret_use":
      case "revoke_agent_secret_use":
        return intent.agent_profile.trim() === "";
      default:
        return false;
    }
  }, [intent]);
  const needsPrincipals =
    intent.kind === "restrict_to_principals" && intent.principals.length === 0;
  const missingRequiredInput = needsAgentProfile || needsPrincipals;

  // Restore focus to opener when modal closes.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    return () => opener?.focus?.();
  }, []);

  const close = useCallback(() => {
    if (!applying) onClose();
  }, [applying, onClose]);

  const onDialogKeyDown = (e: ReactKeyboardEvent) => {
    e.stopPropagation();
    if (e.key === "Escape") {
      close();
    } else if (e.key === "Tab") {
      const items = panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE);
      if (!items || items.length === 0) {
        e.preventDefault();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  // Debounced live proposal + blast-radius diff pipeline.
  useEffect(() => {
    if (!owner) return;
    if (missingRequiredInput) {
      requestSeqRef.current += 1;
      setProposal(null);
      setDiff(null);
      setPreviewError(null);
      setPreviewLoading(false);
      return;
    }

    const seq = ++requestSeqRef.current;
    setPreviewLoading(true);
    setPreviewError(null);

    const timer = setTimeout(() => {
      void (async () => {
        try {
          const nextProposal = await client.proposePolicyIntent({
            intent,
            ref_name: refName,
          });
          if (requestSeqRef.current !== seq) return;
          setProposal(nextProposal);

          if (nextProposal.validation_error) {
            setDiff(null);
            setPreviewLoading(false);
            return;
          }

          const nextDiff = await client.policyDiff({
            base_toml: nextProposal.base_toml,
            head_toml: nextProposal.proposed_toml,
            paths: [],
            ref_name: refName,
            include_agent_profiles: true,
            secret_probes: nextProposal.secret_probes,
            changed_files: [],
          });
          if (requestSeqRef.current !== seq) return;
          setDiff(nextDiff);
        } catch (err: unknown) {
          if (requestSeqRef.current !== seq) return;
          setPreviewError(errorText(err));
          setDiff(null);
        } finally {
          if (requestSeqRef.current === seq) {
            setPreviewLoading(false);
          }
        }
      })();
    }, 180);

    return () => clearTimeout(timer);
  }, [owner, missingRequiredInput, intent, refName, client]);

  const previewPending = previewLoading || !proposal;

  const blast = useMemo(
    () =>
      summarizeBlastRadius(
        diff,
        proposal?.server_override_check ?? null,
        agentProfiles,
        proposal?.server_policy_loaded,
      ),
    [diff, proposal, agentProfiles],
  );

  const tomlDiff = useMemo(() => {
    if (!proposal) return [];
    return computeTomlLineDiff(proposal.base_toml, proposal.proposed_toml, 2);
  }, [proposal]);

  const diffCounts = useMemo(() => {
    let added = 0;
    let removed = 0;
    for (const row of tomlDiff) {
      if (row.kind === "add") added += 1;
      else if (row.kind === "del") removed += 1;
    }
    return { added, removed };
  }, [tomlDiff]);

  const impactCounts = useMemo(() => {
    let granted = 0;
    let revoked = 0;
    for (const d of diff?.deltas ?? []) {
      granted += d.granted.length;
      revoked += d.revoked.length;
    }
    return { granted, revoked };
  }, [diff]);

  const switchPathTarget = (nextTarget: PolicyTarget) => {
    setIntent((prev) => (isSecretIntent(prev) ? prev : { ...prev, target: nextTarget }));
  };

  const switchPathKind = (nextKind: PathIntentKind) => {
    setIntent((prev) => {
      if (isSecretIntent(prev)) return prev;
      const target = prev.target;
      const reason = prev.reason;
      const existingAgent =
        prev.kind === "shield_from_agent" || prev.kind === "allow_agent_access"
          ? prev.agent_profile
          : agentProfiles[0] ?? "";
      const existingWrite =
        prev.kind === "allow_agent_access" || prev.kind === "restrict_to_principals"
          ? prev.write
          : false;
      const existingPrincipals = prev.kind === "restrict_to_principals" ? prev.principals : [];

      switch (nextKind) {
        case "shield_from_anonymous":
          return { kind: "shield_from_anonymous", target, reason };
        case "shield_from_all_agents":
          return { kind: "shield_from_all_agents", target, reason };
        case "shield_from_agent":
          return { kind: "shield_from_agent", target, agent_profile: existingAgent, reason };
        case "allow_agent_access":
          return {
            kind: "allow_agent_access",
            target,
            agent_profile: existingAgent,
            write: existingWrite,
            reason,
          };
        case "restrict_to_principals":
          return {
            kind: "restrict_to_principals",
            target,
            principals: existingPrincipals,
            write: existingWrite,
            reason,
          };
      }
    });
  };

  const switchSecretKind = (nextKind: SecretIntentKind) => {
    setIntent((prev) => {
      if (!isSecretIntent(prev)) return prev;
      if (nextKind === "allow_agent_secret_use") {
        return {
          kind: "allow_agent_secret_use",
          var_name: prev.var_name,
          zone: prev.zone,
          agent_profile: prev.agent_profile,
          human_principals:
            prev.kind === "allow_agent_secret_use" ? prev.human_principals : [],
          reason: prev.reason,
        };
      }
      return {
        kind: "revoke_agent_secret_use",
        var_name: prev.var_name,
        zone: prev.zone,
        agent_profile: prev.agent_profile,
        reason: prev.reason,
      };
    });
  };

  const togglePrincipal = (principal: string) => {
    setIntent((prev) => {
      if (prev.kind === "restrict_to_principals") {
        const exists = prev.principals.includes(principal);
        const next = exists
          ? prev.principals.filter((p) => p !== principal)
          : [...prev.principals, principal];
        return { ...prev, principals: next };
      }
      if (prev.kind === "allow_agent_secret_use") {
        const exists = prev.human_principals.includes(principal);
        const next = exists
          ? prev.human_principals.filter((p) => p !== principal)
          : [...prev.human_principals, principal];
        return { ...prev, human_principals: next };
      }
      return prev;
    });
  };

  const addCustomPrincipal = (e: FormEvent) => {
    e.preventDefault();
    const val = customPrincipal.trim();
    if (!val) return;
    setIntent((prev) => {
      if (prev.kind === "restrict_to_principals") {
        if (prev.principals.includes(val)) return prev;
        return { ...prev, principals: [...prev.principals, val] };
      }
      if (prev.kind === "allow_agent_secret_use") {
        if (prev.human_principals.includes(val)) return prev;
        return { ...prev, human_principals: [...prev.human_principals, val] };
      }
      return prev;
    });
    setCustomPrincipal("");
  };

  const setAgentProfile = (profile: string) => {
    setIntent((prev) => {
      switch (prev.kind) {
        case "shield_from_agent":
        case "allow_agent_access":
        case "allow_agent_secret_use":
        case "revoke_agent_secret_use":
          return { ...prev, agent_profile: profile };
        default:
          return prev;
      }
    });
  };

  const handleApply = async () => {
    if (!owner || !proposal || proposal.validation_error) return;
    setApplying(true);
    setApplyError(null);
    setAppliedMessage(null);
    try {
      const res = await client.updateRepoPolicy(
        proposal.proposed_toml,
        identity.principal,
        proposal.base_sha256,
      );
      setAppliedMessage(
        res.commit
          ? `Committed ${shortOid(res.commit)} · ${plural(res.rule_count, "rule")} live`
          : `Applied (${plural(res.rule_count, "rule")})`,
      );
      onApplied(res);
      onClose();
    } catch (err: unknown) {
      setApplyError(errorText(err));
    } finally {
      setApplying(false);
    }
  };

  const canApply =
    owner &&
    !applying &&
    !previewLoading &&
    !missingRequiredInput &&
    Boolean(proposal) &&
    !proposal?.validation_error &&
    !previewError;

  const selectedPrincipals =
    intent.kind === "restrict_to_principals"
      ? intent.principals
      : intent.kind === "allow_agent_secret_use"
        ? intent.human_principals
        : [];

  const knownPrincipalSet = useMemo(
    () => new Set([...directoryGroups, ...directoryPrincipals]),
    [directoryGroups, directoryPrincipals],
  );
  const customSelectedPrincipals = selectedPrincipals.filter((p) => !knownPrincipalSet.has(p));

  const activeAgentProfile =
    intent.kind === "shield_from_agent" ||
    intent.kind === "allow_agent_access" ||
    intent.kind === "allow_agent_secret_use" ||
    intent.kind === "revoke_agent_secret_use"
      ? intent.agent_profile
      : null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-[#04060d]/80 px-3 py-3 backdrop-blur-sm sm:px-5 sm:py-6"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={onDialogKeyDown}
        className="pr-elevated flex max-h-[calc(100dvh-24px)] w-full max-w-5xl bg-[#0b0f1c]/97 sm:max-h-[calc(100dvh-48px)] flex-col overflow-hidden rounded-2xl focus:outline-none"
      >
        {/* Header */}
        <div className="flex shrink-0 items-center justify-between gap-3 border-b border-white/[0.08] px-3.5 py-2 sm:px-4">
          <div className="flex min-w-0 items-center gap-2.5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[#9ec0f5]/25 bg-[#7f95f8]/14 text-[#9ec0f5]">
              {isSecretIntent(intent) ? (
                <IconVault className="h-[18px] w-[18px] text-[#67d6dc]" />
              ) : (
                <IconPolicy className="h-[18px] w-[18px]" />
              )}
            </div>
            <div className="min-w-0">
              <h2 id={titleId} className="truncate text-[14.5px] font-semibold text-[#f3f6fd]">
                {isSecretIntent(intent) ? "Secret Access Rule" : "Restrict Path Access"}
              </h2>
              <p className="truncate font-mono text-[12.5px] text-[#a6b5cf]">
                {isSecretIntent(intent)
                  ? `Secret ${intent.var_name}${intent.zone ? ` · @${intent.zone}` : ""}`
                  : `Path ${targetLabel(intent.target)}${refName ? ` · branch ${refName}` : ""}`}
              </p>
              <p className="hidden truncate text-[12.5px] text-[#a6b5cf] sm:block">
                Preview who loses or gains access before saving to .access.toml
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={close}
            disabled={applying}
            aria-label="Close"
            className="rounded-lg p-1.5 text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-white disabled:opacity-40"
          >
            <IconClose className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        {!owner ? (
          <div className="p-6">
            <OwnerOnly className="pr-well rounded-2xl py-10" />
          </div>
        ) : (
          <div className="grid min-h-0 flex-1 grid-cols-1 divide-y divide-white/[0.08] overflow-y-auto lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] lg:divide-x lg:divide-y-0 lg:overflow-hidden">
            {/* Left column: Intent Controls */}
            <section className="flex min-h-0 flex-col gap-3 p-3.5 sm:p-4 lg:overflow-y-auto">
              {/* Target scope selector (path vs zone) or Secret invariant badge */}
              {!isSecretIntent(intent) ? (
                <div className="space-y-2">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Target scope
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {basePathTarget && (
                      <button
                        type="button"
                        onClick={() => switchPathTarget(basePathTarget)}
                        className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-mono text-[13px] transition ${
                          intent.target.kind !== "zone"
                            ? "pr-pill-active"
                            : "pr-pill text-[#b6c3db]"
                        }`}
                      >
                        {basePathTarget.kind === "dir" ? (
                          <IconFolderNode className="h-3.5 w-3.5 text-[#9ec0f5]" />
                        ) : (
                          <IconFileNode className="h-3.5 w-3.5 text-[#9ec0f5]" />
                        )}
                        <span className="max-w-[240px] truncate">{targetLabel(basePathTarget)}</span>
                      </button>
                    )}
                    {zoneOptions.map((zone) => {
                      const active =
                        intent.target.kind === "zone" && intent.target.zone === zone;
                      return (
                        <button
                          key={zone}
                          type="button"
                          onClick={() => switchPathTarget({ kind: "zone", zone })}
                          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-mono text-[13px] transition ${
                            active ? "pr-pill-active" : "pr-pill text-[#9ec0f5]"
                          }`}
                        >
                          <IconPolicy className="h-3.5 w-3.5" />
                          <span>Zone @{zone}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Secret capability target
                  </div>
                  <div className="pr-well flex flex-wrap items-center justify-between gap-2 rounded-xl px-3.5 py-2.5">
                    <div className="flex min-w-0 items-center gap-2">
                      <IconVault className="h-4 w-4 text-[#67d6dc]" />
                      <span className="truncate font-mono text-[14px] font-semibold text-[#f3f6fd]">
                        {intent.var_name}
                      </span>
                      {intent.zone && (
                        <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2 py-0.5 font-mono text-[12.5px] text-[#9ec0f5]">
                          @{intent.zone}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 rounded-xl border border-[#67d6dc]/30 bg-[#67d6dc]/10 px-3 py-2 font-mono text-[12.5px] text-[#67d6dc]">
                    <IconShieldCheck className="h-4 w-4 shrink-0" />
                    <span>USE ≠ READ · raw value never readable by agent</span>
                  </div>
                </div>
              )}

              {/* Intent Kind selector */}
              <div className="space-y-2">
                <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                  What to change
                </div>
                {!isSecretIntent(intent) ? (
                  <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                    {PATH_INTENT_OPTIONS.map((opt) => {
                      const active = intent.kind === opt.kind;
                      return (
                        <button
                          key={opt.kind}
                          type="button"
                          onClick={() => switchPathKind(opt.kind)}
                          className={`rounded-xl px-3 py-2 text-left transition ${
                            active ? "pr-pill-active" : "pr-pill text-[#d2dbee]"
                          }`}
                        >
                          <div className="text-[13.5px] font-medium leading-snug">{opt.label}</div>
                          <div className="mt-0.5 text-[12.5px] text-[#a6b5cf]">{opt.hint}</div>
                        </button>
                      );
                    })}
                  </div>
                ) : (
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => switchSecretKind("allow_agent_secret_use")}
                      className={`rounded-xl px-3 py-2 text-left transition ${
                        intent.kind === "allow_agent_secret_use"
                          ? "pr-pill-active"
                          : "pr-pill text-[#d2dbee]"
                      }`}
                    >
                      <div className="text-[13.5px] font-medium">Allow agent USE</div>
                      <div className="mt-0.5 text-[12.5px] text-[#a6b5cf]">
                        Proxy egress only
                      </div>
                    </button>
                    <button
                      type="button"
                      onClick={() => switchSecretKind("revoke_agent_secret_use")}
                      className={`rounded-xl px-3 py-2 text-left transition ${
                        intent.kind === "revoke_agent_secret_use"
                          ? "pr-pill-active"
                          : "pr-pill text-[#d2dbee]"
                      }`}
                    >
                      <div className="text-[13.5px] font-medium">Revoke agent USE</div>
                      <div className="mt-0.5 text-[12.5px] text-[#a6b5cf]">
                        Remove secret capability
                      </div>
                    </button>
                  </div>
                )}
              </div>

              {/* Agent profile selector (for agent-targeted intents) */}
              {activeAgentProfile !== null && (
                <div className="space-y-2">
                  <label
                    htmlFor={`${titleId}-agent`}
                    className="block font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]"
                  >
                    Agent profile
                  </label>
                  {agentProfiles.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {agentProfiles.map((profile) => (
                        <button
                          key={profile}
                          type="button"
                          onClick={() => setAgentProfile(profile)}
                          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                            activeAgentProfile === profile
                              ? "pr-pill-active"
                              : "pr-pill text-[#b6c3db]"
                          }`}
                        >
                          <IconIntersection className="h-3.5 w-3.5 text-[#9ec0f5]" />
                          <span>{profile}</span>
                        </button>
                      ))}
                    </div>
                  )}
                  <input
                    id={`${titleId}-agent`}
                    type="text"
                    value={activeAgentProfile}
                    onChange={(e) => setAgentProfile(e.target.value)}
                    placeholder="e.g. ui-agent"
                    spellCheck={false}
                    className={`${INPUT_CLASS} font-mono text-[13.5px]`}
                  />
                </div>
              )}

              {/* Read-only vs Read+Write toggle */}
              {(intent.kind === "allow_agent_access" ||
                intent.kind === "restrict_to_principals") && (
                <div className="space-y-2">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Access level
                  </div>
                  <div className="inline-flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[13px]">
                    <button
                      type="button"
                      onClick={() => setIntent({ ...intent, write: false })}
                      className={`rounded-full px-3.5 py-1 transition ${
                        !intent.write ? "pr-pill-active" : "text-[#a6b5cf]"
                      }`}
                    >
                      Read-only
                    </button>
                    <button
                      type="button"
                      onClick={() => setIntent({ ...intent, write: true })}
                      className={`rounded-full px-3.5 py-1 transition ${
                        intent.write
                          ? "border border-[#9ec0f5]/40 bg-[#7f95f8]/18 text-[#a8c5ff]"
                          : "text-[#a6b5cf]"
                      }`}
                    >
                      Read + Write
                    </button>
                  </div>
                </div>
              )}

              {/* Principals / Groups picker (for restrict_to_principals & allow_agent_secret_use) */}
              {(intent.kind === "restrict_to_principals" ||
                intent.kind === "allow_agent_secret_use") && (
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                      {intent.kind === "restrict_to_principals"
                        ? "Allowed groups & principals"
                        : "Human principals allowed to USE (optional)"}
                    </span>
                    <span className="font-mono text-[12.5px] text-[#a6b5cf]">
                      {selectedPrincipals.length} selected
                    </span>
                  </div>

                  {directoryGroups.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[12.5px] text-[#a6b5cf]">Directory groups</div>
                      <div className="flex flex-wrap gap-1.5">
                        {directoryGroups.map((grp) => {
                          const active = selectedPrincipals.includes(grp);
                          return (
                            <button
                              key={grp}
                              type="button"
                              onClick={() => togglePrincipal(grp)}
                              className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                                active ? "pr-pill-active" : "pr-pill text-[#b6c3db]"
                              }`}
                            >
                              {active && <IconCheck className="h-3 w-3 text-[#5bdba2]" />}
                              <span>{grp}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {directoryPrincipals.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[12.5px] text-[#a6b5cf]">Directory principals</div>
                      <div className="flex flex-wrap gap-1.5">
                        {directoryPrincipals.map((pr) => {
                          const active = selectedPrincipals.includes(pr);
                          return (
                            <button
                              key={pr}
                              type="button"
                              onClick={() => togglePrincipal(pr)}
                              className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-mono text-[12.5px] transition ${
                                active ? "pr-pill-active" : "pr-pill text-[#b6c3db]"
                              }`}
                            >
                              {active && <IconCheck className="h-3 w-3 text-[#5bdba2]" />}
                              <span>{pr}</span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {customSelectedPrincipals.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {customSelectedPrincipals.map((pr) => (
                        <span
                          key={pr}
                          className="pr-pill-active inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[12.5px]"
                        >
                          <span>{pr}</span>
                          <button
                            type="button"
                            onClick={() => togglePrincipal(pr)}
                            aria-label={`Remove ${pr}`}
                            className="text-[#b6c3db] hover:text-white"
                          >
                            <IconClose className="h-3 w-3" />
                          </button>
                        </span>
                      ))}
                    </div>
                  )}

                  <form onSubmit={addCustomPrincipal} className="flex gap-2">
                    <input
                      type="text"
                      value={customPrincipal}
                      onChange={(e) => setCustomPrincipal(e.target.value)}
                      placeholder="Add @user or group:team…"
                      aria-label="Add custom principal or group"
                      spellCheck={false}
                      className={`${INPUT_CLASS} min-w-0 flex-1 py-1.5! font-mono text-[13.5px]`}
                    />
                    <button
                      type="submit"
                      disabled={!customPrincipal.trim()}
                      className={`${SECONDARY_BTN} shrink-0 px-3! py-1.5! text-[13px]!`}
                    >
                      <IconPlus className="h-3.5 w-3.5" />
                      <span>Add</span>
                    </button>
                  </form>

                  {intent.kind === "restrict_to_principals" ? (
                    <p className="flex items-center gap-1.5 text-[13px] text-[#a6b5cf]">
                      <IconLock className="h-3.5 w-3.5 shrink-0 text-[#5bdba2]" />
                      <span>
                        <code className="text-[#dce4f5]">group:owners</code> is automatically
                        preserved.
                      </span>
                    </p>
                  ) : (
                    <p className="text-[13px] text-[#a6b5cf]">
                      Effective authority stays bounded by{" "}
                      <code className="text-[#dce4f5]">human ∩ agent_task</code>.
                    </p>
                  )}
                </div>
              )}

              {/* Optional audit reason */}
              <div className="space-y-1.5">
                <label
                  htmlFor={`${titleId}-reason`}
                  className="block font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]"
                >
                  Reason (optional)
                </label>
                <input
                  id={`${titleId}-reason`}
                  type="text"
                  value={intent.reason ?? ""}
                  onChange={(e) =>
                    setIntent({
                      ...intent,
                      reason: e.target.value === "" ? undefined : e.target.value,
                    })
                  }
                  placeholder="Why this access rule is being added…"
                  className={INPUT_CLASS}
                />
              </div>
            </section>

            {/* Right column: Live Blast-Radius Preview Card */}
            <section className="flex min-h-0 flex-col bg-black/15">
              <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3.5 py-2 sm:px-4">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Live Blast-Radius Preview
                  </span>
                  {/* Fixed slot: the chip toggles visibility only, so the header never shifts. */}
                  <span
                    role="status"
                    aria-hidden={!previewLoading}
                    className={`inline-flex min-w-[5.5rem] justify-center rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/14 px-2 py-0.5 font-mono text-[12px] text-[#9ec0f5] transition-opacity ${
                      previewLoading ? "opacity-100" : "opacity-0"
                    }`}
                  >
                    Simulating…
                  </span>
                </div>

                <div className="flex items-center gap-1.5 font-mono text-[12.5px]">
                  <span
                    className={`rounded-full px-2 py-0.5 ${
                      !previewPending && impactCounts.granted > 0
                        ? "bg-[#7f95f8]/16 text-[#a8c5ff]"
                        : "bg-white/[0.04] text-[#a6b5cf]"
                    }`}
                  >
                    +{impactCounts.granted}
                  </span>
                  <span
                    className={`rounded-full px-2 py-0.5 ${
                      !previewPending && impactCounts.revoked > 0
                        ? "bg-[#5bdba2]/15 text-[#5bdba2]"
                        : "bg-white/[0.04] text-[#a6b5cf]"
                    }`}
                  >
                    -{impactCounts.revoked}
                  </span>
                </div>
              </div>

              <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3.5 sm:p-4">
                {missingRequiredInput ? (
                  <div className="pr-well rounded-xl p-4 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                    {needsPrincipals
                      ? "Select at least one group or principal to simulate blast radius."
                      : "Select or enter an agent profile to simulate blast radius."}
                  </div>
                ) : !proposal && !previewError ? (
                  <PanelRowsSkeleton rows={3} />
                ) : (
                  <div
                    className={`space-y-3 transition-opacity ${previewLoading ? "opacity-60" : ""}`}
                    aria-busy={previewLoading}
                  >
                    {/* Human-readable Blast-Radius Summary Banner */}
                    <div
                      className={`rounded-xl border p-3.5 ${
                        previewPending
                          ? "border-white/[0.09] bg-white/[0.03]"
                          : !blast.serverCheckPassed
                          ? "border-[#9ec0f5]/35 bg-[#7f95f8]/10"
                          : blast.granted.some((g) => g.critical)
                            ? "border-[#f27c7c]/30 bg-[#f27c7c]/8"
                            : "border-white/[0.09] bg-white/[0.03]"
                      }`}
                    >
                      <p className="text-[14px] font-medium leading-relaxed text-[#f3f6fd]">
                        {blast.headline}
                      </p>

                      {/* Summary delta & verification pills */}
                      <div className="mt-2.5 flex flex-wrap gap-1.5 font-mono text-[12.5px]">
                        {blast.revoked.map((r) => (
                          <span
                            key={`rev-${r.actor}`}
                            className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/14 px-2.5 py-0.5 text-[#5bdba2]"
                          >
                            <span>-{r.capabilities.join(", ")}</span>
                            <span className="text-[#a9ebd0]">· {r.actor}</span>
                          </span>
                        ))}
                        {blast.granted.map((g) => (
                          <span
                            key={`grt-${g.actor}`}
                            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 ${
                              g.critical
                                ? "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]"
                                : "border border-[#9ec0f5]/35 bg-[#7f95f8]/15 text-[#a8c5ff]"
                            }`}
                          >
                            <span>+{g.capabilities.join(", ")}</span>
                            <span>· {g.actor}</span>
                          </span>
                        ))}
                        {proposal && (
                          <span
                            className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 ${
                              blast.serverCheckPassed
                                ? "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                                : "border border-[#9ec0f5]/40 bg-[#7f95f8]/16 text-[#a8c5ff]"
                            }`}
                          >
                            {blast.serverCheckPassed ? (
                              <IconShieldCheck className="h-3.5 w-3.5" />
                            ) : (
                              <IconQuarantine className="h-3.5 w-3.5" />
                            )}
                            <span>{blast.serverCheckLabel}</span>
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Validation Error & Request Error */}
                    <ErrorNote message={proposal?.validation_error ?? null} />
                    <ErrorNote message={previewError} />

                    {/* Warnings & Server Policy Override Details */}
                    {proposal &&
                      (proposal.warnings.length > 0 ||
                        !proposal.server_override_check.passed) && (
                        <div
                          role="alert"
                          className="space-y-2 rounded-xl border border-[#9ec0f5]/35 bg-[#7f95f8]/10 p-3.5 text-[13.5px] text-[#a8c5ff]"
                        >
                          <div className="flex items-center gap-2 font-medium">
                            <IconQuarantine className="h-4 w-4 shrink-0" />
                            <span>Warnings &amp; server rules that override this change</span>
                          </div>
                          {proposal.warnings.map((w, idx) => (
                            <p
                              key={`${w}-${idx}`}
                              className="text-[13px] leading-relaxed text-[#f5d7a3]"
                            >
                              {w}
                            </p>
                          ))}
                          {proposal.server_override_check.overrides.map((ov, idx) => (
                            <div
                              key={`${ov.principal}-${ov.agent_profile ?? ""}-${ov.path}-${idx}`}
                              className="rounded-lg border border-[#9ec0f5]/25 bg-black/25 p-2.5 font-mono text-[12.5px]"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-1 text-[#f3f6fd]">
                                <span>
                                  {ov.principal}
                                  {ov.agent_profile ? ` ∩ ${ov.agent_profile}` : ""}
                                </span>
                                <span className="text-[#b6c3db]">{ov.path}</span>
                              </div>
                              <div className="mt-1 text-[12.5px] text-[#d6e2f8]">
                                repo-only: [{ov.repo_only_effective.join(", ") || "none"}] →
                                effective with server: [
                                {ov.effective_with_server.join(", ") || "none"}]
                              </div>
                              {ov.server_rules.length > 0 && (
                                <div className="mt-1.5 flex flex-wrap gap-1">
                                  {ov.server_rules.map((sr) => (
                                    <span
                                      key={sr.id}
                                      title={sr.reason}
                                      className="rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/14 px-2 py-0.5 text-[12px] text-[#a8c5ff]"
                                    >
                                      server:{sr.id} ({sr.effect})
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                    {/* Quarantine alerts from diff */}
                    {diff?.quarantine_alerts.map((al) => (
                      <div
                        key={al.path}
                        className="flex items-start gap-2 rounded-xl border border-[#9ec0f5]/35 bg-[#7f95f8]/10 p-3 font-mono text-[13px] text-[#a8c5ff]"
                      >
                        <IconQuarantine className="mt-0.5 h-4 w-4 shrink-0" />
                        <div className="min-w-0">
                          <div className="font-semibold">{al.path}</div>
                          <div className="mt-0.5 text-[#d6e2f8]">{al.message}</div>
                        </div>
                      </div>
                    ))}

                    {/* Per-Principal Impact Deltas */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                        <span>Per-principal impact deltas</span>
                        {diff && <span>{plural(diff.deltas.length, "delta")}</span>}
                      </div>

                      {diff && diff.deltas.length === 0 && !proposal?.validation_error && (
                        <div className="pr-well rounded-xl py-5 text-center font-mono text-[13px] text-[#a6b5cf]">
                          No effective capability changes
                        </div>
                      )}

                      {diff && diff.deltas.length > 0 && (
                        <div className="max-h-52 space-y-2 overflow-y-auto pr-0.5">
                          {diff.deltas.map((d, idx) => (
                            <div
                              key={`${d.principal}-${d.agent_profile ?? ""}-${d.path}-${idx}`}
                              className="pr-well rounded-xl p-3 font-mono"
                            >
                              <div className="flex items-center justify-between gap-2 text-[13px]">
                                <span className="font-medium text-[#f3f6fd]">
                                  {d.principal}
                                  {d.agent_profile ? ` ∩ ${d.agent_profile}` : ""}
                                </span>
                                <span className="text-[12px] uppercase text-[#a6b5cf]">
                                  {d.granted.length > 0 ? "escalation" : "tightened"}
                                </span>
                              </div>
                              <div className="mt-0.5 break-all text-[12.5px] text-[#a6b5cf]">
                                {d.path}
                              </div>
                              <div className="mt-2 flex flex-wrap gap-1.5 text-[12.5px]">
                                {d.granted.map((g) => {
                                  const critical = g === "write" || g === "use";
                                  return (
                                    <span
                                      key={`+${g}`}
                                      className={`rounded-full px-2 py-0.5 ${
                                        critical
                                          ? "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]"
                                          : "border border-[#9ec0f5]/35 bg-[#7f95f8]/15 text-[#a8c5ff]"
                                      }`}
                                    >
                                      +{g}
                                    </span>
                                  );
                                })}
                                {d.revoked.map((r) => (
                                  <span
                                    key={`-${r}`}
                                    className="rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/14 px-2 py-0.5 text-[#5bdba2]"
                                  >
                                    -{r}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Clean .access.toml Line Diff */}
                    {proposal && (
                      <div className="space-y-2">
                        <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                          <span className="inline-flex items-center gap-1.5">
                            <IconPolicy className="h-3.5 w-3.5 text-[#9ec0f5]" />
                            <span>.access.toml diff</span>
                            {proposal.rule_id && (
                              <span className="normal-case text-[#9ec0f5]">
                                · {proposal.rule_id}
                              </span>
                            )}
                          </span>
                          <span className="normal-case">
                            <span className="text-[#5bdba2]">+{diffCounts.added}</span>{" "}
                            <span className="text-[#f27c7c]">-{diffCounts.removed}</span>
                          </span>
                        </div>

                        <div className="pr-well max-h-60 overflow-auto rounded-xl font-mono text-[13px] leading-relaxed">
                          {tomlDiff.length === 0 ? (
                            <div className="px-3.5 py-4 text-center text-[#a6b5cf]">
                              No .access.toml changes
                            </div>
                          ) : (
                            <div className="py-1.5">
                              {tomlDiff.map((row, idx) => {
                                if (row.kind === "gap") {
                                  return (
                                    <div
                                      key={`gap-${idx}`}
                                      className="border-y border-white/[0.04] bg-white/[0.02] px-3 py-0.5 text-center text-[12.5px] text-[#a6b5cf]"
                                    >
                                      ···
                                    </div>
                                  );
                                }
                                const rowClass =
                                  row.kind === "add"
                                    ? "bg-[#5bdba2]/10 text-[#86e8bd]"
                                    : row.kind === "del"
                                      ? "bg-[#f27c7c]/12 text-[#f69c9c]"
                                      : "text-[#b6c3db]";
                                const marker =
                                  row.kind === "add" ? "+" : row.kind === "del" ? "-" : " ";
                                return (
                                  <div
                                    key={`${row.kind}-${row.oldLine ?? ""}-${row.newLine ?? ""}-${idx}`}
                                    className={`flex gap-2 px-3 py-0.5 ${rowClass}`}
                                  >
                                    <span className="w-7 shrink-0 select-none text-right text-[12.5px] text-[#54627c]">
                                      {row.oldLine ?? ""}
                                    </span>
                                    <span className="w-7 shrink-0 select-none text-right text-[12.5px] text-[#54627c]">
                                      {row.newLine ?? ""}
                                    </span>
                                    <span className="w-3 shrink-0 select-none font-semibold">
                                      {marker}
                                    </span>
                                    <span className="min-w-0 whitespace-pre">{row.line}</span>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </section>
          </div>
        )}

        {/* Footer */}
        <div className="shrink-0 space-y-2 border-t border-white/[0.08] bg-white/[0.02] px-3.5 py-2 sm:px-4">
          <ErrorNote message={applyError} />
          {appliedMessage && (
            <div className="flex items-center gap-2 rounded-xl border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-3 py-1.5 font-mono text-[13px] text-[#5bdba2]">
              <IconCheck className="h-4 w-4" />
              <span>{appliedMessage}</span>
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between gap-2.5">
            <div className="font-mono text-[12.5px] text-[#a6b5cf]">
              {!owner
                ? "Owner role required to modify .access.toml"
                : proposal?.summary
                  ? proposal.summary
                  : "Server rules always override the repo's .access.toml"}
            </div>

            <div className="flex flex-wrap items-center justify-end gap-2">
              <button
                type="button"
                onClick={close}
                disabled={applying}
                className={SECONDARY_BTN}
              >
                Cancel
              </button>

              {onOpenInPolicyEditor && (
                <button
                  type="button"
                  disabled={!owner || applying || !proposal?.proposed_toml}
                  onClick={() => {
                    if (!proposal?.proposed_toml) return;
                    onOpenInPolicyEditor(proposal.proposed_toml);
                    onClose();
                  }}
                  className={SECONDARY_BTN}
                >
                  <IconPolicy className="h-4 w-4 text-[#9ec0f5]" />
                  <span>Edit as TOML</span>
                </button>
              )}

              <button
                type="button"
                disabled={!canApply}
                onClick={() => void handleApply()}
                title={
                  owner
                    ? "Check against server rules, commit .access.toml, and apply it immediately"
                    : "Owner only"
                }
                className={PRIMARY_BTN}
              >
                <IconCheck className="h-4 w-4" />
                <span>
                  {applying ? "Saving…" : "Save to .access.toml"}
                </span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
