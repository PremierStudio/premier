import { useCallback, useEffect, useMemo, useState } from "react";
import { CodeBlock } from "./CodeBlock";
import { McpGatewaySkeleton } from "./ViewSkeletons";
import {
  api,
  currentRepoIsDefault,
  currentRepoName,
  errorText,
  type AuditDecision,
  type AuditEvent,
  type IdentityPreset,
  type McpDriftAlert,
  type McpGatewaysResponse,
  type McpPinStatus,
  type McpToolPermission,
} from "../api";
import { ENV_PRESETS } from "./AgentConnectModal";
import {
  IconBlock,
  IconCage,
  IconCheck,
  IconCopy,
  IconIntersection,
  IconLens,
  IconLock,
  IconPolicy,
  IconQuarantine,
  IconRefresh,
  IconSearch,
  IconShieldCheck,
  IconTerminal,
} from "./Icons";
import { OwnerOnly, Time } from "./forms";

type ToolStatusFilter = "all" | "allowed" | "jit" | "denied" | "quarantined";
type McpClientKind = "mcp-json" | "claude-code" | "codex" | "cursor";

const MCP_CLIENTS: { id: McpClientKind; label: string }[] = [
  { id: "mcp-json", label: "Any MCP Client" },
  { id: "claude-code", label: "Claude Code" },
  { id: "codex", label: "Codex" },
  { id: "cursor", label: "Cursor" },
];

const STATUS_FILTERS: { id: ToolStatusFilter; label: string }[] = [
  { id: "all", label: "all" },
  { id: "allowed", label: "allowed" },
  { id: "jit", label: "JIT" },
  { id: "denied", label: "denied" },
  { id: "quarantined", label: "quarantined" },
];

/** One pill shape for every badge in the gateway so rows keep a single baseline. */
const PILL = "inline-flex h-5 items-center rounded-full px-2 text-[12px] leading-none";

const RISK_BADGE: Record<McpToolPermission["risk"], string> = {
  read: "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]",
  write: "border border-white/[0.12] bg-white/[0.045] text-[#cbd5e8]",
  destructive: "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]",
};

const APPROVAL_BADGE: Record<McpToolPermission["approval"], string> = {
  auto: "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]",
  jit: "border border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]",
  deny: "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]",
};

const PIN_BADGE: Record<McpPinStatus, string> = {
  pinned: "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]",
  tofu: "border border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]",
  unverified: "border border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]",
  quarantined: "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]",
};

function decisionDot(decision: AuditDecision): string {
  switch (decision) {
    case "allowed":
    case "redacted":
      return "bg-[#5bdba2]";
    case "approval_required":
      return "bg-[#7f95f8]";
    case "denied":
    case "exfiltration_blocked":
    case "rate_limited":
    default:
      return "bg-[#f27c7c]";
  }
}

function formatApprovalLabel(tool: McpToolPermission): string {
  if (tool.approval === "auto") return "auto";
  if (tool.approval === "deny") return "denied";
  return tool.jit_ttl_secs === 0 ? "JIT · once" : `JIT · ${tool.jit_ttl_secs}s`;
}

function formatAlertKind(kind: string): string {
  switch (kind) {
    case "rug_pull_detected":
      return "rug pull";
    case "policy_pin_mismatch":
      return "pin mismatch";
    case "tool_poisoning_heuristic":
      return "tool poisoning";
    default:
      return kind.replace(/_/g, " ");
  }
}

function shortHash(hash?: string): string {
  if (!hash) return "—";
  return hash.length > 14 ? `${hash.slice(0, 12)}…` : hash;
}

const EXAMPLE_MCP_TOML = `[mcp_servers.postgres]
transport = "stdio"
command = ["npx", "-y", "@modelcontextprotocol/server-postgres"]
zone = "data-ops"
default_approval = "jit"
pin_on_first_use = true

[[mcp_servers.postgres.credentials]]
secret = "DATABASE_URL"
inject = "env:POSTGRES_URL"

[[mcp_rules]]
id = "allow-readonly-sql"
effect = "allow"
principals = ["group:eng"]
agent_profiles = ["code-reviewer"]
tools = ["postgres:query"]
approval = "auto"`;

interface Props {
  identity: IdentityPreset;
  owner: boolean;
  activeRef?: string;
  alerts: McpDriftAlert[];
  auditEvents: AuditEvent[];
  onAlertsChanged: () => void;
}

export function McpGatewayPanel({
  identity,
  owner,
  activeRef,
  alerts,
  auditEvents,
  onAlertsChanged,
}: Props) {
  const [data, setData] = useState<McpGatewaysResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<ToolStatusFilter>("all");
  const [selectedToolKey, setSelectedToolKey] = useState<string | null>(null);
  const [clientKind, setClientKind] = useState<McpClientKind>("mcp-json");
  const [mcpEnv, setMcpEnv] = useState<string>("dev");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [alertBusyId, setAlertBusyId] = useState<string | null>(null);
  const [alertError, setAlertError] = useState<string | null>(null);
  const [showAllAlerts, setShowAllAlerts] = useState(false);

  const loadGateways = useCallback(() => {
    setLoading(true);
    setError(null);
    return api
      .mcpGateways(identity, activeRef)
      .then((res) => {
        setData(res);
      })
      .catch((err: unknown) => {
        setError(errorText(err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, [identity, activeRef]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api
      .mcpGateways(identity, activeRef)
      .then((res) => {
        if (active) setData(res);
      })
      .catch((err: unknown) => {
        if (active) setError(errorText(err));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [identity, activeRef]);

  const copyStr = (key: string, text: string) => {
    navigator.clipboard?.writeText(text).catch(() => {});
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const repoName = currentRepoName();
  const isDefaultRepo = currentRepoIsDefault();
  const scopedRepo = !isDefaultRepo && repoName !== "";

  const clientConfigCmd = useMemo(() => {
    if (clientKind === "mcp-json") {
      const server: { command: string; args: string[]; cwd?: string } = {
        command: "premier",
        args: ["mcp", "gateway", "--env", mcpEnv],
      };
      if (scopedRepo) {
        server.cwd = `<path-to>/${repoName}`;
      }
      return JSON.stringify(
        {
          mcpServers: {
            premier: server,
          },
        },
        null,
        2,
      );
    }
    const cdPrefix = scopedRepo ? `cd ${repoName} && ` : "";
    const profileFlag = identity.agentProfile ? ` --agent-profile ${identity.agentProfile}` : "";
    return `${cdPrefix}premier mcp config --gateway --client ${clientKind} --env ${mcpEnv} --principal ${identity.principal}${profileFlag}`;
  }, [clientKind, mcpEnv, scopedRepo, repoName, identity.principal, identity.agentProfile]);

  const matchesToolFilter = useCallback(
    (tool: McpToolPermission): boolean => {
      switch (statusFilter) {
        case "all":
          return true;
        case "allowed":
          return tool.allowed;
        case "jit":
          return tool.approval === "jit";
        case "denied":
          return !tool.allowed || tool.approval === "deny";
        case "quarantined":
          return tool.pin_status === "quarantined";
      }
    },
    [statusFilter],
  );

  const filteredServers = useMemo(() => {
    if (!data) return [];
    const q = search.trim().toLowerCase();
    return data.servers
      .map((srv) => {
        const serverMatchesQuery =
          !q ||
          srv.name.toLowerCase().includes(q) ||
          (srv.description?.toLowerCase().includes(q) ?? false) ||
          (srv.zone?.toLowerCase().includes(q) ?? false) ||
          srv.credentials.some(
            (c) => c.secret.toLowerCase().includes(q) || c.inject.toLowerCase().includes(q),
          );
        const tools = srv.tools.filter((t) => {
          if (!matchesToolFilter(t)) return false;
          if (!q || serverMatchesQuery) return true;
          return (
            t.full_name.toLowerCase().includes(q) ||
            t.tool.toLowerCase().includes(q) ||
            (t.description?.toLowerCase().includes(q) ?? false) ||
            t.reason.toLowerCase().includes(q) ||
            t.required_secrets.some((s) => s.toLowerCase().includes(q)) ||
            t.arg_constraints.some((c) => c.toLowerCase().includes(q))
          );
        });
        return { server: srv, tools, serverMatchesQuery };
      })
      .filter(({ tools, serverMatchesQuery }) => {
        if (tools.length > 0) return true;
        return statusFilter === "all" && serverMatchesQuery;
      });
  }, [data, search, statusFilter, matchesToolFilter]);

  const allTools = useMemo(() => {
    const out: McpToolPermission[] = [];
    for (const entry of filteredServers) {
      for (const tool of entry.tools) out.push(tool);
    }
    return out;
  }, [filteredServers]);

  const selectedTool = useMemo(() => {
    if (selectedToolKey) {
      const inFiltered = allTools.find((t) => t.full_name === selectedToolKey);
      if (inFiltered) return inFiltered;
      const inAll = data?.servers.flatMap((s) => s.tools).find((t) => t.full_name === selectedToolKey);
      if (inAll) return inAll;
    }
    return allTools[0] ?? data?.servers[0]?.tools[0] ?? null;
  }, [allTools, data, selectedToolKey]);

  const sortedAlerts = useMemo(() => {
    return [...alerts].sort((a, b) => {
      const aActive = a.quarantined || !a.resolved_at ? 1 : 0;
      const bActive = b.quarantined || !b.resolved_at ? 1 : 0;
      if (aActive !== bActive) return bActive - aActive;
      return b.detected_at.localeCompare(a.detected_at);
    });
  }, [alerts]);

  const unresolvedAlerts = useMemo(
    () => alerts.filter((a) => a.quarantined || !a.resolved_at),
    [alerts],
  );

  const visibleAlerts = showAllAlerts ? sortedAlerts : sortedAlerts.slice(0, 3);

  const mcpAuditEvents = useMemo(
    () => auditEvents.filter((ev) => ev.component === "premier-mcp-gateway").slice(0, 25),
    [auditEvents],
  );

  const handleAlertAction = async (id: string, action: "approve" | "dismiss") => {
    setAlertBusyId(id);
    setAlertError(null);
    try {
      if (action === "approve") {
        await api.approveMcpAlert(id);
      } else {
        await api.dismissMcpAlert(id, true);
      }
      onAlertsChanged();
      await loadGateways();
    } catch (err: unknown) {
      setAlertError(errorText(err));
    } finally {
      setAlertBusyId(null);
    }
  };

  const clientCopyBar = (
    <div className="pr-well flex flex-wrap items-center justify-between gap-2 rounded-xl px-3 py-2 font-mono text-[12.5px]">
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">Client Config</span>
        <div className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 text-[12.5px]">
          {MCP_CLIENTS.map((c) => (
            <button
              key={c.id}
              type="button"
              onClick={() => setClientKind(c.id)}
              className={`rounded-full px-2 py-0.5 transition ${
                clientKind === c.id ? "bg-[#7f95f8]/25 text-[#f3f6fd]" : "text-[#a6b5cf] hover:text-white"
              }`}
            >
              {c.label}
            </button>
          ))}
        </div>
        <select
          value={mcpEnv}
          onChange={(e) => setMcpEnv(e.target.value)}
          aria-label="MCP gateway environment"
          title="Secret environment for MCP gateway"
          className="pr-well h-6 rounded-full px-2 font-mono text-[12px] text-[#dce4f5] [color-scheme:dark] focus:outline-none"
        >
          {ENV_PRESETS.map((envOpt) => (
            <option key={envOpt} value={envOpt}>
              env: {envOpt}
            </option>
          ))}
        </select>
      </div>
      <button
        type="button"
        onClick={() => copyStr("mcp-client-cmd", clientConfigCmd)}
        title={clientConfigCmd}
        className="pr-pill inline-flex max-w-full min-w-0 items-center gap-2 rounded-full px-2.5 py-1 text-[12.5px] text-[#dce4f5]"
      >
        <IconTerminal className="h-3.5 w-3.5 text-[#9ec0f5]" />
        <span className="max-w-[340px] truncate text-[#d2dbee]">
          {clientKind === "mcp-json"
            ? `.mcp.json · premier mcp gateway --env ${mcpEnv}${scopedRepo ? ` (${repoName})` : ""}`
            : clientConfigCmd}
        </span>
        {copiedKey === "mcp-client-cmd" ? (
          <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
        ) : (
          <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
        )}
      </button>
    </div>
  );

  // Never paint the real panel before data lands: zero counters would read as "all clean".
  if (loading && !data) return <McpGatewaySkeleton />;

  // First load failed: show only the error, never zeroed counters or a "no match" empty state.
  if (!data && error) {
    return (
      <section className="pr-surface flex min-h-[300px] min-w-0 flex-1 flex-col items-center justify-center gap-3 rounded-2xl p-6 text-center">
        <div role="alert" className="font-mono text-[14px] font-semibold text-[#f3f6fd]">
          MCP gateways unavailable
        </div>
        <p className="max-w-md break-words font-mono text-[13px] text-[#f27c7c]">{error}</p>
        <button
          type="button"
          onClick={() => void loadGateways()}
          className="pr-pill rounded-full px-3 py-1 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
        >
          Retry
        </button>
      </section>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
      {/* Left Pane: Viewing-as Status, Metrics, Filters, Server Cards & Tool Matrix */}
      <section className="pr-surface flex min-h-[300px] min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:min-h-0">
        {/* One condensed header: viewing-as lens, policy counters, refresh */}
        <div
          role="status"
          className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5 border-b border-[#9ec0f5]/20 bg-[#7f95f8]/8 px-4 py-2 font-mono text-[12.5px] text-[#cfe0ff] sm:px-5"
        >
          <span
            className="inline-flex min-w-0 items-center gap-2"
            title={
              identity.agentProfile
                ? "Limited to what both you and this agent may do · agents can use API keys without reading them"
                : identity.groups.length > 0
                  ? identity.groups.join(", ")
                  : identity.principal === "anonymous"
                    ? "Public projection"
                    : "Direct human session"
            }
          >
            {identity.agentProfile ? (
              <IconIntersection className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
            ) : (
              <IconLens className="h-4 w-4 shrink-0 text-[#9ec0f5]" />
            )}
            <span className="truncate">
              Viewing as <strong className="text-[#f3f6fd]">{identity.label}</strong>
            </span>
            {(data?.ref_name || activeRef) && (
              <span className="rounded-full bg-black/30 px-2 py-0.5 text-[12px] text-[#b6c3db]">
                {data?.ref_name ?? activeRef}
              </span>
            )}
          </span>
          <div className="flex flex-wrap items-center gap-x-3.5 gap-y-1">
            <span className="text-[#a6b5cf]">
              Servers <strong className="tabular-nums text-[#f3f6fd]">{data?.total_servers ?? 0}</strong>
            </span>
            <span className="text-[#a6b5cf]">
              Allowed <strong className="tabular-nums text-[#5bdba2]">{data?.allowed_tools ?? 0}</strong>
            </span>
            <span className="text-[#a6b5cf]">
              JIT{" "}
              <strong className="tabular-nums text-[#dce4f5]">
                {data?.jit_tools ?? 0}
              </strong>
            </span>
            <span className="text-[#a6b5cf]">
              Denied{" "}
              <strong className="tabular-nums text-[#dce4f5]">
                {data?.denied_tools ?? 0}
              </strong>
            </span>
            <span className="text-[#a6b5cf]">
              Quarantined{" "}
              <strong
                className={`tabular-nums ${
                  (data?.quarantined_alerts ?? 0) > 0 ? "text-[#f27c7c]" : "text-[#dce4f5]"
                }`}
              >
                {data?.quarantined_alerts ?? 0}
              </strong>
            </span>
            <button
              type="button"
              onClick={() => void loadGateways()}
              disabled={loading}
              aria-label="Refresh MCP gateways"
              title="Refresh MCP gateways"
              className="pr-pill inline-flex h-6 w-6 items-center justify-center rounded-full text-[#9ec0f5] disabled:opacity-40"
            >
              <IconRefresh className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>

        {!(data && data.servers.length === 0) && (
          <p className="border-b border-white/[0.06] px-4 py-2 text-[13.5px] leading-snug text-[#b6c3db] sm:px-5">
            Agents connect to your tools through Premier — API keys stay encrypted in your vault and
            destructive actions pause for your 1-click approval.
          </p>
        )}

        {/* Search + Status Filter Bar */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2 sm:px-5">
          <div className="flex min-w-[160px] flex-1 items-center gap-2">
            <IconSearch className="h-4 w-4 text-[#a6b5cf]" />
            <input
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              aria-label="Filter MCP servers and tools"
              placeholder="Filter servers, tools, zones, secrets…"
              className="min-w-0 flex-1 bg-transparent text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
          </div>
          <div className="flex flex-wrap items-center gap-1 font-mono text-[12.5px]">
            {STATUS_FILTERS.map((sf) => (
              <button
                key={sf.id}
                type="button"
                onClick={() => setStatusFilter(sf.id)}
                className={`rounded-full px-2.5 py-0.5 transition ${
                  statusFilter === sf.id
                    ? "pr-pill-active"
                    : "text-[#a6b5cf] hover:bg-white/[0.04] hover:text-[#f3f6fd]"
                }`}
              >
                {sf.label}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div
            role="alert"
            className="border-b border-[#f27c7c]/25 bg-[#f27c7c]/10 px-5 py-2 font-mono text-[13px] text-[#f27c7c]"
          >
            {error}
          </div>
        )}

        {/* Server Cards / Empty State */}
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3 sm:p-4">
          {data && data.servers.length === 0 ? (
            <div className="mx-auto flex max-w-2xl flex-col gap-4 py-4">
              <div className="pr-well space-y-2.5 rounded-2xl p-5">
                <div className="flex items-center gap-2 font-mono text-[14px] font-semibold text-[#f3f6fd]">
                  <IconCage className="h-[18px] w-[18px] text-[#9ec0f5]" />
                  <span>No MCP servers declared in .access.toml</span>
                </div>
                <p className="text-[14px] leading-relaxed text-[#b6c3db]">
                  Declare <code className="font-mono text-[#dce4f5]">[mcp_servers.&lt;name&gt;]</code>{" "}
                  and <code className="font-mono text-[#dce4f5]">[[mcp_rules]]</code> in{" "}
                  <code className="font-mono text-[#dce4f5]">.access.toml</code> to govern agent
                  tool calls with per-folder permissions, hidden API keys (agents can use keys
                  without reading them), 1-click approvals, and automatic tool-tampering
                  detection.
                </p>
                <p className="text-[14px] leading-relaxed text-[#d2dbee]">
                  Agents connect to your tools through Premier — API keys stay encrypted in your
                  vault and destructive actions pause for your 1-click approval.
                </p>
                <CodeBlock
                  code={EXAMPLE_MCP_TOML}
                  label=".access.toml"
                  language="toml"
                  showLineNumbers
                  compact
                />
              </div>
              {clientCopyBar}
            </div>
          ) : filteredServers.length === 0 ? (
            <div className="flex flex-col items-center gap-2.5 py-10 text-center font-mono text-[13.5px] text-[#a6b5cf]">
              <span>No MCP servers or tools match the active filter</span>
              <button
                type="button"
                onClick={() => {
                  setSearch("");
                  setStatusFilter("all");
                }}
                className="pr-pill rounded-full px-3 py-1 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
              >
                Clear filters
              </button>
            </div>
          ) : (
            filteredServers.map(({ server, tools }) => (
              <div
                key={server.name}
                className="pr-well overflow-hidden rounded-2xl border border-white/[0.07]"
              >
                {/* Server Header */}
                <div className="border-b border-white/[0.06] bg-black/25 px-4 py-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex min-w-0 flex-wrap items-center gap-2 font-mono">
                      <IconCage className="h-4 w-4 text-[#9ec0f5]" />
                      <span className="text-[14px] font-semibold text-[#f3f6fd]">{server.name}</span>
                      <span className="inline-flex h-5 items-center rounded-full bg-white/[0.06] px-2 text-[12px] text-[#9ec0f5]">
                        {server.transport}
                      </span>
                      {server.zone && (
                        <span className="rounded-full bg-[#7f95f8]/14 px-2 py-0.5 text-[12px] text-[#b4c8ff]">
                          @{server.zone}
                        </span>
                      )}
                      {server.default_approval && (
                        <span className="rounded-full bg-white/[0.04] px-2 py-0.5 text-[12px] text-[#a6b5cf]">
                          default: {server.default_approval}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12px]">
                      <span className="rounded-full bg-[#5bdba2]/12 px-2 py-0.5 text-[#5bdba2]">
                        {server.pinned_tool_count} pinned
                      </span>
                      {server.pin_on_first_use && (
                        <span className="rounded-full bg-[#7f95f8]/14 px-2 py-0.5 text-[#9ec0f5]">
                          TOFU
                        </span>
                      )}
                      {server.quarantined_count > 0 && (
                        <span className="rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/16 px-2 py-0.5 text-[#f27c7c]">
                          {server.quarantined_count} quarantined
                        </span>
                      )}
                    </div>
                  </div>

                  {server.description && (
                    <p className="mt-1 text-[13.5px] text-[#a6b5cf]">{server.description}</p>
                  )}

                  {/* Bound use != read credential chips (NEVER raw values) */}
                  {server.credentials.length > 0 && (
                    <div className="mt-2.5 flex flex-wrap items-center gap-1.5 font-mono text-[12.5px]">
                      <span className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                        API keys (usable, never readable)
                      </span>
                      {server.credentials.map((cred) => {
                        const statusLabel = !cred.declared_in_schema
                          ? "undeclared"
                          : cred.can_use
                            ? "can use"
                            : "no use";
                        const statusClass = !cred.declared_in_schema
                          ? "bg-white/[0.06] text-[#a6b5cf]"
                          : cred.can_use
                            ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                            : "bg-[#f27c7c]/16 text-[#f27c7c]";
                        return (
                          <span
                            key={`${cred.secret}-${cred.inject}`}
                            title={`Inject target: ${cred.inject} · raw value never exposed`}
                            className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-black/35 px-2.5 py-0.5 text-[#dce4f5]"
                          >
                            <IconLock className="h-3 w-3 text-[#a6b5cf]" />
                            <span>{cred.secret}</span>
                            <span className={`rounded-full px-1.5 py-px text-[12px] ${statusClass}`}>
                              {statusLabel}
                            </span>
                          </span>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Filtered Tool Rows */}
                <div className="divide-y divide-white/[0.05]">
                  {tools.length === 0 ? (
                    <div className="px-4 py-3 font-mono text-[13px] text-[#a6b5cf]">
                      No tools declared or discovered yet
                    </div>
                  ) : (
                    tools.map((tool) => {
                      const isSelected = selectedTool?.full_name === tool.full_name;
                      return (
                        <button
                          key={tool.full_name}
                          type="button"
                          onClick={() => setSelectedToolKey(tool.full_name)}
                          className={`w-full px-4 py-2 text-left transition ${
                            isSelected ? "bg-[#7f95f8]/14" : "hover:bg-white/[0.03]"
                          }`}
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-mono text-[13.5px]">
                              <span className="truncate font-medium text-[#f3f6fd]">
                                {tool.full_name}
                              </span>
                              <span className={`${PILL} ${RISK_BADGE[tool.risk]}`}>{tool.risk}</span>
                              {tool.approval !== "auto" && (
                                <span className={`${PILL} ${APPROVAL_BADGE[tool.approval]}`}>
                                  {formatApprovalLabel(tool)}
                                </span>
                              )}
                              {tool.pin_status !== "pinned" && (
                                <span className={`${PILL} ${PIN_BADGE[tool.pin_status]}`}>
                                  {tool.pin_status}
                                </span>
                              )}
                            </div>

                            {/* human ∩ agent intersection, one chip */}
                            <span
                              title={`human ${tool.human_allowed ? "allowed" : "denied"}${
                                tool.agent_allowed !== undefined
                                  ? ` ∩ agent ${tool.agent_allowed ? "allowed" : "denied"}`
                                  : ""
                              }`}
                              className={`${PILL} shrink-0 border font-mono ${
                                tool.human_allowed && tool.agent_allowed !== false
                                  ? "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                                  : "border-[#f27c7c]/35 bg-[#f27c7c]/14 text-[#f27c7c]"
                              }`}
                            >
                              H {tool.human_allowed ? "✓" : "✕"}
                              {tool.agent_allowed !== undefined &&
                                ` ∩ A ${tool.agent_allowed ? "✓" : "✕"}`}
                            </span>
                          </div>

                          {tool.description && (
                            <div className="mt-1 truncate text-[13px] text-[#a6b5cf]">
                              {tool.description}
                            </div>
                          )}

                          {tool.arg_constraints.length > 0 && (
                            <div className="mt-1.5 flex flex-wrap items-center gap-1 font-mono text-[12px]">
                              {tool.arg_constraints.map((constraint, idx) => (
                                <span
                                  key={`${constraint}-${idx}`}
                                  className="rounded-md border border-white/[0.07] bg-black/30 px-1.5 py-0.5 text-[#9ec0f5]"
                                >
                                  {constraint}
                                </span>
                              ))}
                            </div>
                          )}
                        </button>
                      );
                    })
                  )}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer Client Config Copy Bar when servers exist */}
        {data && data.servers.length > 0 && (
          <div className="shrink-0 border-t border-white/[0.06] px-3 py-2 sm:px-4">
            {clientCopyBar}
          </div>
        )}
      </section>

      {/* Right Aside: Drift Alerts, Selected Tool Detail, Recent MCP Audit Events */}
      <aside className="pr-surface flex shrink-0 flex-col overflow-hidden rounded-2xl lg:w-[376px] xl:w-[424px] 2xl:w-[480px]">
        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-3.5 font-mono text-[13px]">
          {/* 1. Selected Tool Detail (first: the left list drives it) */}
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                <IconPolicy className="h-4 w-4" />
                <span>Selected Tool Detail</span>
              </span>
              {selectedTool && (
                <span className={`${PILL} ${PIN_BADGE[selectedTool.pin_status]}`}>
                  {selectedTool.pin_status}
                </span>
              )}
            </div>

            {!selectedTool ? (
              <div className="pr-well rounded-xl p-3.5 text-center text-[13px] text-[#a6b5cf]">
                Select a tool on the left to inspect policy rules, schema pin, and arguments
              </div>
            ) : (
              <div className="pr-well space-y-2.5 rounded-xl p-3.5">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="break-all text-[14px] font-semibold text-[#f3f6fd]">
                    {selectedTool.full_name}
                  </span>
                  <div className="flex items-center gap-1 text-[12px]">
                    <span className={`${PILL} ${RISK_BADGE[selectedTool.risk]}`}>
                      {selectedTool.risk}
                    </span>
                    <span className={`${PILL} ${APPROVAL_BADGE[selectedTool.approval]}`}>
                      {formatApprovalLabel(selectedTool)}
                    </span>
                  </div>
                </div>

                {selectedTool.description && (
                  <p className="font-sans text-[13.5px] leading-relaxed text-[#b6c3db]">
                    {selectedTool.description}
                  </p>
                )}

                <div className="rounded-lg bg-black/30 px-2.5 py-2 font-sans text-[13px] text-[#dce4f5]">
                  {selectedTool.reason}
                </div>

                {selectedTool.schema_hash && (
                  <div className="flex items-center justify-between gap-2 text-[12.5px]">
                    <span className="text-[#a6b5cf]">schema_hash</span>
                    <button
                      type="button"
                      onClick={() => copyStr("schema-hash", selectedTool.schema_hash!)}
                      title={selectedTool.schema_hash}
                      className="inline-flex items-center gap-1 text-[#9ec0f5] hover:text-[#f3f6fd]"
                    >
                      <span>{shortHash(selectedTool.schema_hash)}</span>
                      {copiedKey === "schema-hash" ? (
                        <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                      ) : (
                        <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
                      )}
                    </button>
                  </div>
                )}

                {selectedTool.required_secrets.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Required API keys (usable, never readable)
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {selectedTool.required_secrets.map((sec) => (
                        <span
                          key={sec}
                          className="rounded-full border border-[#7f95f8]/25 bg-[#7f95f8]/10 px-2 py-0.5 text-[12px] text-[#b8cef8]"
                        >
                          {sec}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {selectedTool.arg_constraints.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                      Argument Constraints
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {selectedTool.arg_constraints.map((ac, idx) => (
                        <span
                          key={`${ac}-${idx}`}
                          className="rounded-md bg-black/35 px-2 py-0.5 text-[12px] text-[#9ec0f5]"
                        >
                          {ac}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Owner-only matched_rules trace */}
                <div className="border-t border-white/[0.06] pt-2.5">
                  <div className="mb-1.5 text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                    Matched Rules Trace
                  </div>
                  {!owner ? (
                    <OwnerOnly className="rounded-lg bg-black/25 py-2 text-[12.5px]" />
                  ) : !selectedTool.matched_rules || selectedTool.matched_rules.length === 0 ? (
                    <div className="text-[12.5px] text-[#a6b5cf]">
                      Default decision (no explicit rule matched)
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {selectedTool.matched_rules.map((rule, idx) => (
                        <div
                          key={`${rule.layer}-${rule.id}-${idx}`}
                          className="rounded-lg bg-black/35 px-2.5 py-2 text-[12.5px]"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-1.5">
                            <span className="font-medium text-[#f3f6fd]">{rule.id}</span>
                            <div className="flex items-center gap-1 text-[12px] uppercase">
                              <span
                                className={`rounded-full border px-1.5 py-px ${
                                  rule.layer === "server"
                                    ? "border-[#7f95f8]/25 bg-[#7f95f8]/10 text-[#b8cef8]"
                                    : "border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
                                }`}
                              >
                                {rule.layer}
                              </span>
                              <span
                                className={`rounded-full px-1.5 py-px ${
                                  rule.effect === "allow"
                                    ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                                    : "bg-[#f27c7c]/16 text-[#f27c7c]"
                                }`}
                              >
                                {rule.effect}
                              </span>
                              {rule.agent_scoped && (
                                <span className="rounded-full bg-[#7f95f8]/18 px-1.5 py-px text-[#9ec0f5]">
                                  agent
                                </span>
                              )}
                            </div>
                          </div>
                          {rule.reason && (
                            <div className="mt-1 font-sans text-[12.5px] text-[#a6b5cf]">
                              {rule.reason}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* 2. Schema-Drift & Tool-Poisoning Alerts (capped) */}
          <div className="space-y-2.5 border-t border-white/[0.06] pt-3">
            <div className="flex items-center justify-between gap-2">
              <span className="inline-flex items-center gap-1.5 text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                <IconQuarantine
                  className={`h-4 w-4 ${unresolvedAlerts.length > 0 ? "text-[#f27c7c]" : "text-[#5bdba2]"}`}
                />
                <span>Drift &amp; Poisoning Alerts</span>
              </span>
              <span
                className={`rounded-full px-2 py-0.5 text-[12px] ${
                  unresolvedAlerts.length > 0
                    ? "bg-[#f27c7c]/18 text-[#f27c7c]"
                    : "bg-[#5bdba2]/14 text-[#5bdba2]"
                }`}
              >
                {unresolvedAlerts.length} active
              </span>
            </div>

            {alertError && (
              <div
                role="alert"
                className="rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-2 text-[12.5px] text-[#f27c7c]"
              >
                {alertError}
              </div>
            )}

            {sortedAlerts.length === 0 ? (
              <div className="pr-well flex items-center gap-2 rounded-xl px-3.5 py-2.5 text-[12.5px] text-[#5bdba2]">
                <IconShieldCheck className="h-4 w-4 shrink-0" />
                <span>All pinned MCP tool schemas verified clean</span>
              </div>
            ) : (
              <div className="space-y-2.5">
                {visibleAlerts.map((al) => {
                  const isActive = al.quarantined || !al.resolved_at;
                  const busy = alertBusyId === al.id;
                  return (
                    <div
                      key={al.id}
                      className={`rounded-xl border p-3 ${
                        al.quarantined
                          ? "border-[#f27c7c]/35 bg-[#f27c7c]/10"
                          : isActive
                            ? "border-[#9ec0f5]/35 bg-[#7f95f8]/10"
                            : "border-white/[0.08] bg-black/25 opacity-80"
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-1.5">
                        <span className="truncate font-semibold text-[#f3f6fd]">{al.full_name}</span>
                        <div className="flex shrink-0 items-center gap-1 text-[12px] uppercase">
                          <span
                            className={`${PILL} bg-black/35 ${
                              al.severity === "critical" ? "text-[#f27c7c]" : "text-[#a8c5ff]"
                            }`}
                          >
                            {formatAlertKind(al.kind)}
                          </span>
                          <span
                            className={`${PILL} ${
                              al.severity === "critical"
                                ? "bg-[#f27c7c]/22 text-[#f27c7c]"
                                : "bg-[#7f95f8]/22 text-[#a8c5ff]"
                            }`}
                          >
                            {al.severity}
                          </span>
                        </div>
                      </div>

                      <div className="mt-1.5 font-sans text-[13px] leading-snug text-[#dce4f5]">
                        {al.message}
                      </div>

                      {/* SHA-256 Expected vs Observed */}
                      <div className="mt-2 grid grid-cols-2 gap-1.5 rounded-lg bg-black/35 px-2.5 py-1.5 text-[12px]">
                        <div className="min-w-0">
                          <div className="text-[#a6b5cf]">expected sha256</div>
                          <div className="truncate text-[#5bdba2]" title={al.expected_hash}>
                            {shortHash(al.expected_hash)}
                          </div>
                        </div>
                        <div className="min-w-0">
                          <div className="text-[#a6b5cf]">observed sha256</div>
                          <div className="truncate text-[#f27c7c]" title={al.observed_hash}>
                            {shortHash(al.observed_hash)}
                          </div>
                        </div>
                      </div>

                      {/* Description diff snippet */}
                      {(al.expected_description || al.observed_description) && (
                        <div className="mt-2 space-y-1 rounded-lg bg-black/35 p-2 text-[12.5px]">
                          {al.expected_description && (
                            <div className="line-clamp-2 text-[#5bdba2]">
                              - {al.expected_description}
                            </div>
                          )}
                          {al.observed_description && (
                            <div className="line-clamp-3 text-[#f27c7c]">
                              + {al.observed_description}
                            </div>
                          )}
                        </div>
                      )}

                      <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-[12px] text-[#a6b5cf]">
                        <span>
                          Detected <Time value={al.detected_at} />
                        </span>
                        {al.resolved_at ? (
                          <span className="text-[#b6c3db]">
                            {al.quarantined ? "Quarantined" : "Re-pinned"}
                            {al.resolved_by ? ` by ${al.resolved_by}` : ""}
                          </span>
                        ) : (
                          <span className="text-[#f27c7c]">
                            {al.quarantined ? "Quarantined" : "Unresolved"}
                          </span>
                        )}
                      </div>

                      {isActive &&
                        (owner ? (
                          <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void handleAlertAction(al.id, "approve")}
                              className="pr-action-btn inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[12.5px] disabled:opacity-50"
                            >
                              <IconShieldCheck className="h-3.5 w-3.5" />
                              <span>{busy ? "Working…" : "Re-pin & Unquarantine"}</span>
                            </button>
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void handleAlertAction(al.id, "dismiss")}
                              className="pr-pill inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-[12.5px] text-[#f27c7c] hover:bg-[#f27c7c]/15 disabled:opacity-50"
                            >
                              <IconBlock className="h-3.5 w-3.5" />
                              <span>Keep Quarantined</span>
                            </button>
                          </div>
                        ) : (
                          <OwnerOnly className="mt-2 rounded-lg bg-black/25 py-2 text-[12.5px]" />
                        ))}
                    </div>
                  );
                })}
                {sortedAlerts.length > 3 && (
                  <button
                    type="button"
                    onClick={() => setShowAllAlerts((v) => !v)}
                    className="pr-pill w-full rounded-full px-3 py-1 text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
                  >
                    {showAllAlerts ? "Show fewer alerts" : `Show ${sortedAlerts.length - 3} more alerts`}
                  </button>
                )}
              </div>
            )}
          </div>

          {/* 3. Recent MCP Audit Events */}
          <div className="space-y-2 border-t border-white/[0.06] pt-3">
            <div className="flex items-center justify-between gap-2">
              <span className="text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                Recent MCP Audit Events
              </span>
              <span className="text-[12.5px] text-[#a6b5cf]">{mcpAuditEvents.length}</span>
            </div>

            {!owner ? (
              <OwnerOnly className="pr-well rounded-xl py-2.5 text-[12.5px]" />
            ) : mcpAuditEvents.length === 0 ? (
              <div className="pr-well rounded-xl p-3 text-center text-[12.5px] text-[#a6b5cf]">
                No premier-mcp-gateway audit events yet
              </div>
            ) : (
              <div className="space-y-1.5">
                {mcpAuditEvents.map((ev, idx) => (
                  <div
                    key={`${ev.timestamp}-${ev.action}-${ev.target ?? ""}-${idx}`}
                    className="pr-well rounded-xl px-3 py-2 text-[12.5px]"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-2">
                        <span
                          className={`h-2 w-2 shrink-0 rounded-full ${decisionDot(ev.decision)}`}
                        />
                        <span className="truncate font-medium text-[#f3f6fd]">
                          {ev.target ?? ev.action}
                        </span>
                      </span>
                      <span className="shrink-0 text-[12px] text-[#a6b5cf]">
                        <Time value={ev.timestamp} />
                      </span>
                    </div>
                    <div className="mt-0.5 truncate font-sans text-[12.5px] text-[#a6b5cf]">
                      {ev.reason}
                    </div>
                    <div className="mt-1 flex items-center justify-between text-[12px] text-[#a6b5cf]">
                      <span className="truncate">
                        {ev.principal}
                        {ev.agent_profile ? ` ∩ ${ev.agent_profile}` : ""}
                      </span>
                      <span className="flex shrink-0 items-center gap-1.5">
                        {ev.bytes_scrubbed > 0 && (
                          <span className="text-[#67d6dc]">{ev.bytes_scrubbed}B scrubbed</span>
                        )}
                        <span className="text-[#9ec0f5]">{ev.decision}</span>
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </aside>
    </div>
  );
}
