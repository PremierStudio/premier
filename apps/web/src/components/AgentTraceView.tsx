import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  getServerOrigin,
  type IdentityPreset,
  type TraceSession,
  type TraceSpan,
  type TraceSpanKind,
} from "../api";
import { AiHarnessCluster, BrandIcon, type BrandIconName } from "./BrandIcons";
import { CodeBlock, DiffBlock, EvidenceValue, RedactedText } from "./CodeBlock";
import {
  IconBlock,
  IconBranchRef,
  IconCheck,
  IconClose,
  IconCopy,
  IconDownload,
  IconFileNode,
  IconLock,
  IconRefresh,
  IconSearch,
  IconShieldCheck,
  IconTerminal,
  IconTimeline,
  IconTrash,
} from "./Icons";
import { TraceSpanInspector, type InspectorTab } from "./TraceSpanInspector";
import { TracesPageSkeleton } from "./ViewSkeletons";
import { useModalDialog } from "../lib/useModalDialog";

export interface AgentTraceViewProps {
  active?: boolean;
  identity: IdentityPreset;
  owner: boolean;
  activeRef?: string;
  repoName?: string;
  isDefaultRepo?: boolean;
  sseConnected?: boolean;
  traceRevision?: number;
  identityPresets?: IdentityPreset[];
  onSelectIdentity?: (id: IdentityPreset) => void;
  onOpenReview?: (changeId: string) => void;
  onOpenFile?: (path: string) => void;
  onOpenCommit?: (oid: string) => void;
  onOpenBranch?: (branch: string) => void;
}

/** Ingest path for hook snippets: bare for the default repo, `/r/{name}` for non-default repos. */
export function traceIngestPath(repoName?: string, isDefaultRepo = true): string {
  if (repoName && !isDefaultRepo) {
    return `/r/${encodeURIComponent(repoName)}/v1/traces/ingest`;
  }
  return "/v1/traces/ingest";
}

type SessionFilter = "all" | "issues" | "active" | "blocked";
type SpanFilter = "all" | TraceSpanKind | "issues" | "redacted";
type RunViewMode = "timeline" | "diffs" | "security" | "compare";
type HookTabId = "claude" | "codex" | "cursor" | "gemini" | "otlp" | "curl";

const INSPECTOR_WIDTH_KEY = "premier.traces.inspectorWidth";
const INSPECTOR_DEFAULT_WIDTH = 370;
const INSPECTOR_WIDE_WIDTH = 560;
const INSPECTOR_MIN_WIDTH = 300;
const INSPECTOR_MAX_WIDTH = 760;

function loadSavedInspectorWidth(): number {
  if (typeof window === "undefined") return INSPECTOR_DEFAULT_WIDTH;
  try {
    const raw = window.localStorage.getItem(INSPECTOR_WIDTH_KEY);
    if (!raw) return INSPECTOR_DEFAULT_WIDTH;
    const parsed = Number(raw);
    if (Number.isFinite(parsed) && parsed >= INSPECTOR_MIN_WIDTH && parsed <= INSPECTOR_MAX_WIDTH) {
      return Math.round(parsed);
    }
  } catch {
    // ignore storage failures
  }
  return INSPECTOR_DEFAULT_WIDTH;
}

const INSPECTOR_TABS: readonly InspectorTab[] = ["overview", "data", "relations", "raw"];

/** `repo` / `ref` the app keeps in the hash; a trace link must carry them or it opens the wrong repo. */
export interface TraceDeepLinkScope {
  repo?: string;
  ref?: string;
}

function hashParams(hash: string): URLSearchParams {
  const raw = hash.replace(/^#/, "");
  const qIdx = raw.indexOf("?");
  return new URLSearchParams(qIdx === -1 ? "" : raw.slice(qIdx + 1));
}

/** Parse `#traces?run=&span=&tab=` (plus the app's `repo` / `ref`) from a hash string. */
export function parseTraceDeepLink(hash: string): {
  run?: string;
  span?: string;
  tab?: InspectorTab;
  repo?: string;
  ref?: string;
} {
  const params = hashParams(hash);
  const rawTab = params.get("tab");
  return {
    run: params.get("run") || undefined,
    span: params.get("span") || undefined,
    tab: INSPECTOR_TABS.find((t) => t === rawTab),
    repo: params.get("repo") || undefined,
    ref: params.get("ref") || undefined,
  };
}

/**
 * The trace hash for `currentHash` with run / span / tab updated. Every other param (`repo`, `ref`,
 * ...) is kept; `scope` only fills `repo` / `ref` the hash lost. `repo` and `ref` come first.
 */
export function buildTraceHash(
  currentHash: string,
  runId: string | null,
  spanId: string | null,
  tab: InspectorTab,
  scope: TraceDeepLinkScope = {},
): string {
  const current = hashParams(currentHash);
  const params = new URLSearchParams();
  for (const key of ["repo", "ref"] as const) {
    const value = current.get(key) || scope[key];
    if (value) params.set(key, value);
  }
  for (const [k, v] of current) {
    if (k !== "repo" && k !== "ref" && k !== "run" && k !== "span" && k !== "tab") {
      params.append(k, v);
    }
  }
  if (runId) params.set("run", runId);
  if (spanId) params.set("span", spanId);
  if (tab !== "overview") params.set("tab", tab);
  const qs = params.toString();
  return qs ? `#traces?${qs}` : "#traces";
}

function readTraceDeepLink() {
  return typeof window === "undefined" ? {} : parseTraceDeepLink(window.location.hash);
}

function buildTraceDeepLink(
  runId: string | null,
  spanId: string | null,
  tab: InspectorTab,
  scope?: TraceDeepLinkScope,
): string {
  if (typeof window === "undefined") return "#traces";
  return buildTraceHash(window.location.hash, runId, spanId, tab, scope);
}

const KIND_META: Record<
  TraceSpanKind,
  { label: string; short: string; dot: string; badge: string; bar: string }
> = {
  prompt_turn: {
    label: "Prompt",
    short: "Prompt",
    dot: "bg-[#7f95f8]",
    badge: "border-[#7f95f8]/30 bg-[#7f95f8]/14 text-[#b4c3ff]",
    bar: "bg-[#7f95f8]",
  },
  tool_call: {
    label: "Tool",
    short: "Tool",
    dot: "bg-[#9ec0f5]",
    badge: "border-[#9ec0f5]/30 bg-[#9ec0f5]/14 text-[#cfe0ff]",
    bar: "bg-[#9ec0f5]",
  },
  file_access: {
    label: "File",
    short: "File",
    dot: "bg-[#5bdba2]",
    badge: "border-[#5bdba2]/30 bg-[#5bdba2]/14 text-[#8beac0]",
    bar: "bg-[#5bdba2]",
  },
  proxy_egress: {
    label: "Egress",
    short: "Egress",
    dot: "bg-[#67d6dc]",
    badge: "border-[#67d6dc]/30 bg-[#67d6dc]/14 text-[#93e6ea]",
    bar: "bg-[#67d6dc]",
  },
  error_diagnostic: {
    label: "Error",
    short: "Error",
    dot: "bg-[#f27c7c]",
    badge: "border-[#f27c7c]/35 bg-[#f27c7c]/15 text-[#ffb4b4]",
    bar: "bg-[#f27c7c]",
  },
  delivery_report: {
    label: "Delivery",
    short: "Delivery",
    dot: "bg-[#c7a7ff]",
    badge: "border-[#c7a7ff]/30 bg-[#c7a7ff]/14 text-[#dcc7ff]",
    bar: "bg-[#c7a7ff]",
  },
};

function statusStyle(status: TraceSession["status"]): { label: string; dot: string; pill: string } {
  switch (status) {
    case "completed":
      return {
        label: "Completed",
        dot: "bg-[#5bdba2]",
        pill: "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#8beac0]",
      };
    case "blocked":
      return {
        label: "Blocked",
        dot: "bg-[#f27c7c]",
        pill: "border-[#f27c7c]/35 bg-[#f27c7c]/15 text-[#ffb4b4]",
      };
    case "failed":
      return {
        label: "Failed",
        dot: "bg-[#f27c7c]",
        pill: "border-[#f27c7c]/35 bg-[#f27c7c]/15 text-[#ffb4b4]",
      };
    default:
      return {
        label: "Active",
        dot: "bg-[#7f95f8]",
        pill: "border-[#7f95f8]/35 bg-[#7f95f8]/15 text-[#b8c6ff]",
      };
  }
}

function decisionStyle(decision: string): string {
  switch (decision) {
    case "allowed":
      return "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#8beac0]";
    case "redacted":
      return "border-[#67d6dc]/30 bg-[#67d6dc]/14 text-[#93e6ea]";
    case "approval_required":
      return "border-[#9ec0f5]/35 bg-[#9ec0f5]/15 text-[#cfe0ff]";
    case "denied":
    case "exfiltration_blocked":
    case "rate_limited":
    case "budget_exceeded":
      return "border-[#f27c7c]/35 bg-[#f27c7c]/15 text-[#ffb4b4]";
    default:
      return "border-white/[0.12] bg-white/[0.06] text-[#d2dbee]";
  }
}

function harnessBrand(toolName: string, model: string): BrandIconName {
  const tool = toolName.toLowerCase();
  if (tool.includes("claude") || tool.includes("anthropic")) return "claude";
  if (tool.includes("codex") || tool.includes("openai")) return "openai";
  if (tool.includes("gemini") || tool.includes("google")) return "gemini";
  if (tool.includes("copilot")) return "copilot";
  if (tool.includes("cursor") || tool.includes("vscode") || tool.includes("code")) return "vscode";

  const mod = model.toLowerCase();
  if (mod.includes("claude") || mod.includes("anthropic")) return "claude";
  if (mod.includes("codex") || mod.includes("openai") || mod.includes("gpt")) return "openai";
  if (mod.includes("gemini") || mod.includes("google")) return "gemini";
  return "terminal";
}

function formatDuration(ms?: number | null): string {
  if (ms === undefined || ms === null || ms < 0) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)}s`;
  const mins = Math.floor(ms / 60_000);
  const secs = Math.round((ms % 60_000) / 1000);
  return secs > 0 ? `${mins}m ${secs}s` : `${mins}m`;
}

function formatRelativeTime(iso: string): string {
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return iso;
  const diffSec = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (diffSec < 45) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86_400) return `${Math.floor(diffSec / 3600)}h ago`;
  return new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function formatOffset(spanIso: string, startMs: number): string {
  const ts = Date.parse(spanIso);
  if (Number.isNaN(ts) || Number.isNaN(startMs)) return "+0.0s";
  const deltaMs = Math.max(0, ts - startMs);
  if (deltaMs < 1000) return `+${deltaMs}ms`;
  if (deltaMs < 60_000) return `+${(deltaMs / 1000).toFixed(1)}s`;
  const mins = Math.floor(deltaMs / 60_000);
  const secs = Math.floor((deltaMs % 60_000) / 1000);
  return `+${mins}m${secs.toString().padStart(2, "0")}s`;
}

function isIssueSpan(span: TraceSpan): boolean {
  return (
    span.kind === "error_diagnostic" ||
    Boolean(span.error_message) ||
    span.decision === "denied" ||
    span.decision === "exfiltration_blocked" ||
    span.decision === "rate_limited" ||
    span.decision === "budget_exceeded"
  );
}

function sessionIssueCount(session: TraceSession): number {
  if (session.spans.length > 0) {
    return session.spans.reduce((acc, sp) => acc + (isIssueSpan(sp) ? 1 : 0), 0);
  }
  return Math.max(session.delivery.error_count, session.delivery.blocked_count);
}

function sessionPreview(session: TraceSession): string {
  const prompt = session.spans.find((s) => s.kind === "prompt_turn");
  if (prompt) return prompt.summary;
  const last = session.spans[session.spans.length - 1];
  return last?.summary ?? "No spans recorded";
}

function humanizeDecision(d: string): string {
  return d.replace(/_/g, " ");
}

function ConnectHookModal({
  open,
  repoName,
  isDefaultRepo = true,
  onClose,
  onTestEventSent,
}: {
  open: boolean;
  repoName?: string;
  isDefaultRepo?: boolean;
  onClose: () => void;
  onTestEventSent?: (sessionId: string, spanId: string) => void;
}) {
  const [tab, setTab] = useState<HookTabId>("claude");
  const [sendingTest, setSendingTest] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    message: string;
  } | null>(null);

  useEffect(() => {
    if (!open) setTestResult(null);
  }, [open]);

  const handleSendTestEvent = async () => {
    setSendingTest(true);
    setTestResult(null);
    try {
      const stamp = Date.now().toString(36).slice(-5);
      const res = await api.ingestTrace({
        hook_event_name: "PostToolUse",
        session_id: `tr_live_hook_${stamp}`,
        tool_name: "Edit",
        model: "claude-sonnet-4-6",
        branch: "main",
        actor_id: "claude-code",
        actor_type: "agent",
        correlation_id: `corr_live_${stamp}`,
        duration_ms: 340,
        tokens_in: 1480,
        tokens_out: 295,
        cost_usd_micros: 2800,
        summary:
          "Live hook test: updated checkout currency helper (synthetic secret sk_live_demo_99887766554433221100aabbcc scrubbed pre-write).",
        tool_input: {
          file_path: "apps/web/src/checkout.ts",
          old_string: "const total = amount / 100;",
          new_string:
            'const total = formatMinorUnits(amount, "USD"); // key=sk_live_demo_99887766554433221100aabbcc',
        },
        tool_response: {
          applied: true,
          zone: "public",
        },
        authority: {
          policy_decision: "allowed",
          secret_broker: "pre_write_scrubber",
          egress_enclave: "premier-proxy",
        },
      });
      setTestResult({
        ok: true,
        message: `Streamed ${res.session_id} · ${res.bytes_scrubbed} B scrubbed pre-write`,
      });
      onTestEventSent?.(res.session_id, res.span.span_id);
    } catch (err) {
      setTestResult({
        ok: false,
        message: err instanceof Error ? err.message : "Failed to send test event",
      });
    } finally {
      setSendingTest(false);
    }
  };

  const { panelRef, onKeyDown } = useModalDialog({ open, onClose });

  if (!open) return null;

  const origin = getServerOrigin();
  const ingestPath = traceIngestPath(repoName, isDefaultRepo);
  const ingestUrl = `${origin}${ingestPath}`;

  const snippets: Record<
    HookTabId,
    { label: string; brand: BrandIconName; pathHint: string; language: string; code: string }
  > = {
    claude: {
      label: "Claude Code",
      brand: "claude",
      pathHint: ".claude/settings.json",
      language: "json",
      code: JSON.stringify(
        {
          hooks: {
            PostToolUse: [
              {
                matcher: "*",
                hooks: [
                  {
                    type: "command",
                    command: `curl -fsS -X POST "${ingestUrl}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-`,
                  },
                ],
              },
            ],
            Stop: [
              {
                hooks: [
                  {
                    type: "command",
                    command: `curl -fsS -X POST "${ingestUrl}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-`,
                  },
                ],
              },
            ],
          },
        },
        null,
        2,
      ),
    },
    codex: {
      label: "Codex",
      brand: "openai",
      pathHint: "~/.codex/config.toml",
      language: "toml",
      code: `notify = [\n  "sh", "-c",\n  "curl -fsS -X POST '${ingestUrl}' -H 'Authorization: Bearer $PREMIER_TOKEN' -H 'Content-Type: application/json' -d \\"$1\\" >/dev/null",\n  "--"\n]`,
    },
    cursor: {
      label: "Cursor",
      brand: "vscode",
      pathHint: ".cursor/hooks.json",
      language: "json",
      code: JSON.stringify(
        {
          version: 1,
          hooks: {
            afterFileEdit: [
              {
                command: `curl -fsS -X POST "${ingestUrl}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-`,
              },
            ],
            afterShellExecution: [
              {
                command: `curl -fsS -X POST "${ingestUrl}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-`,
              },
            ],
          },
        },
        null,
        2,
      ),
    },
    gemini: {
      label: "Gemini CLI",
      brand: "gemini",
      pathHint: "~/.gemini/settings.json",
      language: "json",
      code: JSON.stringify(
        {
          hooks: {
            AfterTool: [
              {
                command: `curl -fsS -X POST "${ingestUrl}" -H "Authorization: Bearer $PREMIER_TOKEN" -H "Content-Type: application/json" --data-binary @-`,
              },
            ],
          },
        },
        null,
        2,
      ),
    },
    otlp: {
      label: "OTLP / OTel",
      brand: "terminal",
      pathHint: "OpenTelemetry HTTP JSON exporter",
      language: "shell",
      code: `# Stream standard OpenTelemetry resourceSpans directly to Premier\nexport OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="${ingestUrl}"\nexport OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer $PREMIER_TOKEN"\n\n# Or verify local hash-chain integrity from CLI:\npremier trace verify`,
    },
    curl: {
      label: "HTTP / cURL",
      brand: "terminal",
      pathHint: "Send a test span",
      language: "curl",
      code: `curl -fsS -X POST "${ingestUrl}" \\\n  -H "Authorization: Bearer $PREMIER_TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d '{"hook_event_name":"PostToolUse","session_id":"sess_local_1","tool_name":"Edit","file_path":"src/index.ts","summary":"Updated handler","duration_ms":180}'`,
    },
  };

  const active = snippets[tab];

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Connect agent trace hook"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="pr-elevated w-full max-w-2xl overflow-hidden rounded-2xl focus:outline-none"
      >
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.08] px-5 py-3.5">
          <div className="flex items-center gap-2.5">
            <div className="pr-icon-tile flex h-8 w-8 items-center justify-center rounded-xl">
              <IconTimeline className="h-4 w-4 text-[#9ec0f5]" />
            </div>
            <div>
              <h2 className="text-[15px] font-semibold tracking-[-0.015em] text-[#f5f7fd]">
                Connect a trace hook
              </h2>
              <p className="text-[12.5px] text-[#a6b5cf]">
                Secrets are scrubbed before write and paths enforce Zone ACLs on read.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-white"
          >
            <IconClose className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <div className="flex flex-wrap gap-1.5" role="tablist">
            {(Object.keys(snippets) as HookTabId[]).map((id) => {
              const item = snippets[id];
              const isSelected = tab === id;
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  onClick={() => setTab(id)}
                  className={`inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-[13px] font-medium transition ${
                    isSelected
                      ? "pr-pill-active text-[#f5f7fd]"
                      : "pr-pill text-[#b6c3db] hover:text-[#f5f7fd]"
                  }`}
                >
                  <BrandIcon name={item.brand} className="h-3.5 w-3.5" />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>

          <CodeBlock
            code={active.code}
            label={active.pathHint}
            language={active.language}
            showLineNumbers={active.code.includes("\n")}
            maxHeightClass="max-h-[300px]"
            collapsibleAt={0}
          />

          <div className="flex flex-wrap items-center justify-between gap-2 text-[12.5px] text-[#a6b5cf]">
            <span>
              Create a token in <span className="text-[#dce4f5]">Settings → Access Tokens</span> and
              export <code className="text-[#9ec0f5]">PREMIER_TOKEN</code>.
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={sendingTest}
                onClick={() => void handleSendTestEvent()}
                className="pr-pill inline-flex h-8 items-center gap-1.5 rounded-lg px-3 font-mono text-[12px] font-medium text-[#cfe0ff] hover:text-white disabled:opacity-50"
              >
                <IconShieldCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                <span>{sendingTest ? "Sending…" : "Send test event"}</span>
              </button>
              <code className="rounded-md bg-white/[0.05] px-2 py-1 font-mono text-[12px] text-[#9ec0f5]">
                POST {ingestPath}
              </code>
            </div>
          </div>

          {testResult && (
            <div
              className={`flex items-center justify-between gap-2 rounded-xl border px-3 py-2 font-mono text-[12px] ${
                testResult.ok
                  ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#8beac0]"
                  : "border-[#f27c7c]/30 bg-[#f27c7c]/10 text-[#ffb4b4]"
              }`}
            >
              <span>{testResult.message}</span>
              {testResult.ok && (
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded-md bg-white/[0.08] px-2 py-0.5 text-white hover:bg-white/[0.14]"
                >
                  Inspect now
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function AgentTraceView({
  active = true,
  identity,
  owner,
  activeRef = "main",
  repoName,
  isDefaultRepo = true,
  sseConnected = false,
  traceRevision = 0,
  identityPresets,
  onSelectIdentity,
  onOpenReview,
  onOpenFile,
  onOpenCommit,
  onOpenBranch,
}: AgentTraceViewProps) {
  const [sessions, setSessions] = useState<TraceSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [seeding, setSeeding] = useState(false);

  const initialDeepLink = useMemo(() => readTraceDeepLink(), []);
  // The default repo is implied by an absent `repo` param, so only a named repo is added back.
  const traceScope = useMemo<TraceDeepLinkScope>(
    () => ({ repo: repoName && !isDefaultRepo ? repoName : undefined }),
    [repoName, isDefaultRepo],
  );
  const [query, setQuery] = useState("");
  const [appliedQuery, setAppliedQuery] = useState("");
  const [sessionFilter, setSessionFilter] = useState<SessionFilter>("all");
  const [spanFilter, setSpanFilter] = useState<SpanFilter>("all");
  const [runView, setRunView] = useState<RunViewMode>("timeline");
  const [compareSessionId, setCompareSessionId] = useState<string | null>(null);
  const [fileFilter, setFileFilter] = useState<string | null>(null);
  const [spanQuery, setSpanQuery] = useState("");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    initialDeepLink.run ?? null,
  );
  const [selectedSpanId, setSelectedSpanId] = useState<string | null>(
    initialDeepLink.span ?? null,
  );
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>(
    initialDeepLink.tab ?? "overview",
  );
  const [correlationScope, setCorrelationScope] = useState<string | null>(null);
  const [inspectorWidth, setInspectorWidth] = useState<number>(() => loadSavedInspectorWidth());
  const [resizingInspector, setResizingInspector] = useState(false);
  const [mobilePane, setMobilePane] = useState<"runs" | "timeline" | "inspector">("timeline");

  const [hookModalOpen, setHookModalOpen] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const initialLoadedRef = useRef(false);
  const spanSearchInputRef = useRef<HTMLInputElement | null>(null);
  const splitContainerRef = useRef<HTMLDivElement | null>(null);

  const clampInspectorWidth = useCallback((px: number) => {
    const containerW = splitContainerRef.current?.getBoundingClientRect().width ?? 1440;
    const maxAllowed = Math.min(INSPECTOR_MAX_WIDTH, Math.max(INSPECTOR_MIN_WIDTH, Math.floor(containerW * 0.56)));
    return Math.round(Math.min(maxAllowed, Math.max(INSPECTOR_MIN_WIDTH, px)));
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem(INSPECTOR_WIDTH_KEY, String(inspectorWidth));
    } catch {
      // ignore storage failures
    }
  }, [inspectorWidth]);

  const startInspectorResize = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const startX = e.clientX;
      const startWidth = inspectorWidth;
      setResizingInspector(true);
      document.body.style.cursor = "col-resize";

      const onMove = (ev: PointerEvent) => {
        const delta = startX - ev.clientX;
        setInspectorWidth(clampInspectorWidth(startWidth + delta));
      };
      const onUp = () => {
        setResizingInspector(false);
        document.body.style.cursor = "";
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
        window.removeEventListener("pointercancel", onUp);
      };
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
      window.addEventListener("pointercancel", onUp);
    },
    [inspectorWidth, clampInspectorWidth],
  );

  const copyValue = useCallback((key: string, text: string) => {
    void navigator.clipboard.writeText(text).then(() => {
      setCopiedKey(key);
      window.setTimeout(() => {
        setCopiedKey((cur) => (cur === key ? null : cur));
      }, 1500);
    });
  }, []);

  const loadTraces = useCallback(
    async (searchText: string, background = false) => {
      if (background && initialLoadedRef.current) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);
      try {
        const trimmed = searchText.trim();
        const data = trimmed
          ? await api.blameTraces(trimmed, identity, activeRef)
          : await api.traces(identity, activeRef);
        setSessions(data);
        initialLoadedRef.current = true;
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load traces");
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [identity, activeRef],
  );

  useEffect(() => {
    void loadTraces(appliedQuery, initialLoadedRef.current);
  }, [loadTraces, appliedQuery, traceRevision]);

  const filteredSessions = useMemo(() => {
    return sessions.filter((s) => {
      if (sessionFilter === "issues") {
        return s.delivery.error_count > 0 || s.delivery.blocked_count > 0;
      }
      if (sessionFilter === "active") return s.status === "active";
      if (sessionFilter === "blocked") return s.status === "blocked" || s.status === "failed";
      return true;
    });
  }, [sessions, sessionFilter]);

  const activeSession = useMemo(() => {
    if (filteredSessions.length === 0) return null;
    if (selectedSessionId) {
      const found = filteredSessions.find((s) => s.session_id === selectedSessionId);
      if (found) return found;
    }
    return filteredSessions[0];
  }, [filteredSessions, selectedSessionId]);

  useEffect(() => {
    if (!activeSession) {
      setSelectedSpanId(null);
      return;
    }
    setSelectedSessionId(activeSession.session_id);
    if (!selectedSpanId || !activeSession.spans.some((sp) => sp.span_id === selectedSpanId)) {
      const firstIssue = activeSession.spans.find(isIssueSpan);
      setSelectedSpanId((firstIssue ?? activeSession.spans[0])?.span_id ?? null);
    }
  }, [activeSession, selectedSpanId]);

  useEffect(() => {
    setFileFilter(null);
    setSpanQuery("");
    setCorrelationScope(null);
  }, [activeSession?.session_id]);

  const filteredSpans = useMemo(() => {
    if (!activeSession) return [];
    const needle = spanQuery.trim().toLowerCase();
    return activeSession.spans.filter((sp) => {
      if (correlationScope && sp.correlation_id !== correlationScope) return false;
      if (fileFilter && sp.path !== fileFilter) return false;
      if (needle) {
        const hay = [
          sp.span_id,
          sp.summary,
          sp.path ?? "",
          sp.zone ?? "",
          sp.tool_name ?? "",
          sp.actor_id ?? "",
          sp.command ?? "",
          sp.error_message ?? "",
          sp.diff ?? "",
          sp.code_snippet ?? "",
        ]
          .join("\n")
          .toLowerCase();
        if (!hay.includes(needle)) return false;
      }
      if (spanFilter === "all") return true;
      if (spanFilter === "issues") return isIssueSpan(sp);
      if (spanFilter === "redacted") return sp.redacted_for_viewer;
      return sp.kind === spanFilter;
    });
  }, [activeSession, spanFilter, correlationScope, fileFilter, spanQuery]);

  const codeEvidenceSpans = useMemo(() => {
    if (!activeSession) return [];
    return activeSession.spans.filter((sp) => Boolean(sp.diff || sp.code_snippet));
  }, [activeSession]);

  const securityAuditSpans = useMemo(() => {
    if (!activeSession) return [];
    return activeSession.spans.filter(
      (sp) =>
        sp.bytes_scrubbed > 0 ||
        sp.redacted_for_viewer ||
        sp.kind === "proxy_egress" ||
        sp.decision === "denied" ||
        sp.decision === "redacted" ||
        sp.decision === "quarantined" ||
        Boolean(sp.authority),
    );
  }, [activeSession]);

  const primaryIncidentSpan = useMemo(() => {
    if (!activeSession) return null;
    return activeSession.spans.find(isIssueSpan) ?? null;
  }, [activeSession]);

  const actorUsage = useMemo(() => {
    if (!activeSession) return [];
    const map = new Map<
      string,
      { actor: string; spans: number; tokensIn: number; tokensOut: number; costMicros: number }
    >();
    for (const sp of activeSession.spans) {
      const actor = sp.actor_id ?? sp.tool_name ?? activeSession.tool_name;
      const cur = map.get(actor) ?? {
        actor,
        spans: 0,
        tokensIn: 0,
        tokensOut: 0,
        costMicros: 0,
      };
      cur.spans += 1;
      cur.tokensIn += sp.tokens_in ?? 0;
      cur.tokensOut += sp.tokens_out ?? 0;
      cur.costMicros += sp.cost_usd_micros ?? 0;
      map.set(actor, cur);
    }
    return Array.from(map.values()).sort(
      (a, b) => b.tokensIn + b.tokensOut - (a.tokensIn + a.tokensOut) || b.spans - a.spans,
    );
  }, [activeSession]);

  const baselineSession = useMemo(() => {
    if (!activeSession || sessions.length < 2) return null;
    if (compareSessionId && compareSessionId !== activeSession.session_id) {
      const found = sessions.find((s) => s.session_id === compareSessionId);
      if (found) return found;
    }
    return sessions.find((s) => s.session_id !== activeSession.session_id) ?? null;
  }, [activeSession, sessions, compareSessionId]);

  const activeSpan = useMemo(() => {
    if (!activeSession) return null;
    if (selectedSpanId) {
      const found = activeSession.spans.find((sp) => sp.span_id === selectedSpanId);
      if (found) return found;
    }
    return filteredSpans[0] ?? activeSession.spans[0] ?? null;
  }, [activeSession, filteredSpans, selectedSpanId]);

  // Sync selected run / span / inspector tab into URL hash for real deep-linking
  useEffect(() => {
    if (typeof window === "undefined") return;
    if (!window.location.hash.startsWith("#traces")) return;
    const next = buildTraceDeepLink(
      activeSession?.session_id ?? null,
      activeSpan?.span_id ?? null,
      inspectorTab,
      traceScope,
    );
    if (window.location.hash !== next) {
      window.history.replaceState(null, "", next);
    }
  }, [activeSession?.session_id, activeSpan?.span_id, inspectorTab, traceScope]);

  const activeSpanIndex = useMemo(
    () => (activeSpan ? filteredSpans.findIndex((s) => s.span_id === activeSpan.span_id) : -1),
    [filteredSpans, activeSpan],
  );

  const stepSpan = useCallback(
    (delta: -1 | 1) => {
      if (filteredSpans.length === 0) return;
      const cur = activeSpanIndex === -1 ? 0 : activeSpanIndex;
      const next = Math.min(filteredSpans.length - 1, Math.max(0, cur + delta));
      const target = filteredSpans[next];
      if (target) setSelectedSpanId(target.span_id);
    },
    [filteredSpans, activeSpanIndex],
  );

  const stepRun = useCallback(
    (delta: -1 | 1) => {
      if (filteredSessions.length === 0) return;
      const idx = activeSession
        ? filteredSessions.findIndex((s) => s.session_id === activeSession.session_id)
        : 0;
      const next = Math.min(filteredSessions.length - 1, Math.max(0, idx + delta));
      const target = filteredSessions[next];
      if (target) setSelectedSessionId(target.session_id);
    },
    [filteredSessions, activeSession],
  );

  useEffect(() => {
    if (!active) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (hookModalOpen || e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      const isEditing =
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.tagName === "SELECT" ||
          target.isContentEditable);

      if (e.key === "Escape") {
        if (fileFilter || correlationScope || spanQuery) {
          setFileFilter(null);
          setCorrelationScope(null);
          setSpanQuery("");
        }
        return;
      }
      if (isEditing) return;

      if (e.key === "ArrowDown" || e.key === "j") {
        e.preventDefault();
        stepSpan(1);
      } else if (e.key === "ArrowUp" || e.key === "k") {
        e.preventDefault();
        stepSpan(-1);
      } else if (e.key === "]") {
        e.preventDefault();
        stepRun(1);
      } else if (e.key === "[") {
        e.preventDefault();
        stepRun(-1);
      } else if (e.key === "1") {
        e.preventDefault();
        setInspectorTab("overview");
      } else if (e.key === "2") {
        e.preventDefault();
        setInspectorTab("data");
      } else if (e.key === "3") {
        e.preventDefault();
        setInspectorTab("relations");
      } else if (e.key === "4") {
        e.preventDefault();
        setInspectorTab("raw");
      } else if (e.key === "/") {
        e.preventDefault();
        setRunView("timeline");
        window.setTimeout(() => spanSearchInputRef.current?.focus(), 0);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [active, hookModalOpen, stepSpan, stepRun, fileFilter, correlationScope, spanQuery]);

  const spanIdsInRun = useMemo(
    () => new Set(activeSession?.spans.map((s) => s.span_id) ?? []),
    [activeSession],
  );

  const spanCounts = useMemo(() => {
    const counts: Record<string, number> = {
      all: 0,
      issues: 0,
      redacted: 0,
      prompt_turn: 0,
      tool_call: 0,
      file_access: 0,
      proxy_egress: 0,
      error_diagnostic: 0,
      delivery_report: 0,
    };
    if (!activeSession) return counts;
    counts.all = activeSession.spans.length;
    for (const sp of activeSession.spans) {
      counts[sp.kind] = (counts[sp.kind] ?? 0) + 1;
      if (isIssueSpan(sp)) counts.issues += 1;
      if (sp.redacted_for_viewer) counts.redacted += 1;
    }
    return counts;
  }, [activeSession]);

  const timelineStats = useMemo(() => {
    if (!activeSession || activeSession.spans.length === 0) {
      return { startMs: 0, endMs: 1, totalSpanMs: 1, maxDurationMs: 1 };
    }
    const timestamps = activeSession.spans
      .map((sp) => Date.parse(sp.timestamp))
      .filter((t) => Number.isFinite(t));
    const startMs = Math.min(
      Date.parse(activeSession.started_at) || Number.POSITIVE_INFINITY,
      ...(timestamps.length > 0 ? timestamps : [0]),
    );
    const endMs = Math.max(
      startMs + 1,
      ...activeSession.spans.map((sp) => {
        const t = Date.parse(sp.timestamp);
        return (Number.isFinite(t) ? t : startMs) + Math.max(sp.duration_ms ?? 0, 1);
      }),
    );
    const maxDurationMs = Math.max(
      1,
      ...activeSession.spans.map((sp) => sp.duration_ms ?? 0),
    );
    return {
      startMs: Number.isFinite(startMs) ? startMs : 0,
      endMs,
      totalSpanMs: Math.max(1, endMs - (Number.isFinite(startMs) ? startMs : 0)),
      maxDurationMs,
    };
  }, [activeSession]);

  const handleSeedSamples = async () => {
    setSeeding(true);
    setError(null);
    try {
      const seeded = await api.seedSampleTraces(identity, activeRef);
      setSessions(seeded);
      setQuery("");
      setAppliedQuery("");
      setSessionFilter("all");
      setSpanFilter("all");
      if (seeded[0]) setSelectedSessionId(seeded[0].session_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sample traces");
    } finally {
      setSeeding(false);
    }
  };

  const handleDeleteSession = async (sessionId: string) => {
    if (confirmDeleteId !== sessionId) {
      setConfirmDeleteId(sessionId);
      window.setTimeout(() => {
        setConfirmDeleteId((cur) => (cur === sessionId ? null : cur));
      }, 3000);
      return;
    }
    setDeleting(true);
    try {
      await api.deleteTrace(sessionId);
      setSessions((prev) => prev.filter((s) => s.session_id !== sessionId));
      setConfirmDeleteId(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete trace");
    } finally {
      setDeleting(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setAppliedQuery(query.trim());
  };

  if (loading && !initialLoadedRef.current) {
    return <TracesPageSkeleton />;
  }

  const totalIssues = sessions.reduce((acc, s) => acc + sessionIssueCount(s), 0);
  const totalScrubbed = sessions.reduce((acc, s) => acc + s.delivery.bytes_scrubbed, 0);

  return (
    <div className="pr-page-enter flex min-h-0 flex-1 flex-col overflow-hidden">
      {/* Top command strip */}
      <div className="flex shrink-0 flex-wrap items-center gap-2.5 border-b border-white/[0.07] bg-[#0a0f1f]/75 px-4 py-2.5">
        <div className="flex items-center gap-2.5">
          <div className="pr-icon-tile flex h-8 w-8 items-center justify-center rounded-xl">
            <IconTimeline className="h-4 w-4 text-[#9ec0f5]" />
          </div>
          <h1 className="text-[15px] font-semibold tracking-[-0.02em] text-[#f5f7fd]">Traces</h1>
          <span className="pr-pill rounded-full px-2.5 py-0.5 font-mono text-[12px] text-[#cfe0ff]">
            {sessions.length}
          </span>
          {sseConnected && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-2.5 py-0.5 text-[12px] font-medium text-[#8beac0]">
              <span className="h-1.5 w-1.5 rounded-full bg-[#5bdba2]" />
              Live
            </span>
          )}
          {totalScrubbed > 0 && (
            <span className="hidden items-center gap-1 rounded-full border border-[#67d6dc]/25 bg-[#67d6dc]/10 px-2.5 py-0.5 font-mono text-[12px] text-[#93e6ea] xl:inline-flex">
              <IconShieldCheck className="h-3.5 w-3.5" />
              {totalScrubbed} B scrubbed
            </span>
          )}
        </div>

        <form onSubmit={handleSearchSubmit} className="relative min-w-[200px] flex-1 max-w-md">
          <IconSearch className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[#98a8c4]" />
          <input
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              if (e.target.value === "" && appliedQuery !== "") setAppliedQuery("");
            }}
            placeholder="Blame by Change-Id, commit, branch, or file…"
            aria-label="Search traces"
            className="h-9 w-full rounded-xl border border-white/[0.10] bg-[#080c18]/85 pl-9 pr-8 text-[13px] text-[#f5f7fd] placeholder:text-[#8e9eb8] transition focus:border-[#7f95f8]/50 focus:outline-none"
          />
          {query && (
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setAppliedQuery("");
              }}
              aria-label="Clear search"
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md p-1 text-[#98a8c4] hover:text-white"
            >
              <IconClose className="h-3.5 w-3.5" />
            </button>
          )}
        </form>

        <div className="inline-flex items-center gap-0.5 rounded-full border border-white/[0.08] bg-white/[0.025] p-0.5">
          {(
            [
              { id: "all", label: "All" },
              { id: "issues", label: totalIssues > 0 ? `Issues (${totalIssues})` : "Issues" },
              { id: "active", label: "Active" },
              { id: "blocked", label: "Blocked" },
            ] as { id: SessionFilter; label: string }[]
          ).map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setSessionFilter(f.id)}
              className={`rounded-full px-3 py-1 text-[12.5px] font-medium transition ${
                sessionFilter === f.id
                  ? "pr-pill-active text-[#f5f7fd]"
                  : "text-[#a6b5cf] hover:text-[#f5f7fd]"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-2">
          {owner && identityPresets && identityPresets.length > 1 && onSelectIdentity && (
            <label className="pr-pill hidden h-9 items-center gap-1.5 rounded-xl px-2.5 text-[12px] text-[#a6b5cf] md:inline-flex">
              <IconLock className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span className="sr-only">Simulate ACL identity</span>
              <select
                aria-label="Simulate ACL identity"
                value={identity.id}
                onChange={(e) => {
                  const found = identityPresets.find((p) => p.id === e.target.value);
                  if (found) onSelectIdentity(found);
                }}
                className="bg-transparent font-mono text-[12px] text-[#cfe0ff] focus:outline-none"
              >
                {identityPresets.map((p) => (
                  <option key={p.id} value={p.id} className="bg-[#0b1020] text-[#f5f7fd]">
                    View as: {p.label}
                  </option>
                ))}
              </select>
            </label>
          )}
          <button
            type="button"
            onClick={() => setHookModalOpen(true)}
            className="pr-pill inline-flex h-9 items-center gap-2 rounded-xl px-3 text-[13px] font-medium text-[#cfe0ff] hover:text-white"
          >
            <IconTerminal className="h-4 w-4 text-[#9ec0f5]" />
            <span>Connect Hook</span>
          </button>
          <button
            type="button"
            onClick={() => void loadTraces(appliedQuery, true)}
            disabled={refreshing}
            title="Refresh traces"
            aria-label="Refresh traces"
            className="pr-pill inline-flex h-9 w-9 items-center justify-center rounded-xl text-[#b6c3db] hover:text-white disabled:opacity-50"
          >
            <IconRefresh className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="flex shrink-0 items-center justify-between gap-3 border-b border-[#f27c7c]/25 bg-[#f27c7c]/10 px-4 py-2 text-[13px] text-[#ffb4b4]">
          <span>{error}</span>
          <button
            type="button"
            onClick={() => void loadTraces(appliedQuery, true)}
            className="rounded-lg border border-[#f27c7c]/30 px-2.5 py-1 text-[12px] font-medium hover:bg-[#f27c7c]/15"
          >
            Retry
          </button>
        </div>
      )}

      {/* Empty state when zero traces exist and no search filter is active */}
      {sessions.length === 0 && !appliedQuery ? (
        <div className="pr-stage-backdrop flex min-h-0 flex-1 items-center justify-center overflow-y-auto px-4 py-10">
          <section className="w-full max-w-lg space-y-6 text-center">
            <div className="flex flex-col items-center space-y-3">
              <div className="pr-icon-tile flex h-12 w-12 items-center justify-center rounded-2xl">
                <IconTimeline className="h-6 w-6 text-[#9ec0f5]" />
              </div>
              <div className="space-y-1.5">
                <h2 className="bg-gradient-to-b from-white via-[#eef3fc] to-[#a7b6d2] bg-clip-text text-[22px] font-semibold tracking-[-0.025em] text-transparent">
                  No agent traces yet
                </h2>
                <p className="mx-auto max-w-md text-[14px] leading-relaxed text-[#a6b5cf]">
                  Stream hooks from your coding agents to inspect spans, error diagnostics, and
                  scrubbed egress in real time.
                </p>
              </div>
              <div className="pt-1">
                <AiHarnessCluster />
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-center gap-3">
              <button
                type="button"
                onClick={() => setHookModalOpen(true)}
                className="pr-pill-active inline-flex h-10 items-center gap-2 rounded-xl px-4 text-[13.5px] font-medium text-[#f5f7fd]"
              >
                <IconTerminal className="h-4 w-4 text-[#9ec0f5]" />
                <span>Connect a harness</span>
              </button>
              {owner && (
                <button
                  type="button"
                  onClick={() => void handleSeedSamples()}
                  disabled={seeding}
                  className="pr-pill inline-flex h-10 items-center gap-2 rounded-xl px-4 text-[13.5px] font-medium text-[#d2dbee] hover:text-white disabled:opacity-50"
                >
                  <IconTimeline className="h-4 w-4 text-[#9ec0f5]" />
                  <span>{seeding ? "Loading samples…" : "Load sample traces"}</span>
                </button>
              )}
            </div>
          </section>
        </div>
      ) : (
        <>
          {/* Mobile pane switcher */}
          <div className="flex shrink-0 items-center gap-1 border-b border-white/[0.06] bg-[#0a0f1f]/60 px-4 py-2 lg:hidden">
            {(
              [
                { id: "runs", label: `Runs (${filteredSessions.length})` },
                { id: "timeline", label: `Timeline (${filteredSpans.length})` },
                { id: "inspector", label: "Inspector" },
              ] as const
            ).map((p) => (
              <button
                key={p.id}
                type="button"
                onClick={() => setMobilePane(p.id)}
                className={`rounded-full px-3 py-1 text-[12.5px] font-medium ${
                  mobilePane === p.id ? "pr-pill-active text-[#f5f7fd]" : "text-[#a6b5cf]"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          <div ref={splitContainerRef} className="flex min-h-0 flex-1 gap-2.5 overflow-hidden p-3">
            {/* Left Rail: Recorded Runs */}
            <aside
              aria-label="Recorded trace runs"
              className={`pr-surface min-h-0 shrink-0 flex-col overflow-hidden rounded-2xl lg:flex lg:w-[268px] xl:w-[288px] ${
                mobilePane === "runs" ? "flex flex-1" : "hidden"
              }`}
            >
              <div className="flex shrink-0 items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
                <span className="text-[13px] font-semibold text-[#d2dbee]">Recorded Runs</span>
                <span className="font-mono text-[12px] text-[#98a8c4]">
                  {filteredSessions.length}
                </span>
              </div>

              <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto p-2.5">
                {filteredSessions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center gap-2 py-12 text-center">
                    <p className="text-[13.5px] text-[#a6b5cf]">No runs match this filter.</p>
                    <button
                      type="button"
                      onClick={() => {
                        setSessionFilter("all");
                        setQuery("");
                        setAppliedQuery("");
                      }}
                      className="pr-pill rounded-lg px-3 py-1 text-[12.5px] text-[#cfe0ff]"
                    >
                      Reset filters
                    </button>
                  </div>
                ) : (
                  filteredSessions.map((sess) => {
                    const selected = activeSession?.session_id === sess.session_id;
                    const st = statusStyle(sess.status);
                    const issues = sessionIssueCount(sess);
                    return (
                      <button
                        key={sess.session_id}
                        type="button"
                        onClick={() => {
                          setSelectedSessionId(sess.session_id);
                          setSpanFilter("all");
                          setCorrelationScope(null);
                          setMobilePane("timeline");
                        }}
                        className={`w-full rounded-xl border p-3 text-left transition ${
                          selected
                            ? "border-[#7f95f8]/45 bg-[#7f95f8]/12"
                            : "border-transparent bg-white/[0.015] hover:border-white/[0.08] hover:bg-white/[0.035]"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex min-w-0 items-center gap-2">
                            <BrandIcon
                              name={harnessBrand(sess.tool_name, sess.model)}
                              className="h-4 w-4"
                            />
                            <span className="truncate font-mono text-[13px] font-medium text-[#f5f7fd]">
                              {sess.change_id ?? sess.session_id}
                            </span>
                          </div>
                          <span
                            className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11.5px] font-medium ${st.pill}`}
                          >
                            <span className={`h-1.5 w-1.5 rounded-full ${st.dot}`} />
                            {st.label}
                          </span>
                        </div>

                        <p className="mt-1.5 line-clamp-2 text-[13px] leading-snug text-[#c4d0e6]">
                          {sessionPreview(sess)}
                        </p>

                        <div className="mt-2.5 flex flex-wrap items-center gap-x-2.5 gap-y-1 font-mono text-[12px] text-[#98a8c4]">
                          <span className="text-[#b6c3db]">{sess.principal}</span>
                          <span className="truncate max-w-[120px]">{sess.branch}</span>
                          <span>
                            {sess.delivery.total_spans}{" "}
                            {sess.delivery.total_spans === 1 ? "span" : "spans"}
                          </span>
                          <span className="ml-auto">{formatRelativeTime(sess.updated_at)}</span>
                        </div>

                        {(issues > 0 || sess.delivery.bytes_scrubbed > 0) && (
                          <div className="mt-2 flex flex-wrap gap-1.5">
                            {issues > 0 && (
                              <span className="inline-flex items-center gap-1 rounded-full border border-[#f27c7c]/30 bg-[#f27c7c]/12 px-2 py-0.5 font-mono text-[11.5px] text-[#ffb4b4]">
                                <IconBlock className="h-3 w-3" />
                                {issues} {issues === 1 ? "issue" : "issues"}
                              </span>
                            )}
                            {sess.delivery.bytes_scrubbed > 0 && (
                              <span className="inline-flex items-center gap-1 rounded-full border border-[#67d6dc]/28 bg-[#67d6dc]/12 px-2 py-0.5 font-mono text-[11.5px] text-[#93e6ea]">
                                <IconShieldCheck className="h-3 w-3" />
                                {sess.delivery.bytes_scrubbed} B scrubbed
                              </span>
                            )}
                          </div>
                        )}
                      </button>
                    );
                  })
                )}
              </div>
            </aside>

            {/* Center Stage: Run Overview + Waterfall Timeline */}
            <section
              aria-label="Trace waterfall timeline"
              className={`pr-surface min-h-0 min-w-0 flex-1 flex-col overflow-hidden rounded-2xl lg:flex ${
                mobilePane === "timeline" ? "flex" : "hidden"
              }`}
            >
              {!activeSession ? (
                <div className="flex flex-1 items-center justify-center p-8 text-[14px] text-[#a6b5cf]">
                  Select a trace run to inspect its spans.
                </div>
              ) : (
                <>
                  {/* Run overview header */}
                  <div className="shrink-0 space-y-3 border-b border-white/[0.07] bg-[#0a0f1f]/65 px-5 py-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex min-w-0 flex-1 items-start gap-2.5">
                        <div className="pr-icon-tile mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl">
                          <BrandIcon
                            name={harnessBrand(activeSession.tool_name, activeSession.model)}
                            className="h-5 w-5"
                          />
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <h2 className="truncate font-mono text-[15px] font-semibold text-[#f5f7fd]">
                              {activeSession.session_id}
                            </h2>
                            <span
                              className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[12px] font-medium ${statusStyle(activeSession.status).pill}`}
                            >
                              <span
                                className={`h-1.5 w-1.5 rounded-full ${statusStyle(activeSession.status).dot}`}
                              />
                              {statusStyle(activeSession.status).label}
                            </span>
                            {activeSession.change_id && (
                              <button
                                type="button"
                                onClick={() => onOpenReview?.(activeSession.change_id!)}
                                disabled={!onOpenReview}
                                className="rounded-full border border-[#7f95f8]/30 bg-[#7f95f8]/14 px-2.5 py-0.5 font-mono text-[12px] text-[#cfe0ff] transition hover:bg-[#7f95f8]/22 disabled:cursor-default"
                              >
                                {activeSession.change_id}
                              </button>
                            )}
                          </div>
                          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-[12.5px] text-[#a6b5cf]">
                            <span className="text-[#dce4f5]">{activeSession.principal}</span>
                            {activeSession.agent_profile && (
                              <span>profile: {activeSession.agent_profile}</span>
                            )}
                            <span>{activeSession.model}</span>
                            {onOpenBranch ? (
                              <button
                                type="button"
                                onClick={() => onOpenBranch(activeSession.branch)}
                                className="inline-flex items-center gap-1 text-[#cfe0ff] hover:text-white hover:underline"
                              >
                                <IconBranchRef className="h-3.5 w-3.5 text-[#9ec0f5]" />
                                {activeSession.branch}
                              </button>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-[#cfe0ff]">
                                <IconBranchRef className="h-3.5 w-3.5 text-[#9ec0f5]" />
                                {activeSession.branch}
                              </span>
                            )}
                            {activeSession.commit_oid &&
                              (onOpenCommit ? (
                                <button
                                  type="button"
                                  onClick={() => onOpenCommit(activeSession.commit_oid!)}
                                  className="text-[#9ec0f5] hover:text-white hover:underline"
                                >
                                  {activeSession.commit_oid.slice(0, 7)}
                                </button>
                              ) : (
                                <span>{activeSession.commit_oid.slice(0, 7)}</span>
                              ))}
                          </div>
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => copyValue("sid", activeSession.session_id)}
                          title={copiedKey === "sid" ? "Copied session ID" : "Copy session ID"}
                          aria-label="Copy session ID"
                          className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#d2dbee] hover:text-white"
                        >
                          {copiedKey === "sid" ? (
                            <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                          ) : (
                            <IconCopy className="h-3.5 w-3.5 text-[#9ec0f5]" />
                          )}
                        </button>
                        <button
                          type="button"
                          title="Export run evidence JSON"
                          onClick={() => {
                            const blob = new Blob([JSON.stringify(activeSession, null, 2)], {
                              type: "application/json",
                            });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement("a");
                            a.href = url;
                            a.download = `${activeSession.session_id}.trace.json`;
                            a.click();
                            window.setTimeout(() => URL.revokeObjectURL(url), 1000);
                          }}
                          className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#b6c3db] hover:text-white"
                          aria-label="Export run evidence JSON"
                        >
                          <IconDownload className="h-3.5 w-3.5" />
                        </button>
                        {owner && (
                          <button
                            type="button"
                            disabled={deleting}
                            onClick={() => void handleDeleteSession(activeSession.session_id)}
                            title={
                              confirmDeleteId === activeSession.session_id
                                ? "Click again to delete trace"
                                : "Delete trace"
                            }
                            className={`inline-flex h-8 items-center gap-1.5 rounded-lg border px-2.5 text-[12.5px] font-medium transition ${
                              confirmDeleteId === activeSession.session_id
                                ? "border-[#f27c7c]/50 bg-[#f27c7c]/20 text-[#ffb4b4]"
                                : "border-white/[0.08] bg-white/[0.03] text-[#a6b5cf] hover:border-[#f27c7c]/35 hover:text-[#ffb4b4]"
                            }`}
                          >
                            <IconTrash className="h-3.5 w-3.5" />
                            {confirmDeleteId === activeSession.session_id && <span>Confirm</span>}
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Compact KPI strip */}
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                      <div className="pr-well rounded-xl px-3 py-2">
                        <div className="text-[12px] text-[#98a8c4]">Spans</div>
                        <div className="mt-0.5 font-mono text-[15px] font-semibold text-[#f5f7fd]">
                          {activeSession.delivery.total_spans}
                        </div>
                      </div>
                      <div className="pr-well rounded-xl px-3 py-2">
                        <div className="text-[12px] text-[#98a8c4]">Duration</div>
                        <div className="mt-0.5 font-mono text-[15px] font-semibold text-[#f5f7fd]">
                          {formatDuration(activeSession.delivery.duration_ms)}
                        </div>
                      </div>
                      <div className="pr-well rounded-xl px-3 py-2">
                        <div className="text-[12px] text-[#98a8c4]">Issues</div>
                        <div
                          className={`mt-0.5 font-mono text-[15px] font-semibold ${
                            sessionIssueCount(activeSession) > 0
                              ? "text-[#f27c7c]"
                              : "text-[#5bdba2]"
                          }`}
                        >
                          {sessionIssueCount(activeSession)}
                        </div>
                      </div>
                      <div className="pr-well rounded-xl px-3 py-2">
                        <div className="text-[12px] text-[#98a8c4]">Scrubbed</div>
                        <div
                          className={`mt-0.5 font-mono text-[15px] font-semibold ${
                            activeSession.delivery.bytes_scrubbed > 0
                              ? "text-[#67d6dc]"
                              : "text-[#d2dbee]"
                          }`}
                        >
                          {activeSession.delivery.bytes_scrubbed} B
                        </div>
                      </div>
                      <div className="pr-well col-span-2 rounded-xl px-3 py-2 sm:col-span-1">
                        <div className="text-[12px] text-[#98a8c4]">
                          {(activeSession.delivery.total_tokens_in ?? 0) +
                            (activeSession.delivery.total_tokens_out ?? 0) >
                          0
                            ? "Tokens"
                            : "Files"}
                        </div>
                        <div className="mt-0.5 font-mono text-[15px] font-semibold text-[#f5f7fd]">
                          {(activeSession.delivery.total_tokens_in ?? 0) +
                            (activeSession.delivery.total_tokens_out ?? 0) >
                          0
                            ? (
                                (activeSession.delivery.total_tokens_in ?? 0) +
                                (activeSession.delivery.total_tokens_out ?? 0)
                              ).toLocaleString()
                            : activeSession.delivery.files_touched.length}
                        </div>
                      </div>
                    </div>

                    {/* Authorized files touched (click to filter) + provenance digest */}
                    {(activeSession.delivery.files_touched.length > 0 ||
                      activeSession.delivery.provenance_digest) && (
                      <div className="flex flex-wrap items-center gap-1.5">
                        {activeSession.delivery.files_touched.slice(0, 5).map((file) => {
                          const isFiltered = fileFilter === file;
                          return (
                            <button
                              key={file}
                              type="button"
                              onClick={() => {
                                setRunView("timeline");
                                setFileFilter((cur) => (cur === file ? null : file));
                              }}
                              title={
                                isFiltered
                                  ? `Clear filter for ${file}`
                                  : `Filter timeline to spans touching ${file}`
                              }
                              className={`inline-flex max-w-[240px] items-center gap-1.5 rounded-lg border px-2.5 py-1 font-mono text-[12px] transition ${
                                isFiltered
                                  ? "border-[#7f95f8]/55 bg-[#7f95f8]/20 text-white"
                                  : "border-white/[0.08] bg-white/[0.03] text-[#cfe0ff] hover:border-[#7f95f8]/40 hover:bg-white/[0.06]"
                              }`}
                            >
                              <IconFileNode className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
                              <span className="truncate">{file}</span>
                            </button>
                          );
                        })}
                        {activeSession.delivery.files_touched.length > 5 && (
                          <span className="font-mono text-[12px] text-[#98a8c4]">
                            +{activeSession.delivery.files_touched.length - 5} more
                          </span>
                        )}
                        {activeSession.delivery.provenance_digest && (() => {
                          const integ = activeSession.delivery.integrity;
                          const st = integ?.status ?? "verified";
                          const badgeCls =
                            st === "tampered"
                              ? "border-[#f27c7c]/40 bg-[#f27c7c]/15 text-[#ffb4b4]"
                              : st === "live"
                                ? "border-[#7f95f8]/30 bg-[#7f95f8]/12 text-[#cfe0ff]"
                                : "border-[#5bdba2]/25 bg-[#5bdba2]/10 text-[#8beac0]";
                          const prefix =
                            st === "tampered" ? "Tampered" : st === "live" ? "Live" : "Verified";
                          return (
                            <button
                              type="button"
                              onClick={() => {
                                setInspectorTab("relations");
                                setMobilePane("inspector");
                              }}
                              title={`SHA-256 hash-chain (${prefix}): ${activeSession.delivery.provenance_digest}`}
                              className={`ml-auto inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 font-mono text-[11.5px] transition hover:brightness-110 ${badgeCls}`}
                            >
                              <IconShieldCheck className="h-3.5 w-3.5" />
                              <span>{prefix}</span>
                              <span className="opacity-75">
                                {activeSession.delivery.provenance_digest.slice(0, 8)}
                              </span>
                            </button>
                          );
                        })()}
                      </div>
                    )}
                  </div>

                  {/* Run sub-view switcher + inline span search */}
                  <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] bg-[#0a0f1f]/45 px-4 py-2">
                    <div
                      role="tablist"
                      aria-label="Run inspection mode"
                      className="inline-flex items-center gap-1 rounded-xl border border-white/[0.07] bg-white/[0.025] p-0.5"
                    >
                      {(
                        [
                          { id: "timeline", label: "Timeline", count: activeSession.spans.length },
                          { id: "diffs", label: "Diffs & Code", count: codeEvidenceSpans.length },
                          { id: "security", label: "Security & ACLs", count: securityAuditSpans.length },
                          ...(sessions.length >= 2
                            ? [{ id: "compare" as RunViewMode, label: "Compare", count: null }]
                            : []),
                        ] as { id: RunViewMode; label: string; count: number | null }[]
                      ).map((m) => (
                        <button
                          key={m.id}
                          type="button"
                          role="tab"
                          aria-selected={runView === m.id}
                          onClick={() => setRunView(m.id)}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[12.5px] font-medium transition ${
                            runView === m.id
                              ? "pr-pill-active text-[#f5f7fd]"
                              : "text-[#a6b5cf] hover:text-[#f5f7fd]"
                          }`}
                        >
                          <span>{m.label}</span>
                          {m.count !== null && (
                            <span
                              className={`rounded-full px-1.5 py-px font-mono text-[11px] ${
                                runView === m.id
                                  ? "bg-white/[0.12] text-white"
                                  : "bg-white/[0.05] text-[#98a8c4]"
                              }`}
                            >
                              {m.count}
                            </span>
                          )}
                        </button>
                      ))}
                    </div>

                    {runView === "timeline" && (
                      <div className="relative min-w-[160px] flex-1 sm:max-w-[220px]">
                        <IconSearch className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#8595b0]" />
                        <input
                          ref={spanSearchInputRef}
                          type="search"
                          value={spanQuery}
                          onChange={(e) => setSpanQuery(e.target.value)}
                          placeholder="Filter spans (/)"
                          aria-label="Filter spans inside this run"
                          className="pr-input h-8 w-full rounded-lg pl-8 pr-2.5 font-mono text-[12px] text-[#f5f7fd] placeholder:text-[#7f8ea8]"
                        />
                      </div>
                    )}
                  </div>

                  {/* Automated Incident / Failure Investigation Callout */}
                  {runView === "timeline" && primaryIncidentSpan && (
                    <div className="flex shrink-0 items-start justify-between gap-3 border-b border-[#f27c7c]/25 bg-[#f27c7c]/[0.07] px-4 py-2.5">
                      <div className="flex min-w-0 items-start gap-2.5">
                        <IconBlock className="mt-0.5 h-4 w-4 shrink-0 text-[#f27c7c]" />
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2 font-mono text-[12px]">
                            <span className="font-semibold text-[#ffb4b4]">
                              First failure / block
                            </span>
                            <span className="text-[#dce4f5]">{primaryIncidentSpan.span_id}</span>
                            {primaryIncidentSpan.zone && (
                              <span className="rounded bg-white/[0.06] px-1.5 py-px text-[11px] text-[#cfe0ff]">
                                zone:{primaryIncidentSpan.zone}
                              </span>
                            )}
                          </div>
                          <p className="mt-0.5 line-clamp-1 text-[12.5px] text-[#ffd2d2]">
                            <RedactedText
                              text={
                                primaryIncidentSpan.error_message ?? primaryIncidentSpan.summary
                              }
                            />
                          </p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedSpanId(primaryIncidentSpan.span_id);
                          setInspectorTab("overview");
                          setMobilePane("inspector");
                        }}
                        className="shrink-0 rounded-lg border border-[#f27c7c]/35 bg-[#f27c7c]/15 px-2.5 py-1 font-mono text-[11.5px] font-medium text-[#ffd2d2] transition hover:bg-[#f27c7c]/25 hover:text-white"
                      >
                        Jump to failure
                      </button>
                    </div>
                  )}

                  {/* Active scope / file filter banners */}
                  {(correlationScope || fileFilter) && (
                    <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-[#7f95f8]/25 bg-[#7f95f8]/10 px-4 py-1.5 font-mono text-[12px] text-[#cfe0ff]">
                      <div className="flex flex-wrap items-center gap-3">
                        {correlationScope && (
                          <span>
                            Correlation: <strong className="text-white">{correlationScope}</strong>
                          </span>
                        )}
                        {fileFilter && (
                          <span>
                            File: <strong className="text-white">{fileFilter}</strong>
                          </span>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setCorrelationScope(null);
                          setFileFilter(null);
                        }}
                        className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[#cfe0ff] hover:bg-white/[0.08] hover:text-white"
                      >
                        <IconClose className="h-3 w-3" />
                        <span>Clear</span>
                      </button>
                    </div>
                  )}

                  {runView === "compare" ? (
                    /* Side-by-side Run Comparison (active vs selectable baseline) */
                    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
                      <div className="pr-well flex flex-wrap items-center justify-between gap-2.5 rounded-xl p-3">
                        <div className="flex flex-wrap items-center gap-2 font-mono text-[12px]">
                          <span className="rounded bg-[#7f95f8]/20 px-2 py-0.5 text-[#cfe0ff]">
                            Active: {activeSession.session_id}
                          </span>
                          <span className="text-[#8595b0]">vs</span>
                          <select
                            aria-label="Baseline run to compare"
                            value={baselineSession?.session_id ?? ""}
                            onChange={(e) => setCompareSessionId(e.target.value)}
                            className="pr-input h-8 rounded-lg px-2.5 font-mono text-[12px] text-[#f5f7fd]"
                          >
                            {sessions
                              .filter((s) => s.session_id !== activeSession.session_id)
                              .map((s) => (
                                <option
                                  key={s.session_id}
                                  value={s.session_id}
                                  className="bg-[#0b1020] text-[#f5f7fd]"
                                >
                                  {s.change_id ?? s.session_id} ({s.status})
                                </option>
                              ))}
                          </select>
                        </div>
                        {baselineSession && (
                          <button
                            type="button"
                            onClick={() => {
                              const prev = activeSession.session_id;
                              setSelectedSessionId(baselineSession.session_id);
                              setCompareSessionId(prev);
                            }}
                            className="pr-pill rounded-lg px-2.5 py-1 font-mono text-[11.5px] text-[#cfe0ff] hover:text-white"
                          >
                            Swap runs
                          </button>
                        )}
                      </div>

                      {!baselineSession ? (
                        <div className="py-10 text-center text-[13.5px] text-[#a6b5cf]">
                          Record at least two trace runs to compare deltas side by side.
                        </div>
                      ) : (() => {
                        const a = activeSession.delivery;
                        const b = baselineSession.delivery;
                        const aTok = (a.total_tokens_in ?? 0) + (a.total_tokens_out ?? 0);
                        const bTok = (b.total_tokens_in ?? 0) + (b.total_tokens_out ?? 0);
                        const aCost = (a.total_cost_usd_micros ?? 0) / 1_000_000;
                        const bCost = (b.total_cost_usd_micros ?? 0) / 1_000_000;
                        const aIssues = sessionIssueCount(activeSession);
                        const bIssues = sessionIssueCount(baselineSession);

                        const deltaRow = (
                          label: string,
                          aText: string,
                          bText: string,
                          delta: number,
                          deltaText: string,
                          lowerIsBetter = true,
                        ) => {
                          const tone =
                            delta === 0
                              ? "text-[#98a8c4]"
                              : (lowerIsBetter ? delta < 0 : delta > 0)
                                ? "text-[#5bdba2]"
                                : "text-[#f27c7c]";
                          return (
                            <div
                              key={label}
                              className="pr-well rounded-xl p-3 font-mono text-[12px]"
                            >
                              <div className="text-[#98a8c4]">{label}</div>
                              <div className="mt-1 flex items-baseline justify-between gap-2">
                                <span className="text-[15px] font-semibold text-[#f5f7fd]">
                                  {aText}
                                </span>
                                <span className={`text-[12px] font-medium ${tone}`}>
                                  {deltaText}
                                </span>
                              </div>
                              <div className="mt-0.5 text-[11.5px] text-[#7f8ea8]">
                                baseline: {bText}
                              </div>
                            </div>
                          );
                        };

                        const aFiles = new Set(a.files_touched);
                        const bFiles = new Set(b.files_touched);
                        const onlyA = a.files_touched.filter((f) => !bFiles.has(f));
                        const onlyB = b.files_touched.filter((f) => !aFiles.has(f));
                        const shared = a.files_touched.filter((f) => bFiles.has(f));

                        const durDelta = a.duration_ms - b.duration_ms;
                        const tokDelta = aTok - bTok;
                        const costDelta = aCost - bCost;
                        const issDelta = aIssues - bIssues;
                        const scrDelta = a.bytes_scrubbed - b.bytes_scrubbed;
                        const spDelta = a.total_spans - b.total_spans;

                        return (
                          <>
                            <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3">
                              {deltaRow(
                                "Duration",
                                formatDuration(a.duration_ms),
                                formatDuration(b.duration_ms),
                                durDelta,
                                `${durDelta >= 0 ? "+" : "-"}${formatDuration(Math.abs(durDelta))}`,
                              )}
                              {deltaRow(
                                "Spans",
                                String(a.total_spans),
                                String(b.total_spans),
                                spDelta,
                                `${spDelta >= 0 ? "+" : ""}${spDelta}`,
                              )}
                              {deltaRow(
                                "Issues",
                                String(aIssues),
                                String(bIssues),
                                issDelta,
                                `${issDelta >= 0 ? "+" : ""}${issDelta}`,
                              )}
                              {deltaRow(
                                "Tokens",
                                aTok.toLocaleString(),
                                bTok.toLocaleString(),
                                tokDelta,
                                `${tokDelta >= 0 ? "+" : ""}${tokDelta.toLocaleString()}`,
                              )}
                              {deltaRow(
                                "Est. Cost",
                                `$${aCost.toFixed(4)}`,
                                `$${bCost.toFixed(4)}`,
                                costDelta,
                                `${costDelta >= 0 ? "+" : "-"}$${Math.abs(costDelta).toFixed(4)}`,
                              )}
                              {deltaRow(
                                "Scrubbed",
                                `${a.bytes_scrubbed} B`,
                                `${b.bytes_scrubbed} B`,
                                scrDelta,
                                `${scrDelta >= 0 ? "+" : ""}${scrDelta} B`,
                                false,
                              )}
                            </div>

                            <div className="pr-well space-y-2.5 rounded-xl p-3.5">
                              <div className="font-mono text-[12px] font-semibold uppercase tracking-wider text-[#98a8c4]">
                                File Footprint Delta
                              </div>
                              <div className="flex flex-wrap gap-1.5 font-mono text-[12px]">
                                {onlyA.map((f) => (
                                  <span
                                    key={`+:${f}`}
                                    className="rounded-lg border border-[#5bdba2]/30 bg-[#5bdba2]/10 px-2 py-0.5 text-[#8beac0]"
                                  >
                                    + {f}
                                  </span>
                                ))}
                                {onlyB.map((f) => (
                                  <span
                                    key={`-:${f}`}
                                    className="rounded-lg border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-2 py-0.5 text-[#ffb4b4]"
                                  >
                                    - {f}
                                  </span>
                                ))}
                                {shared.map((f) => (
                                  <span
                                    key={`=:${f}`}
                                    className="rounded-lg border border-white/[0.08] bg-white/[0.03] px-2 py-0.5 text-[#cfe0ff]"
                                  >
                                    = {f}
                                  </span>
                                ))}
                                {onlyA.length === 0 && onlyB.length === 0 && shared.length === 0 && (
                                  <span className="text-[#8595b0]">No authorized file paths touched in either run.</span>
                                )}
                              </div>
                            </div>
                          </>
                        );
                      })()}
                    </div>
                  ) : runView === "diffs" ? (
                    /* Aggregated Diffs & Code view */
                    <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
                      {codeEvidenceSpans.length === 0 ? (
                        <div className="py-12 text-center text-[13.5px] text-[#a6b5cf]">
                          No unified diffs or code snippets were recorded for this run.
                        </div>
                      ) : (
                        codeEvidenceSpans.map((sp) => (
                          <div
                            key={sp.span_id}
                            className="pr-well space-y-2.5 rounded-2xl border border-white/[0.06] p-3.5"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex min-w-0 flex-wrap items-center gap-2 font-mono text-[12px]">
                                <span className="truncate font-semibold text-[#f5f7fd]">
                                  {sp.path ?? sp.span_id}
                                </span>
                                {sp.zone && (
                                  <span className="rounded-md bg-white/[0.05] px-2 py-0.5 text-[11.5px] text-[#a6b5cf]">
                                    zone:{sp.zone}
                                  </span>
                                )}
                                {sp.actor_id && (
                                  <span className="text-[#98a8c4]">{sp.actor_id}</span>
                                )}
                                <span className="text-[#7f8ea8]">
                                  {formatOffset(sp.timestamp, timelineStats.startMs)}
                                </span>
                              </div>
                              <button
                                type="button"
                                onClick={() => {
                                  setSelectedSpanId(sp.span_id);
                                  setInspectorTab("data");
                                  setMobilePane("inspector");
                                }}
                                className="pr-pill rounded-lg px-2.5 py-1 font-mono text-[11.5px] text-[#cfe0ff] hover:text-white"
                              >
                                Inspect I/O
                              </button>
                            </div>
                            <p className="text-[13px] text-[#b6c3db]">
                              <RedactedText text={sp.summary} />
                            </p>
                            {sp.diff && (
                              <DiffBlock
                                patch={sp.diff}
                                filePath={sp.path ?? undefined}
                                language={sp.language ?? undefined}
                                maxHeightClass="max-h-[420px]"
                                allowSplit
                              />
                            )}
                            {sp.code_snippet && (
                              <CodeBlock
                                code={sp.code_snippet}
                                label={sp.path ?? "Code snippet"}
                                filePath={sp.path ?? undefined}
                                language={sp.language ?? undefined}
                                showLineNumbers
                                maxHeightClass="max-h-[360px]"
                              />
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  ) : runView === "security" ? (
                    /* Dedicated Security, Scrubbing & ACL Audit view */
                    <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
                      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3">
                        <div className="pr-well rounded-xl p-3">
                          <div className="text-[12px] text-[#98a8c4]">Pre-Write Scrubbed</div>
                          <div className="mt-1 font-mono text-[16px] font-semibold text-[#67d6dc]">
                            {activeSession.delivery.bytes_scrubbed} B
                          </div>
                          <div className="mt-0.5 text-[11.5px] text-[#8595b0]">
                            never persisted to disk
                          </div>
                        </div>
                        <div className="pr-well rounded-xl p-3">
                          <div className="text-[12px] text-[#98a8c4]">Audited Spans</div>
                          <div className="mt-1 font-mono text-[16px] font-semibold text-[#f5f7fd]">
                            {securityAuditSpans.length} / {activeSession.spans.length}
                          </div>
                          <div className="mt-0.5 text-[11.5px] text-[#8595b0]">
                            egress, ACL &amp; policy receipts
                          </div>
                        </div>
                        <div className="pr-well col-span-2 rounded-xl p-3 sm:col-span-1">
                          <div className="text-[12px] text-[#98a8c4]">Blocked / Denied</div>
                          <div
                            className={`mt-1 font-mono text-[16px] font-semibold ${
                              activeSession.delivery.blocked_count > 0
                                ? "text-[#f27c7c]"
                                : "text-[#5bdba2]"
                            }`}
                          >
                            {activeSession.delivery.blocked_count}
                          </div>
                          <div className="mt-0.5 text-[11.5px] text-[#8595b0]">
                            enforced server-side
                          </div>
                        </div>
                      </div>

                      {/* Actor Usage & Cost Breakdown */}
                      {actorUsage.length > 0 && (
                        <div className="pr-well space-y-2 rounded-xl p-3.5">
                          <div className="flex items-center justify-between font-mono text-[12px]">
                            <span className="font-semibold uppercase tracking-wider text-[#98a8c4]">
                              Usage &amp; Cost by Actor
                            </span>
                            <span className="text-[#8595b0]">
                              {actorUsage.length} actor{actorUsage.length === 1 ? "" : "s"}
                            </span>
                          </div>
                          <div className="space-y-1.5">
                            {actorUsage.map((row) => {
                              const tok = row.tokensIn + row.tokensOut;
                              const maxTok = Math.max(
                                1,
                                ...actorUsage.map((r) => r.tokensIn + r.tokensOut),
                              );
                              const pct = tok > 0 ? Math.max(6, Math.round((tok / maxTok) * 100)) : 0;
                              return (
                                <div key={row.actor} className="space-y-1 font-mono text-[12px]">
                                  <div className="flex items-center justify-between gap-2">
                                    <span className="truncate text-[#dce4f5]">{row.actor}</span>
                                    <span className="shrink-0 text-[#98a8c4]">
                                      {row.spans} sp
                                      {tok > 0 ? ` · ${tok.toLocaleString()} tok` : ""}
                                      {row.costMicros > 0
                                        ? ` · $${(row.costMicros / 1_000_000).toFixed(4)}`
                                        : ""}
                                    </span>
                                  </div>
                                  {pct > 0 && (
                                    <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
                                      <div
                                        className="h-full rounded-full bg-gradient-to-r from-[#7f95f8] to-[#67d6dc]"
                                        style={{ width: `${pct}%` }}
                                      />
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {securityAuditSpans.length === 0 ? (
                        <div className="py-10 text-center text-[13.5px] text-[#a6b5cf]">
                          No secret scrubs, egress proxy calls, or policy denials in this run.
                        </div>
                      ) : (
                        securityAuditSpans.map((sp) => {
                          const meta = KIND_META[sp.kind] ?? KIND_META.tool_call;
                          return (
                            <div
                              key={sp.span_id}
                              className="pr-well space-y-2.5 rounded-2xl border border-white/[0.06] p-3.5"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex flex-wrap items-center gap-1.5">
                                  <span
                                    className={`rounded-full border px-2 py-0.5 font-mono text-[11.5px] font-medium ${meta.badge}`}
                                  >
                                    {meta.label}
                                  </span>
                                  {sp.decision && (
                                    <span
                                      className={`rounded-full border px-2 py-0.5 font-mono text-[11.5px] ${decisionStyle(sp.decision)}`}
                                    >
                                      {humanizeDecision(sp.decision)}
                                    </span>
                                  )}
                                  {sp.bytes_scrubbed > 0 && (
                                    <span className="inline-flex items-center gap-1 rounded-full border border-[#67d6dc]/30 bg-[#67d6dc]/12 px-2 py-0.5 font-mono text-[11.5px] text-[#93e6ea]">
                                      <IconShieldCheck className="h-3 w-3" />
                                      {sp.bytes_scrubbed} B scrubbed
                                    </span>
                                  )}
                                  {sp.zone && (
                                    <span className="rounded-md bg-white/[0.05] px-2 py-0.5 font-mono text-[11.5px] text-[#a6b5cf]">
                                      zone:{sp.zone}
                                    </span>
                                  )}
                                </div>
                                <button
                                  type="button"
                                  onClick={() => {
                                    setSelectedSpanId(sp.span_id);
                                    setInspectorTab("data");
                                    setMobilePane("inspector");
                                  }}
                                  className="pr-pill rounded-lg px-2.5 py-1 font-mono text-[11.5px] text-[#cfe0ff] hover:text-white"
                                >
                                  Inspect span
                                </button>
                              </div>
                              <p className="text-[13px] leading-relaxed text-[#f5f7fd]">
                                <RedactedText text={sp.summary} />
                              </p>
                              {sp.error_message && (
                                <p className="rounded-lg border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-2 font-mono text-[12px] text-[#ffd2d2]">
                                  <RedactedText text={sp.error_message} />
                                </p>
                              )}
                              {sp.authority !== undefined && sp.authority !== null && (
                                <EvidenceValue label="Policy Receipt" value={sp.authority} compact />
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>
                  ) : (
                    <>
                      {/* Span kind filter bar */}
                      <div className="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-white/[0.06] px-4 py-2">
                        {(
                          [
                            { id: "all", label: `All (${spanCounts.all})` },
                            { id: "issues", label: `Issues (${spanCounts.issues})` },
                            ...(spanCounts.redacted > 0
                              ? [{ id: "redacted" as SpanFilter, label: `Redacted (${spanCounts.redacted})` }]
                              : []),
                            ...(
                              [
                                "prompt_turn",
                                "tool_call",
                                "file_access",
                                "proxy_egress",
                                "error_diagnostic",
                                "delivery_report",
                              ] as TraceSpanKind[]
                            )
                              .filter((k) => spanCounts[k] > 0)
                              .map((k) => ({
                                id: k as SpanFilter,
                                label: `${KIND_META[k].short} (${spanCounts[k]})`,
                              })),
                          ] as { id: SpanFilter; label: string }[]
                        ).map((f) => (
                          <button
                            key={f.id}
                            type="button"
                            onClick={() => setSpanFilter(f.id)}
                            className={`rounded-full px-2.5 py-1 text-[12px] font-medium transition ${
                              spanFilter === f.id
                                ? "pr-pill-active text-[#f5f7fd]"
                                : "text-[#a6b5cf] hover:bg-white/[0.04] hover:text-[#f5f7fd]"
                            }`}
                          >
                            {f.label}
                          </button>
                        ))}
                      </div>

                      {/* Waterfall span list with proportional Gantt bars */}
                      <div className="min-h-0 flex-1 space-y-1.5 overflow-y-auto p-3">
                        {filteredSpans.length === 0 ? (
                          <div className="py-10 text-center text-[13.5px] text-[#a6b5cf]">
                            No spans match this filter.
                          </div>
                        ) : (
                          filteredSpans.map((sp, idx) => {
                            const meta = KIND_META[sp.kind] ?? KIND_META.tool_call;
                            const selected = activeSpan?.span_id === sp.span_id;
                            const isChild = Boolean(
                              sp.parent_span_id && spanIdsInRun.has(sp.parent_span_id),
                            );
                            const spanStartMs = Date.parse(sp.timestamp);
                            const relStart = Number.isFinite(spanStartMs)
                              ? Math.max(0, spanStartMs - timelineStats.startMs)
                              : 0;
                            const rawOffsetPct = (relStart / timelineStats.totalSpanMs) * 100;
                            const durationWidthPct = sp.duration_ms
                              ? Math.max(
                                  10,
                                  Math.min(
                                    62,
                                    (sp.duration_ms / timelineStats.maxDurationMs) * 42,
                                  ),
                                )
                              : 10;
                            const ganttLeftPct = Math.min(
                              Math.max(0, rawOffsetPct * 0.72),
                              100 - durationWidthPct,
                            );

                            return (
                              <div
                                key={`${sp.span_id}-${idx}`}
                                className={isChild ? "ml-2 border-l border-white/[0.08] pl-3.5" : ""}
                              >
                                <button
                                  type="button"
                                  onClick={() => {
                                    setSelectedSpanId(sp.span_id);
                                    setMobilePane("inspector");
                                  }}
                                  aria-current={selected ? "step" : undefined}
                                  className={`flex w-full items-start gap-3 rounded-xl border px-3.5 py-3 text-left transition ${
                                    selected
                                      ? "border-[#7f95f8]/50 bg-[#7f95f8]/12"
                                      : isIssueSpan(sp)
                                        ? "border-[#f27c7c]/22 bg-[#f27c7c]/[0.04] hover:border-[#f27c7c]/38"
                                        : "border-white/[0.05] bg-white/[0.015] hover:border-white/[0.10] hover:bg-white/[0.03]"
                                  }`}
                                >
                                  <span
                                    className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${meta.dot}`}
                                    aria-hidden="true"
                                  />

                                  <div className="min-w-0 flex-1 space-y-1.5">
                                    <div className="flex flex-wrap items-center gap-1.5">
                                      <span
                                        className={`rounded-full border px-2 py-0.5 font-mono text-[11.5px] font-medium ${meta.badge}`}
                                      >
                                        {meta.label}
                                      </span>
                                      {sp.tool_name && (
                                        <span className="font-mono text-[12px] text-[#b6c3db]">
                                          {sp.tool_name}
                                        </span>
                                      )}
                                      {sp.decision && (
                                        <span
                                          className={`rounded-full border px-2 py-0.5 font-mono text-[11.5px] ${decisionStyle(sp.decision)}`}
                                        >
                                          {humanizeDecision(sp.decision)}
                                        </span>
                                      )}
                                      {sp.diff && (
                                        <span className="rounded-md border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-1.5 py-0.5 font-mono text-[11px] text-[#8beac0]">
                                          Diff
                                        </span>
                                      )}
                                      {!sp.diff && sp.code_snippet && (
                                        <span className="rounded-md border border-[#9ec0f5]/25 bg-[#9ec0f5]/10 px-1.5 py-0.5 font-mono text-[11px] text-[#cfe0ff]">
                                          Code
                                        </span>
                                      )}
                                      {sp.redacted_for_viewer && (
                                        <span className="inline-flex items-center gap-1 rounded-full border border-[#7f95f8]/30 bg-[#7f95f8]/12 px-2 py-0.5 font-mono text-[11.5px] text-[#b8c6ff]">
                                          <IconLock className="h-3 w-3" />
                                          ACL Redacted
                                        </span>
                                      )}
                                      {sp.bytes_scrubbed > 0 && (
                                        <span className="inline-flex items-center gap-1 rounded-full border border-[#67d6dc]/28 bg-[#67d6dc]/12 px-2 py-0.5 font-mono text-[11.5px] text-[#93e6ea]">
                                          <IconShieldCheck className="h-3 w-3" />
                                          {sp.bytes_scrubbed} B scrubbed
                                        </span>
                                      )}
                                    </div>

                                    <p
                                      className={`line-clamp-2 text-[13.5px] leading-snug ${
                                        sp.redacted_for_viewer
                                          ? "italic text-[#a6b5cf]"
                                          : "text-[#f5f7fd]"
                                      }`}
                                    >
                                      <RedactedText text={sp.summary} />
                                    </p>

                                    {(sp.path || sp.zone) && (
                                      <div className="flex flex-wrap items-center gap-1.5">
                                        {sp.path && (
                                          <span className="max-w-full truncate rounded-md bg-black/30 px-2 py-0.5 font-mono text-[12px] text-[#9ec0f5]">
                                            {sp.path}
                                          </span>
                                        )}
                                        {sp.zone && (
                                          <span className="rounded-md bg-white/[0.05] px-2 py-0.5 font-mono text-[11.5px] text-[#a6b5cf]">
                                            zone:{sp.zone}
                                          </span>
                                        )}
                                      </div>
                                    )}
                                  </div>

                                  {/* Waterfall proportional Gantt column */}
                                  <div className="hidden w-[138px] shrink-0 flex-col items-end gap-1.5 pt-0.5 sm:flex">
                                    <div className="flex items-center gap-2 font-mono text-[12px]">
                                      <span className="text-[#98a8c4]">
                                        {formatOffset(sp.timestamp, timelineStats.startMs)}
                                      </span>
                                      <span className="text-[#dce4f5]">
                                        {formatDuration(sp.duration_ms)}
                                      </span>
                                    </div>
                                    <div className="relative h-2 w-full overflow-hidden rounded-full bg-white/[0.07]">
                                      <div
                                        className={`absolute top-0 h-full rounded-full ${meta.bar} opacity-90`}
                                        style={{
                                          left: `${ganttLeftPct}%`,
                                          width: `${durationWidthPct}%`,
                                        }}
                                      />
                                    </div>
                                  </div>
                                </button>
                              </div>
                            );
                          })
                        )}
                      </div>
                    </>
                  )}
                </>
              )}
            </section>

            {/* Draggable Center ↔ Inspector Resize Divider */}
            <div
              role="separator"
              tabIndex={0}
              aria-orientation="vertical"
              aria-label="Resize span inspector"
              aria-valuemin={INSPECTOR_MIN_WIDTH}
              aria-valuemax={INSPECTOR_MAX_WIDTH}
              aria-valuenow={inspectorWidth}
              title="Drag to resize inspector · Double-click to reset"
              onPointerDown={startInspectorResize}
              onDoubleClick={() => setInspectorWidth(INSPECTOR_DEFAULT_WIDTH)}
              onKeyDown={(e) => {
                if (e.key === "ArrowLeft") {
                  e.preventDefault();
                  setInspectorWidth((w) => clampInspectorWidth(w + 24));
                } else if (e.key === "ArrowRight") {
                  e.preventDefault();
                  setInspectorWidth((w) => clampInspectorWidth(w - 24));
                } else if (e.key === "Home") {
                  e.preventDefault();
                  setInspectorWidth(INSPECTOR_DEFAULT_WIDTH);
                }
              }}
              className="group relative -mx-1.5 hidden w-3 shrink-0 cursor-col-resize items-center justify-center focus:outline-none xl:flex"
            >
              <span
                className={`h-12 w-[3px] rounded-full transition-all ${
                  resizingInspector
                    ? "h-24 bg-[#7f95f8] shadow-[0_0_12px_rgba(127,149,248,0.65)]"
                    : "bg-white/[0.10] group-hover:h-20 group-hover:bg-[#7f95f8]/80 group-focus-visible:bg-[#7f95f8]"
                }`}
              />
            </div>

            {/* Right Rail: Resizable Span Inspector */}
            <TraceSpanInspector
              session={activeSession}
              span={activeSpan}
              identity={identity}
              startMs={timelineStats.startMs}
              totalDurationMs={activeSession?.delivery.duration_ms ?? 0}
              activeCorrelationId={correlationScope}
              expanded={inspectorWidth >= 480}
              widthPx={inspectorWidth}
              resizing={resizingInspector}
              onToggleExpanded={() =>
                setInspectorWidth((w) =>
                  w >= 480 ? INSPECTOR_DEFAULT_WIDTH : clampInspectorWidth(INSPECTOR_WIDE_WIDTH),
                )
              }
              onSelectSpan={(id) => {
                setSelectedSpanId(id);
                setMobilePane("inspector");
              }}
              onScopeCorrelation={(cid) => {
                setRunView("timeline");
                setCorrelationScope(cid);
              }}
              onStepSpan={stepSpan}
              canStepPrev={activeSpanIndex > 0}
              canStepNext={activeSpanIndex >= 0 && activeSpanIndex < filteredSpans.length - 1}
              harnessBrand={harnessBrand}
              mobileVisible={mobilePane === "inspector"}
              activeTab={inspectorTab}
              onTabChange={setInspectorTab}
              centerViewMode={runView}
              onOpenDiffsView={() => setRunView("diffs")}
              onOpenFile={onOpenFile}
              deepLinkUrl={
                typeof window !== "undefined"
                  ? `${window.location.origin}${window.location.pathname}${buildTraceDeepLink(
                      activeSession?.session_id ?? null,
                      activeSpan?.span_id ?? null,
                      inspectorTab,
                      traceScope,
                    )}`
                  : undefined
              }
            />
          </div>
        </>
      )}

      <ConnectHookModal
        open={hookModalOpen}
        repoName={repoName}
        isDefaultRepo={isDefaultRepo}
        onClose={() => setHookModalOpen(false)}
        onTestEventSent={(sid, spId) => {
          void loadTraces(appliedQuery, true).then(() => {
            setSelectedSessionId(sid);
            setSelectedSpanId(spId);
            setInspectorTab("overview");
            setRunView("timeline");
          });
        }}
      />
    </div>
  );
}
