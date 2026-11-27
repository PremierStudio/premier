import { useState } from "react";
import { AiHarnessCluster, BrandIcon } from "./BrandIcons";
import { CodeBlock } from "./CodeBlock";
import { resolveEnvSelection } from "../lib/uiHelpers";
import { useModalDialog } from "../lib/useModalDialog";

type Mode = "mcp-json" | "mcp-cli" | "proxy";

const MODES: { id: Mode; label: string; icon: "vscode" | "terminal" | "docker" }[] = [
  { id: "mcp-json", label: "MCP Config (JSON)", icon: "vscode" },
  { id: "mcp-cli", label: "MCP Stdio Command", icon: "terminal" },
  { id: "proxy", label: "CLI Wrapper (premier run)", icon: "terminal" },
];

export const ENV_PRESETS = ["dev", "preview", "staging", "prod"] as const;

/** An env name the CLI accepts as a plain argument; anything else falls back to `dev`. */
export function sanitizeEnv(env: string): string {
  const e = env.trim();
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(e) ? e : "dev";
}

export interface AgentConnectSnippets {
  mcpStdioCmd: string;
  mcpJson: string;
  runCmd: string;
}

/**
 * Connection snippets for one repository and environment. The CLI works on the checkout it runs
 * in, so a non-default repo is scoped by `cd` (shell) or `cwd` (MCP config), never a made-up flag.
 */
export function buildAgentConnect(opts: {
  repoName: string;
  isDefaultRepo: boolean;
  env: string;
}): AgentConnectSnippets {
  const env = sanitizeEnv(opts.env);
  const scoped = !opts.isDefaultRepo && opts.repoName !== "";
  const cd = scoped ? `cd ${opts.repoName}
` : "";
  const server: { command: string; args: string[]; cwd?: string } = {
    command: "premier",
    args: ["mcp", "gateway", "--env", env],
  };
  if (scoped) server.cwd = `<path-to>/${opts.repoName}`;
  return {
    mcpStdioCmd: `${cd}premier mcp gateway --env ${env}`,
    mcpJson: JSON.stringify({ mcpServers: { premier: server } }, null, 2),
    runCmd: `${cd}premier run --env ${env} -- <your-agent-or-command>`,
  };
}

function CopyBlock({ label, code }: { label: string; code: string }) {
  return (
    <div className="mt-3">
      <CodeBlock code={code} label={label} showLineNumbers={code.includes("\n")} />
    </div>
  );
}

export function AgentConnectModal({
  open,
  onClose,
  repoName,
  isDefaultRepo,
}: {
  open: boolean;
  onClose: () => void;
  repoName: string;
  isDefaultRepo: boolean;
}) {
  const [mode, setMode] = useState<Mode>("mcp-json");
  const [envPreset, setEnvPreset] = useState<string>("dev");
  const [customEnv, setCustomEnv] = useState<string>("");
  const { panelRef, onKeyDown } = useModalDialog({ open, onClose });
  if (!open) return null;

  const { effective: effectiveEnv, isCustomActive } = resolveEnvSelection(envPreset, customEnv);
  // Real stdio MCP gateway command (runs inside your local repo checkout; works on Windows/macOS/Linux).
  const { mcpStdioCmd, mcpJson, runCmd } = buildAgentConnect({
    repoName,
    isDefaultRepo,
    env: effectiveEnv,
  });

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/65 p-4 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="Connect an AI Coding Agent"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="pr-elevated flex max-h-[86vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl focus:outline-none"
      >
        <div className="flex items-start justify-between gap-3 border-b border-white/[0.08] px-5 py-4">
          <div className="min-w-0 space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="text-[15px] font-semibold text-[#f3f6fd]">Connect an AI Coding Agent</h2>
              <AiHarnessCluster />
            </div>
            <p className="text-[14px] leading-snug text-[#a6b5cf]">
              Works with any MCP-compatible editor or CLI agent. API keys never touch disk or model context.
            </p>
            <p className="font-mono text-[13px] text-[#9ec0f5]" data-testid="connect-target">
              Repository: {repoName || "(default)"}
              {isDefaultRepo ? " · default" : ""}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="pr-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-[#d2dbee] hover:text-white"
          >
            ✕
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <div role="tablist" aria-label="Connection method" className="flex flex-wrap gap-1.5">
            {MODES.map((m) => (
              <button
                key={m.id}
                type="button"
                role="tab"
                aria-selected={mode === m.id}
                onClick={() => setMode(m.id)}
                className={`inline-flex h-8 items-center gap-1.5 rounded-full px-3 text-[14px] font-medium transition ${
                  mode === m.id
                    ? "pr-pill-active"
                    : "border border-transparent text-[#b2c0d8] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
                }`}
              >
                <BrandIcon name={m.icon} className="h-3.5 w-3.5" />
                <span>{m.label}</span>
              </button>
            ))}
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-2 text-[13.5px] text-[#b2c0d8]">
            <span id="connect-env-label">Environment</span>
            <div role="group" aria-labelledby="connect-env-label" className="flex flex-wrap gap-1">
              {ENV_PRESETS.map((e) => {
                const pressed = !isCustomActive && envPreset === e;
                return (
                  <button
                    key={e}
                    type="button"
                    aria-pressed={pressed}
                    onClick={() => {
                      setEnvPreset(e);
                      setCustomEnv("");
                    }}
                    className={`rounded-full px-2.5 py-0.5 font-mono transition ${
                      pressed ? "pr-pill-active" : "border border-white/[0.08] hover:bg-white/[0.05]"
                    }`}
                  >
                    {e}
                  </button>
                );
              })}
            </div>
            <input
              aria-label="Custom environment"
              value={customEnv}
              onChange={(e) => setCustomEnv(e.target.value)}
              placeholder="custom"
              className="w-28 rounded-lg border border-white/[0.08] bg-black/35 px-2 py-0.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
          </div>

          {mode === "mcp-json" && (
            <div role="tabpanel">
              <CopyBlock label="MCP Server Config (.mcp.json / mcp.json)" code={mcpJson} />
              <p className="mt-3 text-[14px] leading-relaxed text-[#d2dbee]">
                Add this server entry to your harness&apos;s MCP config. Restricted folders stay hidden, API keys
                are usable without being readable, and destructive tool calls wait for your approval.
              </p>
            </div>
          )}
          {mode === "mcp-cli" && (
            <div role="tabpanel">
              <CopyBlock label="Stdio MCP Server Command" code={mcpStdioCmd} />
              <p className="mt-3 text-[14px] leading-relaxed text-[#d2dbee]">
                Register this stdio command with any CLI agent harness that supports MCP servers (run inside your
                local checkout on Windows, macOS, or Linux).
              </p>
            </div>
          )}
          {mode === "proxy" && (
            <div role="tabpanel">
              <CopyBlock label="Terminal" code={runCmd} />
              <p className="mt-3 text-[14px] leading-relaxed text-[#d2dbee]">
                Wraps any CLI coding agent or script. The process receives temporary placeholders instead of real
                API keys; Premier injects the real key only on outbound requests.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
