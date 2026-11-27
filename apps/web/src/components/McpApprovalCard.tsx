import { useState } from "react";
import { api, errorText, type PendingApproval } from "../api";
import { IconCheck, IconClose } from "./Icons";

/** Compact JIT approval card for MCP tool calls (egress knocks use KnockApprovalCard). */
const TTL_OPTIONS = [
  { label: "Once", secs: 0 },
  { label: "60s", secs: 60 },
  { label: "5m", secs: 300 },
  { label: "15m", secs: 900 },
] as const;

const APPROVAL_RISK_BADGE: Record<NonNullable<PendingApproval["risk"]>, string> = {
  read: "bg-[#5bdba2]/14 text-[#5bdba2]",
  write: "bg-[#7f95f8]/16 text-[#a8c5ff]",
  destructive: "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]",
};

function defaultApprovalTtl(ap: PendingApproval): number {
  if (ap.ttl_secs === 0) return 0;
  // Destructive approvals default to single-use unless the server proposed a TTL.
  if (ap.ttl_secs == null && ap.risk === "destructive") return 0;
  return ap.ttl_secs || 300;
}


export function McpApprovalCard({
  approval: ap,
  owner,
  onDecided,
  onDismiss,
}: {
  approval: PendingApproval;
  owner: boolean;
  onDecided: () => void;
  /** Floating popover only: hides this card without deciding. */
  onDismiss?: () => void;
}) {
  const [ttl, setTtl] = useState<number>(() => defaultApprovalTtl(ap));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const ttlLabel = TTL_OPTIONS.find((t) => t.secs === ttl)?.label ?? `${ttl}s`;
  const decide = async (approved: boolean) => {
    setBusy(true);
    setErr(null);
    try {
      await api.decideApproval(ap.id, approved, ttl);
      onDecided();
    } catch (e: unknown) {
      setErr(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div
      className={`pr-elevated flex flex-wrap items-center justify-between gap-3 rounded-2xl px-4 py-3 ${
        ap.risk === "destructive" ? "border-[#f27c7c]/40" : "border-[#9ec0f5]/30"
      }`}
    >
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[13.5px] text-[#f3f6fd]">
          <span
            className={`h-2 w-2 shrink-0 motion-safe:animate-pulse rounded-full ${
              ap.risk === "destructive" ? "bg-[#f27c7c]" : "bg-[#7f95f8]"
            }`}
          />
          <span className="rounded-full bg-[#7f95f8]/20 px-1.5 py-0.5 text-[12px] font-semibold uppercase text-[#9ec0f5]">
            MCP
          </span>
          {ap.risk && (
            <span
              className={`rounded-full px-1.5 py-0.5 text-[12px] uppercase ${APPROVAL_RISK_BADGE[ap.risk]}`}
            >
              {ap.risk}
            </span>
          )}
          <span className="truncate font-semibold">
            {ap.mcp_server ?? ap.host} : {ap.mcp_tool ?? ap.var_name}
          </span>
        </div>
        <div className="mt-0.5 truncate font-mono text-[12.5px] text-[#a6b5cf]">
          {ap.principal}
          {ap.agent_profile ? ` ∩ ${ap.agent_profile}` : ""}
        </div>
        {ap.args_summary && (
          <div
            className="pr-well mt-1.5 max-h-14 overflow-y-auto break-all rounded-lg px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee]"
            title={ap.args_summary}
          >
            {ap.args_summary}
          </div>
        )}
        {err && <div className="mt-1 font-mono text-[12.5px] text-[#f27c7c]">{err}</div>}
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-1.5">
        <div className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 font-mono text-[12px]">
          {TTL_OPTIONS.map((opt) => (
            <button
              key={opt.secs}
              type="button"
              onClick={() => setTtl(opt.secs)}
              className={`rounded-full px-2 py-0.5 transition ${
                ttl === opt.secs
                  ? "bg-[#7f95f8]/25 text-[#f3f6fd]"
                  : "text-[#a6b5cf] hover:text-white"
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <button
          type="button"
          disabled={busy || !owner}
          title={owner ? undefined : "Owner only"}
          onClick={() => void decide(true)}
          className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] disabled:opacity-50"
        >
          <IconCheck className="h-4 w-4" />
          <span>Approve · {ttlLabel}</span>
        </button>
        <button
          type="button"
          disabled={busy || !owner}
          title={owner ? "Deny this tool call" : "Owner only"}
          onClick={() => void decide(false)}
          className="pr-pill inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-[13px] text-[#f27c7c] disabled:opacity-50"
        >
          <IconClose className="h-4 w-4" />
          <span>Deny</span>
        </button>
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            title="Hide for now; the approval stays pending"
            className="rounded-full px-2.5 py-1.5 text-[13px] text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white"
          >
            Later
          </button>
        )}
      </div>
    </div>
  );
}
