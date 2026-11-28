import { useEffect, useImperativeHandle, useRef, useState, type Ref } from "react";
import {
  api,
  errorText,
  type GrantScope,
  type PendingApproval,
  type PolicySuggestion,
  type RiskLevel,
} from "../api";
import { CodeBlock } from "./CodeBlock";
import { ErrorNote } from "./forms";
import {
  IconBranchRef,
  IconCheck,
  IconChevron,
  IconClock,
  IconClose,
  IconIntersection,
  IconTerminal,
} from "./Icons";

/** Imperative hooks so a host (the floating popover) can drive the card from the keyboard. */
export interface KnockCardHandle {
  approve: () => void;
  openDeny: () => void;
  toggleProof: () => void;
}

interface Preset {
  scope: GrantScope;
  label: string;
  hint: string;
  ttls: number[];
}

const PRESETS: Preset[] = [
  { scope: "once", label: "Allow Once", hint: "Exact method + path, one request", ttls: [] },
  {
    scope: "read_only_prefix",
    label: "Read-Only (GET)",
    hint: "GET under the schema prefix",
    ttls: [300, 900],
  },
  { scope: "exact_path", label: "Exact Path", hint: "This exact method + path", ttls: [60, 300, 900] },
  { scope: "exact_scope", label: "Prefix Scope", hint: "The whole schema prefix", ttls: [60, 300, 900] },
];

export const RISK_BADGE: Record<RiskLevel, { label: string; cls: string }> = {
  read_only: {
    label: "Read-Only",
    cls: "border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]",
  },
  state_mutation: {
    label: "State Mutation",
    cls: "border-[#9ec0f5]/25 bg-[#7f95f8]/12 text-[#b9cdf8]",
  },
  sensitive_scope: {
    label: "Sensitive Scope",
    cls: "border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f27c7c]",
  },
};

function formatCountdown(secs: number): string {
  if (secs <= 0) return "Expired";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${String(s).padStart(2, "0")}s` : `${s}s`;
}

function ttlLabel(secs: number): string {
  return secs % 60 === 0 && secs >= 60 ? `${secs / 60}m` : `${secs}s`;
}

function barColor(pct: number): string {
  if (pct > 50) return "#5bdba2";
  if (pct > 20) return "#9ec0f5";
  return "#f27c7c";
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} bytes`;
  return `${(n / 1024).toFixed(1)} KB`;
}

function defaultScope(risk: RiskLevel, method: string): { scope: GrantScope; ttl: number } {
  if (risk === "read_only" && method.toUpperCase() === "GET") {
    return { scope: "read_only_prefix", ttl: 300 };
  }
  return { scope: "once", ttl: 0 };
}

export function KnockApprovalCard({
  approval,
  owner,
  variant,
  matchingSuggestion,
  onDecided,
  onOpenSession,
  onOpenAgents,
  onDismiss,
  onPreviewSuggestion,
  onDismissSuggestion,
  index,
  total,
  onPrev,
  onNext,
  ref,
}: {
  approval: PendingApproval;
  owner: boolean;
  variant: "floating" | "queue";
  matchingSuggestion?: PolicySuggestion;
  onDecided: () => void;
  onOpenSession?: (sessionId: string) => void;
  onOpenAgents?: () => void;
  onDismiss?: () => void;
  onPreviewSuggestion?: (s: PolicySuggestion) => void;
  onDismissSuggestion?: (s: PolicySuggestion) => void;
  index?: number;
  total?: number;
  onPrev?: () => void;
  onNext?: () => void;
  ref?: Ref<KnockCardHandle>;
}) {
  const method = approval.method.toUpperCase();
  const isGet = method === "GET";
  const risk: RiskLevel = approval.risk_level ?? (isGet ? "read_only" : "state_mutation");
  const initial = defaultScope(risk, approval.method);

  const [scope, setScope] = useState<GrantScope>(initial.scope);
  const [ttl, setTtl] = useState(initial.ttl);
  const [proofOpen, setProofOpen] = useState(false);
  const [denyOpen, setDenyOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const denyInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (denyOpen) denyInputRef.current?.focus();
  }, [denyOpen]);

  const createdMs = Date.parse(approval.created_at);
  const expiresMs = approval.expires_at
    ? Date.parse(approval.expires_at)
    : createdMs + (approval.ttl_secs || 300) * 1000;
  const totalSecs =
    Number.isFinite(expiresMs) && Number.isFinite(createdMs) && expiresMs > createdMs
      ? (expiresMs - createdMs) / 1000
      : approval.ttl_secs || 300;
  const remainingSecs = Number.isFinite(expiresMs)
    ? Math.max(0, Math.ceil((expiresMs - now) / 1000))
    : approval.ttl_secs || 0;
  const pct = Math.max(0, Math.min(100, (remainingSecs / totalSecs) * 100));
  const expired = remainingSecs <= 0;

  const concretePath = approval.concrete_path ?? approval.path;
  const intent =
    approval.intent_summary || `${approval.method} ${approval.host}${concretePath}`;
  const badge = RISK_BADGE[risk];
  const preview = approval.wire_preview;
  const session = approval.session_context;
  const disabled = !owner || busy || expired;

  const presets = PRESETS.filter((p) => p.scope !== "read_only_prefix" || isGet);
  const activePreset = presets.find((p) => p.scope === scope) ?? presets[0];

  const pickPreset = (p: Preset) => {
    setScope(p.scope);
    setTtl(p.ttls.includes(ttl) ? ttl : (p.ttls[p.ttls.length > 1 ? 1 : 0] ?? 0));
  };

  const approveLabel =
    activePreset.scope === "once"
      ? "Allow Once"
      : activePreset.scope === "read_only_prefix"
        ? `Allow GET · ${ttlLabel(ttl)}`
        : activePreset.scope === "exact_path"
          ? `Allow Path · ${ttlLabel(ttl)}`
          : `Allow Scope · ${ttlLabel(ttl)}`;

  const decide = async (approved: boolean) => {
    setBusy(true);
    setError(null);
    try {
      if (approved) {
        await api.decideApproval(
          approval.id,
          true,
          activePreset.scope === "once" ? undefined : ttl,
          { grant_scope: activePreset.scope },
        );
      } else {
        await api.decideApproval(approval.id, false, undefined, {
          denial_reason: reason.trim() || undefined,
        });
      }
      onDecided();
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  useImperativeHandle(ref, () => ({
    approve: () => {
      if (!disabled) void decide(true);
    },
    openDeny: () => {
      if (!owner) return;
      setDenyOpen(true);
      denyInputRef.current?.focus();
    },
    toggleProof: () => setProofOpen((o) => !o),
  }));

  const paginated = variant === "floating" && (total ?? 0) > 1;

  return (
    <div
      className={`pr-elevated relative overflow-hidden rounded-2xl border ${
        variant === "floating" ? "border-[#9ec0f5]/35 shadow-2xl" : "border-[#9ec0f5]/25"
      }`}
    >
      {/* Countdown progress */}
      <div className="h-[2px] w-full bg-white/[0.05]" aria-hidden="true">
        <div
          className="h-full transition-[width,background-color] duration-1000 ease-linear"
          style={{ width: `${pct}%`, backgroundColor: barColor(pct) }}
        />
      </div>

      <div className="space-y-2 p-3">
        {/* Header: badges + countdown */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-1.5 font-mono text-[12.5px]">
            <span className="pr-presence-dot bg-[#7f95f8]" aria-hidden="true" />
            <span className="font-semibold uppercase tracking-wider text-[#b9cdf8]">Knock</span>
            <span className={`rounded-full border px-2 py-0.5 text-[12px] ${badge.cls}`}>
              {badge.label}
            </span>
            {paginated && (
              <span className="inline-flex items-center gap-0.5 rounded-full bg-black/35 px-1 py-0.5 text-[12px] text-[#d2dbee]">
                <button
                  type="button"
                  onClick={onPrev}
                  aria-label="Previous knock"
                  className="rounded-full p-0.5 hover:bg-white/[0.08] hover:text-white"
                >
                  <IconChevron direction="left" className="h-3 w-3" />
                </button>
                <span className="px-0.5">
                  {(index ?? 0) + 1} of {total}
                </span>
                <button
                  type="button"
                  onClick={onNext}
                  aria-label="Next knock"
                  className="rounded-full p-0.5 hover:bg-white/[0.08] hover:text-white"
                >
                  <IconChevron direction="right" className="h-3 w-3" />
                </button>
              </span>
            )}
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <span
              className={`inline-flex items-center gap-1 rounded-full bg-black/35 px-2 py-0.5 font-mono text-[12.5px] ${
                expired ? "text-[#f27c7c]" : "text-[#dce4f5]"
              }`}
            >
              <IconClock className="h-3.5 w-3.5" style={{ color: barColor(pct) }} />
              <span>{formatCountdown(remainingSecs)}</span>
            </span>
            {onDismiss && (
              <button
                type="button"
                onClick={onDismiss}
                aria-label="Dismiss approval popover"
                className="rounded-lg p-1 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white"
              >
                <IconClose className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Intent */}
        <p className="break-words text-[14px] font-medium leading-snug text-[#f3f6fd]">{intent}</p>

        {/* Capability + target */}
        <div className="space-y-1 font-mono text-[12.5px]">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="font-semibold text-[#f3f6fd]">{approval.var_name}</span>
            {approval.sensitivity && (
              <span className="rounded-md bg-[#7f95f8]/15 px-1.5 py-0.5 text-[12px] text-[#9ec0f5]">
                {approval.sensitivity}
              </span>
            )}
            <span className="rounded-md bg-white/[0.06] px-1.5 py-0.5 text-[12px] text-[#9ec0f5]">
              {method}
            </span>
          </div>
          <div
            className="break-all text-[#d2dbee]"
            title={`${approval.host}${concretePath}`}
          >
            {approval.host}
            {concretePath}
          </div>
          {approval.concrete_path && approval.concrete_path !== approval.path && (
            <span className="inline-block rounded-full border border-white/[0.08] px-2 py-0.5 text-[12px] text-[#a6b5cf]">
              prefix: {approval.path}
            </span>
          )}
        </div>

        {/* Session context */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12.5px] text-[#a6b5cf]">
          <span className="inline-flex min-w-0 items-center gap-1">
            <IconIntersection className="h-3.5 w-3.5 text-[#9ec0f5]" />
            <span className="truncate">
              {approval.principal}
              {approval.agent_profile ? ` ∩ ${approval.agent_profile}` : ""}
            </span>
          </span>
          {session?.branch && (
            <span className="inline-flex items-center gap-1 rounded-full bg-white/[0.06] px-2 py-0.5 text-[#d2dbee]">
              <IconBranchRef className="h-3 w-3" />
              {session.branch}
            </span>
          )}
          {session?.session_id && (
            <button
              type="button"
              onClick={() => onOpenSession?.(session.session_id!)}
              disabled={!onOpenSession}
              title="Open this session in the cage"
              className="pr-pill inline-flex max-w-full items-center gap-1 rounded-full px-2 py-0.5 text-[#9ec0f5] hover:text-[#f3f6fd] disabled:cursor-default"
            >
              <IconTerminal className="h-3 w-3" />
              <span title={session.session_id}>{session.session_id.slice(0, 8)}</span>
              {session.command && (
                <span className="max-w-[140px] truncate text-[#a6b5cf]">
                  · {session.command.length > 28 ? `${session.command.slice(0, 28)}…` : session.command}
                </span>
              )}
            </button>
          )}
        </div>

        {/* Raw wire proof */}
        <div>
          <button
            type="button"
            onClick={() => setProofOpen((o) => !o)}
            aria-expanded={proofOpen}
            className="inline-flex items-center gap-1 font-mono text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
          >
            <IconChevron direction={proofOpen ? "down" : "right"} className="h-3 w-3" />
            Inspect raw wire
          </button>
          {proofOpen && (
            <div className="pr-well mt-1.5 space-y-2 rounded-xl p-2.5 font-mono text-[12.5px]">
              {preview ? (
                <>
                  <div className="break-all text-[#dce4f5]">
                    <div>
                      {preview.method} {preview.concrete_path} HTTP/1.1
                    </div>
                    <div className="text-[#a6b5cf]">Host: {preview.host}</div>
                  </div>
                  {preview.query_keys.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1">
                      {preview.query_keys.map((k) => (
                        <span
                          key={k}
                          className="rounded-md bg-white/[0.06] px-1.5 py-0.5 text-[#d2dbee]"
                        >
                          {k}
                        </span>
                      ))}
                      <span className="text-[#a6b5cf]">query values withheld</span>
                    </div>
                  )}
                  {preview.headers.length > 0 && (
                    <ul className="space-y-1">
                      {preview.headers.map((h, i) => (
                        <li key={`${h.name}-${i}`} className="flex flex-wrap items-center gap-1.5">
                          <span className="break-all text-[#d2dbee]">
                            {h.name}: {h.value}
                          </span>
                          {h.contains_placeholder && (
                            <span className="rounded-full border border-[#67d6dc]/30 bg-[#67d6dc]/12 px-1.5 py-0.5 text-[12px] text-[#67d6dc]">
                              placeholder · swapped on wire
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                  <div>
                    <div className="mb-1 flex flex-wrap items-center gap-1.5 text-[#a6b5cf]">
                      <span>
                        {preview.body_size_bytes > 0
                          ? `Body · ${formatBytes(preview.body_size_bytes)}`
                          : "Body"}
                      </span>
                      {preview.body_truncated && (
                        <span className="rounded-full border border-white/[0.11] bg-white/[0.04] px-2 py-0.5 text-[12px] text-[#9eb0cc]">
                          truncated
                        </span>
                      )}
                    </div>
                    {preview.body_is_binary ? (
                      <div className="text-[#a6b5cf]">Binary payload hidden</div>
                    ) : preview.body_preview ? (
                      <CodeBlock
                        code={preview.body_preview}
                        label="Request body"
                        compact
                        maxHeightClass="max-h-40"
                      />
                    ) : (
                      <div className="text-[#a6b5cf]">No request body</div>
                    )}
                  </div>
                  <p className="text-[#a6b5cf]">
                    Secrets stay behind the proxy: placeholders are swapped on the wire, never shown here.
                  </p>
                </>
              ) : (
                <div className="text-[#a6b5cf]">
                  This request has no wire preview.{" "}
                  <span className="break-all text-[#a6b5cf]">
                    {method} {concretePath} HTTP/1.1 · Host: {approval.host}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Living policy learning */}
        {owner && matchingSuggestion && (
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-[#7f95f8]/25 bg-[#7f95f8]/[0.08] px-2.5 py-2 text-[12.5px] text-[#9ec0f5]">
            <span className="min-w-0 flex-1 basis-40 break-words">{matchingSuggestion.summary}</span>
            <span className="flex shrink-0 items-center gap-1.5">
              <button
                type="button"
                onClick={() => onPreviewSuggestion?.(matchingSuggestion)}
                className="pr-pill rounded-full px-2.5 py-0.5 text-[12.5px] text-[#f3f6fd]"
              >
                Preview diff
              </button>
              <button
                type="button"
                onClick={() => onDismissSuggestion?.(matchingSuggestion)}
                className="rounded-full px-2 py-0.5 text-[12.5px] text-[#a6b5cf] hover:text-white"
              >
                Dismiss
              </button>
            </span>
          </div>
        )}

        {/* Scope narrowing */}
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1.5">
          <div
            role="radiogroup"
            aria-label="Grant scope"
            className="flex flex-wrap items-center gap-1"
          >
            {presets.map((p) => (
              <button
                key={p.scope}
                type="button"
                role="radio"
                aria-checked={activePreset.scope === p.scope}
                disabled={!owner}
                title={owner ? p.hint : "Owner only"}
                onClick={() => pickPreset(p)}
                className={`rounded-full px-2.5 py-0.5 font-mono text-[12.5px] transition disabled:opacity-50 ${
                  activePreset.scope === p.scope
                    ? "pr-pill-active"
                    : "pr-pill text-[#a6b5cf] hover:text-[#f3f6fd]"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
          {activePreset.ttls.length > 0 && (
            <div
              role="radiogroup"
              aria-label="Duration"
              className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 font-mono text-[12px]"
            >
              {activePreset.ttls.map((secs) => (
                <button
                  key={secs}
                  type="button"
                  role="radio"
                  aria-checked={ttl === secs}
                  disabled={!owner}
                  onClick={() => setTtl(secs)}
                  className={`rounded-full px-2 py-0.5 transition ${
                    ttl === secs ? "bg-[#7f95f8]/25 text-[#f3f6fd]" : "text-[#a6b5cf] hover:text-white"
                  }`}
                >
                  {ttlLabel(secs)}
                </button>
              ))}
            </div>
          )}
        </div>

        <ErrorNote message={error} />

        {/* Actions */}
        {denyOpen ? (
          <div className="space-y-1.5">
            <input
              ref={denyInputRef}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  if (!busy) void decide(false);
                } else if (e.key === "Escape") {
                  e.preventDefault();
                  e.stopPropagation();
                  setDenyOpen(false);
                }
              }}
              disabled={busy}
              maxLength={300}
              aria-label="Reason for denying"
              placeholder="Reason for agent & audit (optional)…"
              className="pr-well w-full rounded-xl px-3 py-1.5 text-[13.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
            <div className="flex flex-wrap items-center gap-1.5">
              <button
                type="button"
                disabled={busy || !owner}
                onClick={() => void decide(false)}
                className="inline-flex items-center gap-1 rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/14 px-3 py-1 text-[13px] font-medium text-[#f27c7c] transition hover:bg-[#f27c7c]/24 disabled:opacity-50"
              >
                {busy ? "Denying…" : "Confirm Deny"}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => setDenyOpen(false)}
                className="pr-pill rounded-full px-3 py-1 text-[13px] text-[#dce4f5]"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              disabled={disabled}
              title={owner ? undefined : "Owner only"}
              onClick={() => void decide(true)}
              className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[13.5px] disabled:opacity-50"
            >
              <IconCheck className="h-3.5 w-3.5" />
              <span>{busy ? "Working…" : approveLabel}</span>
            </button>
            <button
              type="button"
              disabled={busy || !owner || expired}
              title={owner ? undefined : "Owner only"}
              onClick={() => setDenyOpen(true)}
              className="pr-pill rounded-full px-3 py-1 font-mono text-[13px] text-[#f27c7c] hover:bg-[#f27c7c]/15 disabled:opacity-50"
            >
              Deny
            </button>
            {onOpenAgents && (
              <button
                type="button"
                onClick={onOpenAgents}
                className="ml-auto font-mono text-[12.5px] text-[#9ec0f5] hover:underline"
              >
                Open Agents
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
