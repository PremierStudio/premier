import { useMemo, useState } from "react";
import type {
  ChangeReviewRecord,
  HealthResponse,
  IdentityPreset,
  ReviewDiffHunk,
} from "../../api";
import { plural } from "../../lib/format";
import {
  buildSteeringContextPreview,
  type SteeringContextPreview,
} from "../../lib/steeringPayload";
import { CodeBlock } from "../CodeBlock";
import {
  IconCage,
  IconChevron,
  IconClose,
  IconComment,
  IconIntersection,
  IconLock,
  IconQuarantine,
  IconSteer,
  IconVault,
} from "../Icons";

export interface InlineSteeringComposerProps {
  change: ChangeReviewRecord;
  hunk: ReviewDiffHunk;
  line: number;
  viewerIdentity: IdentityPreset;
  agentProfiles: string[];
  agentSandbox?: HealthResponse["agent_sandbox"];
  owner: boolean;
  isSimulatingLens?: boolean;
  visibleHunks: ReviewDiffHunk[];
  submitting: boolean;
  onCancel: () => void;
  onSubmitComment: (body: string) => Promise<boolean>;
  onSubmitSteer: (opts: {
    body: string;
    targetAgent: string;
    triggerRevision: boolean;
  }) => Promise<boolean>;
}

export function InlineSteeringComposer({
  change,
  hunk,
  line,
  viewerIdentity,
  agentProfiles,
  agentSandbox,
  owner,
  isSimulatingLens = false,
  visibleHunks,
  submitting,
  onCancel,
  onSubmitComment,
  onSubmitSteer,
}: InlineSteeringComposerProps) {
  const [composerMode, setComposerMode] = useState<"comment" | "steer">("comment");
  const [body, setBody] = useState("");
  const [contextExpanded, setContextExpanded] = useState(false);

  const availableAgents = useMemo(() => {
    const raw = [change.delegated_agent, ...agentProfiles].filter(
      (a): a is string => typeof a === "string" && a.trim().length > 0,
    );
    return Array.from(new Set(raw));
  }, [change.delegated_agent, agentProfiles]);

  const defaultAgent = availableAgents[0] ?? "";
  const [targetAgent, setTargetAgent] = useState<string>(defaultAgent);
  const selectedAgent = availableAgents.includes(targetAgent) ? targetAgent : defaultAgent;

  const preview: SteeringContextPreview = useMemo(
    () =>
      buildSteeringContextPreview({
        viewerPrincipal: viewerIdentity.principal,
        targetAgent: selectedAgent,
        path: hunk.path,
        line,
        hunkLines: hunk.allowed ? hunk.lines : [],
        visibleHunks,
        quarantineFlagged: change.quarantine_flagged,
        directive: body,
        changeId: change.change_id,
        branch: change.branch,
      }),
    [
      viewerIdentity.principal,
      selectedAgent,
      hunk.path,
      hunk.allowed,
      hunk.lines,
      line,
      visibleHunks,
      change.quarantine_flagged,
      change.change_id,
      change.branch,
      body,
    ],
  );

  const targetIsDeclaredProfile = Boolean(selectedAgent) && agentProfiles.includes(selectedAgent);
  const canRunLiveSandbox = Boolean(
    owner &&
      !isSimulatingLens &&
      agentSandbox &&
      agentSandbox !== "none" &&
      targetIsDeclaredProfile &&
      /^[a-z0-9._-]+$/i.test(selectedAgent),
  );
  const reviseButtonLabel = canRunLiveSandbox
    ? `Steer & Revise (${agentSandbox})`
    : "Queue Revision";

  const handleCommentSubmit = async (e: { preventDefault: () => void }) => {
    e.preventDefault();
    const trimmed = body.trim();
    if (!trimmed || submitting) return;
    const ok = await onSubmitComment(trimmed);
    if (ok) setBody("");
  };

  const handleSteerAction = async (triggerRevision: boolean) => {
    const trimmed = body.trim();
    if (!trimmed || submitting) return;
    const ok = await onSubmitSteer({
      body: trimmed,
      targetAgent: selectedAgent,
      triggerRevision,
    });
    if (ok) setBody("");
  };

  // Ctrl/Cmd+Enter submits the focused textarea's primary action.
  const submitOnShortcut = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key !== "Enter" || !(e.ctrlKey || e.metaKey)) return;
    e.preventDefault();
    if (composerMode === "comment") void handleCommentSubmit(e);
    else if (!isSimulatingLens) void handleSteerAction(true);
    else void handleSteerAction(false);
  };

  return (
    <div
      className="pr-elevated relative z-10 mx-3 my-2 space-y-2.5 rounded-2xl bg-[#0b0f1c] p-3.5 font-sans"
      role="region"
      aria-label={`Inline review composer for ${hunk.path} line ${line}`}
    >
      {/* Top bar: mode switch, anchor label, close button */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <div
            role="group"
            aria-label="Composer mode"
            className="inline-flex items-center gap-1 rounded-full border border-white/[0.08] bg-black/30 p-0.5 font-mono text-[12.5px]"
          >
            <button
              type="button"
              onClick={() => setComposerMode("comment")}
              aria-label="Human Comment mode"
              aria-pressed={composerMode === "comment"}
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 transition ${
                composerMode === "comment"
                  ? "pr-pill-active"
                  : "text-[#a6b5cf] hover:text-[#f3f6fd]"
              }`}
            >
              <IconComment className="h-3.5 w-3.5" />
              <span>Human Comment</span>
            </button>
            <button
              type="button"
              onClick={() => setComposerMode("steer")}
              aria-label="Steer Agent mode"
              aria-pressed={composerMode === "steer"}
              className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 transition ${
                composerMode === "steer"
                  ? "pr-pill-active"
                  : "text-[#a6b5cf] hover:text-[#f3f6fd]"
              }`}
            >
              <IconSteer className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span>Steer Agent</span>
            </button>
          </div>

          <span className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-0.5 font-mono text-[12.5px] text-[#9ec0f5]">
            {hunk.path}:L{line}
          </span>
        </div>

        <button
          type="button"
          onClick={onCancel}
          aria-label="Cancel inline comment or steering directive"
          className="rounded-lg p-1 text-[#98a8c4] transition hover:bg-white/[0.06] hover:text-white"
        >
          <IconClose className="h-4 w-4" />
        </button>
      </div>

      {composerMode === "comment" ? (
        <form onSubmit={(e) => void handleCommentSubmit(e)} className="space-y-2">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-end">
            <textarea
              autoFocus
              rows={2}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              onKeyDown={submitOnShortcut}
              aria-label={`Comment for ${hunk.path} line ${line}`}
              placeholder="Write a line-anchored review comment…"
              className="pr-well min-w-0 flex-1 rounded-xl px-3 py-2 text-[14px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
            />
            <button
              type="submit"
              disabled={submitting || !body.trim()}
              title="Post (Ctrl/⌘+Enter)"
              aria-label="Post comment"
              className="pr-action-btn shrink-0 rounded-xl px-3.5 py-2 text-[13.5px] disabled:opacity-45"
            >
              Post
            </button>
          </div>
        </form>
      ) : (
        <div className="space-y-2.5">
          {/* Agent selector & collapsible ACL-Safe Context Preview toggle */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[12.5px]">
              <label htmlFor="steer-target-agent" className="text-[#a6b5cf]">
                Target agent:
              </label>
              {availableAgents.length > 0 ? (
                <select
                  id="steer-target-agent"
                  value={selectedAgent}
                  onChange={(e) => setTargetAgent(e.target.value)}
                  aria-label="Target agent profile"
                  className="pr-well rounded-full bg-[#0b0f1c] px-2.5 py-1 font-mono text-[12.5px] text-[#f3f6fd] [color-scheme:dark] focus:outline-none [&>option]:bg-[#0b0f1c] [&>option]:text-[#f3f6fd]"
                >
                  {availableAgents.map((agent) => (
                    <option key={agent} value={agent} className="bg-[#0b0f1b]">
                      {agent}
                    </option>
                  ))}
                </select>
              ) : (
                <span className="rounded-full border border-white/[0.08] bg-white/[0.03] px-2.5 py-0.5 text-[#a6b5cf]">
                  No agent profiles configured
                </span>
              )}
            </div>

            <button
              type="button"
              onClick={() => setContextExpanded((prev) => !prev)}
              aria-expanded={contextExpanded}
              aria-label="Toggle ACL-Safe Context Preview"
              className="inline-flex items-center gap-1 font-mono text-[12.5px] text-[#9ec0f5] hover:underline"
            >
              <IconChevron
                direction={contextExpanded ? "down" : "right"}
                className="h-3.5 w-3.5"
              />
              <span>Agent context (ACL-safe)</span>
            </button>
          </div>

          {/* Collapsible/visible ACL-Safe Context Preview panel */}
          {contextExpanded && (
            <div
              className="pr-well space-y-2 rounded-xl p-3 font-mono text-[12.5px]"
              aria-label="ACL-Safe Context Preview"
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <span
                  className="pr-pill inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[#dce4f5]"
                  title="Delegated intersection authority"
                >
                  <IconIntersection className="h-3.5 w-3.5 text-[#9ec0f5]" />
                  <span>{preview.effectiveAuthority}</span>
                </span>

                <span className="pr-pill inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[#9ec0f5]">
                  <span>
                    {preview.path}:L{preview.line}
                  </span>
                </span>

                <span
                  className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/10 px-2.5 py-0.5 text-[#5bdba2]"
                  title={preview.secretsPolicy}
                >
                  <IconVault className="h-3.5 w-3.5" />
                  <span>use ≠ read</span>
                </span>

                {preview.excludedRedactedCount > 0 && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-2.5 py-0.5 text-[#f27c7c]">
                    <IconLock className="h-3.5 w-3.5" />
                    <span>
                      {plural(preview.excludedRedactedCount, "redacted hunk")} excluded from agent
                      context
                    </span>
                  </span>
                )}
              </div>

              {(change.quarantine_flagged || preview.quarantineWarning) && (
                <div
                  role="alert"
                  className="flex items-center gap-2 rounded-lg border border-[#9ec0f5]/35 bg-[#7f95f8]/12 px-2.5 py-1.5 text-[12.5px] text-[#a8c5ff]"
                >
                  <IconQuarantine className="h-4 w-4 shrink-0" />
                  <span>
                    {preview.quarantineWarning ??
                      "Quarantined instruction files detected in this change; repo-resident agent instructions remain untrusted and cannot escalate permissions or egress."}
                  </span>
                </div>
              )}

              {preview.snippetLines.length > 0 && (
                <CodeBlock
                  code={preview.snippetLines.join("\n")}
                  filePath={hunk.path}
                  label={hunk.path}
                  compact
                  maxHeightClass="max-h-36"
                />
              )}
            </div>
          )}

          {/* Directive textarea + action row */}
          <textarea
            autoFocus
            rows={2}
            value={body}
            onChange={(e) => setBody(e.target.value)}
            onKeyDown={submitOnShortcut}
            aria-label={`Steering directive for ${selectedAgent || "agent"} at ${hunk.path} line ${line}`}
            placeholder={`Direct ${selectedAgent || "the agent"} on how to revise ${hunk.path}:L${line}…`}
            className="pr-well w-full rounded-xl px-3 py-2 text-[14px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
          />

          <div className="flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              disabled={submitting || !body.trim()}
              onClick={() => void handleSteerAction(false)}
              aria-label="Post steering directive without triggering immediate revision"
              className="pr-pill inline-flex items-center gap-1.5 rounded-xl px-3 py-1.5 font-mono text-[13px] text-[#dce4f5] disabled:opacity-45"
            >
              <IconSteer className="h-3.5 w-3.5 text-[#9ec0f5]" />
              <span>Post Directive</span>
            </button>

            <button
              type="button"
              disabled={submitting || !body.trim() || isSimulatingLens}
              title={
                isSimulatingLens
                  ? "Live session dispatch is disabled while simulating another identity via View as"
                  : canRunLiveSandbox
                    ? "Post steering directive and launch caged revision session"
                    : "Queue steering directive for the next revision"
              }
              onClick={() => void handleSteerAction(true)}
              aria-label={reviseButtonLabel}
              className="pr-action-btn inline-flex items-center gap-1.5 rounded-xl px-3.5 py-1.5 font-mono text-[13px] disabled:opacity-45"
            >
              <IconCage className="h-3.5 w-3.5" />
              <span>{reviseButtonLabel}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
