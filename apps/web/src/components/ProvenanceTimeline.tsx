import { useMemo } from "react";
import type { ProvenanceStep } from "../api";
import { Time } from "./forms";

const KIND_TONE: Record<string, string> = {
  session_start: "bg-[#7f95f8]/18 text-[#9caeff]",
  command_exec: "bg-[#9ec0f5]/15 text-[#9ec0f5]",
  file_change: "bg-[#5bdba2]/14 text-[#5bdba2]",
  egress_request: "bg-white/[0.07] text-[#d2dbee]",
  egress_scrub: "bg-[#67d6dc]/14 text-[#67d6dc]",
  egress_blocked: "bg-[#f27c7c]/15 text-[#f27c7c]",
  jit_approval: "bg-[#7f95f8]/15 text-[#a8c5ff]",
  auto_rebase: "bg-[#c7a7ff]/15 text-[#c7a7ff]",
  lane_conflict: "bg-[#f27c7c]/15 text-[#f27c7c]",
  round_commit: "bg-[#5bdba2]/14 text-[#5bdba2]",
  session_exit: "bg-white/[0.07] text-[#a6b5cf]",
};

const DOT_TONE: Record<string, string> = {
  egress_blocked: "bg-[#f27c7c]",
  lane_conflict: "bg-[#f27c7c]",
  jit_approval: "bg-[#7f95f8]",
  egress_scrub: "bg-[#67d6dc]",
  file_change: "bg-[#5bdba2]",
  round_commit: "bg-[#5bdba2]",
  auto_rebase: "bg-[#c7a7ff]",
};

function decisionTone(decision: string): string {
  switch (decision) {
    case "allowed":
      return "bg-[#5bdba2]/15 text-[#5bdba2]";
    case "redacted":
      return "bg-[#67d6dc]/15 text-[#67d6dc]";
    case "approval_required":
      return "bg-[#7f95f8]/15 text-[#a8c5ff]";
    case "denied":
    case "exfiltration_blocked":
      return "bg-[#f27c7c]/15 text-[#f27c7c]";
    default:
      return "bg-white/[0.07] text-[#d2dbee]";
  }
}

const label = (s: string) => s.replace(/_/g, " ");

/** Chronological record of what an agent session did, from the server's provenance steps. */
export function ProvenanceTimeline({
  steps,
  emptyLabel = "No provenance recorded",
}: {
  steps: ProvenanceStep[];
  emptyLabel?: string;
}) {
  const ordered = useMemo(() => [...steps].sort((a, b) => a.seq - b.seq), [steps]);
  if (ordered.length === 0) {
    return <div className="py-4 text-center font-mono text-[13.5px] text-[#a6b5cf]">{emptyLabel}</div>;
  }
  return (
    <ol
      aria-label="Provenance timeline"
      className="relative space-y-2 font-mono text-[13px]"
    >
      {ordered.map((step, i) => (
        <li key={`${step.seq}-${i}`} className="relative flex gap-2.5">
          <div className="flex w-3 shrink-0 flex-col items-center">
            <span
              className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${DOT_TONE[step.kind] ?? "bg-[#8595b0]"}`}
            />
            {i < ordered.length - 1 && <span className="mt-1 w-px flex-1 bg-white/[0.08]" />}
          </div>
          <div className="min-w-0 flex-1 pb-1">
            <div className="flex flex-wrap items-center gap-1.5">
              <span
                className={`rounded-full px-2 py-0.5 text-[12px] uppercase tracking-wide ${
                  KIND_TONE[step.kind] ?? "bg-white/[0.07] text-[#d2dbee]"
                }`}
              >
                {label(step.kind)}
              </span>
              {step.decision && (
                <span
                  className={`rounded-full px-2 py-0.5 text-[12px] ${decisionTone(step.decision)}`}
                >
                  {label(step.decision)}
                </span>
              )}
              {step.exit_code !== undefined && step.exit_code !== null && (
                <span
                  className={`rounded-full px-2 py-0.5 text-[12px] ${
                    step.exit_code === 0
                      ? "bg-[#5bdba2]/12 text-[#5bdba2]"
                      : "bg-[#f27c7c]/15 text-[#f27c7c]"
                  }`}
                >
                  exit {step.exit_code}
                </span>
              )}
              {step.bytes_scrubbed !== undefined && step.bytes_scrubbed > 0 && (
                <span className="text-[12.5px] text-[#67d6dc]">{step.bytes_scrubbed}B scrubbed</span>
              )}
              <span className="ml-auto text-[12.5px] text-[#a6b5cf]">
                <Time value={step.timestamp} />
              </span>
            </div>
            <div className="mt-0.5 break-words text-[#dce4f5]">{step.summary}</div>
            {(step.path || step.target) && (
              <div className="mt-1 flex flex-wrap gap-1.5">
                {step.path && (
                  <span
                    title={step.path}
                    className="max-w-full truncate rounded-md bg-black/30 px-2 py-0.5 text-[12.5px] text-[#9ec0f5]"
                  >
                    {step.path}
                  </span>
                )}
                {step.target && (
                  <span
                    title={step.target}
                    className="max-w-full truncate rounded-md bg-black/30 px-2 py-0.5 text-[12.5px] text-[#a6b5cf]"
                  >
                    → {step.target}
                  </span>
                )}
              </div>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}
