import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import {
  api,
  errorText,
  shortOid,
  type PolicySuggestion,
  type PolicySuggestionPreview,
} from "../api";
import { ErrorNote, PRIMARY_BTN, SECONDARY_BTN, useAction } from "./forms";
import { IconCheck, IconClose } from "./Icons";
import { CodeLinesSkeleton } from "./ViewSkeletons";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])';

function diffLineClass(line: string): string {
  if (line.startsWith("@@") || line.startsWith("---") || line.startsWith("+++")) {
    return "bg-[#7f95f8]/10 text-[#9ec0f5]";
  }
  if (line.startsWith("+")) return "bg-[#5bdba2]/10 text-[#5bdba2]";
  if (line.startsWith("-")) return "bg-[#f27c7c]/10 text-[#f27c7c]";
  return "text-[#a6b5cf]";
}

/** Owner-only: previews and commits a `.env.schema` egress rule promoted from repeated approvals. */
export function PolicyGraduationModal({
  suggestion,
  onClose,
  onApplied,
}: {
  suggestion: PolicySuggestion;
  onClose: () => void;
  onApplied: () => void;
}) {
  const [preview, setPreview] = useState<PolicySuggestionPreview | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [commit, setCommit] = useState<string | null>(null);
  const action = useAction();
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);

  // Hand focus back to whatever opened the dialog.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    panelRef.current?.focus();
    return () => opener?.focus?.();
  }, []);

  useEffect(() => {
    let active = true;
    api
      .previewApprovalSuggestion(suggestion.id)
      .then((res) => {
        if (active) setPreview(res);
      })
      .catch((err: unknown) => {
        if (active) setLoadError(errorText(err));
      });
    return () => {
      active = false;
    };
  }, [suggestion.id]);

  // Disabling controls drops focus to <body>; park it on the panel so the trap and Escape hold.
  useEffect(() => {
    if (action.pending) panelRef.current?.focus();
  }, [action.pending]);

  const close = () => {
    if (!action.pending) onClose();
  };

  const onKeyDown = (e: KeyboardEvent) => {
    // Keeps the Studio's global shortcuts (1–7, g-chords, palette, knock keys) from firing behind the modal.
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

  const apply = () => {
    void action.run(async () => {
      const res = await api.applyApprovalSuggestion(suggestion.id);
      setCommit(res.commit);
      onApplied();
    });
  };

  const s = preview?.suggestion ?? suggestion;
  const diffLines = preview ? preview.unified_diff.split("\n") : [];

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-[#04060d]/80 px-4 py-10 backdrop-blur-sm sm:pt-20"
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
        onKeyDown={onKeyDown}
        className="pr-elevated w-full max-w-2xl overflow-hidden rounded-2xl focus:outline-none"
      >
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.08] px-4 py-3">
          <h2 id={titleId} className="text-[14px] font-semibold text-[#f3f6fd]">
            Promote to .env.schema
          </h2>
          <button
            type="button"
            onClick={close}
            disabled={action.pending}
            aria-label="Close"
            className="rounded-lg p-1.5 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white disabled:opacity-40"
          >
            <IconClose className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-3.5 p-4">
          <div className="flex flex-wrap items-center gap-1.5 font-mono text-[13px]">
            <span className="font-semibold text-[#f3f6fd]">{s.var_name}</span>
            <span className="rounded-md bg-[#7f95f8]/15 px-1.5 py-0.5 text-[12.5px] text-[#9ec0f5]">
              {s.agent_profile}
            </span>
            <span className="text-[#d2dbee]">{s.host}</span>
            <span className="rounded-md bg-white/[0.06] px-1.5 py-0.5 text-[12.5px] text-[#9ec0f5]">
              GET {s.path_prefix}
            </span>
            <span className="text-[#a6b5cf]">
              {s.approved_count} approval{s.approved_count === 1 ? "" : "s"}
            </span>
          </div>

          {loadError && <ErrorNote message={loadError} />}
          {!preview && !loadError && (
            <div className="pr-well overflow-hidden rounded-xl">
              <CodeLinesSkeleton className="max-h-[340px]" />
            </div>
          )}

          {preview && (
            <>
              {preview.already_covered && (
                <div
                  role="status"
                  className="rounded-xl border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-3 py-2 text-[13.5px] text-[#5bdba2]"
                >
                  Already covered: {preview.schema_path} has an equivalent rule, so committing changes
                  nothing.
                </div>
              )}
              <div className="pr-well overflow-hidden rounded-xl">
                <div className="border-b border-white/[0.06] px-3 py-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                  {preview.schema_path}
                </div>
                <div className="max-h-[340px] overflow-auto py-1.5 font-mono text-[12.5px] leading-[1.58]">
                  {diffLines.map((line, i) => (
                    <div key={i} className={`whitespace-pre px-3 ${diffLineClass(line)}`}>
                      {line || " "}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          <p className="text-[13px] leading-relaxed text-[#a6b5cf]">
            Commits to .env.schema on the default branch. Only this exact (agent_profile, host, GET,
            path_prefix) will auto-allow; mutations and other agents remain JIT-gated.
          </p>

          {commit && (
            <div
              role="status"
              className="flex items-center gap-2 rounded-xl border border-[#5bdba2]/25 bg-[#5bdba2]/10 px-3 py-2 font-mono text-[13.5px] text-[#5bdba2]"
            >
              <IconCheck className="h-4 w-4" />
              <span>
                Committed <span title={commit}>{shortOid(commit)}</span> to .env.schema
              </span>
            </div>
          )}
          <ErrorNote message={action.error} />

          <div className="flex flex-wrap justify-end gap-2">
            <button type="button" onClick={close} disabled={action.pending} className={SECONDARY_BTN}>
              {commit ? "Done" : "Cancel"}
            </button>
            {!commit && (
              <button
                type="button"
                onClick={apply}
                disabled={action.pending || !preview || preview.already_covered}
                className={PRIMARY_BTN}
              >
                {action.pending ? "Committing…" : "Commit to .env.schema"}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
