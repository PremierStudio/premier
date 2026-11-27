import { useEffect, useRef, useState } from "react";
import {
  api,
  errorText,
  type IdentityPreset,
  type LaneConflict,
  type LaneRebaseResponse,
  type LaneResolveResponse,
} from "../api";
import {
  buildWholeFileConflictContent,
  canCustomEditConflict,
  MARKER_LINE_RE,
  spliceHunksIntoTargetFile,
} from "../lib/conflictMerge";
import { plural } from "../lib/format";
import { CodeBlock } from "./CodeBlock";
import { IconLock, IconQuarantine } from "./Icons";
import { ConfirmButton, ErrorNote, useAction } from "./forms";

interface Props {
  laneId?: string | null;
  conflicts: LaneConflict[];
  owner: boolean;
  /** Identity used to fetch full target file contents for safe custom editing. */
  identity?: IdentityPreset;
  onResolved?: (res: LaneResolveResponse) => void;
  onRebased?: (res: LaneRebaseResponse) => void;
  onSteerToResolve?: (conflicts: LaneConflict[]) => void;
  /** Branch the resolution lands on, shown so "apply" is not a surprise and used to load full files. */
  branch?: string | null;
}

type Choice = "target" | "agent" | "delete" | "edit";

interface Resolution {
  choice: Choice;
  /** Full file content to write for `choice === "edit"`; `null` while loading/errored or for non-edit strategies. */
  content: string | null;
}

type FullFileLoadState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; content: string; mode: "whole_file" | "splice"; lineCount: number }
  | { status: "error"; message: string };

const KIND_TONE: Record<string, string> = {
  content_overlap: "bg-[#7f95f8]/15 text-[#a8c5ff]",
  modify_delete: "bg-[#f27c7c]/15 text-[#f27c7c]",
  delete_modify: "bg-[#f27c7c]/15 text-[#f27c7c]",
  add_add: "bg-[#c7a7ff]/15 text-[#c7a7ff]",
  binary_conflict: "bg-white/[0.08] text-[#d2dbee]",
  mode_conflict: "bg-[#67d6dc]/15 text-[#67d6dc]",
  path_type_collision: "bg-[#f27c7c]/15 text-[#f27c7c]",
};

function isResolutionReady(r: Resolution | undefined): boolean {
  if (!r) return false;
  if (r.choice === "edit") {
    return r.content !== null && !MARKER_LINE_RE.test(r.content);
  }
  return true;
}

function SideLines({
  title,
  tone,
  lines,
  filePath,
}: {
  title: string;
  tone: string;
  lines: string[];
  filePath: string;
}) {
  if (lines.length === 0) {
    return (
      <div className="min-w-0 overflow-hidden rounded-xl border border-white/[0.08] bg-[#060913]/95">
        <div
          className={`border-b border-white/[0.06] bg-white/[0.025] px-3 py-1.5 text-[12px] uppercase tracking-wider ${tone}`}
        >
          {title}
        </div>
        <div className="px-3 py-2 font-mono text-[12px] text-[#8595b0]">(empty)</div>
      </div>
    );
  }
  return (
    <CodeBlock
      code={lines.join("\n")}
      filePath={filePath}
      label={title}
      showLineNumbers
      compact
      maxHeightClass="max-h-52"
    />
  );
}

function ConflictCard({
  conflict,
  editable,
  identity,
  branch,
  resolution,
  onResolution,
}: {
  conflict: LaneConflict;
  editable: boolean;
  identity?: IdentityPreset;
  branch?: string | null;
  resolution: Resolution | undefined;
  onResolution: (r: Resolution | undefined) => void;
}) {
  const [showMarkers, setShowMarkers] = useState(false);
  const [fullFileState, setFullFileState] = useState<FullFileLoadState>({ status: "idle" });
  const loadSeqRef = useRef(0);
  const choiceRef = useRef<Choice | undefined>(resolution?.choice);
  choiceRef.current = resolution?.choice;

  const hasHunks = conflict.hunks.length > 0;
  const eligibility = canCustomEditConflict(conflict);
  const stillHasMarkers =
    resolution?.choice === "edit" &&
    resolution.content !== null &&
    MARKER_LINE_RE.test(resolution.content);

  // Reset cached full-file state when conflict path, branch, or hunks change.
  const hunksKey = conflict.hunks.map((h) => `${h.start_line}:${h.end_line}`).join(",");
  useEffect(() => {
    loadSeqRef.current += 1;
    setFullFileState({ status: "idle" });
  }, [conflict.path, conflict.kind, branch, hunksKey]);

  const startCustomEdit = () => {
    if (!eligibility.ok) return;

    // Keep an already-loaded or edited draft when clicking Edit again.
    if (resolution?.choice === "edit" && resolution.content !== null) {
      return;
    }

    if (eligibility.mode === "whole_file") {
      const built = buildWholeFileConflictContent(conflict);
      setFullFileState({
        status: "ready",
        content: built.content,
        mode: "whole_file",
        lineCount: built.lineCount,
      });
      onResolution({ choice: "edit", content: built.content });
      return;
    }

    if (fullFileState.status === "ready") {
      onResolution({ choice: "edit", content: fullFileState.content });
      return;
    }

    // Enter edit mode with `content: null` so Apply stays strictly disabled until the full file loads.
    onResolution({ choice: "edit", content: null });

    if (!identity || !branch) {
      setFullFileState({
        status: "error",
        message:
          "Cannot load full target file without branch context. Custom editing is disabled to prevent truncating the file — choose Use Target, Use Agent, or Delete.",
      });
      return;
    }

    const seq = ++loadSeqRef.current;
    setFullFileState({ status: "loading" });

    void api
      .repoFile(identity, conflict.path, branch)
      .then((file) => {
        if (loadSeqRef.current !== seq) return;
        if (!file.allowed) {
          setFullFileState({
            status: "error",
            message:
              file.reason ||
              "Read access to the full file was denied. Custom editing is disabled to prevent truncating the file.",
          });
          return;
        }
        if (file.binary) {
          setFullFileState({
            status: "error",
            message:
              "This file is binary and cannot be edited inline. Choose Use Target, Use Agent, or Delete.",
          });
          return;
        }
        if (file.truncated || file.content === undefined) {
          setFullFileState({
            status: "error",
            message:
              "This file exceeds the 512 KiB inline preview cap. Custom editing is disabled to prevent truncating the file — choose Use Target, Use Agent, or Delete.",
          });
          return;
        }
        const spliced = spliceHunksIntoTargetFile(file.content, conflict.hunks);
        if (!spliced.ok) {
          setFullFileState({ status: "error", message: spliced.reason });
          return;
        }
        setFullFileState({
          status: "ready",
          content: spliced.content,
          mode: "splice",
          lineCount: spliced.lineCount,
        });
        // Only populate the editor if the user hasn't switched away from Edit while loading.
        if (choiceRef.current === "edit") {
          onResolution({ choice: "edit", content: spliced.content });
        }
      })
      .catch((err: unknown) => {
        if (loadSeqRef.current !== seq) return;
        setFullFileState({
          status: "error",
          message: `Could not load full file from ${branch}: ${errorText(err)}. Custom editing is disabled to prevent truncating the file.`,
        });
      });
  };

  const choiceBtn = (
    choice: Choice,
    text: string,
    disabled: boolean,
    onClick: () => void,
    title?: string,
  ) => (
    <button
      type="button"
      disabled={disabled}
      title={title}
      aria-pressed={resolution?.choice === choice}
      onClick={onClick}
      className={`rounded-full px-2.5 py-0.5 text-[12.5px] transition disabled:cursor-not-allowed disabled:opacity-40 ${
        resolution?.choice === choice ? "pr-pill-active" : "pr-pill text-[#d2dbee] hover:text-white"
      }`}
    >
      {text}
    </button>
  );

  return (
    <div className="pr-well space-y-2 rounded-xl p-2.5 font-mono text-[13px]">
      <div className="flex flex-wrap items-center gap-2">
        <span
          className="min-w-0 flex-1 truncate text-[13.5px] text-[#f3f6fd]"
          title={conflict.allowed ? conflict.path : undefined}
        >
          {conflict.allowed ? conflict.path : "[SERVER-REDACTED]"}
        </span>
        <span
          className={`rounded-full px-2 py-0.5 text-[12px] uppercase tracking-wide ${
            KIND_TONE[conflict.kind] ?? "bg-white/[0.08] text-[#d2dbee]"
          }`}
        >
          {conflict.kind.replace(/_/g, " ")}
        </span>
      </div>

      {!conflict.allowed ? (
        <div className="flex items-start gap-2 text-[#9eb0cc]">
          <IconLock className="mt-px h-4 w-4 shrink-0" />
          <span>
            This conflict is in a path this identity cannot read. The server withheld its details,
            so it can only be resolved by someone with access.
          </span>
        </div>
      ) : (
        <>
          <p className="break-words text-[#b6c3db]">{conflict.summary}</p>

          {hasHunks && (
            <div className="space-y-2">
              {conflict.hunks.map((h, i) => (
                <div key={i} className="space-y-1.5">
                  <div className="text-[12.5px] text-[#a6b5cf]">
                    L{h.start_line}–{h.end_line}
                  </div>
                  <div className="grid gap-2 md:grid-cols-3">
                    <SideLines
                      title="Target / Ours"
                      tone="text-[#9ec0f5]"
                      lines={h.ours_lines}
                      filePath={conflict.path}
                    />
                    <SideLines
                      title="Common Base"
                      tone="text-[#a6b5cf]"
                      lines={h.base_lines}
                      filePath={conflict.path}
                    />
                    <SideLines
                      title="Agent / Theirs"
                      tone="text-[#c7a7ff]"
                      lines={h.theirs_lines}
                      filePath={conflict.path}
                    />
                  </div>
                </div>
              ))}
              <button
                type="button"
                aria-expanded={showMarkers}
                onClick={() => setShowMarkers((v) => !v)}
                className="text-[12.5px] text-[#9ec0f5] hover:underline"
              >
                {showMarkers ? "Hide raw markers" : "Show raw markers"}
              </button>
              {showMarkers && (
                <CodeBlock
                  code={conflict.hunks.map((h) => h.markers).join("\n")}
                  filePath={conflict.path}
                  label="Conflict markers"
                  showLineNumbers
                  compact
                  maxHeightClass="max-h-56"
                />
              )}
            </div>
          )}

          {editable && (
            <div className="space-y-2 border-t border-white/[0.06] pt-2.5">
              <div
                role="group"
                aria-label={`Resolve ${conflict.path}`}
                className="flex flex-wrap items-center gap-1.5"
              >
                {choiceBtn("target", "Use Target", false, () =>
                  onResolution({ choice: "target", content: null }),
                )}
                {choiceBtn("agent", "Use Agent", false, () =>
                  onResolution({ choice: "agent", content: null }),
                )}
                {choiceBtn("delete", "Delete file", false, () =>
                  onResolution({ choice: "delete", content: null }),
                )}
                {choiceBtn(
                  "edit",
                  "Edit full file…",
                  !eligibility.ok,
                  startCustomEdit,
                  eligibility.ok ? undefined : eligibility.reason,
                )}
                {resolution && (
                  <button
                    type="button"
                    onClick={() => onResolution(undefined)}
                    className="text-[12.5px] text-[#a6b5cf] hover:text-white"
                  >
                    Clear
                  </button>
                )}
              </div>
              {resolution?.choice === "target" && (
                <p className="text-[#9ec0f5]">Target version will be kept.</p>
              )}
              {resolution?.choice === "agent" && (
                <p className="text-[#c7a7ff]">Agent version will be kept.</p>
              )}
              {resolution?.choice === "edit" && fullFileState.status === "loading" && (
                <p role="status" className="text-[#a6b5cf]">
                  Loading full file from {branch}…
                </p>
              )}
              {resolution?.choice === "edit" && fullFileState.status === "error" && (
                <div
                  role="alert"
                  className="space-y-1.5 rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-2 text-[12.5px] text-[#ffb4b4]"
                >
                  <p>{fullFileState.message}</p>
                  <button
                    type="button"
                    onClick={startCustomEdit}
                    className="text-[#9ec0f5] underline hover:text-white"
                  >
                    Retry loading full file
                  </button>
                </div>
              )}
              {resolution?.choice === "edit" && resolution.content !== null && (
                <>
                  {fullFileState.status === "ready" && (
                    <p className="text-[12px] text-[#a6b5cf]">
                      {fullFileState.mode === "whole_file"
                        ? `Editing full file (${plural(fullFileState.lineCount, "line")}) with conflict markers.`
                        : `Editing full file (${plural(fullFileState.lineCount, "line")} from ${branch}) with conflict markers in context. Non-conflicting agent edits outside these hunks are not previewed here.`}
                    </p>
                  )}
                  <textarea
                    value={resolution.content}
                    onChange={(e) => onResolution({ choice: "edit", content: e.target.value })}
                    spellCheck={false}
                    rows={Math.min(18, Math.max(6, resolution.content.split("\n").length + 1))}
                    aria-label={`Resolved full file content for ${conflict.path}`}
                    className="pr-well w-full resize-y rounded-xl px-3 py-2 text-[13px] leading-[1.55] text-[#f3f6fd] focus:outline-none"
                  />
                  {stillHasMarkers && (
                    <p role="alert" className="text-[#a8c5ff]">
                      Remove the &lt;&lt;&lt;&lt;&lt;&lt;&lt; / ======= / &gt;&gt;&gt;&gt;&gt;&gt;&gt;
                      marker lines before applying.
                    </p>
                  )}
                </>
              )}
              {resolution?.choice === "delete" && (
                <p className="text-[#f27c7c]">This file will be deleted on the lane.</p>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}

/** Shows a lane's conflicts as diff3 hunks; owners can resolve them or rebase the lane. */
export function LaneConflictInspector({
  laneId,
  conflicts,
  owner,
  identity,
  onResolved,
  onRebased,
  onSteerToResolve,
  branch,
}: Props) {
  const [resolutions, setResolutions] = useState<Record<string, Resolution>>({});
  const [note, setNote] = useState<string | null>(null);
  const resolve = useAction();
  const rebase = useAction();

  const canAct = owner && Boolean(laneId);
  const allowed = conflicts.filter((c) => c.allowed);
  const withheld = conflicts.length - allowed.length;
  const resolvedCount = allowed.filter((c) => isResolutionReady(resolutions[c.path])).length;
  const complete =
    allowed.length > 0 && allowed.every((c) => isResolutionReady(resolutions[c.path]));

  const handleResolve = async () => {
    // ConfirmButton may still be armed after a resolution was cleared; never submit unresolved or partial edits.
    if (!laneId || !complete) return;
    setNote(null);
    await resolve.run(async () => {
      const payloadResolutions = allowed.map((c) => {
        const r = resolutions[c.path];
        if (r?.choice === "target") {
          return { path: c.path, content: null, strategy: "ours" as const };
        }
        if (r?.choice === "agent") {
          return { path: c.path, content: null, strategy: "theirs" as const };
        }
        if (r?.choice === "delete") {
          return { path: c.path, content: null, strategy: "delete" as const };
        }
        if (!r || r.content === null) {
          throw new Error(`Full file content for ${c.path} is not loaded yet.`);
        }
        return {
          path: c.path,
          content: r.content,
          strategy: "custom" as const,
        };
      });
      const res = await api.resolveLane(laneId, {
        resolutions: payloadResolutions,
        apply_to_branch: true,
      });
      setResolutions({});
      setNote(
        res.review_round != null
          ? `Resolved and applied as R${res.review_round}.`
          : "Resolved and applied.",
      );
      onResolved?.(res);
    });
  };

  const handleRebase = async () => {
    if (!laneId) return;
    setNote(null);
    await rebase.run(async () => {
      const res = await api.rebaseLane(laneId, { cascade: true });
      setResolutions({});
      setNote(
        res.rebased
          ? `Rebased cleanly (${plural(res.merged_paths.length, "path")} merged).`
          : `Rebase left ${plural(res.conflicts.length, "conflict")}.`,
      );
      onRebased?.(res);
    });
  };

  if (conflicts.length === 0) {
    return (
      <div className="font-mono text-[13px] text-[#5bdba2]" role="status">
        {note ?? "No conflicts"}
      </div>
    );
  }

  return (
    <section
      aria-label="Lane conflicts"
      className="space-y-2 rounded-xl border border-[#f27c7c]/25 bg-[#f27c7c]/[0.05] p-2.5"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px]">
        <span className="inline-flex items-center gap-1.5 uppercase tracking-wider text-[#f27c7c]">
          <IconQuarantine className="h-4 w-4" />
          {plural(conflicts.length, "conflict")}
          {laneId ? <span className="normal-case text-[#a6b5cf]">· {laneId}</span> : null}
        </span>
        {withheld > 0 && (
          <span className="text-[#9eb0cc]">{plural(withheld, "conflict")} withheld by ACL</span>
        )}
      </div>

      {conflicts.map((c, i) => (
        <ConflictCard
          key={`${c.path}-${i}`}
          conflict={c}
          editable={canAct}
          identity={identity}
          branch={branch}
          resolution={resolutions[c.path]}
          onResolution={(r) =>
            setResolutions((prev) => {
              const next = { ...prev };
              if (r) next[c.path] = r;
              else delete next[c.path];
              return next;
            })
          }
        />
      ))}

      {canAct && allowed.length > 0 && (
        <p className="font-mono text-[12.5px] text-[#a6b5cf]">
          <span className="tabular-nums">
            {resolvedCount} of {allowed.length}
          </span>{" "}
          resolved · Applies to {branch || "the branch"} as a new review round
        </p>
      )}
      {canAct && (
        <div className="flex flex-wrap items-center gap-2 font-sans">
          <ConfirmButton
            disabled={!complete || resolve.pending}
            title={complete ? undefined : "Choose a valid resolution for every readable conflict"}
            confirmLabel="Apply"
            question={`Apply to ${branch || "the branch"}?`}
            onConfirm={() => void handleResolve()}
            className="pr-action-btn rounded-full px-3 py-1 text-[13.5px] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {resolve.pending ? "Applying…" : "Resolve & Apply"}
          </ConfirmButton>
          <button
            type="button"
            disabled={rebase.pending}
            onClick={() => void handleRebase()}
            className="pr-pill rounded-full px-3 py-1 text-[13.5px] text-[#dce4f5] disabled:cursor-not-allowed disabled:opacity-40"
          >
            {rebase.pending ? "Rebasing…" : "Rebase Lane"}
          </button>
          {onSteerToResolve && (
            <button
              type="button"
              onClick={() => onSteerToResolve(conflicts)}
              className="pr-pill rounded-full px-3 py-1 text-[13.5px] text-[#9ec0f5] hover:text-white"
            >
              Steer Agent to Resolve
            </button>
          )}
        </div>
      )}
      {owner && !laneId && (
        <p className="font-mono text-[12.5px] text-[#a6b5cf]">
          No lane is attached to these conflicts yet, so they can't be resolved from here.
        </p>
      )}
      {note && (
        <p role="status" className="font-mono text-[13px] text-[#5bdba2]">
          {note}
        </p>
      )}
      <ErrorNote message={resolve.error ?? rebase.error} />
    </section>
  );
}
