import { useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  errorText,
  type AgentSessionRecord,
  type SessionWorkspaceFileEntry,
  type SessionWorkspaceFileResponse,
  type SessionWorkspaceFilesResponse,
} from "../api";
import { plural } from "../lib/format";
import {
  IconCheck,
  IconClose,
  IconFileNode,
  IconLock,
  IconPlay,
  IconRefresh,
  IconSearch,
} from "./Icons";
import { CodeLinesSkeleton, FileTreeSkeleton } from "./ViewSkeletons";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export interface SessionStepInEditorProps {
  session: AgentSessionRecord;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onResumed: (newSession: AgentSessionRecord) => void;
  onClose?: () => void;
  onDirtyChange?: (dirty: boolean) => void;
}

/** Owner-only obsidian-glass Human Step-In Workspace Editor for paused or ended (uncommitted) cage sessions. */
export function SessionStepInEditor({
  session,
  onSessionChange,
  onResumed,
  onClose,
  onDirtyChange,
}: SessionStepInEditorProps) {
  const [filesData, setFilesData] = useState<SessionWorkspaceFilesResponse | null>(null);
  const [loadingFiles, setLoadingFiles] = useState(false);
  const [filter, setFilter] = useState("");
  const [selectedPath, setSelectedPath] = useState<string | null>(null);

  const [fileData, setFileData] = useState<SessionWorkspaceFileResponse | null>(null);
  const [loadingFile, setLoadingFile] = useState(false);
  const [draft, setDraft] = useState("");
  const [loadedContent, setLoadedContent] = useState("");

  const [savingFile, setSavingFile] = useState(false);
  const [savedNotice, setSavedNotice] = useState<string | null>(null);

  const [checkpointLabel, setCheckpointLabel] = useState("");
  const [checkpointBusy, setCheckpointBusy] = useState(false);
  const [checkpointNotice, setCheckpointNotice] = useState<string | null>(null);

  const [resumeCmd, setResumeCmd] = useState(session.command);
  const [resuming, setResuming] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [filesReloadNonce, setFilesReloadNonce] = useState(0);
  const [pendingNav, setPendingNav] = useState<
    { kind: "file"; path: string } | { kind: "close" } | null
  >(null);

  const selectedPathRef = useRef<string | null>(selectedPath);
  selectedPathRef.current = selectedPath;
  const sessionIdRef = useRef(session.id);
  sessionIdRef.current = session.id;
  const onDirtyChangeRef = useRef(onDirtyChange);
  onDirtyChangeRef.current = onDirtyChange;
  const savedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const checkpointTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setResumeCmd(session.command);
    setPendingNav(null);
  }, [session.id, session.command]);

  useEffect(() => {
    return () => {
      if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
      if (checkpointTimerRef.current) clearTimeout(checkpointTimerRef.current);
      onDirtyChangeRef.current?.(false);
    };
  }, []);

  useEffect(() => {
    let active = true;
    setLoadingFiles(true);
    setError(null);
    api
      .sessionWorkspaceFiles(session.id)
      .then((res) => {
        if (!active) return;
        setFilesData(res);
        setSelectedPath((cur) => {
          if (cur && res.files.some((f) => f.path === cur)) return cur;
          const firstChanged = res.files.find((f) => Boolean(f.change_kind));
          return firstChanged?.path ?? res.files[0]?.path ?? null;
        });
      })
      .catch((err: unknown) => {
        if (!active) return;
        setError(errorText(err));
      })
      .finally(() => {
        if (active) setLoadingFiles(false);
      });
    return () => {
      active = false;
    };
  }, [session.id, filesReloadNonce]);

  useEffect(() => {
    if (!selectedPath) {
      setFileData(null);
      setDraft("");
      setLoadedContent("");
      return;
    }
    let active = true;
    setLoadingFile(true);
    setError(null);
    setSavedNotice(null);
    api
      .sessionWorkspaceFile(session.id, selectedPath)
      .then((res) => {
        if (!active) return;
        setFileData(res);
        const text = res.content ?? "";
        setDraft(text);
        setLoadedContent(text);
      })
      .catch((err: unknown) => {
        if (!active) return;
        setFileData(null);
        setError(errorText(err));
      })
      .finally(() => {
        if (active) setLoadingFile(false);
      });
    return () => {
      active = false;
    };
  }, [session.id, selectedPath]);

  const sortedFiles = useMemo(() => {
    const list = filesData?.files ?? [];
    const q = filter.trim().toLowerCase();
    const filtered = q ? list.filter((f) => f.path.toLowerCase().includes(q)) : list;
    return [...filtered].sort((a: SessionWorkspaceFileEntry, b: SessionWorkspaceFileEntry) => {
      const aChanged = a.change_kind ? 0 : 1;
      const bChanged = b.change_kind ? 0 : 1;
      if (aChanged !== bChanged) return aChanged - bChanged;
      return a.path.localeCompare(b.path);
    });
  }, [filesData, filter]);

  const isDirty = Boolean(fileData && !fileData.binary && fileData.can_write && draft !== loadedContent);
  const checkpoints = session.checkpoints ?? [];

  useEffect(() => {
    onDirtyChange?.(isDirty);
    if (!isDirty) setPendingNav(null);
  }, [isDirty, onDirtyChange]);

  const handleSaveFile = async () => {
    if (!selectedPath || !fileData || !fileData.can_write || fileData.binary) return;
    const targetSessionId = session.id;
    const targetPath = selectedPath;
    const savedText = draft;
    setSavingFile(true);
    setError(null);
    setSavedNotice(null);
    try {
      const res = await api.writeSessionWorkspaceFile(targetSessionId, targetPath, savedText);
      if (
        sessionIdRef.current === targetSessionId &&
        selectedPathRef.current === targetPath
      ) {
        setLoadedContent(savedText);
        setFileData((prev) =>
          prev ? { ...prev, content: savedText, size: res.bytes_written } : prev,
        );
        setPendingNav(null);
        setSavedNotice(`Saved ${formatSize(res.bytes_written)}`);
        if (savedTimerRef.current) clearTimeout(savedTimerRef.current);
        savedTimerRef.current = setTimeout(() => setSavedNotice(null), 2500);
      }
      onSessionChange(res.session);
      setFilesReloadNonce((n) => n + 1);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setSavingFile(false);
    }
  };

  const handleCheckpoint = async (e: React.FormEvent) => {
    e.preventDefault();
    setCheckpointBusy(true);
    setError(null);
    setCheckpointNotice(null);
    try {
      const res = await api.checkpointSession(session.id, checkpointLabel.trim() || undefined);
      setCheckpointLabel("");
      setCheckpointNotice(`Saved ${res.checkpoint.id}`);
      onSessionChange(res.session);
      if (checkpointTimerRef.current) clearTimeout(checkpointTimerRef.current);
      checkpointTimerRef.current = setTimeout(() => setCheckpointNotice(null), 2500);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setCheckpointBusy(false);
    }
  };

  const handleResume = async (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = resumeCmd.trim();
    if (!cmd || isDirty) return;
    setResuming(true);
    setError(null);
    try {
      const limitSecs =
        session.limit_secs && session.limit_secs > 0 ? session.limit_secs : undefined;
      const next = await api.resumeSession(session.id, cmd, limitSecs);
      onResumed(next);
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setResuming(false);
    }
  };

  const handleSelectFile = (path: string) => {
    if (path === selectedPath) return;
    if (isDirty) {
      setPendingNav({ kind: "file", path });
      return;
    }
    setPendingNav(null);
    setSelectedPath(path);
  };

  const handleRequestClose = () => {
    if (!onClose) return;
    if (isDirty) {
      setPendingNav({ kind: "close" });
      return;
    }
    onClose();
  };

  return (
    <div className="flex min-h-[300px] max-h-[58%] shrink-0 flex-col border-t border-[#9ec0f5]/22 bg-[#0b0f1c]">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-1.5 font-mono text-[12.5px]">
        <div className="flex min-w-0 items-center gap-2">
          <span className="uppercase tracking-wider text-[#9ec0f5]">Step-In Workspace</span>
          {(filesData?.branch || session.branch) && (
            <span className="rounded-full bg-white/[0.05] px-2 py-0.5 text-[12px] text-[#d2dbee]">
              {filesData?.branch || session.branch}
            </span>
          )}
          {filesData?.truncated && (
            <span className="rounded-full border border-white/[0.11] bg-white/[0.04] px-2 py-0.5 text-[12px] text-[#9eb0cc]">
              list truncated
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setFilesReloadNonce((n) => n + 1)}
            disabled={loadingFiles}
            title="Refresh workspace files"
            aria-label="Refresh workspace files"
            className="rounded-lg p-1 text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-[#f3f6fd] disabled:opacity-40"
          >
            <IconRefresh className={`h-3.5 w-3.5 ${loadingFiles ? "animate-spin" : ""}`} />
          </button>
          {onClose && (
            <button
              type="button"
              onClick={handleRequestClose}
              aria-label="Close step-in editor"
              className="rounded-lg p-1 text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-white"
            >
              <IconClose className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="border-b border-[#f27c7c]/25 bg-[#1c0d12] px-3 py-1.5 font-mono text-[12.5px] text-[#f27c7c]"
        >
          {error}
        </div>
      )}

      {pendingNav && (
        <div
          role="alert"
          className="flex flex-wrap items-center justify-between gap-2 border-b border-[#9ec0f5]/30 bg-[#111830] px-3 py-1.5 font-mono text-[12.5px] text-[#cfe0ff]"
        >
          <span>
            Unsaved edits in <strong className="text-[#f3f6fd]">{selectedPath}</strong>. Save
            first or discard them?
          </span>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setPendingNav(null)}
              className="pr-pill rounded-full px-2.5 py-0.5 text-[12.5px] text-[#dce4f5] hover:text-white"
            >
              Keep editing
            </button>
            <button
              type="button"
              onClick={() => {
                const nav = pendingNav;
                setPendingNav(null);
                if (nav.kind === "file") {
                  setSelectedPath(nav.path);
                } else {
                  onClose?.();
                }
              }}
              className="rounded-full border border-[#9ec0f5]/40 bg-[#7f95f8]/18 px-2.5 py-0.5 text-[12.5px] text-[#cfe0ff] hover:bg-[#7f95f8]/28"
            >
              Discard & continue
            </button>
          </div>
        </div>
      )}

      {/* Split: Left File Rail + Right Editor Pane */}
      <div className="flex min-h-0 flex-1 flex-col sm:flex-row">
        {/* Left File Rail */}
        <div className="flex max-h-[150px] shrink-0 flex-col border-b border-white/[0.06] sm:max-h-none sm:w-56 sm:border-r sm:border-b-0 xl:w-64">
          <div className="flex items-center gap-1.5 border-b border-white/[0.06] px-2.5 py-1.5">
            <IconSearch className="h-3.5 w-3.5 text-[#a6b5cf]" />
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              aria-label="Filter workspace files"
              placeholder="Filter files…"
              className="min-w-0 flex-1 bg-transparent font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
            />
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-1.5">
            {loadingFiles && !filesData ? (
              <FileTreeSkeleton rows={6} />
            ) : sortedFiles.length === 0 ? (
              <div className="px-2 py-3 font-mono text-[12.5px] text-[#a6b5cf]">No matching files</div>
            ) : (
              sortedFiles.map((entry) => {
                const active = selectedPath === entry.path;
                return (
                  <button
                    key={entry.path}
                    type="button"
                    onClick={() => handleSelectFile(entry.path)}
                    title={entry.path}
                    className={`flex w-full items-center justify-between gap-1.5 rounded-lg px-2 py-1 text-left font-mono text-[12.5px] transition ${
                      active
                        ? "bg-[#7f95f8]/18 text-[#f3f6fd]"
                        : "text-[#d2dbee] hover:bg-white/[0.045] hover:text-[#f3f6fd]"
                    }`}
                  >
                    <span className="flex min-w-0 items-center gap-1.5">
                      {!entry.can_write ? (
                        <IconLock
                          className="h-3.5 w-3.5 shrink-0 text-[#a6b5cf]"
                          aria-label="Read-only"
                        />
                      ) : (
                        <IconFileNode className="h-3.5 w-3.5 shrink-0 text-[#a6b5cf]" />
                      )}
                      <span className="truncate">{entry.path}</span>
                    </span>
                    {entry.change_kind && (
                      <span
                        className={`shrink-0 rounded-full px-1.5 py-0.5 text-[12px] ${
                          entry.change_kind === "added"
                            ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                            : "bg-[#9ec0f5]/14 text-[#9ec0f5]"
                        }`}
                      >
                        {entry.change_kind}
                      </span>
                    )}
                  </button>
                );
              })
            )}
          </div>
        </div>

        {/* Right Editor Pane */}
        <div className="flex min-h-[160px] min-w-0 flex-1 flex-col">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] bg-black/20 px-3 py-1.5 font-mono text-[12.5px]">
            <div className="flex min-w-0 items-center gap-2">
              <span className="truncate text-[#e6ecf8]">{selectedPath ?? "Select a file"}</span>
              {loadingFile && fileData && (
                <IconRefresh className="h-3 w-3 shrink-0 animate-spin text-[#a6b5cf]" aria-label="Loading file" />
              )}
              {isDirty && (
                <span
                  title="Unsaved changes"
                  className="h-2 w-2 shrink-0 rounded-full bg-[#7f95f8]"
                />
              )}
              {fileData && !fileData.can_write && (
                <span className="inline-flex shrink-0 items-center gap-1 rounded-full border border-white/[0.12] bg-white/[0.045] px-2 py-0.5 text-[12px] text-[#cbd5e8]">
                  <IconLock className="h-3 w-3 text-[#a8c5ff]" />
                  <span>read-only ceiling</span>
                </span>
              )}
              {fileData?.binary && (
                <span className="shrink-0 rounded-full bg-white/[0.06] px-2 py-0.5 text-[12px] text-[#b6c3db]">
                  binary
                </span>
              )}
            </div>
            <div className="flex shrink-0 items-center gap-2">
              {fileData && (
                <span className="hidden text-[12px] text-[#a6b5cf] md:inline">
                  {formatSize(fileData.size)} · {fileData.sha256.slice(0, 8)}
                </span>
              )}
              {savedNotice && (
                <span className="inline-flex items-center gap-1 text-[12.5px] text-[#5bdba2]">
                  <IconCheck className="h-3.5 w-3.5" />
                  <span>{savedNotice}</span>
                </span>
              )}
              <button
                type="button"
                disabled={!isDirty || savingFile || loadingFile || !fileData?.can_write || Boolean(fileData?.binary)}
                onClick={() => void handleSaveFile()}
                className="pr-action-btn inline-flex items-center gap-1 rounded-full px-3 py-1 font-sans text-[12.5px] disabled:cursor-not-allowed disabled:opacity-40"
              >
                <IconCheck className="h-3.5 w-3.5" />
                <span>{savingFile ? "Saving…" : "Save File"}</span>
              </button>
            </div>
          </div>

          <div className="min-h-0 flex-1 overflow-hidden">
            {!fileData && loadingFile ? (
              <CodeLinesSkeleton className="p-3" />
            ) : !fileData ? (
              <div className="flex h-full items-center justify-center p-4 font-mono text-[13px] text-[#a6b5cf]">
                Select a workspace file to inspect or edit
              </div>
            ) : fileData.binary ? (
              <div className="flex h-full items-center justify-center p-4 text-center font-mono text-[13px] text-[#a6b5cf]">
                Binary file ({formatSize(fileData.size)}) — inline editing unavailable
              </div>
            ) : (
              <textarea
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                readOnly={!fileData.can_write || loadingFile}
                aria-busy={loadingFile}
                aria-label={`Workspace contents of ${fileData.path}`}
                spellCheck={false}
                className={`h-full min-h-[140px] w-full resize-none p-3 font-mono text-[13.5px] leading-[1.6] transition-opacity focus:outline-none ${
                  fileData.can_write ? "bg-black/30 text-[#e6ecf8]" : "bg-black/20 text-[#b6c3db]"
                } ${loadingFile ? "opacity-60" : ""}`}
              />
            )}
          </div>
        </div>
      </div>

      {/* Footer: checkpoint + resume share one row on wide panes */}
      <div className="grid shrink-0 gap-x-4 gap-y-2 border-t border-white/[0.06] bg-black/25 px-3 py-2 font-mono text-[12.5px] lg:grid-cols-2">
        <div className="min-w-0 space-y-1.5">
        <form onSubmit={(e) => void handleCheckpoint(e)} className="flex flex-wrap items-center gap-2">
          <input
            value={checkpointLabel}
            onChange={(e) => setCheckpointLabel(e.target.value)}
            disabled={checkpointBusy}
            aria-label="Checkpoint label"
            placeholder="Checkpoint label (optional)…"
            className="pr-well min-w-[160px] flex-1 rounded-xl px-2.5 py-1 text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
          />
          <button
            type="submit"
            disabled={checkpointBusy}
            className="pr-pill inline-flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1 text-[12.5px] text-[#dce4f5] hover:text-white disabled:opacity-45"
          >
            <IconCheck className="h-3.5 w-3.5 text-[#9ec0f5]" />
            <span>{checkpointBusy ? "Saving…" : "Save Checkpoint"}</span>
          </button>
          {checkpointNotice && <span className="text-[12.5px] text-[#5bdba2]">{checkpointNotice}</span>}
        </form>

        {checkpoints.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {checkpoints.map((cp) => (
              <span
                key={cp.id}
                title={`${cp.id} · by ${cp.author} at ${cp.created_at}${
                  cp.edited_paths.length > 0 ? `\n${cp.edited_paths.join(", ")}` : ""
                }`}
                className="pr-well inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[12px] text-[#cfe0ff]"
              >
                <span className="text-[#9ec0f5]">{cp.id}</span>
                {cp.label && <span className="max-w-[140px] truncate text-[#dce4f5]">{cp.label}</span>}
                <span className="text-[#a6b5cf]">
                  {plural(cp.edited_paths.length, "edit")}
                </span>
              </span>
            ))}
          </div>
        )}
        </div>

      {/* Resume */}
      <form
        onSubmit={(e) => void handleResume(e)}
        className="flex min-w-0 flex-wrap items-center gap-2 self-start"
      >
        <span className="text-[#a6b5cf]">$</span>
        <input
          value={resumeCmd}
          onChange={(e) => setResumeCmd(e.target.value)}
          disabled={resuming}
          aria-label="Command to resume in cage"
          placeholder="Command to resume in cage…"
          className="pr-well min-w-[180px] flex-1 rounded-xl px-2.5 py-1 text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
        />
        <button
          type="submit"
          disabled={resuming || !resumeCmd.trim() || isDirty}
          title={
            isDirty ? "Save or discard unsaved file edits before resuming" : undefined
          }
          className="pr-action-btn inline-flex shrink-0 items-center gap-1.5 rounded-full px-3.5 py-1 font-sans text-[13px] disabled:cursor-not-allowed disabled:opacity-45"
        >
          <IconPlay className="h-3.5 w-3.5" />
          <span>{resuming ? "Resuming…" : "Resume in Cage"}</span>
        </button>
      </form>
      </div>
    </div>
  );
}
