import { useEffect, useRef, useState } from "react";
import type * as Monaco from "monaco-editor";
import { shortOid, type BlameLine } from "../api";
import { CodeLinesSkeleton } from "./ViewSkeletons";
import {
  loadMonaco,
  monacoLanguageForPath,
  PREMIER_MARKER_OWNER,
  PREMIER_MONACO_THEME,
  type MonacoMarkerInput,
} from "../lib/monaco";

export interface MonacoCodeEditorProps {
  value: string;
  onChange?: (next: string) => void;
  path?: string;
  language?: string;
  readOnly?: boolean;
  wordWrap?: boolean;
  minimap?: boolean;
  stickyScroll?: boolean;
  lineNumbers?: "on" | "off";
  className?: string;
  minHeight?: number | string;
  selectedLines?: [number, number] | null;
  onSelectLines?: (lines: [number, number] | null) => void;
  scrollToLine?: { line: number; nonce: number } | null;
  blameLines?: Map<number, BlameLine> | null;
  markers?: MonacoMarkerInput[];
  onSave?: () => void;
  findTriggerNonce?: number;
  ariaLabel?: string;
}

function toMarkerSeverity(
  monaco: typeof Monaco,
  severity: MonacoMarkerInput["severity"],
): Monaco.MarkerSeverity {
  switch (severity) {
    case "error":
      return monaco.MarkerSeverity.Error;
    case "warning":
      return monaco.MarkerSeverity.Warning;
    case "info":
      return monaco.MarkerSeverity.Info;
  }
}

function formatBlameAuthor(author: string): string {
  const trimmed = author.trim();
  if (trimmed.length <= 14) return trimmed;
  return `${trimmed.slice(0, 13)}…`;
}

export function MonacoCodeEditor({
  value,
  onChange,
  path,
  language,
  readOnly = false,
  wordWrap = false,
  minimap = false,
  stickyScroll = true,
  lineNumbers = "on",
  className = "",
  minHeight = 280,
  selectedLines = null,
  onSelectLines,
  scrollToLine = null,
  blameLines = null,
  markers,
  onSave,
  findTriggerNonce = 0,
  ariaLabel,
}: MonacoCodeEditorProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const monacoRef = useRef<typeof Monaco | null>(null);
  const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
  const modelRef = useRef<Monaco.editor.ITextModel | null>(null);
  const selectedDecorationsRef =
    useRef<Monaco.editor.IEditorDecorationsCollection | null>(null);
  const blameDecorationsRef =
    useRef<Monaco.editor.IEditorDecorationsCollection | null>(null);
  const flashDecorationsRef =
    useRef<Monaco.editor.IEditorDecorationsCollection | null>(null);
  const flashTimerRef = useRef<number | null>(null);
  const suppressChangeRef = useRef(false);
  const lastEmittedValueRef = useRef<string | null>(null);
  const prevPathRef = useRef<string | undefined>(path);

  // Latest values/callbacks kept in refs to avoid stale closures and unnecessary remounts
  const latestValueRef = useRef(value);
  latestValueRef.current = value;
  const onChangeRef = useRef(onChange);
  onChangeRef.current = onChange;
  const onSelectLinesRef = useRef(onSelectLines);
  onSelectLinesRef.current = onSelectLines;
  const selectedLinesRef = useRef(selectedLines);
  selectedLinesRef.current = selectedLines;
  const onSaveRef = useRef(onSave);
  onSaveRef.current = onSave;

  const resolvedLanguage = language ?? monacoLanguageForPath(path);
  const latestLanguageRef = useRef(resolvedLanguage);
  latestLanguageRef.current = resolvedLanguage;
  const latestReadOnlyRef = useRef(readOnly);
  latestReadOnlyRef.current = readOnly;
  const latestWordWrapRef = useRef(wordWrap);
  latestWordWrapRef.current = wordWrap;
  const latestMinimapRef = useRef(minimap);
  latestMinimapRef.current = minimap;
  const latestStickyScrollRef = useRef(stickyScroll);
  latestStickyScrollRef.current = stickyScroll;
  const latestLineNumbersRef = useRef(lineNumbers);
  latestLineNumbersRef.current = lineNumbers;
  const latestAriaLabelRef = useRef(ariaLabel);
  latestAriaLabelRef.current = ariaLabel;

  const [ready, setReady] = useState(false);
  const [loadFailed, setLoadFailed] = useState(false);
  const [retryNonce, setRetryNonce] = useState(0);

  // Mount & dispose Monaco editor instance once
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    let disposed = false;
    let resizeObserver: ResizeObserver | null = null;
    let rafId: number | null = null;
    const disposables: Monaco.IDisposable[] = [];

    setLoadFailed(false);
    void loadMonaco().then((monaco) => {
      if (disposed || !containerRef.current) return;

      monacoRef.current = monaco;
      const model = monaco.editor.createModel(
        latestValueRef.current,
        latestLanguageRef.current,
      );
      modelRef.current = model;

      const editor = monaco.editor.create(containerRef.current, {
        model,
        theme: PREMIER_MONACO_THEME,
        readOnly: latestReadOnlyRef.current,
        wordWrap: latestWordWrapRef.current ? "on" : "off",
        minimap: { enabled: latestMinimapRef.current },
        stickyScroll: { enabled: latestStickyScrollRef.current },
        lineNumbers: latestLineNumbersRef.current,
        bracketPairColorization: { enabled: true },
        guides: { bracketPairs: true, indentation: true },
        smoothScrolling: true,
        cursorSmoothCaretAnimation: "on",
        fontFamily:
          '"JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        fontSize: 12.5,
        lineHeight: 20,
        padding: { top: 10, bottom: 14 },
        automaticLayout: false,
        fixedOverflowWidgets: true,
        scrollBeyondLastLine: false,
        renderLineHighlight: "line",
        tabSize: 2,
        ariaLabel: latestAriaLabelRef.current,
        scrollbar: {
          verticalScrollbarSize: 8,
          horizontalScrollbarSize: 8,
          useShadows: false,
        },
      });
      editorRef.current = editor;

      selectedDecorationsRef.current = editor.createDecorationsCollection();
      blameDecorationsRef.current = editor.createDecorationsCollection();
      flashDecorationsRef.current = editor.createDecorationsCollection();

      // Wire Ctrl/Cmd+S save shortcut
      editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
        onSaveRef.current?.();
      });

      // Emit controlled edits
      disposables.push(
        model.onDidChangeContent(() => {
          if (suppressChangeRef.current) return;
          const nextValue = model.getValue();
          lastEmittedValueRef.current = nextValue;
          onChangeRef.current?.(nextValue);
        }),
      );

      // Gutter line-number click + Shift-click range selection
      disposables.push(
        editor.onMouseDown((e) => {
          if (!onSelectLinesRef.current) return;
          if (
            e.target.type !== monaco.editor.MouseTargetType.GUTTER_LINE_NUMBERS ||
            !e.target.position
          ) {
            return;
          }
          const clickedLine = e.target.position.lineNumber;
          const prev = selectedLinesRef.current;

          if (e.event.shiftKey && prev) {
            const anchor = prev[0];
            onSelectLinesRef.current([
              Math.min(anchor, clickedLine),
              Math.max(anchor, clickedLine),
            ]);
          } else if (prev && prev[0] === clickedLine && prev[1] === clickedLine) {
            onSelectLinesRef.current(null);
          } else {
            onSelectLinesRef.current([clickedLine, clickedLine]);
          }
        }),
      );

      // ResizeObserver-driven layout (never automaticLayout polling)
      resizeObserver = new ResizeObserver(() => {
        if (rafId !== null) cancelAnimationFrame(rafId);
        rafId = requestAnimationFrame(() => {
          rafId = null;
          editorRef.current?.layout();
        });
      });
      resizeObserver.observe(containerRef.current);
      editor.layout();

      setReady(true);
    }).catch(() => {
      if (!disposed) setLoadFailed(true);
    });

    return () => {
      disposed = true;
      setReady(false);

      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }
      if (flashTimerRef.current !== null) {
        window.clearTimeout(flashTimerRef.current);
        flashTimerRef.current = null;
      }
      resizeObserver?.disconnect();
      resizeObserver = null;

      for (const d of disposables) {
        d.dispose();
      }

      selectedDecorationsRef.current?.clear();
      selectedDecorationsRef.current = null;
      blameDecorationsRef.current?.clear();
      blameDecorationsRef.current = null;
      flashDecorationsRef.current?.clear();
      flashDecorationsRef.current = null;

      const model = modelRef.current;
      const monaco = monacoRef.current;
      if (monaco && model && !model.isDisposed()) {
        monaco.editor.setModelMarkers(model, PREMIER_MARKER_OWNER, []);
      }

      editorRef.current?.dispose();
      editorRef.current = null;

      if (model && !model.isDisposed()) {
        model.dispose();
      }
      modelRef.current = null;
    };
  }, [retryNonce]);

  // Sync controlled value without resetting cursor/scroll/undo stack unnecessarily
  useEffect(() => {
    const model = modelRef.current;
    const editor = editorRef.current;
    if (!ready || !model || !editor || model.isDisposed()) return;
    if (model.getValue() === value) {
      lastEmittedValueRef.current = value;
      return;
    }
    // Skip stale echoed values if the user already typed ahead in editable mode
    if (!readOnly && lastEmittedValueRef.current === value) {
      return;
    }

    suppressChangeRef.current = true;
    try {
      if (readOnly) {
        model.setValue(value);
        lastEmittedValueRef.current = value;
      } else {
        const selection = editor.getSelection();
        const scrollTop = editor.getScrollTop();
        const scrollLeft = editor.getScrollLeft();
        editor.pushUndoStop();
        model.pushEditOperations(
          [],
          [
            {
              range: model.getFullModelRange(),
              text: value,
            },
          ],
          () => null,
        );
        editor.pushUndoStop();
        lastEmittedValueRef.current = value;
        if (selection) {
          const maxLine = model.getLineCount();
          const clampLine = (l: number) => Math.min(maxLine, Math.max(1, l));
          const clampCol = (l: number, c: number) =>
            Math.min(model.getLineMaxColumn(l), Math.max(1, c));
          const startL = clampLine(selection.startLineNumber);
          const endL = clampLine(selection.endLineNumber);
          editor.setSelection({
            startLineNumber: startL,
            startColumn: clampCol(startL, selection.startColumn),
            endLineNumber: endL,
            endColumn: clampCol(endL, selection.endColumn),
          });
        }
        editor.setScrollTop(scrollTop);
        editor.setScrollLeft(scrollLeft);
      }
    } finally {
      suppressChangeRef.current = false;
    }
  }, [ready, value, readOnly]);

  // Reset scroll & stale flash decorations when switching viewed files in place
  useEffect(() => {
    if (!ready) {
      prevPathRef.current = path;
      return;
    }
    if (prevPathRef.current === path) return;
    prevPathRef.current = path;

    if (flashTimerRef.current !== null) {
      window.clearTimeout(flashTimerRef.current);
      flashTimerRef.current = null;
    }
    flashDecorationsRef.current?.clear();

    const editor = editorRef.current;
    if (editor && readOnly && !scrollToLine) {
      editor.setScrollTop(0);
      editor.setScrollLeft(0);
      editor.setPosition({ lineNumber: 1, column: 1 });
    }
  }, [ready, path, readOnly, scrollToLine]);

  // Sync language when path/language changes
  useEffect(() => {
    const monaco = monacoRef.current;
    const model = modelRef.current;
    if (!ready || !monaco || !model || model.isDisposed()) return;
    if (model.getLanguageId() !== resolvedLanguage) {
      monaco.editor.setModelLanguage(model, resolvedLanguage);
    }
  }, [ready, resolvedLanguage]);

  // Sync dynamic editor options
  useEffect(() => {
    const editor = editorRef.current;
    if (!ready || !editor) return;
    editor.updateOptions({
      readOnly,
      wordWrap: wordWrap ? "on" : "off",
      minimap: { enabled: minimap },
      stickyScroll: { enabled: stickyScroll },
      lineNumbers,
      ariaLabel,
    });
  }, [ready, readOnly, wordWrap, minimap, stickyScroll, lineNumbers, ariaLabel]);

  // Sync selected lines highlight decoration
  useEffect(() => {
    const collection = selectedDecorationsRef.current;
    const model = modelRef.current;
    const monaco = monacoRef.current;
    if (!ready || !collection || !model || !monaco || model.isDisposed()) return;

    if (!selectedLines) {
      collection.clear();
      return;
    }

    const maxLine = model.getLineCount();
    const lo = Math.max(1, Math.min(selectedLines[0], selectedLines[1], maxLine));
    const hi = Math.max(1, Math.min(Math.max(selectedLines[0], selectedLines[1]), maxLine));

    collection.set([
      {
        range: new monaco.Range(lo, 1, hi, 1),
        options: {
          isWholeLine: true,
          className: "premier-monaco-selected-line",
          linesDecorationsClassName: "premier-monaco-selected-gutter",
        },
      },
    ]);
  }, [ready, selectedLines, value]);

  // Sync inline blame chips & rich commit hover tooltips
  useEffect(() => {
    const collection = blameDecorationsRef.current;
    const model = modelRef.current;
    const monaco = monacoRef.current;
    if (!ready || !collection || !model || !monaco || model.isDisposed()) return;

    if (!blameLines || blameLines.size === 0) {
      collection.clear();
      return;
    }

    const decorations: Monaco.editor.IModelDeltaDecoration[] = [];
    const lineCount = model.getLineCount();
    let prevOid: string | null = null;

    for (let line = 1; line <= lineCount; line++) {
      const blame = blameLines.get(line);
      if (!blame) {
        prevOid = null;
        continue;
      }

      const oidShort = shortOid(blame.oid);
      const isBlockStart = prevOid !== blame.oid;
      prevOid = blame.oid;

      const hoverLines = [
        `**\`${oidShort}\`** · ${blame.author}`,
        blame.date ? `_${blame.date}_` : "",
        blame.summary ? `\n${blame.summary}` : "",
        `\n\`${blame.oid}\``,
      ].filter(Boolean);

      const options: Monaco.editor.IModelDecorationOptions = {
        hoverMessage: { value: hoverLines.join("\n") },
      };

      if (isBlockStart) {
        options.before = {
          content: `${oidShort} · ${formatBlameAuthor(blame.author)}`,
          inlineClassName: "premier-monaco-blame-chip",
        };
      }

      decorations.push({
        range: new monaco.Range(line, 1, line, 1),
        options,
      });
    }

    collection.set(decorations);
  }, [ready, blameLines, value]);

  // Scroll to line + brief highlight flash
  useEffect(() => {
    const editor = editorRef.current;
    const model = modelRef.current;
    const monaco = monacoRef.current;
    const flash = flashDecorationsRef.current;
    if (!ready || !editor || !model || !monaco || !scrollToLine || model.isDisposed()) {
      return;
    }

    const targetLine = Math.min(
      model.getLineCount(),
      Math.max(1, scrollToLine.line),
    );
    editor.revealLineInCenter(targetLine);
    editor.setPosition({ lineNumber: targetLine, column: 1 });

    if (flash) {
      flash.set([
        {
          range: new monaco.Range(targetLine, 1, targetLine, 1),
          options: {
            isWholeLine: true,
            className: "premier-monaco-flash-line",
          },
        },
      ]);
      if (flashTimerRef.current !== null) {
        window.clearTimeout(flashTimerRef.current);
      }
      flashTimerRef.current = window.setTimeout(() => {
        flashTimerRef.current = null;
        flashDecorationsRef.current?.clear();
      }, 1200);
    }
  }, [ready, scrollToLine?.line, scrollToLine?.nonce]);

  // Sync validation markers
  useEffect(() => {
    const monaco = monacoRef.current;
    const model = modelRef.current;
    if (!ready || !monaco || !model || model.isDisposed()) return;

    const mapped: Monaco.editor.IMarkerData[] = (markers ?? []).map((m) => ({
      startLineNumber: m.startLineNumber,
      startColumn: m.startColumn,
      endLineNumber: m.endLineNumber,
      endColumn: m.endColumn,
      message: m.message,
      severity: toMarkerSeverity(monaco, m.severity),
    }));

    monaco.editor.setModelMarkers(model, PREMIER_MARKER_OWNER, mapped);
  }, [ready, markers]);

  // Trigger Monaco find widget when nonce increments
  useEffect(() => {
    if (!ready || !findTriggerNonce || findTriggerNonce <= 0) return;
    const editor = editorRef.current;
    if (!editor) return;
    void editor.getAction("actions.find")?.run();
  }, [ready, findTriggerNonce]);

  const hostStyle =
    minHeight !== undefined && minHeight !== 0 && minHeight !== "0px"
      ? { minHeight: typeof minHeight === "number" ? `${minHeight}px` : minHeight }
      : undefined;

  return (
    <div
      className={`premier-monaco-host relative flex flex-col overflow-hidden ${className}`.trim()}
      style={hostStyle}
    >
      <div ref={containerRef} className="absolute inset-0" />
      <div
        aria-hidden={loadFailed ? undefined : true}
        className={`absolute inset-0 transition-opacity duration-200 ${
          ready ? "pointer-events-none opacity-0" : "opacity-100"
        }`}
      >
        <CodeLinesSkeleton className="absolute inset-0 bg-[#090d18]" />
        {loadFailed && (
          <div
            role="alert"
            className="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-[#090d18]/95 p-6 text-center"
          >
            <p className="font-mono text-[13.5px] text-[#f27c7c]">The code editor failed to load.</p>
            <button
              type="button"
              onClick={() => setRetryNonce((n) => n + 1)}
              className="pr-pill inline-flex h-7 items-center rounded-full px-3 font-mono text-[13px] text-[#e6ecf8]"
            >
              Retry
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
