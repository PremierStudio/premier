import { useEffect, useRef, useState } from "react";
import type * as Monaco from "monaco-editor";
import {
  loadMonaco,
  monacoLanguageForPath,
  PREMIER_MARKER_OWNER,
  PREMIER_MONACO_THEME,
  type MonacoMarkerInput,
} from "../lib/monaco";

export interface MonacoDiffCommentBadge {
  line: number;
  side: "old" | "new";
  count: number;
}

export interface MonacoDiffViewerProps {
  original: string;
  modified: string;
  path?: string;
  language?: string;
  readOnly?: boolean;
  onModifiedChange?: (next: string) => void;
  renderSideBySide?: boolean;
  collapseUnchanged?: boolean;
  wordWrap?: boolean;
  minHeight?: number;
  maxHeight?: number;
  autoHeight?: boolean;
  className?: string;
  markers?: MonacoMarkerInput[];
  onSave?: () => void;
  originalLineMap?: number[];
  modifiedLineMap?: number[];
  commentedLines?: MonacoDiffCommentBadge[];
  onLineCommentClick?: (line: number, side: "old" | "new") => void;
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

function estimateDiffHeight(
  original: string,
  modified: string,
  minHeight: number,
  maxHeight: number,
  renderSideBySide: boolean,
): number {
  const origArr = original ? original.split(/\r?\n/) : [];
  const modArr = modified ? modified.split(/\r?\n/) : [];
  let visualLines: number;
  if (renderSideBySide) {
    visualLines = Math.max(1, origArr.length, modArr.length);
  } else {
    // In inline mode, deleted lines stack vertically above added/context lines.
    // Approximate unique deleted lines so initial layout height is close before Monaco measures.
    const modSet = new Set(modArr);
    let deletedExtra = 0;
    for (const line of origArr) {
      if (!modSet.has(line)) deletedExtra++;
    }
    visualLines = Math.max(1, modArr.length + deletedExtra, origArr.length);
  }
  const approx = visualLines * 20 + 36;
  return Math.max(minHeight, Math.min(maxHeight, approx));
}

function resolveMonacoLine(
  realLine: number,
  lineMap: number[] | undefined,
  maxLine: number,
): number | null {
  if (lineMap !== undefined) {
    const idx = lineMap.findIndex((mapped) => mapped === realLine);
    if (idx < 0) return null;
    const monacoLine = idx + 1;
    return monacoLine <= maxLine ? monacoLine : null;
  }
  if (realLine < 1 || realLine > maxLine) return null;
  return realLine;
}

function resolveDeletedLineFromViewZone(
  monaco: typeof Monaco,
  diffEditor: Monaco.editor.IStandaloneDiffEditor,
  modifiedEditor: Monaco.editor.IStandaloneCodeEditor,
  event: Monaco.editor.IEditorMouseEvent,
): number | null {
  if (event.target.type !== monaco.editor.MouseTargetType.GUTTER_VIEW_ZONE) {
    return null;
  }
  const afterLineNumber = event.target.detail?.afterLineNumber;
  if (typeof afterLineNumber !== "number") return null;

  const lineChanges = diffEditor.getLineChanges();
  if (!lineChanges || lineChanges.length === 0) return null;

  const matched = lineChanges.find((ch) => {
    if (ch.originalEndLineNumber <= 0) return false;
    const expectedAfter =
      ch.modifiedEndLineNumber === 0
        ? ch.modifiedStartLineNumber
        : ch.modifiedStartLineNumber - 1;
    return expectedAfter === afterLineNumber;
  });

  if (!matched) return null;

  let offset = 0;
  const el = event.target.element as HTMLElement | null;
  const zoneEl = el?.closest?.(".inline-deleted-margin-view-zone") as HTMLElement | null;
  if (zoneEl) {
    const rect = zoneEl.getBoundingClientRect();
    const lineHeight = modifiedEditor.getOption(monaco.editor.EditorOption.lineHeight) || 20;
    offset = Math.max(0, Math.floor((event.event.posy - rect.top) / lineHeight));
  }

  return Math.min(matched.originalEndLineNumber, matched.originalStartLineNumber + offset);
}

export function MonacoDiffViewer({
  original,
  modified,
  path,
  language,
  readOnly = true,
  onModifiedChange,
  renderSideBySide = true,
  collapseUnchanged = true,
  wordWrap = false,
  minHeight = 160,
  maxHeight = 540,
  autoHeight = false,
  className = "",
  markers,
  onSave,
  originalLineMap,
  modifiedLineMap,
  commentedLines,
  onLineCommentClick,
  ariaLabel,
}: MonacoDiffViewerProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const monacoRef = useRef<typeof Monaco | null>(null);
  const diffEditorRef = useRef<Monaco.editor.IStandaloneDiffEditor | null>(null);
  const originalModelRef = useRef<Monaco.editor.ITextModel | null>(null);
  const modifiedModelRef = useRef<Monaco.editor.ITextModel | null>(null);
  const origDecorationsRef =
    useRef<Monaco.editor.IEditorDecorationsCollection | null>(null);
  const modDecorationsRef =
    useRef<Monaco.editor.IEditorDecorationsCollection | null>(null);
  const suppressChangeRef = useRef(false);
  const lastEmittedModifiedRef = useRef<string | null>(null);

  const resolvedLanguage = language ?? monacoLanguageForPath(path);
  const hasGlyphMargin = Boolean(
    onLineCommentClick || (commentedLines && commentedLines.length > 0),
  );

  // Refs for latest values/callbacks so mount runs once without stale closures
  const latestOriginalRef = useRef(original);
  latestOriginalRef.current = original;
  const latestModifiedRef = useRef(modified);
  latestModifiedRef.current = modified;
  const latestLanguageRef = useRef(resolvedLanguage);
  latestLanguageRef.current = resolvedLanguage;
  const latestReadOnlyRef = useRef(readOnly);
  latestReadOnlyRef.current = readOnly;
  const latestSideBySideRef = useRef(renderSideBySide);
  latestSideBySideRef.current = renderSideBySide;
  const latestCollapseRef = useRef(collapseUnchanged);
  latestCollapseRef.current = collapseUnchanged;
  const latestWordWrapRef = useRef(wordWrap);
  latestWordWrapRef.current = wordWrap;
  const latestGlyphMarginRef = useRef(hasGlyphMargin);
  latestGlyphMarginRef.current = hasGlyphMargin;
  const latestAriaLabelRef = useRef(ariaLabel);
  latestAriaLabelRef.current = ariaLabel;
  const originalLineMapRef = useRef(originalLineMap);
  originalLineMapRef.current = originalLineMap;
  const modifiedLineMapRef = useRef(modifiedLineMap);
  modifiedLineMapRef.current = modifiedLineMap;
  const onModifiedChangeRef = useRef(onModifiedChange);
  onModifiedChangeRef.current = onModifiedChange;
  const onSaveRef = useRef(onSave);
  onSaveRef.current = onSave;
  const onLineCommentClickRef = useRef(onLineCommentClick);
  onLineCommentClickRef.current = onLineCommentClick;
  const autoHeightRef = useRef(autoHeight);
  autoHeightRef.current = autoHeight;
  const minHeightRef = useRef(minHeight);
  minHeightRef.current = minHeight;
  const maxHeightRef = useRef(maxHeight);
  maxHeightRef.current = maxHeight;

  const [ready, setReady] = useState(false);
  const [computedHeight, setComputedHeight] = useState<number>(() =>
    estimateDiffHeight(original, modified, minHeight, maxHeight, renderSideBySide),
  );

  // Only build the (expensive) editor once the host is near the viewport; stays mounted after.
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [visible, setVisible] = useState(() => typeof IntersectionObserver === "undefined");
  useEffect(() => {
    if (visible) return;
    const host = hostRef.current;
    if (!host) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setVisible(true);
          io.disconnect();
        }
      },
      { rootMargin: "320px 0px" },
    );
    io.observe(host);
    return () => io.disconnect();
  }, [visible]);

  // Mount & safely dispose Monaco DiffEditor
  useEffect(() => {
    if (!visible) return;
    const container = containerRef.current;
    if (!container) return;

    let disposed = false;
    let resizeObserver: ResizeObserver | null = null;
    let rafId: number | null = null;
    const disposables: Monaco.IDisposable[] = [];

    const syncAutoHeight = () => {
      if (!autoHeightRef.current || !diffEditorRef.current) return;
      const origH = diffEditorRef.current.getOriginalEditor().getContentHeight();
      const modH = diffEditorRef.current.getModifiedEditor().getContentHeight();
      const contentH = Math.max(origH, modH) + 14;
      if (Number.isFinite(contentH) && contentH > 0) {
        const clamped = Math.max(
          minHeightRef.current,
          Math.min(maxHeightRef.current, Math.ceil(contentH)),
        );
        setComputedHeight(clamped);
      }
    };

    void loadMonaco().then((monaco) => {
      if (disposed || !containerRef.current) return;

      monacoRef.current = monaco;
      const origModel = monaco.editor.createModel(
        latestOriginalRef.current,
        latestLanguageRef.current,
      );
      const modModel = monaco.editor.createModel(
        latestModifiedRef.current,
        latestLanguageRef.current,
      );
      originalModelRef.current = origModel;
      modifiedModelRef.current = modModel;

      const diffEditor = monaco.editor.createDiffEditor(containerRef.current, {
        theme: PREMIER_MONACO_THEME,
        originalEditable: false,
        readOnly: latestReadOnlyRef.current,
        renderSideBySide: latestSideBySideRef.current,
        renderSideBySideInlineBreakpoint: 640,
        wordWrap: latestWordWrapRef.current ? "on" : "off",
        hideUnchangedRegions: {
          enabled: latestCollapseRef.current,
          contextLineCount: 3,
          minimumLineCount: 4,
          revealLineCount: 20,
        },
        minimap: { enabled: false },
        stickyScroll: { enabled: false },
        bracketPairColorization: { enabled: true },
        guides: { bracketPairs: true, indentation: true },
        smoothScrolling: true,
        fontFamily:
          '"JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
        fontSize: 12,
        lineHeight: 20,
        padding: { top: 8, bottom: 10 },
        automaticLayout: false,
        fixedOverflowWidgets: true,
        scrollBeyondLastLine: false,
        renderIndicators: true,
        ignoreTrimWhitespace: false,
        glyphMargin: latestGlyphMarginRef.current,
        ariaLabel: latestAriaLabelRef.current,
        scrollbar: {
          verticalScrollbarSize: 8,
          horizontalScrollbarSize: 8,
          useShadows: false,
          // Never trap page scroll wheel inside auto-sized diff cards
          alwaysConsumeMouseWheel: !autoHeightRef.current,
        },
      });
      diffEditorRef.current = diffEditor;

      diffEditor.setModel({
        original: origModel,
        modified: modModel,
      });

      const originalEditor = diffEditor.getOriginalEditor();
      const modifiedEditor = diffEditor.getModifiedEditor();

      origDecorationsRef.current = originalEditor.createDecorationsCollection();
      modDecorationsRef.current = modifiedEditor.createDecorationsCollection();

      // Wire Ctrl/Cmd+S save on both panes
      originalEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
        onSaveRef.current?.();
      });
      modifiedEditor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, () => {
        onSaveRef.current?.();
      });

      // Emit edits from the modified pane when editable
      disposables.push(
        modModel.onDidChangeContent(() => {
          if (suppressChangeRef.current) return;
          const nextValue = modModel.getValue();
          lastEmittedModifiedRef.current = nextValue;
          onModifiedChangeRef.current?.(nextValue);
        }),
      );

      const isGutterClickTarget = (type: Monaco.editor.MouseTargetType) =>
        type === monaco.editor.MouseTargetType.GUTTER_GLYPH_MARGIN ||
        type === monaco.editor.MouseTargetType.GUTTER_LINE_NUMBERS ||
        type === monaco.editor.MouseTargetType.GUTTER_LINE_DECORATIONS;

      // Gutter / line-number comment click handlers for old & new sides (Split & Inline)
      disposables.push(
        originalEditor.onMouseDown((e) => {
          if (!onLineCommentClickRef.current) return;
          if (!isGutterClickTarget(e.target.type) || !e.target.position) {
            return;
          }
          const rawLine = e.target.position.lineNumber;
          const map = originalLineMapRef.current;
          const mapped = map !== undefined ? (map[rawLine - 1] ?? 0) : rawLine;
          if (mapped > 0) {
            onLineCommentClickRef.current(mapped, "old");
          }
        }),
      );

      disposables.push(
        modifiedEditor.onMouseDown((e) => {
          if (!onLineCommentClickRef.current) return;

          // Inline mode renders deleted lines inside modifiedEditor view zones.
          if (e.target.type === monaco.editor.MouseTargetType.GUTTER_VIEW_ZONE) {
            const origRawLine = resolveDeletedLineFromViewZone(
              monaco,
              diffEditor,
              modifiedEditor,
              e,
            );
            if (origRawLine !== null) {
              const map = originalLineMapRef.current;
              const mapped = map !== undefined ? (map[origRawLine - 1] ?? 0) : origRawLine;
              if (mapped > 0) {
                onLineCommentClickRef.current(mapped, "old");
              }
            }
            return;
          }

          if (!isGutterClickTarget(e.target.type) || !e.target.position) {
            return;
          }
          const rawLine = e.target.position.lineNumber;
          const map = modifiedLineMapRef.current;
          const mapped = map !== undefined ? (map[rawLine - 1] ?? 0) : rawLine;
          if (mapped > 0) {
            onLineCommentClickRef.current(mapped, "new");
          }
        }),
      );

      // Track dynamic content height when autoHeight is enabled
      disposables.push(originalEditor.onDidContentSizeChange(syncAutoHeight));
      disposables.push(modifiedEditor.onDidContentSizeChange(syncAutoHeight));
      disposables.push(diffEditor.onDidUpdateDiff(syncAutoHeight));

      resizeObserver = new ResizeObserver(() => {
        if (rafId !== null) cancelAnimationFrame(rafId);
        rafId = requestAnimationFrame(() => {
          rafId = null;
          diffEditorRef.current?.layout();
        });
      });
      resizeObserver.observe(containerRef.current);
      diffEditor.layout();

      setReady(true);
    }).catch(() => {});

    return () => {
      disposed = true;
      setReady(false);

      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }
      resizeObserver?.disconnect();
      resizeObserver = null;

      for (const d of disposables) {
        d.dispose();
      }

      origDecorationsRef.current?.clear();
      origDecorationsRef.current = null;
      modDecorationsRef.current?.clear();
      modDecorationsRef.current = null;

      const monaco = monacoRef.current;
      const origModel = originalModelRef.current;
      const modModel = modifiedModelRef.current;
      const diffEditor = diffEditorRef.current;

      if (monaco && modModel && !modModel.isDisposed()) {
        monaco.editor.setModelMarkers(modModel, PREMIER_MARKER_OWNER, []);
      }

      // CRITICAL: Detach models via setModel(null) BEFORE disposing models or diffEditor.
      if (diffEditor) {
        diffEditor.setModel(null);
      }
      if (origModel && !origModel.isDisposed()) {
        origModel.dispose();
      }
      if (modModel && !modModel.isDisposed()) {
        modModel.dispose();
      }
      if (diffEditor) {
        diffEditor.dispose();
      }

      originalModelRef.current = null;
      modifiedModelRef.current = null;
      diffEditorRef.current = null;
    };
  }, [visible]);

  // Keep original buffer in sync without recreating the diff editor
  useEffect(() => {
    const model = originalModelRef.current;
    if (!ready || !model || model.isDisposed()) return;
    if (model.getValue() !== original) {
      model.setValue(original);
    }
  }, [ready, original]);

  // Keep modified buffer in sync without losing undo/cursor/scroll when editable
  useEffect(() => {
    const model = modifiedModelRef.current;
    const diffEditor = diffEditorRef.current;
    if (!ready || !model || !diffEditor || model.isDisposed()) return;
    if (model.getValue() === modified) {
      lastEmittedModifiedRef.current = modified;
      return;
    }
    if (!readOnly && lastEmittedModifiedRef.current === modified) {
      return;
    }

    suppressChangeRef.current = true;
    try {
      if (readOnly) {
        model.setValue(modified);
        lastEmittedModifiedRef.current = modified;
      } else {
        const modEditor = diffEditor.getModifiedEditor();
        const selection = modEditor.getSelection();
        const scrollTop = modEditor.getScrollTop();
        const scrollLeft = modEditor.getScrollLeft();
        modEditor.pushUndoStop();
        model.pushEditOperations(
          [],
          [
            {
              range: model.getFullModelRange(),
              text: modified,
            },
          ],
          () => null,
        );
        modEditor.pushUndoStop();
        lastEmittedModifiedRef.current = modified;
        if (selection) {
          const maxLine = model.getLineCount();
          const clampLine = (l: number) => Math.min(maxLine, Math.max(1, l));
          const clampCol = (l: number, c: number) =>
            Math.min(model.getLineMaxColumn(l), Math.max(1, c));
          const startL = clampLine(selection.startLineNumber);
          const endL = clampLine(selection.endLineNumber);
          modEditor.setSelection({
            startLineNumber: startL,
            startColumn: clampCol(startL, selection.startColumn),
            endLineNumber: endL,
            endColumn: clampCol(endL, selection.endColumn),
          });
        }
        modEditor.setScrollTop(scrollTop);
        modEditor.setScrollLeft(scrollLeft);
      }
    } finally {
      suppressChangeRef.current = false;
    }
  }, [ready, modified, readOnly]);

  // Update language on both models dynamically
  useEffect(() => {
    const monaco = monacoRef.current;
    const origModel = originalModelRef.current;
    const modModel = modifiedModelRef.current;
    if (!ready || !monaco) return;

    if (origModel && !origModel.isDisposed() && origModel.getLanguageId() !== resolvedLanguage) {
      monaco.editor.setModelLanguage(origModel, resolvedLanguage);
    }
    if (modModel && !modModel.isDisposed() && modModel.getLanguageId() !== resolvedLanguage) {
      monaco.editor.setModelLanguage(modModel, resolvedLanguage);
    }
  }, [ready, resolvedLanguage]);

  // Update diff options dynamically without teardown
  useEffect(() => {
    const diffEditor = diffEditorRef.current;
    if (!ready || !diffEditor) return;

    diffEditor.updateOptions({
      readOnly,
      renderSideBySide,
      wordWrap: wordWrap ? "on" : "off",
      glyphMargin: hasGlyphMargin,
      ariaLabel,
      scrollbar: {
        verticalScrollbarSize: 8,
        horizontalScrollbarSize: 8,
        useShadows: false,
        alwaysConsumeMouseWheel: !autoHeight,
      },
      hideUnchangedRegions: {
        enabled: collapseUnchanged,
        contextLineCount: 3,
        minimumLineCount: 4,
        revealLineCount: 20,
      },
    });
  }, [ready, readOnly, renderSideBySide, collapseUnchanged, wordWrap, hasGlyphMargin, ariaLabel, autoHeight]);

  // Update real-file line number formatters when line maps change
  useEffect(() => {
    const diffEditor = diffEditorRef.current;
    if (!ready || !diffEditor) return;

    const origEditor = diffEditor.getOriginalEditor();
    const modEditor = diffEditor.getModifiedEditor();

    origEditor.updateOptions({
      lineNumbers:
        originalLineMap !== undefined
          ? (lineNumber: number) => {
              const mapped = originalLineMap[lineNumber - 1];
              if (mapped === undefined) return "";
              return mapped > 0 ? String(mapped) : "⋯";
            }
          : "on",
    });

    modEditor.updateOptions({
      lineNumbers:
        modifiedLineMap !== undefined
          ? (lineNumber: number) => {
              const mapped = modifiedLineMap[lineNumber - 1];
              if (mapped === undefined) return "";
              return mapped > 0 ? String(mapped) : "⋯";
            }
          : "on",
    });
  }, [ready, originalLineMap, modifiedLineMap]);

  // Update gutter comment badges & hover hints on original/modified editors
  useEffect(() => {
    const monaco = monacoRef.current;
    const origModel = originalModelRef.current;
    const modModel = modifiedModelRef.current;
    const origDec = origDecorationsRef.current;
    const modDec = modDecorationsRef.current;
    if (!ready || !monaco || !origModel || !modModel || !origDec || !modDec) return;
    if (origModel.isDisposed() || modModel.isDisposed()) return;

    const oldDecorations: Monaco.editor.IModelDeltaDecoration[] = [];
    const newDecorations: Monaco.editor.IModelDeltaDecoration[] = [];

    for (const badge of commentedLines ?? []) {
      const label = badge.count === 1 ? "1 review comment" : `${badge.count} review comments`;
      const hoverText = onLineCommentClick
        ? `${label} — click gutter to add or inspect`
        : label;

      if (badge.side === "old") {
        const line = resolveMonacoLine(
          badge.line,
          originalLineMap,
          origModel.getLineCount(),
        );
        if (line !== null) {
          oldDecorations.push({
            range: new monaco.Range(line, 1, line, 1),
            options: {
              glyphMarginClassName: "premier-monaco-comment-glyph",
              glyphMarginHoverMessage: { value: hoverText },
              // Visible even in inline mode where Monaco hides originalEditor's glyphMargin
              linesDecorationsClassName: "premier-monaco-comment-old-line",
              marginClassName: "premier-monaco-comment-old-margin",
            },
          });
        }
      } else {
        const line = resolveMonacoLine(
          badge.line,
          modifiedLineMap,
          modModel.getLineCount(),
        );
        if (line !== null) {
          newDecorations.push({
            range: new monaco.Range(line, 1, line, 1),
            options: {
              glyphMarginClassName: "premier-monaco-comment-glyph",
              glyphMarginHoverMessage: { value: hoverText },
            },
          });
        }
      }
    }

    origDec.set(oldDecorations);
    modDec.set(newDecorations);
  }, [ready, commentedLines, originalLineMap, modifiedLineMap, onLineCommentClick, original, modified]);

  // Update markers on modified model
  useEffect(() => {
    const monaco = monacoRef.current;
    const modModel = modifiedModelRef.current;
    if (!ready || !monaco || !modModel || modModel.isDisposed()) return;

    const mapped: Monaco.editor.IMarkerData[] = (markers ?? []).map((m) => ({
      startLineNumber: m.startLineNumber,
      startColumn: m.startColumn,
      endLineNumber: m.endLineNumber,
      endColumn: m.endColumn,
      message: m.message,
      severity: toMarkerSeverity(monaco, m.severity),
    }));

    monaco.editor.setModelMarkers(modModel, PREMIER_MARKER_OWNER, mapped);
  }, [ready, markers]);

  // Keep autoHeight responsive to content/bounds/layout changes before and after Monaco mounts
  useEffect(() => {
    if (!autoHeight) return;
    if (!ready || !diffEditorRef.current) {
      setComputedHeight(
        estimateDiffHeight(original, modified, minHeight, maxHeight, renderSideBySide),
      );
      return;
    }

    const measure = () => {
      if (!diffEditorRef.current) return;
      const origH = diffEditorRef.current.getOriginalEditor().getContentHeight();
      const modH = diffEditorRef.current.getModifiedEditor().getContentHeight();
      const contentH = Math.max(origH, modH) + 14;
      if (Number.isFinite(contentH) && contentH > 0) {
        setComputedHeight(
          Math.max(minHeight, Math.min(maxHeight, Math.ceil(contentH))),
        );
      }
    };

    measure();
    const raf = requestAnimationFrame(measure);
    return () => cancelAnimationFrame(raf);
  }, [ready, autoHeight, original, modified, minHeight, maxHeight, renderSideBySide, collapseUnchanged, wordWrap]);

  // Relayout when autoHeight adjusts container size
  useEffect(() => {
    if (!ready || !autoHeight) return;
    diffEditorRef.current?.layout();
  }, [ready, autoHeight, computedHeight]);

  // When autoHeight is false, never apply maxHeight (so flex-1 full-height panes fill cleanly)
  const containerStyle = autoHeight
    ? { height: `${computedHeight}px`, minHeight: `${minHeight}px`, maxHeight: `${maxHeight}px` }
    : minHeight > 0
      ? { minHeight: `${minHeight}px` }
      : undefined;

  const commentableClass = onLineCommentClick ? "premier-monaco-commentable" : "";

  return (
    <div
      ref={hostRef}
      className={`premier-monaco-host relative flex flex-col overflow-hidden ${commentableClass} ${className}`.trim()}
      style={containerStyle}
    >
      <div
        ref={containerRef}
        className={autoHeight ? "h-full w-full" : "absolute inset-0"}
        style={autoHeight ? { height: `${computedHeight}px` } : undefined}
      />
      {!ready && (
        <div
          aria-hidden="true"
          className={`pointer-events-none absolute inset-0 grid gap-4 bg-[#090d18] p-4 ${
            renderSideBySide ? "grid-cols-2" : "grid-cols-1"
          }`}
        >
          {(renderSideBySide ? [0, 1] : [0]).map((col) => (
            <div key={col} className="flex flex-col gap-2">
              <div className="pr-shimmer h-3 w-36 rounded" />
              <div className="pr-shimmer h-3 w-52 rounded" />
              <div className="pr-shimmer h-3 w-44 rounded" />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
