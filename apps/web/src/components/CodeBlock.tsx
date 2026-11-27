import { Fragment, memo, useMemo, useState, type ReactNode } from "react";
import {
  detectLanguage,
  languageLabel,
  parseUnifiedPatch,
  tokenClassName,
  tokenizeLine,
  type SourceLanguage,
} from "../lib/highlight";
import { IconCheck, IconChevron, IconCopy, IconSearch, IconShieldCheck, IconWrap } from "./Icons";

const REDACTED_TOKEN_RE = /(\[(?:REDACTED(?::[^\]]+)?|SERVER-REDACTED)\])/g;

/**
 * Splits text around `[REDACTED:...]` / `[SERVER-REDACTED]` markers so scrubbed
 * secret tokens stand out visually as cool cyan security badges everywhere.
 */
export function RedactedText({
  text,
  className,
}: {
  text: string;
  className?: string;
}) {
  if (!text.includes("REDACTED")) {
    return <span className={className}>{text}</span>;
  }
  const parts = text.split(REDACTED_TOKEN_RE);
  return (
    <>
      {parts.map((part, idx) => {
        if (!part) return null;
        if (
          (part.startsWith("[REDACTED") || part === "[SERVER-REDACTED]") &&
          part.endsWith("]")
        ) {
          return (
            <span
              key={idx}
              title="Scrubbed pre-write by Premier secret redactor"
              className="mx-0.5 inline-flex items-center gap-1 rounded border border-[#67d6dc]/40 bg-[#67d6dc]/14 px-1.5 py-px align-baseline font-mono text-[11px] font-medium leading-tight text-[#93e6ea]"
            >
              <IconShieldCheck className="h-3 w-3 shrink-0 text-[#67d6dc]" />
              <span>{part}</span>
            </span>
          );
        }
        return (
          <span key={idx} className={className}>
            {part}
          </span>
        );
      })}
    </>
  );
}

export interface CodeBlockProps {
  code: string;
  language?: SourceLanguage | string;
  filePath?: string;
  label?: string;
  showLineNumbers?: boolean;
  maxHeightClass?: string;
  collapsibleAt?: number;
  compact?: boolean;
  searchable?: boolean;
  headerExtra?: ReactNode;
  className?: string;
}

export function normalizeLanguage(
  language?: SourceLanguage | string,
  filePath?: string,
  sample?: string,
): SourceLanguage {
  if (language) {
    const low = language.toLowerCase().trim();
    if (low === "rs" || low === "rust") return "rust";
    if (
      low === "ts" ||
      low === "tsx" ||
      low === "typescript" ||
      low === "js" ||
      low === "jsx" ||
      low === "javascript"
    ) {
      return "typescript";
    }
    if (low === "json" || low === "jsonc") return "json";
    if (low === "toml") return "toml";
    if (low === "md" || low === "markdown" || low === "mdx") return "markdown";
    if (low === "css") return "css";
    if (
      low === "sh" ||
      low === "bash" ||
      low === "zsh" ||
      low === "shell" ||
      low === "curl" ||
      low === "yaml" ||
      low === "yml"
    ) {
      return "shell";
    }
    if (low === "plain" || low === "text") return "plain";
  }
  if (filePath) {
    const detected = detectLanguage(filePath);
    if (detected !== "plain") return detected;
  }
  if (sample) {
    const trimmed = sample.trim();
    if (
      (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
      (trimmed.startsWith("[") && trimmed.endsWith("]"))
    ) {
      try {
        JSON.parse(trimmed);
        return "json";
      } catch {
        // fall through
      }
    }
    if (/^(curl|git|cargo|pnpm|npm|npx|premier|sh|bash|export|GET|POST|PUT|DELETE)\b/.test(trimmed)) {
      return "shell";
    }
  }
  return "plain";
}

function displayLanguage(lang: SourceLanguage, raw?: string): string {
  if (lang === "shell") {
    const low = raw?.toLowerCase().trim();
    if (low === "yaml" || low === "yml") return "YAML";
    if (low === "curl") return "cURL";
    return "Shell";
  }
  return languageLabel(lang);
}

/**
 * Reusable syntax-highlighted obsidian code block with optional line numbers, wrap toggle,
 * inline line filter/search, `[REDACTED:...]` shield highlighting, collapsible long output,
 * and 1-click Copy button.
 */
export const CodeBlock = memo(function CodeBlock({
  code,
  language,
  filePath,
  label,
  showLineNumbers = false,
  maxHeightClass = "max-h-[340px]",
  collapsibleAt = 1600,
  compact = false,
  searchable = false,
  headerExtra,
  className = "",
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const [wrap, setWrap] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [query, setQuery] = useState("");

  const lang = useMemo(
    () => normalizeLanguage(language, filePath, code),
    [language, filePath, code],
  );
  const trimmedQuery = query.trim().toLowerCase();
  const isLong = collapsibleAt > 0 && code.length > collapsibleAt && !trimmedQuery;
  const visibleCode = isLong && !expanded ? `${code.slice(0, collapsibleAt).trimEnd()}\n…` : code;
  const allLines = useMemo(() => visibleCode.split(/\r?\n/), [visibleCode]);
  const totalLines = useMemo(() => code.split(/\r?\n/).length, [code]);
  const showSearchToggle = searchable || totalLines >= 18;

  const indexedLines = useMemo(() => {
    const mapped = allLines.map((text, idx) => ({ num: idx + 1, text }));
    if (!trimmedQuery) return mapped;
    return mapped.filter((entry) => entry.text.toLowerCase().includes(trimmedQuery));
  }, [allLines, trimmedQuery]);

  const handleCopy = () => {
    void navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div
      className={`overflow-hidden rounded-xl border border-white/[0.08] bg-[#060913]/95 ${className}`}
    >
      <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.025] px-3 py-1.5">
        <div className="flex min-w-0 items-center gap-2">
          {label && (
            <span className="truncate font-mono text-[12px] font-medium text-[#b6c3db]">
              {label}
            </span>
          )}
          <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 font-mono text-[11px] text-[#9ec0f5]">
            {displayLanguage(lang, language)}
          </span>
          {totalLines > 1 && (
            <span className="font-mono text-[11.5px] text-[#8595b0]">
              {trimmedQuery ? `${indexedLines.length}/${totalLines}L` : `${totalLines}L`}
            </span>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {showSearchToggle && (
            <button
              type="button"
              onClick={() => {
                setSearchOpen((open) => {
                  if (open) setQuery("");
                  return !open;
                });
              }}
              title={searchOpen ? "Close filter" : "Filter lines"}
              aria-label={searchOpen ? "Close filter" : "Filter lines"}
              className={`inline-flex h-6 items-center gap-1 rounded-md px-1.5 font-mono text-[11.5px] transition ${
                searchOpen || trimmedQuery
                  ? "bg-[#7f95f8]/20 text-[#cfe0ff]"
                  : "text-[#98a8c4] hover:bg-white/[0.06] hover:text-white"
              }`}
            >
              <IconSearch className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            onClick={() => setWrap((w) => !w)}
            title={wrap ? "Disable line wrap" : "Wrap long lines"}
            aria-label={wrap ? "Disable line wrap" : "Wrap long lines"}
            className={`inline-flex h-6 items-center gap-1 rounded-md px-1.5 font-mono text-[11.5px] transition ${
              wrap
                ? "bg-[#7f95f8]/20 text-[#cfe0ff]"
                : "text-[#98a8c4] hover:bg-white/[0.06] hover:text-white"
            }`}
          >
            <IconWrap className="h-3.5 w-3.5" />
          </button>
          {headerExtra}
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex h-6 items-center gap-1 rounded-md px-2 font-mono text-[11.5px] text-[#b6c3db] transition hover:bg-white/[0.06] hover:text-white"
          >
            {copied ? (
              <>
                <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                <span className="text-[#8beac0]">Copied</span>
              </>
            ) : (
              <>
                <IconCopy className="h-3.5 w-3.5 text-[#9ec0f5]" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {searchOpen && (
        <div className="flex items-center gap-2 border-b border-white/[0.06] bg-[#080d1b] px-3 py-1.5">
          <IconSearch className="h-3.5 w-3.5 shrink-0 text-[#8595b0]" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter lines…"
            aria-label="Filter code lines"
            className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-[#f5f7fd] placeholder:text-[#7f8ea8] focus:outline-none"
          />
          {trimmedQuery && (
            <span className="shrink-0 font-mono text-[11px] text-[#9ec0f5]">
              {indexedLines.length} match{indexedLines.length === 1 ? "" : "es"}
            </span>
          )}
        </div>
      )}

      <div className={`${maxHeightClass} overflow-auto`}>
        {indexedLines.length === 0 ? (
          <div className="px-3.5 py-4 text-center font-mono text-[12px] text-[#8595b0]">
            No lines match “{query}”.
          </div>
        ) : (
          <pre
            className={`font-mono ${
              compact
                ? "px-3 py-2 text-[12px] leading-[1.55]"
                : "px-3.5 py-2.5 text-[12.5px] leading-[1.6]"
            } ${wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"}`}
          >
            <code>
              {indexedLines.map(({ num, text }) => {
                const tokens = tokenizeLine(text, lang);
                return (
                  <div
                    key={num}
                    className={`flex min-w-0 ${trimmedQuery ? "bg-[#7f95f8]/[0.07]" : ""}`}
                  >
                    {showLineNumbers && (
                      <span className="mr-3 inline-block w-7 shrink-0 select-none text-right text-[#5f708e]">
                        {num}
                      </span>
                    )}
                    <span className="min-w-0 flex-1">
                      {tokens.length === 0 ? (
                        "\n"
                      ) : (
                        tokens.map((tok, j) => (
                          <Fragment key={j}>
                            <RedactedText text={tok.text} className={tokenClassName(tok.kind)} />
                          </Fragment>
                        ))
                      )}
                    </span>
                  </div>
                );
              })}
            </code>
          </pre>
        )}
      </div>

      {isLong && (
        <div className="border-t border-white/[0.06] bg-white/[0.02] px-3 py-1.5 text-center">
          <button
            type="button"
            onClick={() => setExpanded((e) => !e)}
            className="font-mono text-[12px] text-[#9ec0f5] transition hover:text-white"
          >
            {expanded
              ? "Show less"
              : `Show full output (${totalLines} lines · ${code.length.toLocaleString()} chars)`}
          </button>
        </div>
      )}
    </div>
  );
});

interface SplitRow {
  kind: "hunk" | "pair";
  hunkBody?: string;
  left?: { num: number | null; body: string; kind: "del" | "ctx" };
  right?: { num: number | null; body: string; kind: "add" | "ctx" };
}

function buildSplitRows(lines: ReturnType<typeof parseUnifiedPatch>["lines"]): SplitRow[] {
  const rows: SplitRow[] = [];
  let pendingDel: { num: number | null; body: string }[] = [];
  let pendingAdd: { num: number | null; body: string }[] = [];

  const flush = () => {
    const len = Math.max(pendingDel.length, pendingAdd.length);
    for (let i = 0; i < len; i++) {
      const d = pendingDel[i];
      const a = pendingAdd[i];
      rows.push({
        kind: "pair",
        left: d ? { num: d.num, body: d.body, kind: "del" } : undefined,
        right: a ? { num: a.num, body: a.body, kind: "add" } : undefined,
      });
    }
    pendingDel = [];
    pendingAdd = [];
  };

  for (const line of lines) {
    if (line.kind === "meta") continue;
    if (line.kind === "hunk") {
      flush();
      rows.push({ kind: "hunk", hunkBody: line.body });
      continue;
    }
    if (line.kind === "del") {
      pendingDel.push({ num: line.oldLine, body: line.body });
    } else if (line.kind === "add") {
      pendingAdd.push({ num: line.newLine, body: line.body });
    } else {
      flush();
      rows.push({
        kind: "pair",
        left: { num: line.oldLine, body: line.body, kind: "ctx" },
        right: { num: line.newLine, body: line.body, kind: "ctx" },
      });
    }
  }
  flush();
  return rows;
}

/**
 * Syntax-highlighted unified / side-by-side diff viewer powered by `parseUnifiedPatch` and `tokenizeLine`.
 */
export const DiffBlock = memo(function DiffBlock({
  patch,
  filePath,
  language,
  maxHeightClass = "max-h-[380px]",
  allowSplit = false,
  defaultView = "unified",
}: {
  patch: string;
  filePath?: string;
  language?: string;
  maxHeightClass?: string;
  allowSplit?: boolean;
  defaultView?: "unified" | "split";
}) {
  const [copied, setCopied] = useState(false);
  const [view, setView] = useState<"unified" | "split">(defaultView);
  const parsed = useMemo(() => parseUnifiedPatch(patch), [patch]);
  const splitRows = useMemo(
    () => (allowSplit && view === "split" ? buildSplitRows(parsed.lines) : []),
    [allowSplit, view, parsed.lines],
  );
  const lang = useMemo(() => normalizeLanguage(language, filePath), [language, filePath]);

  const handleCopy = () => {
    void navigator.clipboard?.writeText(patch).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#060913]/95">
      <div className="flex items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.025] px-3 py-1.5">
        <div className="flex min-w-0 items-center gap-2 font-mono text-[12px]">
          <span className="truncate font-medium text-[#cfe0ff]">{filePath ?? "Unified diff"}</span>
          <span className="text-[#5bdba2]">+{parsed.additions}</span>
          <span className="text-[#f27c7c]">-{parsed.deletions}</span>
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          {allowSplit && (
            <div className="inline-flex items-center rounded-md border border-white/[0.08] bg-white/[0.02] p-0.5 font-mono text-[11px]">
              <button
                type="button"
                onClick={() => setView("unified")}
                className={`rounded px-1.5 py-px transition ${
                  view === "unified"
                    ? "bg-[#7f95f8]/25 text-[#e6eeff]"
                    : "text-[#98a8c4] hover:text-white"
                }`}
              >
                Unified
              </button>
              <button
                type="button"
                onClick={() => setView("split")}
                className={`rounded px-1.5 py-px transition ${
                  view === "split"
                    ? "bg-[#7f95f8]/25 text-[#e6eeff]"
                    : "text-[#98a8c4] hover:text-white"
                }`}
              >
                Split
              </button>
            </div>
          )}
          <button
            type="button"
            onClick={handleCopy}
            className="inline-flex h-6 shrink-0 items-center gap-1 rounded-md px-2 font-mono text-[11.5px] text-[#b6c3db] transition hover:bg-white/[0.06] hover:text-white"
          >
            {copied ? (
              <>
                <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                <span className="text-[#8beac0]">Copied</span>
              </>
            ) : (
              <>
                <IconCopy className="h-3.5 w-3.5 text-[#9ec0f5]" />
                <span>Copy diff</span>
              </>
            )}
          </button>
        </div>
      </div>

      {allowSplit && view === "split" ? (
        <div className={`${maxHeightClass} overflow-auto font-mono text-[12px] leading-[1.6]`}>
          <div className="min-w-[680px]">
          {splitRows.map((row, idx) => {
            if (row.kind === "hunk") {
              return (
                <div
                  key={idx}
                  className="whitespace-pre border-y border-white/[0.05] bg-[#7f95f8]/[0.09] px-3 py-0.5 text-[#9ec0f5]"
                >
                  {row.hunkBody}
                </div>
              );
            }
            const leftTokens = row.left ? tokenizeLine(row.left.body, lang) : [];
            const rightTokens = row.right ? tokenizeLine(row.right.body, lang) : [];
            return (
              <div key={idx} className="grid grid-cols-2 divide-x divide-white/[0.06]">
                <div
                  className={`flex min-w-0 px-2 ${
                    row.left?.kind === "del" ? "bg-[#f27c7c]/[0.10]" : ""
                  }`}
                >
                  <span className="w-7 shrink-0 select-none pr-2 text-right text-[#5f708e]">
                    {row.left?.num ?? ""}
                  </span>
                  <span
                    className={`w-3.5 shrink-0 select-none ${
                      row.left?.kind === "del" ? "text-[#f27c7c]" : "text-[#5f708e]"
                    }`}
                  >
                    {row.left?.kind === "del" ? "-" : row.left ? " " : ""}
                  </span>
                  <span className="whitespace-pre pr-2">
                    {leftTokens.map((tok, j) => (
                      <Fragment key={j}>
                        <RedactedText text={tok.text} className={tokenClassName(tok.kind)} />
                      </Fragment>
                    ))}
                  </span>
                </div>
                <div
                  className={`flex min-w-0 px-2 ${
                    row.right?.kind === "add" ? "bg-[#5bdba2]/[0.09]" : ""
                  }`}
                >
                  <span className="w-7 shrink-0 select-none pr-2 text-right text-[#5f708e]">
                    {row.right?.num ?? ""}
                  </span>
                  <span
                    className={`w-3.5 shrink-0 select-none ${
                      row.right?.kind === "add" ? "text-[#5bdba2]" : "text-[#5f708e]"
                    }`}
                  >
                    {row.right?.kind === "add" ? "+" : row.right ? " " : ""}
                  </span>
                  <span className="whitespace-pre pr-2">
                    {rightTokens.map((tok, j) => (
                      <Fragment key={j}>
                        <RedactedText text={tok.text} className={tokenClassName(tok.kind)} />
                      </Fragment>
                    ))}
                  </span>
                </div>
              </div>
            );
          })}
          </div>
        </div>
      ) : (
        <div className={`${maxHeightClass} overflow-auto font-mono text-[12px] leading-[1.6]`}>
        {parsed.lines.map((line, i) => {
          if (line.kind === "meta") {
            if (filePath && (line.body.startsWith("--- ") || line.body.startsWith("+++ "))) {
              return null;
            }
            return (
              <div key={i} className="min-w-max whitespace-pre px-3 py-0.5 text-[#7f8ea8]">
                {line.body}
              </div>
            );
          }
          if (line.kind === "hunk") {
            return (
              <div
                key={i}
                className="min-w-max whitespace-pre border-y border-white/[0.05] bg-[#7f95f8]/[0.09] px-3 py-0.5 text-[#9ec0f5]"
              >
                {line.body}
              </div>
            );
          }
          const rowBg =
            line.kind === "add"
              ? "bg-[#5bdba2]/[0.09]"
              : line.kind === "del"
                ? "bg-[#f27c7c]/[0.10]"
                : "";
          const sigilColor =
            line.kind === "add"
              ? "text-[#5bdba2]"
              : line.kind === "del"
                ? "text-[#f27c7c]"
                : "text-[#5f708e]";
          const tokens = tokenizeLine(line.body, lang);
          return (
            <div key={i} className={`flex min-w-max px-2 ${rowBg}`}>
              <span className="w-8 shrink-0 select-none pr-1.5 text-right text-[#5f708e]">
                {line.oldLine ?? ""}
              </span>
              <span className="w-8 shrink-0 select-none pr-2 text-right text-[#5f708e]">
                {line.newLine ?? ""}
              </span>
              <span className={`w-4 shrink-0 select-none ${sigilColor}`}>{line.sigil}</span>
              <span className="whitespace-pre pr-3">
                {tokens.map((tok, j) => (
                  <Fragment key={j}>
                    <RedactedText text={tok.text} className={tokenClassName(tok.kind)} />
                  </Fragment>
                ))}
              </span>
            </div>
          );
        })}
        </div>
      )}
    </div>
  );
});

function matchesJsonQuery(key: string | null, value: unknown, query: string): boolean {
  if (!query) return true;
  if (key && key.toLowerCase().includes(query)) return true;
  if (value === null || value === undefined) return "null".includes(query);
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    return String(value).toLowerCase().includes(query);
  }
  if (Array.isArray(value)) {
    return value.some((item, i) => matchesJsonQuery(String(i), item, query));
  }
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(([k, v]) =>
      matchesJsonQuery(k, v, query),
    );
  }
  return false;
}

function JsonTreeNode({
  name,
  value,
  depth,
  defaultExpandDepth,
  query,
  copiedPath,
  path,
  onCopy,
}: {
  name: string | null;
  value: unknown;
  depth: number;
  defaultExpandDepth: number;
  query: string;
  copiedPath: string | null;
  path: string;
  onCopy: (path: string, value: unknown) => void;
}) {
  const [open, setOpen] = useState(depth < defaultExpandDepth);
  const effectiveOpen = query ? true : open;

  if (query && !matchesJsonQuery(name, value, query)) {
    return null;
  }

  const isArray = Array.isArray(value);
  const isObject = value !== null && typeof value === "object" && !isArray;

  if (!isArray && !isObject) {
    const valEl =
      value === null || value === undefined ? (
        <span className="text-[var(--pr-syn-kw)]">null</span>
      ) : typeof value === "boolean" ? (
        <span className="text-[var(--pr-syn-kw)]">{String(value)}</span>
      ) : typeof value === "number" ? (
        <span className="text-[var(--pr-syn-num)]">{String(value)}</span>
      ) : (
        <span className="break-words [overflow-wrap:anywhere] text-[var(--pr-syn-str)]">
          &quot;<RedactedText text={String(value)} className="text-[var(--pr-syn-str)]" />&quot;
        </span>
      );

    return (
      <div
        className="group flex items-start gap-1.5 rounded px-1.5 py-0.5 hover:bg-white/[0.04]"
        style={{ paddingLeft: `${depth * 14 + 6}px` }}
      >
        {name !== null && (
          <span className="shrink-0 text-[var(--pr-syn-fn)]">
            {name}
            <span className="text-[#697896]">:</span>
          </span>
        )}
        <span className="min-w-0 flex-1">{valEl}</span>
        <button
          type="button"
          onClick={() => onCopy(path, value)}
          title={`Copy ${path}`}
          className="shrink-0 rounded px-1 text-[10.5px] text-[#8595b0] opacity-0 transition hover:bg-white/[0.08] hover:text-white group-hover:opacity-100"
        >
          {copiedPath === path ? "Copied" : "Copy"}
        </button>
      </div>
    );
  }

  const entries: [string, unknown][] = isArray
    ? (value as unknown[]).map((v, i) => [String(i), v])
    : Object.entries(value as Record<string, unknown>);

  const openBracket = isArray ? "[" : "{";
  const closeBracket = isArray ? "]" : "}";
  const countLabel = isArray ? `${entries.length} items` : `${entries.length} keys`;

  return (
    <div>
      <div
        className="group flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-white/[0.04]"
        style={{ paddingLeft: `${depth * 14 + 2}px` }}
      >
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="inline-flex min-w-0 flex-1 items-center gap-1 text-left"
        >
          <IconChevron
            className={`h-3 w-3 shrink-0 text-[#7f8ea8] transition-transform ${
              effectiveOpen ? "" : "-rotate-90"
            }`}
          />
          {name !== null && (
            <span className="text-[var(--pr-syn-fn)]">
              {name}
              <span className="text-[#697896]">:</span>
            </span>
          )}
          <span className="text-[#8595b0]">{openBracket}</span>
          {!effectiveOpen && (
            <>
              <span className="rounded bg-white/[0.04] px-1.5 text-[11px] text-[#98a8c4]">
                {countLabel}
              </span>
              <span className="text-[#8595b0]">{closeBracket}</span>
            </>
          )}
        </button>
        <button
          type="button"
          onClick={() => onCopy(path, value)}
          title={`Copy ${path}`}
          className="shrink-0 rounded px-1 text-[10.5px] text-[#8595b0] opacity-0 transition hover:bg-white/[0.08] hover:text-white group-hover:opacity-100"
        >
          {copiedPath === path ? "Copied" : "Copy"}
        </button>
      </div>

      {effectiveOpen && (
        <div>
          {entries.length === 0 ? (
            <div
              className="py-0.5 text-[11.5px] text-[#7f8ea8]"
              style={{ paddingLeft: `${(depth + 1) * 14 + 8}px` }}
            >
              (empty)
            </div>
          ) : (
            entries.map(([k, v]) => (
              <JsonTreeNode
                key={k}
                name={isArray ? `[${k}]` : k}
                value={v}
                depth={depth + 1}
                defaultExpandDepth={defaultExpandDepth}
                query={query}
                copiedPath={copiedPath}
                path={isArray ? `${path}[${k}]` : `${path}.${k}`}
                onCopy={onCopy}
              />
            ))
          )}
          <div
            className="text-[#8595b0]"
            style={{ paddingLeft: `${depth * 14 + 16}px` }}
          >
            {closeBracket}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Interactive structured JSON viewer with Tree / Code toggle, key/value search,
 * expand/collapse, click-to-copy values, and `[REDACTED:...]` highlighting.
 */
export const JsonTreeView = memo(function JsonTreeView({
  value,
  label,
  defaultMode = "tree",
  maxHeightClass = "max-h-[340px]",
  compact = true,
  searchable = false,
}: {
  value: unknown;
  label?: string;
  defaultMode?: "tree" | "code";
  maxHeightClass?: string;
  compact?: boolean;
  searchable?: boolean;
}) {
  const [mode, setMode] = useState<"tree" | "code">(defaultMode);
  const [expandDepth, setExpandDepth] = useState(2);
  const [treeEpoch, setTreeEpoch] = useState(0);
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [copiedPath, setCopiedPath] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  const rawJson = useMemo(() => JSON.stringify(value, null, 2), [value]);
  const lineCount = useMemo(() => rawJson.split(/\r?\n/).length, [rawJson]);
  const trimmedQuery = query.trim().toLowerCase();

  const copyLeaf = (path: string, val: unknown) => {
    const text = typeof val === "string" ? val : JSON.stringify(val, null, 2);
    void navigator.clipboard?.writeText(text).then(() => {
      setCopiedPath(path);
      window.setTimeout(() => setCopiedPath((cur) => (cur === path ? null : cur)), 1400);
    });
  };

  const copyAll = () => {
    void navigator.clipboard?.writeText(rawJson).then(() => {
      setCopiedAll(true);
      window.setTimeout(() => setCopiedAll(false), 1500);
    });
  };

  if (mode === "code") {
    return (
      <CodeBlock
        code={rawJson}
        label={label}
        language="json"
        showLineNumbers
        compact={compact}
        maxHeightClass={maxHeightClass}
        searchable={searchable || lineCount >= 14}
        collapsibleAt={0}
        headerExtra={
          <div className="inline-flex items-center rounded-md border border-white/[0.08] bg-white/[0.02] p-0.5 font-mono text-[11px]">
            <button
              type="button"
              onClick={() => setMode("tree")}
              className="rounded px-1.5 py-px text-[#98a8c4] transition hover:text-white"
            >
              Tree
            </button>
            <button
              type="button"
              onClick={() => setMode("code")}
              className="rounded bg-[#7f95f8]/25 px-1.5 py-px text-[#e6eeff]"
            >
              Code
            </button>
          </div>
        }
      />
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#060913]/95">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] bg-white/[0.025] px-3 py-1.5">
        <div className="flex min-w-0 items-center gap-2">
          {label && (
            <span className="truncate font-mono text-[12px] font-medium text-[#b6c3db]">
              {label}
            </span>
          )}
          <span className="rounded-md border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 font-mono text-[11px] text-[#9ec0f5]">
            JSON
          </span>
          <span className="font-mono text-[11.5px] text-[#8595b0]">{lineCount}L</span>
        </div>

        <div className="flex shrink-0 items-center gap-1">
          {(searchable || lineCount >= 10) && (
            <button
              type="button"
              onClick={() => {
                setSearchOpen((o) => {
                  if (o) setQuery("");
                  return !o;
                });
              }}
              title="Filter keys or values"
              aria-label="Filter JSON tree"
              className={`inline-flex h-6 items-center rounded-md px-1.5 transition ${
                searchOpen || trimmedQuery
                  ? "bg-[#7f95f8]/20 text-[#cfe0ff]"
                  : "text-[#98a8c4] hover:bg-white/[0.06] hover:text-white"
              }`}
            >
              <IconSearch className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            onClick={() => {
              setExpandDepth((d) => (d >= 10 ? 1 : 10));
              setTreeEpoch((n) => n + 1);
            }}
            title={expandDepth >= 10 ? "Collapse nested nodes" : "Expand all nodes"}
            className="inline-flex h-6 items-center rounded-md px-1.5 font-mono text-[11px] text-[#98a8c4] transition hover:bg-white/[0.06] hover:text-white"
          >
            {expandDepth >= 10 ? "Fold" : "Expand"}
          </button>
          <div className="inline-flex items-center rounded-md border border-white/[0.08] bg-white/[0.02] p-0.5 font-mono text-[11px]">
            <button
              type="button"
              onClick={() => setMode("tree")}
              className="rounded bg-[#7f95f8]/25 px-1.5 py-px text-[#e6eeff]"
            >
              Tree
            </button>
            <button
              type="button"
              onClick={() => setMode("code")}
              className="rounded px-1.5 py-px text-[#98a8c4] transition hover:text-white"
            >
              Code
            </button>
          </div>
          <button
            type="button"
            onClick={copyAll}
            className="inline-flex h-6 items-center gap-1 rounded-md px-2 font-mono text-[11.5px] text-[#b6c3db] transition hover:bg-white/[0.06] hover:text-white"
          >
            {copiedAll ? (
              <>
                <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                <span className="text-[#8beac0]">Copied</span>
              </>
            ) : (
              <>
                <IconCopy className="h-3.5 w-3.5 text-[#9ec0f5]" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {searchOpen && (
        <div className="flex items-center gap-2 border-b border-white/[0.06] bg-[#080d1b] px-3 py-1.5">
          <IconSearch className="h-3.5 w-3.5 shrink-0 text-[#8595b0]" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter keys or values…"
            aria-label="Filter JSON keys or values"
            className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-[#f5f7fd] placeholder:text-[#7f8ea8] focus:outline-none"
          />
        </div>
      )}

      <div
        className={`${maxHeightClass} overflow-auto px-2 py-2 font-mono ${
          compact ? "text-[12px] leading-[1.55]" : "text-[12.5px] leading-[1.6]"
        }`}
      >
        <JsonTreeNode
          key={treeEpoch}
          name={null}
          value={value}
          depth={0}
          defaultExpandDepth={expandDepth}
          query={trimmedQuery}
          copiedPath={copiedPath}
          path="$"
          onCopy={copyLeaf}
        />
      </div>
    </div>
  );
});

/** Smart evidence value viewer for structured Inspector fields (interactive JSON Tree/Code, code, or plain scalars). */
export function EvidenceValue({
  label,
  value,
  language,
  filePath,
  compact = true,
  defaultJsonMode = "tree",
}: {
  label?: string;
  value: unknown;
  language?: string;
  filePath?: string;
  compact?: boolean;
  defaultJsonMode?: "tree" | "code";
}) {
  if (value === null || value === undefined) {
    return <span className="font-mono text-[12.5px] text-[#8595b0]">—</span>;
  }
  if (typeof value === "boolean" || typeof value === "number") {
    return (
      <span className="font-mono text-[13px] text-[var(--pr-syn-num)]">{String(value)}</span>
    );
  }
  if (typeof value === "string") {
    const looksStructured =
      value.includes("\n") ||
      value.length > 90 ||
      Boolean(language) ||
      /^(curl|git|cargo|pnpm|premier|GET|POST|PUT|DELETE)\b/.test(value.trim());
    if (looksStructured) {
      return (
        <CodeBlock
          code={value}
          label={label}
          language={language}
          filePath={filePath}
          compact={compact}
          showLineNumbers={value.includes("\n")}
        />
      );
    }
    return (
      <span className="break-words font-mono text-[12.5px] text-[#dce4f5]">
        <RedactedText text={value} />
      </span>
    );
  }

  return (
    <JsonTreeView
      value={value}
      label={label}
      compact={compact}
      defaultMode={defaultJsonMode}
    />
  );
}
