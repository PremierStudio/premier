import { Fragment, memo, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  languageLabel,
  tokenClassName,
  tokenizeLine,
  type SourceLanguage,
} from "../lib/highlight";

function CopyCodeButton({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 1400);
    return () => window.clearTimeout(t);
  }, [copied]);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(code).catch(() => {});
        setCopied(true);
      }}
      aria-label={copied ? "Copied" : "Copy code"}
      className="rounded px-1.5 py-0.5 text-[12.5px] text-[#a6b5cf] transition hover:bg-white/[0.06] hover:text-[#f3f6fd]"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

interface Props {
  content: string;
  currentPath?: string;
  onOpenFile?: (path: string) => void;
}

type Alignment = "left" | "center" | "right";

interface ListItem {
  text: string;
  indent: number;
}

type Block =
  | { kind: "heading"; level: 1 | 2 | 3 | 4; text: string; slug: string }
  | { kind: "code"; langTag: string; code: string }
  | { kind: "hr" }
  | { kind: "blockquote"; lines: string[] }
  | { kind: "ul"; items: ListItem[] }
  | { kind: "ol"; start: number; items: ListItem[] }
  | { kind: "table"; headers: string[]; alignments: Alignment[]; rows: string[][] }
  | { kind: "paragraph"; text: string };

function mapFenceLanguage(tag: string): SourceLanguage {
  const lower = tag.trim().toLowerCase();
  if (lower === "rs" || lower === "rust") return "rust";
  if (
    lower === "ts" ||
    lower === "tsx" ||
    lower === "typescript" ||
    lower === "js" ||
    lower === "jsx" ||
    lower === "javascript" ||
    lower === "mjs"
  ) {
    return "typescript";
  }
  if (lower === "toml") return "toml";
  if (lower === "json" || lower === "jsonc") return "json";
  if (lower === "md" || lower === "markdown" || lower === "mdx") return "markdown";
  if (lower === "css") return "css";
  if (
    lower === "sh" ||
    lower === "bash" ||
    lower === "zsh" ||
    lower === "shell" ||
    lower === "yml" ||
    lower === "yaml"
  ) {
    return "shell";
  }
  return "plain";
}

function isSafeHttpUrl(raw: string): boolean {
  const trimmed = raw.trim();
  if (!/^https?:\/\//i.test(trimmed)) return false;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
}

function slugifyHeading(text: string): string {
  return text
    .toLowerCase()
    .replace(/[`*_~[\]()]/g, "")
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function resolveRepoRelativePath(href: string, currentPath?: string): string | null {
  const cleaned = href.trim().split(/[?#]/)[0].trim();
  if (!cleaned) return null;
  // Reject any URI scheme (javascript:, data:, mailto:, ftp:, etc.) or protocol-relative URL.
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(cleaned) || cleaned.startsWith("//")) return null;
  const baseParts = cleaned.startsWith("/")
    ? []
    : (currentPath ?? "").split("/").slice(0, -1).filter(Boolean);
  const relParts = cleaned.replace(/^\/+/, "").split("/");
  const out = [...baseParts];
  for (const part of relParts) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (out.length === 0) return null;
      out.pop();
    } else {
      out.push(part);
    }
  }
  return out.length > 0 ? out.join("/") : null;
}

function leadingIndent(line: string): number {
  let count = 0;
  for (let i = 0; i < line.length; i++) {
    if (line[i] === " ") count += 1;
    else if (line[i] === "\t") count += 2;
    else break;
  }
  return count;
}

function splitTableRow(line: string): string[] {
  let trimmed = line.trim();
  if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
  if (trimmed.endsWith("|")) trimmed = trimmed.slice(0, -1);
  const cells: string[] = [];
  let cur = "";
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === "\\" && trimmed[i + 1] === "|") {
      cur += "|";
      i += 1;
    } else if (trimmed[i] === "|") {
      cells.push(cur.trim());
      cur = "";
    } else {
      cur += trimmed[i];
    }
  }
  cells.push(cur.trim());
  return cells;
}

function parseTableAlignments(sepLine: string): Alignment[] | null {
  const trimmed = sepLine.trim();
  if (!trimmed.includes("-")) return null;
  if (!/^\|?[\s:|-]+\|?$/.test(trimmed)) return null;
  const cells = splitTableRow(trimmed);
  if (cells.length === 0) return null;
  const alignments: Alignment[] = [];
  for (const c of cells) {
    if (!/^:?-{1,}:?$/.test(c)) return null;
    if (c.startsWith(":") && c.endsWith(":")) alignments.push("center");
    else if (c.endsWith(":")) alignments.push("right");
    else alignments.push("left");
  }
  return alignments;
}

function isBlockStarter(lines: string[], idx: number): boolean {
  const line = lines[idx];
  const trimmed = line.trim();
  if (!trimmed) return true;
  if (/^#{1,6}\s+/.test(trimmed)) return true;
  if (/^```/.test(trimmed) || /^~~~/.test(trimmed)) return true;
  if (/^(?:---+|\*\*\*+|___+)$/.test(trimmed)) return true;
  if (/^>\s?/.test(trimmed)) return true;
  if (/^[-*+]\s+/.test(trimmed)) return true;
  if (/^\d+\.\s+/.test(trimmed)) return true;
  if (
    line.includes("|") &&
    idx + 1 < lines.length &&
    parseTableAlignments(lines[idx + 1]) !== null
  ) {
    return true;
  }
  return false;
}

function parseBlocks(content: string): Block[] {
  const lines = content.split(/\r?\n/);
  const blocks: Block[] = [];
  const slugCounts = new Map<string, number>();
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed) {
      i += 1;
      continue;
    }

    // Fenced code block (``` or ~~~)
    const fenceMatch = trimmed.match(/^(```+|~~~+)(.*)$/);
    if (fenceMatch) {
      const markerChar = fenceMatch[1][0];
      const markerLen = fenceMatch[1].length;
      const langTag = fenceMatch[2].trim().split(/\s+/)[0] ?? "";
      const codeLines: string[] = [];
      i += 1;
      while (i < lines.length) {
        const closeTrimmed = lines[i].trim();
        if (
          closeTrimmed.startsWith(markerChar.repeat(markerLen)) &&
          new RegExp(`^${markerChar}{${markerLen},}\\s*$`).test(closeTrimmed)
        ) {
          i += 1;
          break;
        }
        codeLines.push(lines[i]);
        i += 1;
      }
      blocks.push({ kind: "code", langTag, code: codeLines.join("\n") });
      continue;
    }

    // Headings #..#### (clamp 5-6 to 4)
    const headingMatch = trimmed.match(/^(#{1,6})\s+(.*?)\s*#*$/);
    if (headingMatch) {
      const rawLevel = headingMatch[1].length;
      const level = (rawLevel > 4 ? 4 : rawLevel) as 1 | 2 | 3 | 4;
      const baseSlug = slugifyHeading(headingMatch[2]) || `section-${blocks.length}`;
      const seen = slugCounts.get(baseSlug) ?? 0;
      slugCounts.set(baseSlug, seen + 1);
      const slug = seen === 0 ? baseSlug : `${baseSlug}-${seen}`;
      blocks.push({ kind: "heading", level, text: headingMatch[2], slug });
      i += 1;
      continue;
    }

    // Horizontal rule
    if (/^(?:---+|\*\*\*+|___+)$/.test(trimmed)) {
      blocks.push({ kind: "hr" });
      i += 1;
      continue;
    }

    // GFM table
    if (line.includes("|") && i + 1 < lines.length) {
      const alignments = parseTableAlignments(lines[i + 1]);
      if (alignments) {
        const headers = splitTableRow(line);
        const rows: string[][] = [];
        i += 2;
        while (i < lines.length && lines[i].trim() && lines[i].includes("|")) {
          rows.push(splitTableRow(lines[i]));
          i += 1;
        }
        blocks.push({ kind: "table", headers, alignments, rows });
        continue;
      }
    }

    // Blockquote
    if (/^>\s?/.test(trimmed)) {
      const qLines: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i].trim())) {
        qLines.push(lines[i].trim().replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push({ kind: "blockquote", lines: qLines });
      continue;
    }

    // Unordered list (preserving nested indentation)
    if (/^\s*[-*+]\s+/.test(line)) {
      const items: ListItem[] = [];
      let minIndent = Infinity;
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        const indent = leadingIndent(lines[i]);
        if (indent < minIndent) minIndent = indent;
        items.push({ text: lines[i].replace(/^\s*[-*+]\s+/, ""), indent });
        i += 1;
      }
      const baseIndent = Number.isFinite(minIndent) ? minIndent : 0;
      blocks.push({
        kind: "ul",
        items: items.map((it) => ({ ...it, indent: Math.max(0, it.indent - baseIndent) })),
      });
      continue;
    }

    // Ordered list (preserving nested indentation)
    const olMatch = line.match(/^\s*(\d+)\.\s+(.*)$/);
    if (olMatch) {
      const start = Number(olMatch[1]) || 1;
      const items: ListItem[] = [];
      let minIndent = Infinity;
      while (i < lines.length) {
        const m = lines[i].match(/^\s*\d+\.\s+(.*)$/);
        if (!m) break;
        const indent = leadingIndent(lines[i]);
        if (indent < minIndent) minIndent = indent;
        items.push({ text: m[1], indent });
        i += 1;
      }
      const baseIndent = Number.isFinite(minIndent) ? minIndent : 0;
      blocks.push({
        kind: "ol",
        start,
        items: items.map((it) => ({ ...it, indent: Math.max(0, it.indent - baseIndent) })),
      });
      continue;
    }

    // Paragraph
    const paraLines: string[] = [trimmed];
    i += 1;
    while (i < lines.length && !isBlockStarter(lines, i)) {
      paraLines.push(lines[i].trim());
      i += 1;
    }
    blocks.push({ kind: "paragraph", text: paraLines.join(" ") });
  }

  return blocks;
}

interface InlineContext {
  currentPath?: string;
  onOpenFile?: (path: string) => void;
}

/**
 * Matches `[label](href)` starting at the `[` at `start`, balancing nested brackets and parens
 * (so `alert(1)` inside a URL stays inside it). `end` is the index just past the closing `)`.
 */
function matchBracketLink(
  text: string,
  start: number,
): { label: string; href: string; end: number } | null {
  const close = (from: number, open: string, shut: string): number => {
    let depth = 0;
    for (let j = from; j < text.length; j++) {
      if (text[j] === "\\") j++;
      else if (text[j] === open) depth++;
      else if (text[j] === shut && --depth === 0) return j;
    }
    return -1;
  };
  const closeBracket = close(start, "[", "]");
  if (closeBracket < 0 || text[closeBracket + 1] !== "(") return null;
  const closeParen = close(closeBracket + 1, "(", ")");
  if (closeParen < 0) return null;
  return {
    label: text.slice(start + 1, closeBracket),
    href: text.slice(closeBracket + 2, closeParen).trim(),
    end: closeParen + 1,
  };
}

/** Pure-React XSS-safe inline parser (code, links, anchors, bold, italic, strikethrough). Images are never fetched. */
function renderInline(text: string, ctx: InlineContext, keyPrefix = ""): ReactNode[] {
  const nodes: ReactNode[] = [];
  let i = 0;
  let plain = "";
  let tokenIdx = 0;

  const flushPlain = () => {
    if (plain) {
      nodes.push(<Fragment key={`${keyPrefix}p${tokenIdx++}`}>{plain}</Fragment>);
      plain = "";
    }
  };

  while (i < text.length) {
    // Escaped punctuation
    if (text[i] === "\\" && i + 1 < text.length && /[\\`*_{}[\]()#+\-.!~|]/.test(text[i + 1])) {
      plain += text[i + 1];
      i += 2;
      continue;
    }

    // Inline code `...`
    if (text[i] === "`") {
      const end = text.indexOf("`", i + 1);
      if (end > i + 1) {
        flushPlain();
        nodes.push(
          <code
            key={`${keyPrefix}c${tokenIdx++}`}
            className="rounded-md border border-white/[0.08] bg-white/[0.06] px-1.5 py-0.5 font-mono text-[0.88em] text-[#9ec0f5]"
          >
            {text.slice(i + 1, end)}
          </code>,
        );
        i = end + 1;
        continue;
      }
    }

    // Images are never rendered (no remote fetches from previewed content): show the alt text,
    // consuming the whole ![alt](src) so nothing of the URL leaks into the text.
    if (text[i] === "!" && text[i + 1] === "[") {
      const img = matchBracketLink(text, i + 1);
      if (img) {
        plain += img.label;
        i = img.end;
        continue;
      }
    }

    // Links [label](url): external http(s), #heading anchor, or clickable repo-relative path;
    // anything else keeps only its label.
    if (text[i] === "[") {
      const link = matchBracketLink(text, i);
      if (link) {
        const { label } = link;
        // Drop an optional `<...>` wrapper and a trailing link title.
        const href = link.href.replace(/^<|>$/g, "").split(/\s+/)[0] ?? "";
        flushPlain();
        if (isSafeHttpUrl(href)) {
          nodes.push(
            <a
              key={`${keyPrefix}a${tokenIdx++}`}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-[#9ec0f5] underline decoration-[#7f95f8]/45 underline-offset-2 transition hover:text-[#dce8ff] hover:decoration-[#9ec0f5]"
            >
              {renderInline(label, ctx, `${keyPrefix}l${tokenIdx}_`)}
            </a>,
          );
        } else if (href.startsWith("#") && href.length > 1) {
          let targetSlug = "";
          try {
            targetSlug = slugifyHeading(decodeURIComponent(href.slice(1)));
          } catch {
            targetSlug = slugifyHeading(href.slice(1));
          }
          nodes.push(
            <button
              key={`${keyPrefix}anc${tokenIdx++}`}
              type="button"
              onClick={() => {
                const el = document.getElementById(`premier-md-h-${targetSlug}`);
                el?.scrollIntoView({ behavior: "smooth", block: "start" });
              }}
              className="inline cursor-pointer text-left text-[#9ec0f5] underline decoration-[#7f95f8]/45 underline-offset-2 transition hover:text-[#dce8ff] hover:decoration-[#9ec0f5]"
            >
              {renderInline(label, ctx, `${keyPrefix}anc${tokenIdx}_`)}
            </button>,
          );
        } else {
          const resolved = ctx.onOpenFile ? resolveRepoRelativePath(href, ctx.currentPath) : null;
          if (resolved) {
            nodes.push(
              <button
                key={`${keyPrefix}rel${tokenIdx++}`}
                type="button"
                onClick={() => ctx.onOpenFile?.(resolved)}
                title={`Open ${resolved}`}
                className="inline cursor-pointer text-left text-[#9ec0f5] underline decoration-[#7f95f8]/45 underline-offset-2 transition hover:text-[#dce8ff] hover:decoration-[#9ec0f5]"
              >
                {renderInline(label, ctx, `${keyPrefix}rel${tokenIdx}_`)}
              </button>,
            );
          } else {
            nodes.push(
              <span key={`${keyPrefix}u${tokenIdx++}`} className="text-[#d2dbee]">
                {renderInline(label, ctx, `${keyPrefix}u${tokenIdx}_`)}
              </span>,
            );
          }
        }
        i = link.end;
        continue;
      }
    }

    // Bold **...** or __...__
    if (
      (text.startsWith("**", i) || text.startsWith("__", i)) &&
      text[i + 2] &&
      text[i + 2] !== " "
    ) {
      const delim = text.slice(i, i + 2);
      const end = text.indexOf(delim, i + 2);
      if (end > i + 2) {
        flushPlain();
        nodes.push(
          <strong key={`${keyPrefix}b${tokenIdx++}`} className="font-semibold text-[#f3f6fd]">
            {renderInline(text.slice(i + 2, end), ctx, `${keyPrefix}b${tokenIdx}_`)}
          </strong>,
        );
        i = end + 2;
        continue;
      }
    }

    // Strikethrough ~~...~~
    if (text.startsWith("~~", i)) {
      const end = text.indexOf("~~", i + 2);
      if (end > i + 2) {
        flushPlain();
        nodes.push(
          <del key={`${keyPrefix}s${tokenIdx++}`} className="text-[#a6b5cf] line-through">
            {renderInline(text.slice(i + 2, end), ctx, `${keyPrefix}s${tokenIdx}_`)}
          </del>,
        );
        i = end + 2;
        continue;
      }
    }

    // Italic *...* or _..._ (avoid matching mid-word underscores)
    if (
      (text[i] === "*" || (text[i] === "_" && (i === 0 || !/[A-Za-z0-9]/.test(text[i - 1])))) &&
      text[i + 1] &&
      text[i + 1] !== " " &&
      text[i + 1] !== text[i]
    ) {
      const delim = text[i];
      const end = text.indexOf(delim, i + 1);
      if (
        end > i + 1 &&
        text[end - 1] !== " " &&
        (delim === "*" || end + 1 >= text.length || !/[A-Za-z0-9]/.test(text[end + 1]))
      ) {
        flushPlain();
        nodes.push(
          <em key={`${keyPrefix}i${tokenIdx++}`} className="italic text-[#e6ecf8]">
            {renderInline(text.slice(i + 1, end), ctx, `${keyPrefix}i${tokenIdx}_`)}
          </em>,
        );
        i = end + 1;
        continue;
      }
    }

    plain += text[i];
    i += 1;
  }

  flushPlain();
  return nodes;
}

const ALIGN_CLASS: Record<Alignment, string> = {
  left: "text-left",
  center: "text-center",
  right: "text-right",
};

export const MarkdownPreview = memo(function MarkdownPreview({
  content,
  currentPath,
  onOpenFile,
}: Props) {
  const blocks = useMemo(() => parseBlocks(content), [content]);
  const inlineCtx = useMemo<InlineContext>(
    () => ({ currentPath, onOpenFile }),
    [currentPath, onOpenFile],
  );

  return (
    <article className="mx-auto max-w-4xl space-y-3 px-4 py-4 text-[14.5px] leading-[1.65] text-[#cbd5e8] sm:px-6">
      {blocks.map((block, idx) => {
        switch (block.kind) {
          case "heading": {
            const cls =
              block.level === 1
                ? "border-b border-white/[0.08] pb-2 text-[22px] font-semibold tracking-[-0.02em] text-[#f3f6fd]"
                : block.level === 2
                  ? "mt-4 border-b border-white/[0.06] pb-1.5 text-[18px] font-semibold tracking-[-0.015em] text-[#f3f6fd]"
                  : block.level === 3
                    ? "mt-3 text-[15.5px] font-semibold text-[#eef3fd]"
                    : "mt-3 text-[14px] font-semibold text-[#dce4f5]";
            const Tag = `h${block.level}` as "h1" | "h2" | "h3" | "h4";
            return (
              <Tag key={idx} id={`premier-md-h-${block.slug}`} className={cls}>
                {renderInline(block.text, inlineCtx, `h${idx}_`)}
              </Tag>
            );
          }

          case "code": {
            const lang = mapFenceLanguage(block.langTag);
            const codeLines = block.code.split(/\r?\n/);
            return (
              <div key={idx} className="pr-well overflow-hidden rounded-xl">
                <div className="flex items-center justify-between border-b border-white/[0.06] px-3.5 py-1 font-mono text-[12.5px] text-[#a6b5cf]">
                  <span>{block.langTag || (lang !== "plain" ? languageLabel(lang) : "")}</span>
                  <CopyCodeButton code={block.code} />
                </div>
                <pre className="overflow-x-auto px-4 py-3 font-mono text-[13.5px] leading-[1.65]">
                  {codeLines.map((ln, li) => (
                    <div key={li}>
                      {ln ? (
                        tokenizeLine(ln, lang).map((tok, ti) => (
                          <span key={ti} className={tokenClassName(tok.kind)}>
                            {tok.text}
                          </span>
                        ))
                      ) : (
                        " "
                      )}
                    </div>
                  ))}
                </pre>
              </div>
            );
          }

          case "hr":
            return <hr key={idx} className="my-5 border-0 border-t border-white/[0.08]" />;

          case "blockquote":
            return (
              <blockquote
                key={idx}
                className="space-y-1.5 rounded-r-xl border-l-2 border-[#7f95f8]/55 bg-white/[0.025] px-4 py-2.5 text-[#a9b7d0]"
              >
                {block.lines.map((ql, qi) => (
                  <p key={qi}>{renderInline(ql, inlineCtx, `q${idx}_${qi}_`)}</p>
                ))}
              </blockquote>
            );

          case "ul":
            return (
              <ul key={idx} className="list-disc space-y-1.5 pl-6 marker:text-[#7f95f8]">
                {block.items.map((item, ii) => {
                  const depth = Math.min(6, Math.floor(item.indent / 2));
                  return (
                    <li key={ii} style={depth > 0 ? { marginLeft: `${depth * 18}px` } : undefined}>
                      {renderInline(item.text, inlineCtx, `ul${idx}_${ii}_`)}
                    </li>
                  );
                })}
              </ul>
            );

          case "ol":
            return (
              <ol
                key={idx}
                start={block.start}
                className="list-decimal space-y-1.5 pl-6 marker:font-mono marker:text-[13.5px] marker:text-[#7f95f8]"
              >
                {block.items.map((item, ii) => {
                  const depth = Math.min(6, Math.floor(item.indent / 2));
                  return (
                    <li key={ii} style={depth > 0 ? { marginLeft: `${depth * 18}px` } : undefined}>
                      {renderInline(item.text, inlineCtx, `ol${idx}_${ii}_`)}
                    </li>
                  );
                })}
              </ol>
            );

          case "table":
            return (
              <div key={idx} className="pr-well overflow-x-auto rounded-xl">
                <table className="w-full border-collapse text-[14px]">
                  <thead>
                    <tr className="border-b border-white/[0.08] bg-white/[0.03] text-[#f3f6fd]">
                      {block.headers.map((cell, ci) => (
                        <th
                          key={ci}
                          scope="col"
                          className={`px-3.5 py-2 font-semibold ${
                            ALIGN_CLASS[block.alignments[ci] ?? "left"]
                          }`}
                        >
                          {renderInline(cell, inlineCtx, `th${idx}_${ci}_`)}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-white/[0.05]">
                    {block.rows.map((row, ri) => (
                      <tr key={ri} className="hover:bg-white/[0.02]">
                        {block.headers.map((_, ci) => (
                          <td
                            key={ci}
                            className={`px-3.5 py-2 text-[#cbd5e8] ${
                              ALIGN_CLASS[block.alignments[ci] ?? "left"]
                            }`}
                          >
                            {renderInline(row[ci] ?? "", inlineCtx, `td${idx}_${ri}_${ci}_`)}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );

          case "paragraph":
            return (
              <p key={idx} className="leading-[1.72]">
                {renderInline(block.text, inlineCtx, `p${idx}_`)}
              </p>
            );
        }
      })}
    </article>
  );
});
