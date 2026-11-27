/**
 * Zero-dependency pure-TS obsidian syntax tokenizer & unified diff parser.
 */

export type TokenKind =
  | "plain"
  | "kw"
  | "type"
  | "fn"
  | "str"
  | "num"
  | "comment"
  | "attr"
  | "op"
  | "punct";

export interface SyntaxToken {
  kind: TokenKind;
  text: string;
}

export type SourceLanguage =
  | "rust"
  | "typescript"
  | "toml"
  | "json"
  | "markdown"
  | "css"
  | "shell"
  | "plain";

export function detectLanguage(path: string): SourceLanguage {
  const lower = path.toLowerCase();
  if (lower.endsWith(".rs")) return "rust";
  if (
    lower.endsWith(".ts") ||
    lower.endsWith(".tsx") ||
    lower.endsWith(".js") ||
    lower.endsWith(".jsx") ||
    lower.endsWith(".mjs")
  ) {
    return "typescript";
  }
  if (lower.endsWith(".toml") || lower.endsWith(".env.schema") || lower.endsWith("cargo.lock")) {
    return "toml";
  }
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".md") || lower.endsWith(".mdx")) return "markdown";
  if (lower.endsWith(".css")) return "css";
  if (lower.endsWith(".sh") || lower.endsWith(".yml") || lower.endsWith(".yaml")) return "shell";
  return "plain";
}

export function languageLabel(lang: SourceLanguage): string {
  switch (lang) {
    case "rust":
      return "Rust";
    case "typescript":
      return "TypeScript";
    case "toml":
      return "TOML";
    case "json":
      return "JSON";
    case "markdown":
      return "Markdown";
    case "css":
      return "CSS";
    case "shell":
      return "Config";
    case "plain":
      return "Text";
  }
}

const RUST_KW = new Set([
  "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
  "extern", "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod",
  "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
  "trait", "true", "type", "unsafe", "use", "where", "while",
]);

const TS_KW = new Set([
  "as", "async", "await", "break", "case", "catch", "class", "const", "continue",
  "default", "delete", "do", "else", "enum", "export", "extends", "false", "finally",
  "for", "from", "function", "if", "implements", "import", "in", "instanceof",
  "interface", "let", "new", "null", "of", "private", "protected", "public", "readonly",
  "return", "static", "super", "switch", "this", "throw", "true", "try", "type",
  "typeof", "undefined", "var", "void", "while", "yield",
]);

const RUST_TYPES = new Set([
  "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16",
  "i32", "i64", "i128", "isize", "f32", "f64", "String", "Vec", "Option", "Result",
  "Arc", "Box", "BTreeMap", "BTreeSet", "HashMap", "HashSet", "Path", "PathBuf",
]);

const TS_TYPES = new Set([
  "string", "number", "boolean", "unknown", "never", "any", "object", "Record",
  "Partial", "Pick", "Omit", "Promise", "Array", "Set", "Map", "HTMLElement",
]);

export function tokenizeLine(line: string, lang: SourceLanguage): SyntaxToken[] {
  if (!line || lang === "plain") {
    return [{ kind: "plain", text: line }];
  }

  if (lang === "markdown") {
    if (/^\s*#{1,6}\s/.test(line)) return [{ kind: "kw", text: line }];
    if (/^\s*```/.test(line)) return [{ kind: "attr", text: line }];
    if (/^\s*>\s/.test(line)) return [{ kind: "comment", text: line }];
    if (/^\s*[-*+]\s/.test(line)) {
      const m = line.match(/^(\s*[-*+]\s)(.*)$/);
      if (m) return [{ kind: "op", text: m[1] }, { kind: "plain", text: m[2] }];
    }
    return [{ kind: "plain", text: line }];
  }

  if (lang === "toml") {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("#")) return [{ kind: "comment", text: line }];
    if (trimmed.startsWith("[")) return [{ kind: "attr", text: line }];
    const eqIdx = line.indexOf("=");
    if (eqIdx > 0) {
      const left = line.slice(0, eqIdx);
      const right = line.slice(eqIdx + 1);
      return [
        { kind: "fn", text: left },
        { kind: "op", text: "=" },
        ...tokenizeCodeExpr(right, new Set(["true", "false"]), new Set(), "#"),
      ];
    }
    return [{ kind: "plain", text: line }];
  }

  if (lang === "json") {
    return tokenizeJsonLine(line);
  }

  if (lang === "css") {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("/*") || trimmed.startsWith("*") || trimmed.startsWith("//")) {
      return [{ kind: "comment", text: line }];
    }
    if (trimmed.startsWith("@")) return [{ kind: "kw", text: line }];
    return tokenizeCodeExpr(line, new Set(), new Set(), null);
  }

  if (lang === "shell") {
    return tokenizeShellLine(line);
  }

  if (lang === "rust") {
    const trimmed = line.trimStart();
    if (trimmed.startsWith("#[") || trimmed.startsWith("#![")) {
      return [{ kind: "attr", text: line }];
    }
    return tokenizeCodeExpr(line, RUST_KW, RUST_TYPES, "//");
  }

  return tokenizeCodeExpr(line, TS_KW, TS_TYPES, "//");
}

function tokenizeCodeExpr(
  line: string,
  keywords: Set<string>,
  types: Set<string>,
  commentPrefix: string | null,
): SyntaxToken[] {
  const out: SyntaxToken[] = [];
  let i = 0;
  const n = line.length;

  const push = (kind: TokenKind, text: string) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.kind === kind) {
      last.text += text;
    } else {
      out.push({ kind, text });
    }
  };

  while (i < n) {
    if (commentPrefix && line.startsWith(commentPrefix, i)) {
      push("comment", line.slice(i));
      break;
    }

    const ch = line[i];

    // Strings
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      let j = i + 1;
      while (j < n) {
        if (line[j] === "\\") {
          j += 2;
          continue;
        }
        if (line[j] === quote) {
          j += 1;
          break;
        }
        j += 1;
      }
      push("str", line.slice(i, j));
      i = j;
      continue;
    }

    // Numbers
    if (ch >= "0" && ch <= "9" && (i === 0 || !/[A-Za-z0-9_$]/.test(line[i - 1]))) {
      let j = i + 1;
      while (j < n && /[0-9a-fA-FxXbBoO._]/.test(line[j])) j += 1;
      push("num", line.slice(i, j));
      i = j;
      continue;
    }

    // Identifiers
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_$]/.test(line[j])) j += 1;
      const word = line.slice(i, j);
      const nextCh = line[j];

      if (keywords.has(word)) {
        push("kw", word);
      } else if (types.has(word) || (/^[A-Z][A-Za-z0-9_]*$/.test(word) && word.length > 1)) {
        push("type", word);
      } else if (nextCh === "(" || nextCh === "!") {
        push("fn", word);
      } else {
        push("plain", word);
      }
      i = j;
      continue;
    }

    // Operators / punctuation
    if (/[=<>!+\-*/%&|^~?:]/.test(ch)) {
      push("op", ch);
      i += 1;
      continue;
    }
    if (/[{}()[\].,;]/.test(ch)) {
      push("punct", ch);
      i += 1;
      continue;
    }

    push("plain", ch);
    i += 1;
  }

  return out;
}

const SHELL_CMDS = new Set([
  "curl",
  "git",
  "cargo",
  "pnpm",
  "npm",
  "npx",
  "node",
  "premier",
  "sh",
  "bash",
  "export",
  "cd",
  "echo",
  "cat",
  "docker",
  "ssh",
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
]);

function tokenizeJsonLine(line: string): SyntaxToken[] {
  const tokens = tokenizeCodeExpr(line, new Set(["true", "false", "null"]), new Set(), null);
  // Distinguish JSON property keys (`"key":`) from string values for much cleaner visual scanning.
  for (let i = 0; i < tokens.length; i += 1) {
    if (tokens[i].kind !== "str") continue;
    let nextIdx = i + 1;
    while (nextIdx < tokens.length && tokens[nextIdx].kind === "plain" && /^\s+$/.test(tokens[nextIdx].text)) {
      nextIdx += 1;
    }
    if (nextIdx < tokens.length && tokens[nextIdx].kind === "op" && tokens[nextIdx].text.startsWith(":")) {
      tokens[i] = { kind: "fn", text: tokens[i].text };
    }
  }
  return tokens;
}

function tokenizeShellLine(line: string): SyntaxToken[] {
  const trimmed = line.trimStart();
  if (trimmed.startsWith("#")) return [{ kind: "comment", text: line }];

  const out: SyntaxToken[] = [];
  let i = 0;
  const n = line.length;
  const push = (kind: TokenKind, text: string) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.kind === kind) last.text += text;
    else out.push({ kind, text });
  };

  while (i < n) {
    const ch = line[i];
    if (ch === "#" && (i === 0 || /\s/.test(line[i - 1]))) {
      push("comment", line.slice(i));
      break;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      const quote = ch;
      let j = i + 1;
      while (j < n) {
        if (quote !== "'" && line[j] === "\\") {
          j += 2;
          continue;
        }
        if (line[j] === quote) {
          j += 1;
          break;
        }
        j += 1;
      }
      push("str", line.slice(i, j));
      i = j;
      continue;
    }
    if (ch === "$") {
      let j = i + 1;
      if (line[j] === "{") {
        while (j < n && line[j] !== "}") j += 1;
        if (j < n) j += 1;
      } else {
        while (j < n && /[A-Za-z0-9_?]/.test(line[j])) j += 1;
      }
      push("type", line.slice(i, j));
      i = j;
      continue;
    }
    if (
      (line.startsWith("https://", i) || line.startsWith("http://", i)) &&
      (i === 0 || /[\s=([,]/.test(line[i - 1]))
    ) {
      let j = i;
      while (j < n && !/[\s"'`)]/.test(line[j])) j += 1;
      push("str", line.slice(i, j));
      i = j;
      continue;
    }
    if (ch === "-" && (i === 0 || /\s/.test(line[i - 1])) && i + 1 < n && /[A-Za-z-]/.test(line[i + 1])) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_-]/.test(line[j])) j += 1;
      push("attr", line.slice(i, j));
      i = j;
      continue;
    }
    if (ch === "|" || ch === "&" || ch === ">" || ch === "<" || ch === "\\" || ch === "=") {
      push("op", ch);
      i += 1;
      continue;
    }
    if (/[A-Za-z_/.]/.test(ch)) {
      let j = i + 1;
      while (j < n && /[A-Za-z0-9_./:-]/.test(line[j])) j += 1;
      const word = line.slice(i, j);
      if (SHELL_CMDS.has(word)) {
        push("kw", word);
      } else if (word === "true" || word === "false") {
        push("kw", word);
      } else {
        push("plain", word);
      }
      i = j;
      continue;
    }
    if (ch >= "0" && ch <= "9" && (i === 0 || !/[A-Za-z0-9_]/.test(line[i - 1]))) {
      let j = i + 1;
      while (j < n && /[0-9.]/.test(line[j])) j += 1;
      push("num", line.slice(i, j));
      i = j;
      continue;
    }
    push("plain", ch);
    i += 1;
  }

  return out;
}

export function tokenClassName(kind: TokenKind): string {
  switch (kind) {
    case "kw":
      return "text-[var(--pr-syn-kw)]";
    case "type":
      return "text-[var(--pr-syn-type)]";
    case "fn":
      return "text-[var(--pr-syn-fn)]";
    case "str":
      return "text-[var(--pr-syn-str)]";
    case "num":
      return "text-[var(--pr-syn-num)]";
    case "comment":
      return "text-[var(--pr-syn-comment)] italic";
    case "attr":
      return "text-[var(--pr-syn-attr)]";
    case "op":
      return "text-[var(--pr-syn-op)]";
    case "punct":
      return "text-[var(--pr-syn-punct)]";
    case "plain":
      return "text-[#dce4f5]";
  }
}

export interface ParsedDiffLine {
  kind: "meta" | "hunk" | "add" | "del" | "ctx";
  oldLine: number | null;
  newLine: number | null;
  sigil: string;
  body: string;
}

export interface ParsedPatch {
  additions: number;
  deletions: number;
  lines: ParsedDiffLine[];
}

export function parseUnifiedPatch(patch: string): ParsedPatch {
  const rawLines = patch.split(/\r?\n/);
  const lines: ParsedDiffLine[] = [];
  let oldNum = 0;
  let newNum = 0;
  let additions = 0;
  let deletions = 0;
  let inHunk = false;

  for (const raw of rawLines) {
    if (raw.startsWith("diff --git")) {
      inHunk = false;
      lines.push({ kind: "meta", oldLine: null, newLine: null, sigil: "", body: raw });
      continue;
    }
    if (
      !inHunk &&
      (raw.startsWith("index ") ||
        raw.startsWith("--- ") ||
        raw.startsWith("+++ ") ||
        raw.startsWith("new file mode") ||
        raw.startsWith("deleted file mode") ||
        raw.startsWith("old mode") ||
        raw.startsWith("new mode") ||
        raw.startsWith("rename ") ||
        raw.startsWith("similarity "))
    ) {
      lines.push({ kind: "meta", oldLine: null, newLine: null, sigil: "", body: raw });
      continue;
    }
    if (raw.startsWith("@@")) {
      inHunk = true;
      const m = raw.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (m) {
        oldNum = Number(m[1]);
        newNum = Number(m[2]);
      }
      inHunk = true;
      lines.push({ kind: "hunk", oldLine: null, newLine: null, sigil: "@@", body: raw });
      continue;
    }
    if (inHunk && raw.startsWith("+")) {
      additions += 1;
      lines.push({
        kind: "add",
        oldLine: null,
        newLine: newNum++,
        sigil: "+",
        body: raw.slice(1),
      });
      continue;
    }
    if (inHunk && raw.startsWith("-")) {
      deletions += 1;
      lines.push({
        kind: "del",
        oldLine: oldNum++,
        newLine: null,
        sigil: "-",
        body: raw.slice(1),
      });
      continue;
    }
    if (inHunk && raw.startsWith(" ")) {
      lines.push({
        kind: "ctx",
        oldLine: oldNum++,
        newLine: newNum++,
        sigil: " ",
        body: raw.slice(1),
      });
      continue;
    }
    if (raw.length > 0) {
      lines.push({ kind: "meta", oldLine: null, newLine: null, sigil: "", body: raw });
    }
  }

  return { additions, deletions, lines };
}

export function formatByteSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
