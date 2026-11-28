import { describe, expect, it } from "vitest";
import {
  detectLanguage,
  formatByteSize,
  languageLabel,
  parseUnifiedPatch,
  tokenClassName,
  tokenizeLine,
  type SourceLanguage,
  type TokenKind,
} from "../lib/highlight";

describe("detectLanguage", () => {
  it("detects supported source and config languages", () => {
    expect(detectLanguage("src/main.rs")).toBe("rust");
    expect(detectLanguage("src/App.tsx")).toBe("typescript");
    expect(detectLanguage("src/api.ts")).toBe("typescript");
    expect(detectLanguage("scripts/run.js")).toBe("typescript");
    expect(detectLanguage("scripts/view.jsx")).toBe("typescript");
    expect(detectLanguage("scripts/mod.mjs")).toBe("typescript");
    expect(detectLanguage(".access.toml")).toBe("toml");
    expect(detectLanguage(".env.schema")).toBe("toml");
    expect(detectLanguage("Cargo.lock")).toBe("toml");
    expect(detectLanguage("package.json")).toBe("json");
    expect(detectLanguage("README.md")).toBe("markdown");
    expect(detectLanguage("docs/page.mdx")).toBe("markdown");
    expect(detectLanguage("src/index.css")).toBe("css");
    expect(detectLanguage("deploy.sh")).toBe("shell");
    expect(detectLanguage(".github/workflows/ci.yml")).toBe("shell");
    expect(detectLanguage("config.yaml")).toBe("shell");
  });

  it("is case-insensitive and falls back to plain", () => {
    expect(detectLanguage("CRATES/LIB.RS")).toBe("rust");
    expect(detectLanguage("CONFIG.JSON")).toBe("json");
    expect(detectLanguage("LICENSE")).toBe("plain");
    expect(detectLanguage("archive.bin")).toBe("plain");
  });
});

describe("languageLabel", () => {
  it("returns the human label for every SourceLanguage", () => {
    const expected: Record<SourceLanguage, string> = {
      rust: "Rust",
      typescript: "TypeScript",
      toml: "TOML",
      json: "JSON",
      markdown: "Markdown",
      css: "CSS",
      shell: "Config",
      plain: "Text",
    };

    for (const [lang, label] of Object.entries(expected) as Array<[SourceLanguage, string]>) {
      expect(languageLabel(lang)).toBe(label);
    }
  });
});

describe("formatByteSize", () => {
  it("formats bytes, kilobytes, and megabytes", () => {
    expect(formatByteSize(0)).toBe("0 B");
    expect(formatByteSize(42)).toBe("42 B");
    expect(formatByteSize(1023)).toBe("1023 B");
    expect(formatByteSize(1024)).toBe("1.0 KB");
    expect(formatByteSize(1536)).toBe("1.5 KB");
    expect(formatByteSize(1024 * 1024)).toBe("1.0 MB");
    expect(formatByteSize(2.5 * 1024 * 1024)).toBe("2.5 MB");
  });
});

describe("parseUnifiedPatch", () => {
  it("classifies diff headers outside hunks as meta and tracks multi-hunk line numbers", () => {
    const patch = [
      "diff --git a/src/lib.rs b/src/lib.rs",
      "index 1111111..2222222 100644",
      "--- a/src/lib.rs",
      "+++ b/src/lib.rs",
      "@@ -1,3 +1,3 @@",
      " fn a() {}",
      "-let old = 1;",
      "+let next = 2;",
      " fn b() {}",
      "@@ -20,2 +20,3 @@",
      " fn c() {",
      "+  run();",
      " }",
    ].join("\n");

    const parsed = parseUnifiedPatch(patch);
    expect(parsed.additions).toBe(2);
    expect(parsed.deletions).toBe(1);

    // Header lines outside hunks are meta
    expect(parsed.lines.slice(0, 4).map((l) => l.kind)).toEqual(["meta", "meta", "meta", "meta"]);
    expect(parsed.lines[4]).toMatchObject({ kind: "hunk", sigil: "@@", oldLine: null, newLine: null });

    // First hunk body
    expect(parsed.lines[5]).toMatchObject({ kind: "ctx", oldLine: 1, newLine: 1, body: "fn a() {}" });
    expect(parsed.lines[6]).toMatchObject({ kind: "del", oldLine: 2, newLine: null, body: "let old = 1;" });
    expect(parsed.lines[7]).toMatchObject({ kind: "add", oldLine: null, newLine: 2, body: "let next = 2;" });
    expect(parsed.lines[8]).toMatchObject({ kind: "ctx", oldLine: 3, newLine: 3, body: "fn b() {}" });

    // Second hunk resets line numbers
    expect(parsed.lines[9]).toMatchObject({ kind: "hunk", sigil: "@@" });
    expect(parsed.lines[10]).toMatchObject({ kind: "ctx", oldLine: 20, newLine: 20 });
    expect(parsed.lines[11]).toMatchObject({ kind: "add", oldLine: null, newLine: 21, body: "  run();" });
    expect(parsed.lines[12]).toMatchObject({ kind: "ctx", oldLine: 21, newLine: 22 });
  });

  it("classifies hunk body lines starting with '--- ' and '+++ ' as del/add (never meta)", () => {
    const patch = [
      "diff --git a/notes.sql b/notes.sql",
      "--- a/notes.sql",
      "+++ b/notes.sql",
      "@@ -10,2 +10,2 @@",
      "--- removed SQL comment",
      "+++ added prefix line",
      " SELECT 1;",
    ].join("\n");

    const parsed = parseUnifiedPatch(patch);
    expect(parsed.additions).toBe(1);
    expect(parsed.deletions).toBe(1);

    const headerMinus = parsed.lines[1];
    const headerPlus = parsed.lines[2];
    expect(headerMinus).toMatchObject({ kind: "meta", body: "--- a/notes.sql" });
    expect(headerPlus).toMatchObject({ kind: "meta", body: "+++ b/notes.sql" });

    const bodyDel = parsed.lines[4];
    const bodyAdd = parsed.lines[5];
    expect(bodyDel).toMatchObject({
      kind: "del",
      sigil: "-",
      oldLine: 10,
      newLine: null,
      body: "-- removed SQL comment",
    });
    expect(bodyAdd).toMatchObject({
      kind: "add",
      sigil: "+",
      oldLine: null,
      newLine: 10,
      body: "++ added prefix line",
    });
  });

  it("resets hunk state on subsequent diff --git headers in multi-file patches", () => {
    const patch = [
      "diff --git a/a.txt b/a.txt",
      "--- a/a.txt",
      "+++ b/a.txt",
      "@@ -1,1 +1,1 @@",
      "-a",
      "+b",
      "diff --git a/b.txt b/b.txt",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/b.txt",
      "@@ -0,0 +1,1 @@",
      "+hello",
    ].join("\n");

    const parsed = parseUnifiedPatch(patch);
    expect(parsed.additions).toBe(2);
    expect(parsed.deletions).toBe(1);

    const secondFileHeaders = parsed.lines.slice(6, 10);
    expect(secondFileHeaders.map((l) => l.kind)).toEqual(["meta", "meta", "meta", "meta"]);
    expect(parsed.lines[11]).toMatchObject({ kind: "add", newLine: 1, body: "hello" });
  });
});

describe("tokenizeLine", () => {
  it("tokenizes Rust attributes, keywords, types, functions, strings, numbers, and comments", () => {
    expect(tokenizeLine("#[derive(Debug)]", "rust")).toEqual([
      { kind: "attr", text: "#[derive(Debug)]" },
    ]);

    const line = 'pub fn check(n: usize) -> Option<String> { let x = 0xff; println!("ok"); // done';
    const tokens = tokenizeLine(line, "rust");
    expect(tokens.map((t) => t.text).join("")).toBe(line);

    expect(tokens).toContainEqual({ kind: "kw", text: "pub" });
    expect(tokens).toContainEqual({ kind: "kw", text: "fn" });
    expect(tokens).toContainEqual({ kind: "fn", text: "check" });
    expect(tokens).toContainEqual({ kind: "type", text: "usize" });
    expect(tokens).toContainEqual({ kind: "type", text: "Option" });
    expect(tokens).toContainEqual({ kind: "type", text: "String" });
    expect(tokens).toContainEqual({ kind: "kw", text: "let" });
    expect(tokens).toContainEqual({ kind: "num", text: "0xff" });
    expect(tokens).toContainEqual({ kind: "fn", text: "println" });
    expect(tokens).toContainEqual({ kind: "str", text: '"ok"' });
    expect(tokens).toContainEqual({ kind: "comment", text: "// done" });
  });

  it("tokenizes TypeScript keywords, types, template/quoted strings, numbers, and comments", () => {
    const line = "export const count: number = 42; // `msg`";
    const tokens = tokenizeLine(line, "typescript");
    expect(tokens.map((t) => t.text).join("")).toBe(line);

    expect(tokens).toContainEqual({ kind: "kw", text: "export" });
    expect(tokens).toContainEqual({ kind: "kw", text: "const" });
    expect(tokens).toContainEqual({ kind: "type", text: "number" });
    expect(tokens).toContainEqual({ kind: "num", text: "42" });
    expect(tokens).toContainEqual({ kind: "comment", text: "// `msg`" });

    const strLine = 'const s = "a\\"b" + `tpl` + \'c\';';
    const strTokens = tokenizeLine(strLine, "typescript");
    expect(strTokens.map((t) => t.text).join("")).toBe(strLine);
    expect(strTokens.filter((t) => t.kind === "str").map((t) => t.text)).toEqual([
      '"a\\"b"',
      "`tpl`",
      "'c'",
    ]);
  });

  it("tokenizes TOML comments, headers, keys, booleans, strings, and numbers", () => {
    expect(tokenizeLine("  # comment", "toml")).toEqual([{ kind: "comment", text: "  # comment" }]);
    expect(tokenizeLine("[zones.billing]", "toml")).toEqual([
      { kind: "attr", text: "[zones.billing]" },
    ]);

    const kvLine = 'enabled = true # inline';
    const kvTokens = tokenizeLine(kvLine, "toml");
    expect(kvTokens.map((t) => t.text).join("")).toBe(kvLine);
    expect(kvTokens).toContainEqual({ kind: "fn", text: "enabled " });
    expect(kvTokens).toContainEqual({ kind: "op", text: "=" });
    expect(kvTokens).toContainEqual({ kind: "kw", text: "true" });
    expect(kvTokens).toContainEqual({ kind: "comment", text: "# inline" });

    const strKv = 'effect = "deny"';
    const strTokens = tokenizeLine(strKv, "toml");
    expect(strTokens).toContainEqual({ kind: "str", text: '"deny"' });

    const numKv = "version = 1";
    const numTokens = tokenizeLine(numKv, "toml");
    expect(numTokens).toContainEqual({ kind: "num", text: "1" });
  });

  it("tokenizes JSON keys distinctly from string values, booleans, null, and numbers", () => {
    const line = '{"ok": true, "msg": "hello", "err": null, "count": 3.14}';
    const tokens = tokenizeLine(line, "json");
    expect(tokens.map((t) => t.text).join("")).toBe(line);

    expect(tokens).toContainEqual({ kind: "fn", text: '"ok"' });
    expect(tokens).toContainEqual({ kind: "fn", text: '"msg"' });
    expect(tokens).toContainEqual({ kind: "str", text: '"hello"' });
    expect(tokens).toContainEqual({ kind: "kw", text: "true" });
    expect(tokens).toContainEqual({ kind: "kw", text: "null" });
    expect(tokens).toContainEqual({ kind: "num", text: "3.14" });
  });

  it("tokenizes shell commands, flags, env vars, and quoted strings", () => {
    const line = 'curl -fsSL -X POST "$PREMIER_URL/api/v1/traces/hook" --data \'{"ok":true}\'';
    const tokens = tokenizeLine(line, "shell");
    expect(tokens.map((t) => t.text).join("")).toBe(line);

    expect(tokens).toContainEqual({ kind: "kw", text: "curl" });
    expect(tokens).toContainEqual({ kind: "attr", text: "-fsSL" });
    expect(tokens).toContainEqual({ kind: "kw", text: "POST" });
    expect(tokens).toContainEqual({ kind: "attr", text: "--data" });
    expect(tokens).toContainEqual({ kind: "str", text: '"$PREMIER_URL/api/v1/traces/hook"' });
  });

  it("handles empty lines, plain text, and returns class names for all token kinds", () => {
    expect(tokenizeLine("", "rust")).toEqual([{ kind: "plain", text: "" }]);
    expect(tokenizeLine("just text", "plain")).toEqual([{ kind: "plain", text: "just text" }]);

    const kinds: TokenKind[] = [
      "plain",
      "kw",
      "type",
      "fn",
      "str",
      "num",
      "comment",
      "attr",
      "op",
      "punct",
    ];
    for (const kind of kinds) {
      expect(tokenClassName(kind).length).toBeGreaterThan(0);
    }
  });
});
