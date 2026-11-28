import { describe, expect, it } from "vitest";
import {
  PREMIER_ACCESS_TOML_LANGUAGE,
  monacoLanguageForPath,
  unifiedPatchToSides,
  validateAccessToml,
} from "../lib/monaco";

interface NodeFsSubset {
  readFileSync(path: URL, encoding: "utf8"): string;
}

async function readRepoFile(repoRelativePath: string): Promise<string> {
  const fsSpecifier: string = "node:fs";
  const fs = (await import(/* @vite-ignore */ fsSpecifier)) as NodeFsSubset;
  const fileUrl = new URL(`../../../../${repoRelativePath}`, import.meta.url);
  return fs.readFileSync(fileUrl, "utf8");
}

describe("monacoLanguageForPath", () => {
  it("maps Premier access policy filenames with highest precedence", () => {
    expect(monacoLanguageForPath(".access.toml")).toBe(PREMIER_ACCESS_TOML_LANGUAGE);
    expect(monacoLanguageForPath(".access.server.toml")).toBe(PREMIER_ACCESS_TOML_LANGUAGE);
    expect(monacoLanguageForPath("server-policy.toml")).toBe(PREMIER_ACCESS_TOML_LANGUAGE);
    expect(monacoLanguageForPath("fixtures/demo/.access.toml")).toBe(PREMIER_ACCESS_TOML_LANGUAGE);
    expect(monacoLanguageForPath("configs\\prod\\server-policy.toml")).toBe(
      PREMIER_ACCESS_TOML_LANGUAGE,
    );
    expect(monacoLanguageForPath("custom-access.toml")).toBe(PREMIER_ACCESS_TOML_LANGUAGE);
  });

  it("maps special config and build filenames", () => {
    expect(monacoLanguageForPath(".env.schema")).toBe("toml");
    expect(monacoLanguageForPath("apps/web/.env.schema")).toBe("toml");
    expect(monacoLanguageForPath("Cargo.toml")).toBe("toml");
    expect(monacoLanguageForPath("Cargo.lock")).toBe("toml");
    expect(monacoLanguageForPath("Dockerfile")).toBe("dockerfile");
    expect(monacoLanguageForPath("Dockerfile.prod")).toBe("dockerfile");
    expect(monacoLanguageForPath("docker/app.dockerfile")).toBe("dockerfile");
    expect(monacoLanguageForPath("Caddyfile")).toBe("shell");
    expect(monacoLanguageForPath("Caddyfile.staging")).toBe("shell");
    expect(monacoLanguageForPath("Makefile")).toBe("shell");
    expect(monacoLanguageForPath("GNUmakefile")).toBe("shell");
    expect(monacoLanguageForPath(".env")).toBe("ini");
    expect(monacoLanguageForPath(".env.local")).toBe("ini");
  });

  it("maps all major source code and document extensions", () => {
    const cases: Array<[string, string]> = [
      ["src/App.tsx", "typescript"],
      ["src/lib/monaco.ts", "typescript"],
      ["scripts/build.mts", "typescript"],
      ["scripts/cjs.cts", "typescript"],
      ["src/Widget.jsx", "javascript"],
      ["src/index.js", "javascript"],
      ["src/esm.mjs", "javascript"],
      ["src/common.cjs", "javascript"],
      ["crates/premier-server/src/main.rs", "rust"],
      ["scripts/audit.py", "python"],
      ["cmd/proxy/main.go", "go"],
      ["scripts/deploy.sh", "shell"],
      ["scripts/env.bash", "shell"],
      ["scripts/prompt.zsh", "shell"],
      ["scripts/setup.ps1", "powershell"],
      ["migrations/001_init.sql", "sql"],
      ["docs/architecture.md", "markdown"],
      ["docs/guide.mdx", "markdown"],
      ["package.json", "json"],
      ["tsconfig.jsonc", "json"],
      [".github/workflows/ci.yml", "yaml"],
      ["docker-compose.yaml", "yaml"],
      ["styles/theme.css", "css"],
      ["styles/base.scss", "css"],
      ["styles/old.less", "css"],
      ["index.html", "html"],
      ["assets/logo.svg", "html"],
      ["pom.xml", "xml"],
      ["native/shim.c", "c"],
      ["native/shim.h", "c"],
      ["native/engine.cpp", "cpp"],
      ["native/engine.hpp", "cpp"],
      ["Main.java", "java"],
      ["Rakefile.rb", "ruby"],
      ["index.php", "php"],
      ["app.ini", "ini"],
      ["nginx.conf", "ini"],
    ];

    for (const [path, expected] of cases) {
      expect(monacoLanguageForPath(path), path).toBe(expected);
    }
  });

  it("handles uppercase paths and falls back to plaintext for unknown or empty paths", () => {
    expect(monacoLanguageForPath("SRC/MAIN.RS")).toBe("rust");
    expect(monacoLanguageForPath("DOCKERFILE")).toBe("dockerfile");
    expect(monacoLanguageForPath("README")).toBe("plaintext");
    expect(monacoLanguageForPath("notes.unknownext")).toBe("plaintext");
    expect(monacoLanguageForPath("")).toBe("plaintext");
    expect(monacoLanguageForPath(undefined)).toBe("plaintext");
  });
});

describe("validateAccessToml", () => {
  it("produces zero false positives on real fixtures/demo/.access.toml", async () => {
    const content = await readRepoFile("fixtures/demo/.access.toml");
    expect(content.trim().length).toBeGreaterThan(0);
    expect(validateAccessToml(content)).toEqual([]);
  });

  it("produces zero false positives on real fixtures/demo/server-policy.toml", async () => {
    const content = await readRepoFile("fixtures/demo/server-policy.toml");
    expect(content.trim().length).toBeGreaterThan(0);
    expect(validateAccessToml(content)).toEqual([]);
  });

  it("allows multiline arrays, quoted table headers, and triple-quoted strings without false positives", () => {
    const policy = [
      "version = 1",
      "",
      "[defaults]",
      'public = ["traverse", "list", "read"]',
      'authenticated = ["traverse", "list", "read"]',
      "",
      '[zones."billing.v2"]',
      "paths = [",
      '  "billing/**", # primary billing subtree',
      '  "payments/v2/**",',
      "]",
      'description = """',
      'Multiline basic string with [not a section] and "inner quotes" and # hashes',
      '"""',
      "",
      "[zones.'ops.literal']",
      "paths = ['ops/**']",
      "description = '''",
      "Literal multiline string with [fake], 'single quotes', and C:\\raw\\path",
      "'''",
      "",
      "[[rules]]",
      'id = "multiline-valid"',
      'effect = "allow"',
      "principals = [",
      '  "group:billing",',
      '  "@alice",',
      "]",
      "capabilities = [",
      '  "traverse",',
      '  "list",',
      '  "read",',
      '  "write",',
      '  "use",',
      '  "none",',
      "]",
      'reason = """inline triple double"""',
      "notes = '''inline triple single'''",
    ].join("\n");

    expect(validateAccessToml(policy)).toEqual([]);
  });

  it("detects invalid effect values", () => {
    const policy = [
      "[[rules]]",
      'id = "bad-effect"',
      'effect = "permit"',
      'principals = ["*"]',
    ].join("\n");

    const markers = validateAccessToml(policy);
    expect(markers).toHaveLength(1);
    expect(markers[0].severity).toBe("error");
    expect(markers[0].startLineNumber).toBe(3);
    expect(markers[0].message).toMatch(/Invalid effect/i);
  });

  it("detects unknown capabilities in inline arrays, multiline arrays, and [defaults]", () => {
    const policy = [
      "[defaults]",
      'public = ["read", "superuser"]',
      "",
      "[[rules]]",
      'id = "bad-caps"',
      'effect = "allow"',
      'capabilities = ["traverse", "admin"]',
      "",
      "[[rules]]",
      'id = "bad-caps-multiline"',
      'effect = "deny"',
      "capabilities = [",
      '  "write",',
      '  "execute",',
      "]",
    ].join("\n");

    const markers = validateAccessToml(policy);
    expect(markers).toHaveLength(3);
    expect(markers.map((m) => m.startLineNumber)).toEqual([2, 7, 14]);
    expect(markers[0].message).toContain('"superuser"');
    expect(markers[1].message).toContain('"admin"');
    expect(markers[2].message).toContain('"execute"');
    for (const m of markers) {
      expect(m.severity).toBe("error");
    }
  });

  it("detects '..' path traversal segments across path keys", () => {
    const policy = [
      "[[rules]]",
      'id = "traversal-array"',
      'effect = "allow"',
      'paths = ["billing/../secrets/**"]',
      'exclude = ["../outside"]',
      'allow_paths = ["safe\\\\..\\\\escape"]',
      'deny_paths = "../scalar"',
    ].join("\n");

    const markers = validateAccessToml(policy);
    expect(markers).toHaveLength(4);
    expect(markers.map((m) => m.startLineNumber)).toEqual([4, 5, 6, 7]);
    for (const m of markers) {
      expect(m.severity).toBe("error");
      expect(m.message).toContain('".."');
    }
  });

  it("detects unclosed quotes, unclosed multiline strings, and unbalanced brackets", () => {
    const unclosedDouble = validateAccessToml('reason = "never closed');
    expect(unclosedDouble).toHaveLength(1);
    expect(unclosedDouble[0].message).toMatch(/Unclosed double-quoted/i);

    const unclosedSingle = validateAccessToml("reason = 'never closed");
    expect(unclosedSingle).toHaveLength(1);
    expect(unclosedSingle[0].message).toMatch(/Unclosed single-quoted/i);

    const unclosedTriple = validateAccessToml('description = """\nstill open');
    expect(unclosedTriple).toHaveLength(1);
    expect(unclosedTriple[0].message).toMatch(/Unclosed multi-line string/i);

    const unclosedBracket = validateAccessToml('paths = [\n  "billing/**"');
    expect(unclosedBracket).toHaveLength(1);
    expect(unclosedBracket[0].startLineNumber).toBe(1);
    expect(unclosedBracket[0].message).toMatch(/Unclosed array bracket/i);

    const extraClose = validateAccessToml('paths = ["billing/**"]]');
    expect(extraClose).toHaveLength(1);
    expect(extraClose[0].message).toMatch(/Unexpected closing bracket/i);
  });

  it("detects malformed table and array-of-tables headers", () => {
    const policy = ["[zones.", "[[rules]", "[bad header]"].join("\n");
    const markers = validateAccessToml(policy);
    expect(markers).toHaveLength(3);
    expect(markers.map((m) => m.startLineNumber)).toEqual([1, 2, 3]);
    expect(markers[0].message).toMatch(/Malformed table section header/i);
    expect(markers[1].message).toMatch(/Malformed array-of-tables header/i);
    expect(markers[2].message).toMatch(/Malformed table section header/i);
  });

  it("warns on duplicate [[rules]] ids", () => {
    const policy = [
      "[[rules]]",
      'id = "dup-rule"',
      'effect = "deny"',
      "",
      "[[rules]]",
      'id = "dup-rule"',
      'effect = "allow"',
    ].join("\n");

    const markers = validateAccessToml(policy);
    expect(markers).toHaveLength(1);
    expect(markers[0].severity).toBe("warning");
    expect(markers[0].startLineNumber).toBe(6);
    expect(markers[0].message).toContain("line 2");
  });

  it("parses serverError line/column patterns into error markers", () => {
    const doc = [
      "version = 1",
      "[defaults]",
      'public = ["read"]',
      'authenticated = ["read"]',
      "[quarantine]",
    ].join("\n");

    const m1 = validateAccessToml(doc, "TOML parse error at line 4, col 10: unexpected token");
    expect(m1).toHaveLength(1);
    expect(m1[0]).toMatchObject({
      startLineNumber: 4,
      startColumn: 10,
      endLineNumber: 4,
      severity: "error",
    });

    const m2 = validateAccessToml(doc, "invalid policy at line 3 column 8");
    expect(m2).toHaveLength(1);
    expect(m2[0]).toMatchObject({ startLineNumber: 3, startColumn: 8, severity: "error" });

    const m3 = validateAccessToml(doc, "parse failure at line 2:5");
    expect(m3).toHaveLength(1);
    expect(m3[0]).toMatchObject({ startLineNumber: 2, startColumn: 5, severity: "error" });

    const m4 = validateAccessToml(doc, ".access.toml:5:4: unexpected section");
    expect(m4).toHaveLength(1);
    expect(m4[0]).toMatchObject({ startLineNumber: 5, startColumn: 4, severity: "error" });

    // Clamps out-of-range line numbers to document length
    const m5 = validateAccessToml(doc, "error at line 999, col 1");
    expect(m5).toHaveLength(1);
    expect(m5[0].startLineNumber).toBe(5);

    // Fallback when serverError has no line/column
    const m6 = validateAccessToml(doc, "policy rejected by server");
    expect(m6).toHaveLength(1);
    expect(m6[0]).toMatchObject({ startLineNumber: 1, startColumn: 1, severity: "error" });

    // Whitespace-only serverError produces no marker
    expect(validateAccessToml(doc, "   ")).toEqual([]);
  });
});

describe("unifiedPatchToSides", () => {
  it("handles an empty patch", () => {
    expect(unifiedPatchToSides("")).toEqual({
      original: "",
      modified: "",
      hasChanges: false,
      originalLineMap: [],
      modifiedLineMap: [],
    });
  });

  it("reconstructs a single hunk with accurate line maps", () => {
    const patch = [
      "diff --git a/src/app.ts b/src/app.ts",
      "index 1111111..2222222 100644",
      "--- a/src/app.ts",
      "+++ b/src/app.ts",
      "@@ -10,4 +10,4 @@ export function run() {",
      " const a = 1;",
      "-const b = 2;",
      "+const b = 3;",
      " return a + b;",
      "",
    ].join("\n");

    const sides = unifiedPatchToSides(patch);
    expect(sides.hasChanges).toBe(true);
    expect(sides.original).toBe("const a = 1;\nconst b = 2;\nreturn a + b;");
    expect(sides.modified).toBe("const a = 1;\nconst b = 3;\nreturn a + b;");
    expect(sides.originalLineMap).toEqual([10, 11, 12]);
    expect(sides.modifiedLineMap).toEqual([10, 11, 12]);
  });

  it("inserts synthetic separator lines with 0 in line maps between multiple hunks", () => {
    const patch = [
      "diff --git a/lib.rs b/lib.rs",
      "--- a/lib.rs",
      "+++ b/lib.rs",
      "@@ -2,2 +2,2 @@",
      "-let x = 1;",
      "+let x = 2;",
      " let y = 3;",
      "@@ -25,2 +25,3 @@",
      " fn end() {",
      "+  log();",
      " }",
    ].join("\n");

    const sides = unifiedPatchToSides(patch);
    expect(sides.hasChanges).toBe(true);
    const origLines = sides.original.split("\n");
    const modLines = sides.modified.split("\n");

    expect(origLines[2]).toContain("hunk @@ -25,2 +25,3 @@");
    expect(modLines[2]).toContain("hunk @@ -25,2 +25,3 @@");
    expect(sides.originalLineMap).toEqual([2, 3, 0, 25, 26]);
    expect(sides.modifiedLineMap).toEqual([2, 3, 0, 25, 26, 27]);
  });

  it("handles added-only files (@@ -0,0 +1,3 @@)", () => {
    const patch = [
      "diff --git a/new.txt b/new.txt",
      "new file mode 100644",
      "--- /dev/null",
      "+++ b/new.txt",
      "@@ -0,0 +1,3 @@",
      "+alpha",
      "+beta",
      "+gamma",
    ].join("\n");

    const sides = unifiedPatchToSides(patch);
    expect(sides.hasChanges).toBe(true);
    expect(sides.original).toBe("");
    expect(sides.originalLineMap).toEqual([]);
    expect(sides.modified).toBe("alpha\nbeta\ngamma");
    expect(sides.modifiedLineMap).toEqual([1, 2, 3]);
  });

  it("handles deleted-only files (@@ -1,3 +0,0 @@)", () => {
    const patch = [
      "diff --git a/old.txt b/old.txt",
      "deleted file mode 100644",
      "--- a/old.txt",
      "+++ /dev/null",
      "@@ -1,3 +0,0 @@",
      "-one",
      "-two",
      "-three",
    ].join("\n");

    const sides = unifiedPatchToSides(patch);
    expect(sides.hasChanges).toBe(true);
    expect(sides.original).toBe("one\ntwo\nthree");
    expect(sides.originalLineMap).toEqual([1, 2, 3]);
    expect(sides.modified).toBe("");
    expect(sides.modifiedLineMap).toEqual([]);
  });

  it("preserves empty context lines (both space-prefixed and bare empty) and skips no-newline markers", () => {
    const patch = [
      "--- a/file.txt",
      "+++ b/file.txt",
      "@@ -1,5 +1,5 @@",
      " first",
      " ",
      "",
      "-old_end",
      "\\ No newline at end of file",
      "+new_end",
      "\\ No newline at end of file",
      " tail",
    ].join("\n");

    const sides = unifiedPatchToSides(patch);
    expect(sides.original).toBe("first\n\n\nold_end\ntail");
    expect(sides.modified).toBe("first\n\n\nnew_end\ntail");
    expect(sides.originalLineMap).toEqual([1, 2, 3, 4, 5]);
    expect(sides.modifiedLineMap).toEqual([1, 2, 3, 4, 5]);
  });

  it("never drops hunk body lines starting with '--- ' or '+++ '", () => {
    const patch = [
      "diff --git a/doc.md b/doc.md",
      "--- a/doc.md",
      "+++ b/doc.md",
      "@@ -5,3 +5,3 @@",
      " # Heading",
      "--- old sql comment",
      "+++ new increment note",
      " footer",
    ].join("\n");

    const sides = unifiedPatchToSides(patch);
    expect(sides.hasChanges).toBe(true);
    expect(sides.original).toBe("# Heading\n-- old sql comment\nfooter");
    expect(sides.modified).toBe("# Heading\n++ new increment note\nfooter");
    expect(sides.originalLineMap).toEqual([5, 6, 7]);
    expect(sides.modifiedLineMap).toEqual([5, 6, 7]);
  });
});
