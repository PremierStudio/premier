import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { MarkdownPreview } from "../components/MarkdownPreview";

function renderMd(
  content: string,
  options?: { currentPath?: string; onOpenFile?: (path: string) => void },
): string {
  return renderToStaticMarkup(
    createElement(MarkdownPreview, {
      content,
      currentPath: options?.currentPath,
      onOpenFile: options?.onOpenFile,
    }),
  );
}

describe("MarkdownPreview XSS protection", () => {
  it("escapes raw HTML script and img onerror payloads", () => {
    const html = renderMd(
      "<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>",
    );

    expect(html).not.toMatch(/<script\b/i);
    expect(html).not.toMatch(/<img\b/i);
    expect(html).not.toMatch(/<[^>]*\bonerror\s*=/i);
    expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("blocks javascript: and data: link schemes even when onOpenFile is provided", () => {
    const noop = () => {};
    const html = renderMd(
      [
        "[click-js](javascript:alert(1))",
        "[click-mixed](JaVaScRiPt:alert(1))",
        "[click-data](data:text/html,<script>alert(1)</script>)",
        "[click-proto](//evil.example/payload)",
      ].join("\n\n"),
      { currentPath: "docs/README.md", onOpenFile: noop },
    );

    expect(html).not.toMatch(/<a\b/i);
    expect(html).not.toMatch(/<button\b/i);
    expect(html).not.toMatch(/<script\b/i);
    expect(html).not.toMatch(/javascript:/i);
    expect(html).not.toMatch(/data:text\/html/i);
    expect(html).toContain("click-js");
    expect(html).toContain("click-mixed");
    expect(html).toContain("click-data");
    expect(html).toContain("click-proto");
  });

  it("blocks non-http(s) image schemes such as javascript: and data:", () => {
    const html = renderMd(
      "![x](javascript:alert(1))\n\n![svg](data:image/svg+xml,<svg onload=alert(1)>)",
    );

    expect(html).not.toMatch(/<img\b/i);
    expect(html).not.toMatch(/javascript:/i);
    expect(html).not.toMatch(/data:image/i);
    expect(html).toContain(">x<");
    expect(html).toContain(">svg<");
  });

  it("rejects repo-relative path traversal escaping repository root", () => {
    const html = renderMd("[escape](../../../etc/passwd)", {
      currentPath: "docs/guide.md",
      onOpenFile: () => {},
    });

    expect(html).not.toMatch(/<button\b/i);
    expect(html).not.toMatch(/<a\b/i);
    expect(html).toContain("escape");
  });
});

describe("MarkdownPreview rendering", () => {
  it("suppresses remote image fetches while rendering safe https links with noopener noreferrer", () => {
    const html = renderMd(
      "![Architecture](https://example.com/a.png)\n\nSee [Premier](https://example.com).",
    );

    expect(html).not.toMatch(/<img\b/i);
    expect(html).toContain("Architecture");
    expect(html).toContain('href="https://example.com"');
    expect(html).toContain('rel="noopener noreferrer"');
    expect(html).toContain('target="_blank"');
  });

  it("renders headings with stable, deduplicated slug IDs and clamps h5/h6 to h4", () => {
    const html = renderMd(
      [
        "# Premier Overview",
        "## Access Policy",
        "## Access Policy",
        "##### Deep Section",
      ].join("\n\n"),
    );

    expect(html).toContain('<h1 id="premier-md-h-premier-overview"');
    expect(html).toContain('<h2 id="premier-md-h-access-policy"');
    expect(html).toContain('<h2 id="premier-md-h-access-policy-1"');
    expect(html).toContain('<h4 id="premier-md-h-deep-section"');
  });

  it("renders nested unordered and ordered lists preserving indentation", () => {
    const html = renderMd(
      [
        "- top item",
        "  - nested item",
        "    - deep item",
        "",
        "3. third step",
        "  1. sub step",
      ].join("\n"),
    );

    expect(html).toContain("<ul");
    expect(html).toContain("top item");
    expect(html).toContain('style="margin-left:18px"');
    expect(html).toContain('style="margin-left:36px"');
    expect(html).toContain('<ol start="3"');
    expect(html).toContain("third step");
    expect(html).toContain("sub step");
  });

  it("renders GFM tables including 1-2 dash separators and column alignments", () => {
    const shortSep = renderMd(
      ["| Key | Value |", "|-|--|", "| mode | deny |"].join("\n"),
    );
    expect(shortSep).toContain("<table");
    expect(shortSep).toContain("<th");
    expect(shortSep).toContain("Key");
    expect(shortSep).toContain("Value");
    expect(shortSep).toContain("<td");
    expect(shortSep).toContain("deny");

    const aligned = renderMd(
      [
        "| Left | Center | Right |",
        "|:---|:---:|---:|",
        "| a | b | c |",
      ].join("\n"),
    );
    expect(aligned).toContain("text-left");
    expect(aligned).toContain("text-center");
    expect(aligned).toContain("text-right");
  });

  it("renders fenced code blocks with syntax highlighting", () => {
    const html = renderMd(
      ["```rust", "pub fn verify() -> bool {", "  true", "}", "```"].join("\n"),
    );

    expect(html).toContain("<pre");
    expect(html).toContain(">rust<");
    expect(html).toContain(">pub<");
    expect(html).toContain(">fn<");
    expect(html).toContain(">verify<");
  });

  it("renders clickable repo-relative links resolved against currentPath", () => {
    const html = renderMd(
      [
        "See [Blueprint](../architecture-blueprint.md)",
        "and [Root](/README.md)",
        "and [Section](./setup.md#install)",
      ].join(" "),
      {
        currentPath: "docs/guides/intro.md",
        onOpenFile: () => {},
      },
    );

    expect(html).toContain('title="Open docs/architecture-blueprint.md"');
    expect(html).toContain('title="Open README.md"');
    expect(html).toContain('title="Open docs/guides/setup.md"');
    expect(html).toContain("<button");
  });

  it("renders inline emphasis without mangling snake_case identifiers", () => {
    const html = renderMd("Use **bold**, *italic*, ~~old~~, `code`, and allow_secret_use.");
    expect(html).toContain("<strong");
    expect(html).toContain("bold");
    expect(html).toContain("<em");
    expect(html).toContain("italic");
    expect(html).toContain("<del");
    expect(html).toContain("old");
    expect(html).toContain("<code");
    expect(html).toContain("code");
    expect(html).toContain("allow_secret_use");
    expect(html).not.toContain("<em>secret</em>");
  });
});
