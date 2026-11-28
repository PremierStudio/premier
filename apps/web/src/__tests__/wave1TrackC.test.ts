import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ConflictHunk, LaneConflict } from "../api";
import { traceIngestPath } from "../components/AgentTraceView";
import { ErrorBoundary, isChunkLoadError } from "../components/ErrorBoundary";
import { InlineSteeringComposer } from "../components/review/InlineSteeringComposer";
import {
  buildWholeFileConflictContent,
  canCustomEditConflict,
  spliceHunksIntoTargetFile,
} from "../lib/conflictMerge";

interface NodeFsSubset {
  readFileSync(path: URL, encoding: "utf8"): string;
}

async function readRepoFile(repoRelativePath: string): Promise<string> {
  const fsSpecifier: string = "node:fs";
  const fs = (await import(/* @vite-ignore */ fsSpecifier)) as NodeFsSubset;
  const fileUrl = new URL(`../../../../${repoRelativePath}`, import.meta.url);
  return fs.readFileSync(fileUrl, "utf8");
}

describe("Track C.1: ErrorBoundary", () => {
  it("identifies dynamic chunk load errors without false positives", () => {
    expect(
      isChunkLoadError(new TypeError("Failed to fetch dynamically imported module: /assets/x.js")),
    ).toBe(true);
    expect(isChunkLoadError(new Error("Importing a module script failed."))).toBe(true);
    const chunkErr = new Error("Loading chunk 42 failed.");
    chunkErr.name = "ChunkLoadError";
    expect(isChunkLoadError(chunkErr)).toBe(true);
    expect(isChunkLoadError(new Error("Cannot read properties of undefined"))).toBe(false);
    expect(isChunkLoadError(null)).toBe(false);
  });

  it("renders children when healthy and renders dark-obsidian recovery UI when errored", () => {
    const healthyHtml = renderToStaticMarkup(
      createElement(ErrorBoundary, { scope: "Traces" }, createElement("div", null, "Healthy view")),
    );
    expect(healthyHtml).toContain("Healthy view");
    expect(healthyHtml).not.toContain("Reload tab");

    const boundary = new ErrorBoundary({
      scope: "Traces",
      children: createElement("div", null, "Hidden"),
    });
    const derived = ErrorBoundary.getDerivedStateFromError(new Error("Boom in trace panel"));
    boundary.state = { ...boundary.state, ...derived };
    const fallbackHtml = renderToStaticMarkup(createElement(() => boundary.render()));
    expect(fallbackHtml).toContain("View Crashed");
    expect(fallbackHtml).toContain("Traces");
    expect(fallbackHtml).toContain("Boom in trace panel");
    expect(fallbackHtml).toContain("Reload tab");
    expect(fallbackHtml).toContain("Hard reload");

    const chunkBoundary = new ErrorBoundary({
      scope: "Files",
      fullScreen: true,
      children: createElement("div", null, "Hidden"),
    });
    chunkBoundary.state = {
      ...chunkBoundary.state,
      ...ErrorBoundary.getDerivedStateFromError(
        new TypeError("Failed to fetch dynamically imported module: /assets/Files.js"),
      ),
    };
    const chunkHtml = renderToStaticMarkup(createElement(() => chunkBoundary.render()));
    expect(chunkHtml).toContain("Bundle Update Needed");
    expect(chunkHtml).toContain("Reload tab");
    expect(chunkHtml).toContain("Hard reload");
  });

  it("wraps both root App (main.tsx) and lazy tab Suspense panes (App.tsx)", async () => {
    const [mainSrc, appSrc] = await Promise.all([
      readRepoFile("apps/web/src/main.tsx"),
      readRepoFile("apps/web/src/App.tsx"),
    ]);
    expect(mainSrc).toContain("<ErrorBoundary");
    expect(appSrc).toMatch(/<ErrorBoundary[^>]*>\s*<Suspense fallback=\{<ViewSkeleton tab=\{id\} \/>\}>/);
  });
});

describe("Track C.2: AgentTraceView hotkeys, deep links, mobile nav, hook URL & SSE resync", () => {
  it("respects isDefaultRepo in trace hook ingest paths", () => {
    expect(traceIngestPath("premier", true)).toBe("/v1/traces/ingest");
    expect(traceIngestPath("billing", false)).toBe("/r/billing/v1/traces/ingest");
    expect(traceIngestPath("team/app", false)).toBe("/r/team%2Fapp/v1/traces/ingest");
    expect(traceIngestPath(undefined, false)).toBe("/v1/traces/ingest");
  });

  it("gates AgentTraceView hotkeys on active and avoids 1–4 collision with App.tsx", async () => {
    const [appSrc, traceSrc] = await Promise.all([
      readRepoFile("apps/web/src/App.tsx"),
      readRepoFile("apps/web/src/components/AgentTraceView.tsx"),
    ]);

    expect(appSrc).toContain('active={tab === "traces"}');
    expect(appSrc).toContain("isDefaultRepo={repo.is_default}");
    expect(traceSrc).toMatch(/useEffect\(\(\) => \{\s*if \(!active\) return;\s*const onKeyDown/);

    // 1-4 on Traces do not trigger global tab jump
    expect(appSrc).toContain('if (tab === "traces" && e.key >= "1" && e.key <= "4")');

    // Deep-link branch selection from Traces
    expect(appSrc).toMatch(
      /onOpenBranch=\{\(branch\) => \{\s*setRequestedBranch\(branch\);\s*setTab\("branches"\);\s*\}\}/,
    );

    // Shortcut drift fixes & mobile Traces navigation
    expect(appSrc).toContain('title="Settings (9)"');
    expect(appSrc).toContain("1–9 views · g w home · Shift+L view as");
    expect(appSrc).toContain(
      "const PALETTE_GROUP_CAP: Record<string, number> = { Views: 9, Files: 8, Commits: 5, Repositories: 5 };",
    );
    expect(appSrc).toMatch(/setTab\("traces"\);\s*setUserOpen\(false\);/);

    // SSE reconnect resync invalidates cache and refreshes active state
    expect(appSrc).toContain("let hadDisconnect = false;");
    expect(appSrc).toMatch(
      /if \(hadDisconnect\) \{\s*hadDisconnect = false;\s*refreshMetadata\(\);\s*setReviewRevision\(\(n\) => n \+ 1\);\s*setTraceRevision\(\(n\) => n \+ 1\);/,
    );
  });
});

describe("Track C.3: Review Rounds inline Steer & Revise wiring", () => {
  it("wires handleSubmitInlineSteer to api.steerReview without stub echo or Platform 3 copy", async () => {
    const [reviewSrc, composerSrc] = await Promise.all([
      readRepoFile("apps/web/src/components/ReviewRoundsView.tsx"),
      readRepoFile("apps/web/src/components/review/InlineSteeringComposer.tsx"),
    ]);

    expect(reviewSrc).not.toContain("Platform 3 revision hook ready");
    expect(reviewSrc).not.toContain('echo "[steer');
    expect(reviewSrc).toMatch(/handleSubmitInlineSteer[\s\S]*?api\.steerReview\(activeChange\.change_id/);

    expect(composerSrc).not.toContain('"ui-agent"');
  });

  it("renders InlineSteeringComposer cleanly with no agent profiles and no fake ui-agent", () => {
    const html = renderToStaticMarkup(
      createElement(InlineSteeringComposer, {
        change: {
          change_id: "chg_1",
          title: "Fix billing rounding",
          branch: "feat/rounding",
          base_ref: "main",
          author: "@alice",
          visibility: { scope: "public" },
          readiness: "ready",
          quarantine_flagged: false,
          rounds: [],
          comments: [],
          verdicts: {},
        },
        hunk: {
          id: "h1",
          path: "src/billing.ts",
          zone: "public",
          header: "@@ -10,2 +10,3 @@",
          allowed: true,
          lines: ["+const total = roundCents(n);"],
        },
        line: 12,
        viewerIdentity: {
          id: "alice",
          label: "Alice",
          subtitle: "Owner",
          principal: "@alice",
          groups: ["owners"],
          badgeColor: "emerald",
        },
        agentProfiles: [],
        agentSandbox: "none",
        owner: true,
        visibleHunks: [],
        submitting: false,
        onCancel: () => {},
        onSubmitComment: async () => true,
        onSubmitSteer: async () => true,
      }),
    );

    expect(html).not.toContain("ui-agent");
    expect(html).toContain("src/billing.ts:L12");
  });
});

describe("Track C.4: Custom lane conflict full-file splicing", () => {
  const makeHunk = (overrides: Partial<ConflictHunk>): ConflictHunk => ({
    start_line: 1,
    end_line: 6,
    base_lines: [],
    ours_lines: [],
    theirs_lines: [],
    markers: "",
    ...overrides,
  });

  it("splices a single conflict hunk into a multi-line target file without truncating surrounding lines", () => {
    const target = [
      "line 1",
      "line 2",
      "const rate = 1.05;",
      "line 4",
      "line 5",
    ].join("\n") + "\n";

    const hunk = makeHunk({
      start_line: 3,
      end_line: 9,
      ours_lines: ["const rate = 1.05;"],
      base_lines: ["const rate = 1.0;"],
      theirs_lines: ["const rate = 1.1;"],
      markers: [
        "<<<<<<< target",
        "const rate = 1.05;",
        "||||||| base",
        "const rate = 1.0;",
        "=======",
        "const rate = 1.1;",
        ">>>>>>> lane",
        "",
      ].join("\n"),
    });

    const result = spliceHunksIntoTargetFile(target, [hunk]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.content).toBe(
      [
        "line 1",
        "line 2",
        "<<<<<<< target",
        "const rate = 1.05;",
        "||||||| base",
        "const rate = 1.0;",
        "=======",
        "const rate = 1.1;",
        ">>>>>>> lane",
        "line 4",
        "line 5",
        "",
      ].join("\n"),
    );
  });

  it("splices multiple hunks accurately using cumulative merged-line delta and preserves CRLF", () => {
    const target = [
      "header",
      "alpha = 1;",
      "middle 1",
      "middle 2",
      "beta = 2;",
      "footer",
    ].join("\r\n");

    const h1 = makeHunk({
      start_line: 2,
      end_line: 8, // 7 lines replacing 1 line => +6 delta
      ours_lines: ["alpha = 1;"],
      base_lines: ["alpha = 0;"],
      theirs_lines: ["alpha = 2;"],
      markers: "<<<<<<< target\nalpha = 1;\n||||||| base\nalpha = 0;\n=======\nalpha = 2;\n>>>>>>> lane\n",
    });
    const h2 = makeHunk({
      start_line: 11, // target line 5 + delta 6 = merged line 11
      end_line: 17,
      ours_lines: ["beta = 2;"],
      base_lines: ["beta = 0;"],
      theirs_lines: ["beta = 3;"],
      markers: "<<<<<<< target\nbeta = 2;\n||||||| base\nbeta = 0;\n=======\nbeta = 3;\n>>>>>>> lane\n",
    });

    const result = spliceHunksIntoTargetFile(target, [h1, h2]);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.content).toContain("header\r\n<<<<<<< target\r\nalpha = 1;");
    expect(result.content).toContain(">>>>>>> lane\r\nmiddle 1\r\nmiddle 2\r\n<<<<<<< target\r\nbeta = 2;");
    expect(result.content.endsWith(">>>>>>> lane\r\nfooter")).toBe(true);
  });

  it("refuses to splice when target file has drifted or matches are ambiguous", () => {
    const drifted = spliceHunksIntoTargetFile("totally different content\n", [
      makeHunk({
        start_line: 1,
        end_line: 5,
        ours_lines: ["missing_line();"],
        theirs_lines: ["other();"],
        markers: "<<<<<<< target\nmissing_line();\n=======\nother();\n>>>>>>> lane\n",
      }),
    ]);
    expect(drifted.ok).toBe(false);

    // Equidistant identical lines around estimated index 2 (indices 1 and 3)
    const ambiguous = spliceHunksIntoTargetFile("a\ndup\nc\ndup\ne\n", [
      makeHunk({
        start_line: 3, // estimatedIdx = 2, equidistant from 1 and 3
        end_line: 7,
        ours_lines: ["dup"],
        theirs_lines: ["dup2"],
        markers: "<<<<<<< target\ndup\n=======\ndup2\n>>>>>>> lane\n",
      }),
    ]);
    expect(ambiguous.ok).toBe(false);
  });

  it("classifies custom edit eligibility safely across conflict kinds", () => {
    const baseConflict: LaneConflict = {
      path: "src/app.ts",
      kind: "content_overlap",
      summary: "overlap",
      allowed: true,
      hunks: [
        makeHunk({
          ours_lines: ["a"],
          theirs_lines: ["b"],
          markers: "<<<<<<< target\na\n=======\nb\n>>>>>>> lane\n",
        }),
      ],
    };

    expect(canCustomEditConflict(baseConflict)).toEqual({ ok: true, mode: "splice" });
    expect(canCustomEditConflict({ ...baseConflict, kind: "add_add" })).toEqual({
      ok: true,
      mode: "whole_file",
    });
    expect(
      buildWholeFileConflictContent({ ...baseConflict, kind: "add_add" }).content,
    ).toContain("<<<<<<< target");
    expect(canCustomEditConflict({ ...baseConflict, kind: "binary_conflict", hunks: [] }).ok).toBe(
      false,
    );
    expect(canCustomEditConflict({ ...baseConflict, kind: "mode_conflict", hunks: [] }).ok).toBe(
      false,
    );
    expect(
      canCustomEditConflict({ ...baseConflict, kind: "path_type_collision", hunks: [] }).ok,
    ).toBe(false);
    expect(canCustomEditConflict({ ...baseConflict, allowed: false }).ok).toBe(false);
  });

  it("verifies LaneConflictInspector loads full files via api.repoFile and blocks null-content custom saves", async () => {
    const [inspectorSrc, missionSrc, reviewSrc] = await Promise.all([
      readRepoFile("apps/web/src/components/LaneConflictInspector.tsx"),
      readRepoFile("apps/web/src/components/AgentMissionControl.tsx"),
      readRepoFile("apps/web/src/components/ReviewRoundsView.tsx"),
    ]);

    expect(inspectorSrc).toMatch(/api\s*\.repoFile\(identity, conflict\.path, branch\)/);
    expect(inspectorSrc).toContain("spliceHunksIntoTargetFile");
    expect(inspectorSrc).toContain("r.content !== null && !MARKER_LINE_RE.test(r.content)");
    expect(inspectorSrc).toContain("if (!r || r.content === null)");
    expect(missionSrc).toContain("identity={identity}");
    expect(reviewSrc).toContain("branch={activeChange.branch}");
    expect(reviewSrc).toContain("identity={identity}");
  });
});
