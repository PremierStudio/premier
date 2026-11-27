import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  CONCERN_DEFINITIONS,
  classifyPathConcern,
  computeRiskRadar,
  extractZoneFootprint,
  groupItemsByConcern,
} from "../src/lib/reviewConcerns.ts";
import {
  computeProgress,
  flattenOrderedIds,
  loadReviewedSet,
  resolveReviewKeyAction,
  saveReviewedSet,
  stepNavigationId,
  toggleReviewedId,
} from "../src/lib/reviewProgress.ts";
import {
  buildSteeringContextPreview,
  isSteeringComment,
  steeringTargetAgent,
} from "../src/lib/steeringPayload.ts";

describe("reviewConcerns: CONCERN_DEFINITIONS & classifyPathConcern", () => {
  it("exposes 6 concern definitions in exact order with expected collapse defaults", () => {
    assert.deepEqual(
      CONCERN_DEFINITIONS.map((d) => ({
        id: d.id,
        order: d.order,
        label: d.label,
        shortLabel: d.shortLabel,
        defaultCollapsed: d.defaultCollapsed,
      })),
      [
        {
          id: "policy_security",
          order: 1,
          label: "1. Policy & Security Boundaries",
          shortLabel: "Policy & Security",
          defaultCollapsed: false,
        },
        {
          id: "schema_types",
          order: 2,
          label: "2. Schema & Core Types",
          shortLabel: "Schema & Types",
          defaultCollapsed: false,
        },
        {
          id: "engine_server",
          order: 3,
          label: "3. Engine / Server Logic",
          shortLabel: "Engine & Server",
          defaultCollapsed: false,
        },
        {
          id: "ui_components",
          order: 4,
          label: "4. UI Components",
          shortLabel: "UI Components",
          defaultCollapsed: false,
        },
        {
          id: "tests",
          order: 5,
          label: "5. Tests & Verification",
          shortLabel: "Tests",
          defaultCollapsed: false,
        },
        {
          id: "boilerplate",
          order: 6,
          label: "6. Lockfiles / Boilerplate",
          shortLabel: "Boilerplate",
          defaultCollapsed: true,
        },
      ],
    );
  });

  it("classifies instruction, policy, .env.schema, and redacted files as critical policy_security", () => {
    const agents = classifyPathConcern("packages/sub/AGENTS.md");
    assert.equal(agents.concern, "policy_security");
    assert.equal(agents.risk, "critical");
    assert.equal(agents.isInstructionFile, true);
    assert.equal(agents.isPolicyFile, false);
    assert.equal(agents.autoCollapsed, false);
    assert.ok(agents.riskReasons.length > 0);

    const claude = classifyPathConcern("CLAUDE.md");
    assert.equal(claude.concern, "policy_security");
    assert.equal(claude.risk, "critical");
    assert.equal(claude.isInstructionFile, true);

    const cursor = classifyPathConcern(".cursorrules");
    assert.equal(cursor.isInstructionFile, true);
    assert.equal(cursor.risk, "critical");

    const copilot = classifyPathConcern(".github/copilot-instructions.md");
    assert.equal(copilot.isInstructionFile, true);
    assert.equal(copilot.risk, "critical");

    const accessToml = classifyPathConcern(".access.toml");
    assert.equal(accessToml.concern, "policy_security");
    assert.equal(accessToml.risk, "critical");
    assert.equal(accessToml.isPolicyFile, true);

    const serverPolicy = classifyPathConcern("config/server-policy.toml");
    assert.equal(serverPolicy.isPolicyFile, true);
    assert.equal(serverPolicy.risk, "critical");

    const envSchema = classifyPathConcern(".env.schema");
    assert.equal(envSchema.concern, "policy_security");
    assert.equal(envSchema.risk, "critical");
    assert.equal(envSchema.isEnvSchema, true);

    const redacted = classifyPathConcern("billing/stripe.rs", {
      allowed: false,
      zone: "billing",
    });
    assert.equal(redacted.concern, "policy_security");
    assert.equal(redacted.risk, "critical");
    assert.equal(redacted.isSensitiveZone, false);
    assert.ok(redacted.riskReasons.some((r) => r.toLowerCase().includes("redacted")));
  });

  it("classifies lockfiles and generated artifacts as low-risk auto-collapsed boilerplate", () => {
    for (const p of [
      "Cargo.lock",
      "pnpm-lock.yaml",
      "package-lock.json",
      "yarn.lock",
      "poetry.lock",
      "snapshots/ui.snap",
      "dist/app.min.js",
      "src/api.generated.ts",
    ]) {
      const cls = classifyPathConcern(p);
      assert.equal(cls.concern, "boilerplate", p);
      assert.equal(cls.risk, "low", p);
      assert.equal(cls.autoCollapsed, true, p);
    }
  });

  it("classifies tests with elevated medium risk when security/auth/acl/policy related", () => {
    const plainTest = classifyPathConcern("apps/web/tests/format.test.ts");
    assert.equal(plainTest.concern, "tests");
    assert.equal(plainTest.risk, "low");

    const secTest = classifyPathConcern("crates/premier-core/tests/acl_policy_test.rs");
    assert.equal(secTest.concern, "tests");
    assert.equal(secTest.risk, "medium");

    const zoneSecTest = classifyPathConcern("tests/verify.spec.ts", { zone: "auth" });
    assert.equal(zoneSecTest.concern, "tests");
    assert.equal(zoneSecTest.risk, "medium");

    const fixture = classifyPathConcern("crates/server/fixtures/sample.json");
    assert.equal(fixture.concern, "tests");
    assert.equal(fixture.risk, "low");
  });

  it("classifies security/policy/proxy/secrets/sandbox/cage/overlay/billing sources & sensitive zones as high policy_security", () => {
    for (const p of [
      "crates/premier-proxy/src/egress.rs",
      "crates/premier-sandbox/src/cage.rs",
      "crates/premier-core/src/overlay.rs",
      "src/auth/jwt.ts",
      "billing/invoice.rs",
      "secrets/kms.rs",
      "private/roadmap.txt",
    ]) {
      const cls = classifyPathConcern(p);
      assert.equal(cls.concern, "policy_security", p);
      assert.equal(cls.risk, "high", p);
    }

    const byZone = classifyPathConcern("src/worker.ts", { zone: "embargo" });
    assert.equal(byZone.concern, "policy_security");
    assert.equal(byZone.risk, "high");
    assert.equal(byZone.isSensitiveZone, true);
  });

  it("classifies schema & core types with churn-sensitive risk", () => {
    const coreFile = classifyPathConcern("crates/premier-core/src/graph.rs", { churn: 40 });
    assert.equal(coreFile.concern, "schema_types");
    assert.equal(coreFile.risk, "medium");

    const highChurnApi = classifyPathConcern("apps/web/src/api.ts", { churn: 121 });
    assert.equal(highChurnApi.concern, "schema_types");
    assert.equal(highChurnApi.risk, "high");

    const sql = classifyPathConcern("migrations/001_init.sql");
    assert.equal(sql.concern, "schema_types");
    assert.equal(sql.risk, "medium");

    const proto = classifyPathConcern("proto/v1/repo.proto");
    assert.equal(proto.concern, "schema_types");

    const dts = classifyPathConcern("apps/web/src/env.d.ts");
    assert.equal(dts.concern, "schema_types");

    const store = classifyPathConcern("crates/premier-server/src/store.rs");
    assert.equal(store.concern, "schema_types");
  });

  it("classifies UI components, docs/config boilerplate, and engine/server fallback", () => {
    const uiSmall = classifyPathConcern("apps/web/src/components/ReviewRoundsView.tsx", {
      churn: 80,
    });
    assert.equal(uiSmall.concern, "ui_components");
    assert.equal(uiSmall.risk, "low");

    const uiBig = classifyPathConcern("apps/web/src/styles/theme.css", { churn: 180 });
    assert.equal(uiBig.concern, "ui_components");
    assert.equal(uiBig.risk, "medium");

    for (const p of [
      "README.md",
      "docs/architecture-blueprint.md",
      ".gitignore",
      "LICENSE-MIT",
      "apps/web/tsconfig.json",
      "apps/web/package.json",
      "Cargo.toml",
    ]) {
      const cls = classifyPathConcern(p);
      assert.equal(cls.concern, "boilerplate", p);
      assert.equal(cls.risk, "low", p);
      assert.equal(cls.autoCollapsed, true, p);
    }

    const engineMed = classifyPathConcern("crates/premier-server/src/routes.rs", { churn: 50 });
    assert.equal(engineMed.concern, "engine_server");
    assert.equal(engineMed.risk, "medium");

    const engineHigh = classifyPathConcern("crates/premier-server/src/routes.rs", { churn: 150 });
    assert.equal(engineHigh.concern, "engine_server");
    assert.equal(engineHigh.risk, "high");
  });
});

describe("reviewConcerns: groupItemsByConcern, computeRiskRadar, extractZoneFootprint", () => {
  it("groups items in CONCERN_DEFINITIONS order, omits empty groups, and sorts by risk -> churn -> path", () => {
    const sample = [
      { id: "h1", path: "README.md", churn: 10 },
      { id: "h2", path: "crates/premier-server/src/b.rs", churn: 30 },
      { id: "h3", path: "crates/premier-server/src/a.rs", churn: 30 },
      { id: "h4", path: "crates/premier-server/src/big.rs", churn: 140 },
      { id: "h5", path: "billing/charge.rs", churn: 200 },
      { id: "h6", path: ".access.toml", churn: 5 },
      { id: "h7", path: "apps/web/src/components/Panel.tsx", churn: 25 },
    ];

    const groups = groupItemsByConcern(sample, (x) => x);

    // tests and schema_types are empty so omitted
    assert.deepEqual(
      groups.map((g) => g.definition.id),
      ["policy_security", "engine_server", "ui_components", "boilerplate"],
    );

    // policy_security: critical .access.toml before high billing/charge.rs despite lower churn
    assert.deepEqual(
      groups[0].items.map((i) => i.id),
      ["h6", "h5"],
    );
    assert.equal(groups[0].highestRisk, "critical");
    assert.equal(groups[0].totalChurn, 205);
    assert.equal(groups[0].defaultCollapsed, false);

    // engine_server: high churn big.rs first, then a.rs before b.rs lexicographically
    assert.deepEqual(
      groups[1].items.map((i) => i.id),
      ["h4", "h3", "h2"],
    );
    assert.equal(groups[1].highestRisk, "high");

    // boilerplate defaults collapsed
    assert.equal(groups[3].defaultCollapsed, true);
  });

  it("computes risk radar signals without leaking redacted paths", () => {
    const signals = computeRiskRadar(
      [
        { path: ".access.toml", allowed: true },
        { path: ".env.schema", allowed: true },
        { path: "AGENTS.md", allowed: true },
        { path: "billing/secret_ledger.rs", allowed: false, zone: "billing" },
        { path: "secrets/rotate.rs", allowed: true, zone: "secrets" },
      ],
      false,
    );

    const byKind = new Map(signals.map((s) => [s.kind, s]));
    assert.equal(byKind.get("policy")?.severity, "critical");
    assert.deepEqual(byKind.get("policy")?.paths, [".access.toml"]);

    assert.equal(byKind.get("quarantine")?.severity, "critical");
    assert.deepEqual(byKind.get("quarantine")?.paths, ["AGENTS.md"]);

    assert.equal(byKind.get("env_schema")?.severity, "critical");
    assert.deepEqual(byKind.get("env_schema")?.paths, [".env.schema"]);

    assert.equal(byKind.get("redacted")?.severity, "warn");
    assert.deepEqual(byKind.get("redacted")?.paths, []);
    assert.ok(!byKind.get("redacted")?.detail.includes("secret_ledger"));

    assert.equal(byKind.get("sensitive_zone")?.severity, "warn");
    assert.deepEqual(byKind.get("sensitive_zone")?.paths, ["secrets/rotate.rs"]);

    // Also emits quarantine when only quarantineFlagged=true
    const flaggedOnly = computeRiskRadar([{ path: "src/app.ts", allowed: true }], true);
    assert.equal(flaggedOnly.length, 1);
    assert.equal(flaggedOnly[0].kind, "quarantine");
    assert.equal(flaggedOnly[0].severity, "critical");
  });

  it("extracts zone footprint from allowed items only and counts redacted without leakage", () => {
    const footprint = extractZoneFootprint([
      { path: "crates/premier-core/src/lib.rs", allowed: true },
      { path: "apps/web/src/App.tsx", allowed: true },
      { path: "docs/spec.md", allowed: true },
      { path: "README.md", allowed: true },
      { path: "src/custom.ts", allowed: true, zone: "payments-public" },
      { path: "embargo/secret-plan.md", allowed: false, zone: "embargo" },
      { path: "private/keys.pem", allowed: false, zone: "private-keys" },
    ]);

    assert.equal(footprint.redactedCount, 2);
    assert.deepEqual(footprint.zones, [
      "apps/web",
      "crates/premier-core",
      "docs",
      "payments-public",
      "root",
    ]);
    assert.ok(!footprint.zones.includes("embargo"));
    assert.ok(!footprint.zones.includes("private-keys"));
  });
});

describe("reviewProgress: persistence, progress, ordering, navigation & keyboard actions", () => {
  it("handles localStorage load/save safely in Node and with a mock Storage", () => {
    // No window/localStorage in Node -> returns empty set, save is safe no-op
    assert.equal(loadReviewedSet("scope-none").size, 0);
    assert.doesNotThrow(() => saveReviewedSet("scope-none", new Set(["a", "b"])));

    // Mock globalThis.localStorage
    const store = new Map<string, string>();
    const mockStorage = {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => {
        store.set(k, v);
      },
      removeItem: (k: string) => {
        store.delete(k);
      },
      clear: () => store.clear(),
      key: () => null,
      length: 0,
    };
    const prev = (globalThis as { localStorage?: unknown }).localStorage;
    Object.defineProperty(globalThis, "localStorage", {
      value: mockStorage,
      configurable: true,
      writable: true,
    });
    try {
      saveReviewedSet("chg-1", new Set(["h1", "h2"]));
      const loaded = loadReviewedSet("chg-1");
      assert.deepEqual(Array.from(loaded).sort(), ["h1", "h2"]);

      // Malformed JSON falls back cleanly
      store.set("premier:review:reviewed:bad", "{not-json");
      assert.equal(loadReviewedSet("bad").size, 0);
    } finally {
      Object.defineProperty(globalThis, "localStorage", {
        value: prev,
        configurable: true,
        writable: true,
      });
    }
  });

  it("toggles reviewed IDs immutably and computes accurate progress", () => {
    const s0 = new Set<string>();
    const s1 = toggleReviewedId(s0, "a");
    assert.equal(s0.size, 0);
    assert.equal(s1.has("a"), true);
    const s2 = toggleReviewedId(s1, "a");
    assert.equal(s2.has("a"), false);

    assert.deepEqual(computeProgress([], new Set(["a"])), {
      reviewed: 0,
      total: 0,
      percent: 0,
    });

    assert.deepEqual(computeProgress(["a", "b", "c"], new Set(["a", "stale-id"])), {
      reviewed: 1,
      total: 3,
      percent: 33,
    });

    assert.deepEqual(computeProgress(["a", "b"], new Set(["a", "b"])), {
      reviewed: 2,
      total: 2,
      percent: 100,
    });
  });

  it("flattens ordered IDs for guided vs all mode and steps navigation cleanly", () => {
    const raw = [
      { id: "raw-1", path: "README.md", churn: 5 },
      { id: "raw-2", path: ".access.toml", churn: 2 },
      { id: "raw-3", path: "apps/web/src/components/App.tsx", churn: 10 },
    ];
    const groups = groupItemsByConcern(raw, (x) => x);
    const allIds = raw.map((x) => x.id);

    assert.deepEqual(flattenOrderedIds(groups, allIds, "all"), ["raw-1", "raw-2", "raw-3"]);
    assert.deepEqual(flattenOrderedIds(groups, allIds, "guided"), [
      "raw-2",
      "raw-3",
      "raw-1",
    ]);

    const ordered = ["raw-2", "raw-3", "raw-1"];
    assert.equal(stepNavigationId([], null, "next"), null);
    assert.equal(stepNavigationId(ordered, null, "next"), "raw-2");
    assert.equal(stepNavigationId(ordered, null, "prev"), "raw-1");
    assert.equal(stepNavigationId(ordered, "raw-2", "next"), "raw-3");
    assert.equal(stepNavigationId(ordered, "raw-1", "next"), "raw-1");
    assert.equal(stepNavigationId(ordered, "raw-3", "prev"), "raw-2");
    assert.equal(stepNavigationId(ordered, "raw-2", "prev"), "raw-2");
  });

  it("resolves keyboard shortcuts respecting editable, modifiers, g-chord, shift, mode, and Escape", () => {
    const base = {
      mode: "rounds" as const,
      isEditable: false,
      hasModifiers: false,
      shiftKey: false,
      withinGChord: false,
      composerOpen: false,
    };

    assert.equal(resolveReviewKeyAction("j", base), "next");
    assert.equal(resolveReviewKeyAction("k", base), "prev");
    assert.equal(resolveReviewKeyAction("v", base), "toggle_reviewed");
    assert.equal(resolveReviewKeyAction("c", base), "open_comment");
    assert.equal(resolveReviewKeyAction("x", base), null);

    // Commits mode disallows c -> open_comment
    assert.equal(resolveReviewKeyAction("c", { ...base, mode: "commits" }), null);
    assert.equal(resolveReviewKeyAction("j", { ...base, mode: "commits" }), "next");

    // Ignored when editable, modifiers, shiftKey, or withinGChord
    assert.equal(resolveReviewKeyAction("j", { ...base, isEditable: true }), null);
    assert.equal(resolveReviewKeyAction("v", { ...base, hasModifiers: true }), null);
    assert.equal(resolveReviewKeyAction("c", { ...base, shiftKey: true }), null);
    assert.equal(resolveReviewKeyAction("c", { ...base, withinGChord: true }), null);
    assert.equal(resolveReviewKeyAction("j", { ...base, withinGChord: true }), null);

    // Escape closes composer even while editing or inside g-chord
    assert.equal(
      resolveReviewKeyAction("Escape", { ...base, isEditable: true, composerOpen: true }),
      "close_composer",
    );
    assert.equal(
      resolveReviewKeyAction("Escape", { ...base, withinGChord: true, composerOpen: true }),
      "close_composer",
    );
    assert.equal(resolveReviewKeyAction("Escape", { ...base, composerOpen: false }), null);
  });
});

describe("steeringPayload: ACL-safe context preview and steering comment helpers", () => {
  it("builds ACL-safe steering preview with effective authority, snippet cap, redaction count, and quarantine warning", () => {
    const lines = Array.from({ length: 12 }, (_, idx) => `+ line ${idx + 1}`);
    const preview = buildSteeringContextPreview({
      viewerPrincipal: "alice",
      targetAgent: "coder-agent",
      path: "crates/premier-server/src/routes.rs",
      line: 42,
      hunkLines: lines,
      visibleHunks: [{ allowed: true }, { allowed: false }, { allowed: false }],
      quarantineFlagged: true,
      directive: "Check bounds before indexing.",
      changeId: "chg-101",
      branch: "feat/review-ui",
    });

    assert.equal(preview.effectiveAuthority, "alice ∩ coder-agent");
    assert.equal(preview.targetAgent, "coder-agent");
    assert.equal(preview.path, "crates/premier-server/src/routes.rs");
    assert.equal(preview.line, 42);
    assert.equal(preview.snippetLines.length, 8);
    assert.equal(preview.snippetLines[0], "+ line 1");
    assert.equal(preview.snippetLines[7], "+ line 8");
    assert.equal(preview.excludedRedactedCount, 2);
    assert.equal(
      preview.secretsPolicy,
      "Placeholders only (use ≠ read); raw secrets never enter agent context",
    );
    assert.ok(preview.quarantineWarning !== null);
    assert.ok(preview.directivePrompt.includes("alice ∩ coder-agent"));
    assert.ok(preview.directivePrompt.includes("crates/premier-server/src/routes.rs:42"));
    assert.ok(preview.directivePrompt.includes("2 redacted hunks excluded"));
    assert.ok(preview.directivePrompt.includes("Check bounds before indexing."));

    const unflagged = buildSteeringContextPreview({
      viewerPrincipal: "bob",
      targetAgent: "reviewer-bot",
      path: "src/index.ts",
      line: 10,
      hunkLines: ["+ const x = 1;"],
      visibleHunks: [{ allowed: true }],
      quarantineFlagged: false,
      directive: "Rename x.",
      changeId: "chg-102",
      branch: "main",
    });
    assert.equal(unflagged.quarantineWarning, null);
    assert.equal(unflagged.excludedRedactedCount, 0);
  });

  it("identifies steering comments and extracts target agent with fallback", () => {
    assert.equal(isSteeringComment({ kind: "steer", body: "Fix error handling" }), true);
    assert.equal(isSteeringComment({ kind: "comment", body: "Looks good" }), false);
    assert.equal(
      isSteeringComment({ body: "Tighten validation", target_agent: "coder-agent" }),
      true,
    );
    assert.equal(isSteeringComment({ body: "[steer @refactor-bot] Split helper" }), true);
    assert.equal(isSteeringComment({ body: "/steer @test-agent Add edge cases" }), true);
    assert.equal(isSteeringComment({ body: "Regular inline comment" }), false);

    assert.equal(
      steeringTargetAgent({ target_agent: "security-bot", body: "Check ACL" }),
      "security-bot",
    );
    assert.equal(
      steeringTargetAgent({ target_agent: null, body: "[steer @refactor-bot] Split helper" }),
      "refactor-bot",
    );
    assert.equal(
      steeringTargetAgent({ body: "/steer @qa-bot Add regression test" }),
      "qa-bot",
    );
    assert.equal(
      steeringTargetAgent({ body: "Please add docs" }, "default-agent"),
      "default-agent",
    );
    assert.equal(
      steeringTargetAgent({ body: "Steer the retry loop to backoff" }, "default-agent"),
      "default-agent",
    );
    assert.equal(steeringTargetAgent({ body: "Please add docs" }), "agent");
  });
});
