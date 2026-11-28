import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  computeTomlLineDiff,
  matchingZonesForPath,
  summarizeBlastRadius,
  type ServerOverrideCheck,
} from "../src/lib/policyIntent.ts";
import type { AccessImpactDiff } from "../src/api.ts";

describe("matchingZonesForPath", () => {
  const samplePolicy = {
    zones: {
      billing: {
        paths: ["billing/**", "packages/payments/*"],
        exclude: ["billing/public/**", "billing/README.md"],
      },
      public_docs: {
        paths: ["docs/**", "billing/public/**", "README.md"],
      },
      all_markdown: {
        paths: ["**/*.md"],
      },
      infra: {
        paths: ["infra/"],
        exclude: ["infra/dev/**"],
      },
    },
  };

  it("matches recursive ** globs, single-segment * globs, and literal prefixes", () => {
    assert.deepEqual(matchingZonesForPath("billing/invoices/2026.ts", samplePolicy), ["billing"]);
    assert.deepEqual(matchingZonesForPath("billing", samplePolicy), ["billing"]);
    assert.deepEqual(matchingZonesForPath("packages/payments/stripe.ts", samplePolicy), ["billing"]);
    // Single-segment `*` must not cross directory boundaries
    assert.deepEqual(matchingZonesForPath("packages/payments/nested/stripe.ts", samplePolicy), []);
    assert.deepEqual(matchingZonesForPath("infra/prod/main.tf", samplePolicy), ["infra"]);
    assert.deepEqual(matchingZonesForPath("infra/dev/local.tf", samplePolicy), []);
  });

  it("respects exclude globs and returns sorted zone names", () => {
    assert.deepEqual(matchingZonesForPath("billing/public/guide.md", samplePolicy), [
      "all_markdown",
      "public_docs",
    ]);
    assert.deepEqual(matchingZonesForPath("billing/README.md", samplePolicy), ["all_markdown"]);
    assert.deepEqual(matchingZonesForPath("README.md", samplePolicy), [
      "all_markdown",
      "public_docs",
    ]);
  });

  it("normalizes leading slashes and backslashes and handles invalid policy objects safely", () => {
    assert.deepEqual(matchingZonesForPath("/billing/core.ts", samplePolicy), ["billing"]);
    assert.deepEqual(matchingZonesForPath("billing\\core.ts", samplePolicy), ["billing"]);
    assert.deepEqual(matchingZonesForPath("billing/core.ts", null), []);
    assert.deepEqual(matchingZonesForPath("billing/core.ts", {}), []);
    assert.deepEqual(matchingZonesForPath("billing/core.ts", { zones: [] }), []);
  });
});

describe("summarizeBlastRadius", () => {
  it("formats revocations, unchanged agents, and passed server policy check cleanly", () => {
    const deltas = Array.from({ length: 12 }, (_, idx) => ({
      principal: "anonymous",
      path: `billing/file-${idx}.ts`,
      before: ["traverse", "list", "read"],
      after: [],
      granted: [],
      revoked: ["read", "traverse", "list"],
    }));
    const diff: AccessImpactDiff = {
      ref_name: "main",
      deltas,
      quarantine_alerts: [],
    };
    const serverCheck: ServerOverrideCheck = {
      passed: true,
      total_overrides: 0,
      overrides: [],
    };

    const summary = summarizeBlastRadius(diff, serverCheck, ["ui-agent"], true);
    assert.equal(
      summary.headline,
      "Revokes traverse, list, read from anonymous on 12 files · ui-agent unchanged · Server Policy override check: ✓ passed",
    );
    assert.equal(summary.serverCheckPassed, true);
    assert.equal(summary.totalDeltas, 12);
    assert.deepEqual(summary.unchangedAgents, ["ui-agent"]);
    assert.deepEqual(summary.revoked, [
      {
        actor: "anonymous",
        capabilities: ["traverse", "list", "read"],
        pathCount: 12,
        critical: false,
      },
    ]);
    assert.deepEqual(summary.granted, []);
  });

  it("reports Server Policy overrides clearly in headline and flags", () => {
    const diff: AccessImpactDiff = {
      ref_name: "main",
      deltas: [
        {
          principal: "@mia",
          path: "billing/a.ts",
          before: ["read"],
          after: [],
          granted: [],
          revoked: ["read"],
        },
        {
          principal: "@mia",
          path: "billing/b.ts",
          before: ["read"],
          after: [],
          granted: [],
          revoked: ["read"],
        },
        {
          principal: "@mia",
          path: "billing/c.ts",
          before: ["read"],
          after: [],
          granted: [],
          revoked: ["read"],
        },
      ],
      quarantine_alerts: [],
    };
    const serverCheck: ServerOverrideCheck = {
      passed: false,
      total_overrides: 1,
      overrides: [
        {
          principal: "@mia",
          path: "billing/a.ts",
          repo_only_effective: [],
          effective_with_server: ["read"],
          server_rules: [
            {
              id: "org-billing-auditor",
              layer: "server",
              effect: "allow",
              capabilities: ["read"],
              reason: "Compliance auditor floor",
            },
          ],
        },
      ],
    };

    const summary = summarizeBlastRadius(diff, serverCheck, [], true);
    assert.equal(
      summary.headline,
      "Revokes read from @mia on 3 files · Server Policy override check: ⚠ 1 overridden by Server Policy",
    );
    assert.equal(summary.serverCheckPassed, false);
    assert.equal(
      summary.serverCheckLabel,
      "Server Policy override check: ⚠ 1 overridden by Server Policy",
    );
  });

  it("distinguishes human ∩ agent_profile actors, marks write/use grants critical, and tracks unchanged agents", () => {
    const diff: AccessImpactDiff = {
      ref_name: "main",
      deltas: [
        {
          principal: "@alice",
          agent_profile: "ui-agent",
          path: "apps/web/App.tsx",
          before: ["read"],
          after: ["read", "write"],
          granted: ["write"],
          revoked: [],
        },
        {
          principal: "@alice",
          agent_profile: "billing-bot",
          path: "secret:STRIPE_API_KEY",
          before: [],
          after: ["use"],
          granted: ["use"],
          revoked: [],
        },
        {
          principal: "@bob",
          path: "apps/web/App.tsx",
          before: [],
          after: ["read"],
          granted: ["read"],
          revoked: [],
        },
      ],
      quarantine_alerts: [],
    };

    const summary = summarizeBlastRadius(
      diff,
      { passed: true, total_overrides: 0, overrides: [] },
      ["ui-agent", "billing-bot", "docs-agent"],
      true,
    );

    assert.deepEqual(summary.unchangedAgents, ["docs-agent"]);
    const uiGrant = summary.granted.find((g) => g.actor === "@alice ∩ ui-agent");
    const secretGrant = summary.granted.find((g) => g.actor === "@alice ∩ billing-bot");
    const bobGrant = summary.granted.find((g) => g.actor === "@bob");

    assert.ok(uiGrant);
    assert.equal(uiGrant.critical, true);
    assert.ok(secretGrant);
    assert.equal(secretGrant.critical, true);
    assert.ok(bobGrant);
    assert.equal(bobGrant.critical, false);
    assert.match(summary.headline, /docs-agent unchanged/);
  });

  it("handles null diff and empty diff cleanly", () => {
    const pending = summarizeBlastRadius(null, null, ["ui-agent"]);
    assert.equal(pending.totalDeltas, 0);
    assert.deepEqual(pending.unchangedAgents, []);
    assert.match(pending.headline, /Simulating/);

    const empty = summarizeBlastRadius(
      { ref_name: "main", deltas: [], quarantine_alerts: [] },
      { passed: true, total_overrides: 0, overrides: [] },
      ["ui-agent"],
      true,
    );
    assert.equal(
      empty.headline,
      "No effective capability changes · ui-agent unchanged · Server Policy override check: ✓ passed",
    );
  });
});

describe("computeTomlLineDiff", () => {
  it("returns empty array when base and proposed TOML are identical", () => {
    const doc = 'version = 1\n\n[defaults]\npublic = ["read"]\n';
    assert.deepEqual(computeTomlLineDiff(doc, doc), []);
  });

  it("computes clean LCS diff and collapses long unchanged runs with gap markers", () => {
    const base = [
      "version = 1",
      "",
      "[defaults]",
      'public = ["traverse", "list", "read"]',
      'authenticated = ["traverse", "list", "read", "write"]',
      "",
      "[zones.billing]",
      'paths = ["billing/**"]',
      "",
      "[[rules]]",
      'id = "existing-rule"',
      'effect = "allow"',
      'principals = ["group:owners"]',
      'paths = ["**"]',
      'capabilities = ["*"]',
    ].join("\n");

    const proposed = [
      ...base.split("\n"),
      "",
      "[[rules]]",
      'id = "shield-billing-anon"',
      'effect = "deny"',
      'principals = ["anonymous"]',
      'zones = ["billing"]',
      'capabilities = ["traverse", "list", "read"]',
    ].join("\n");

    const diff = computeTomlLineDiff(base, proposed, 2);
    assert.equal(diff[0]?.kind, "gap");
    assert.equal(diff[0]?.line, "...");

    const ctxLines = diff.filter((d) => d.kind === "ctx");
    assert.equal(ctxLines.length, 2);
    assert.equal(ctxLines[0]?.oldLine, 14);
    assert.equal(ctxLines[1]?.oldLine, 15);

    const added = diff.filter((d) => d.kind === "add");
    assert.equal(added.length, 7);
    assert.equal(added[0]?.newLine, 16);
    assert.equal(added[added.length - 1]?.line, 'capabilities = ["traverse", "list", "read"]');
  });

  it("handles inline replacements and CRLF line endings cleanly", () => {
    const base = 'line1\r\nline2\r\ncapabilities = ["read"]\r\nline4\r\nline5\r\n';
    const proposed = 'line1\nline2\ncapabilities = ["read", "write"]\nline4\nline5\n';

    const diff = computeTomlLineDiff(base, proposed, 1);
    assert.deepEqual(
      diff.map((d) => [d.kind, d.line, d.oldLine, d.newLine]),
      [
        ["gap", "...", undefined, undefined],
        ["ctx", "line2", 2, 2],
        ["del", 'capabilities = ["read"]', 3, undefined],
        ["add", 'capabilities = ["read", "write"]', undefined, 3],
        ["ctx", "line4", 4, 4],
        ["gap", "...", undefined, undefined],
      ],
    );
  });

  it("handles empty base or empty proposed documents", () => {
    const fromEmpty = computeTomlLineDiff("", "version = 1\n");
    assert.deepEqual(fromEmpty, [{ kind: "add", line: "version = 1", newLine: 1 }]);

    const toEmpty = computeTomlLineDiff("version = 1\n", "");
    assert.deepEqual(toEmpty, [{ kind: "del", line: "version = 1", oldLine: 1 }]);
  });
});
