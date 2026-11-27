// Run with Node 24+: node --test apps/web/tests/glassWall.test.ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  CAP_ORDER,
  clampSplitPct,
  computeCapabilityDiff,
  formatCapPlaceholder,
  ghostLineWidths,
  splitLineSecretRefs,
  type SecretRefInfo,
} from "../src/lib/glassWall.ts";
import type { MatchedRuleTrace, RepoTreeEntry } from "../src/api.ts";

const entry = (effective: string[], rules?: MatchedRuleTrace[]): RepoTreeEntry => ({
  path: "src/a.rs",
  kind: "file",
  visibility_state: "visible",
  effective,
  human_effective: effective,
  synthesized_traverse: false,
  is_instruction_file: false,
  matched_rules: rules,
});

const rule = (
  id: string,
  layer: "server" | "repo",
  effect: "allow" | "deny",
): MatchedRuleTrace => ({ id, layer, effect, capabilities: ["read"] });

const secret = (over: Partial<SecretRefInfo> & { name: string }): SecretRefInfo => ({
  sensitivity: "secret",
  canTargetUse: true,
  hasEgress: true,
  ...over,
});

describe("CAP_ORDER", () => {
  it("is T/L/R/W/U", () => {
    assert.deepEqual([...CAP_ORDER], ["traverse", "list", "read", "write", "use"]);
  });
});

describe("computeCapabilityDiff", () => {
  it("computes revoked and granted caps in T/L/R/W/U order", () => {
    const d = computeCapabilityDiff(
      entry(["use", "write", "read", "list", "traverse"]),
      entry(["traverse", "list"]),
    );
    assert.deepEqual(d.ownerCaps, ["traverse", "list", "read", "write", "use"]);
    assert.deepEqual(d.targetCaps, ["traverse", "list"]);
    assert.deepEqual(d.revoked, ["read", "write", "use"]);
    assert.deepEqual(d.granted, []);
    assert.equal(d.identical, false);
  });

  it("reports granted caps the owner lacks", () => {
    const d = computeCapabilityDiff(entry(["read"]), entry(["read", "use"]));
    assert.deepEqual(d.granted, ["use"]);
    assert.deepEqual(d.revoked, []);
    assert.equal(d.identical, false);
  });

  it("is identical for equal sets regardless of order", () => {
    const d = computeCapabilityDiff(entry(["read", "list"]), entry(["list", "read"]));
    assert.equal(d.identical, true);
  });

  it("treats null/undefined entries as empty", () => {
    const d = computeCapabilityDiff(entry(["read"]), null);
    assert.deepEqual(d.targetCaps, []);
    assert.deepEqual(d.revoked, ["read"]);
    assert.equal(d.hasServerOverride, false);
    assert.deepEqual(d.winningRules, []);
    assert.equal(computeCapabilityDiff(undefined, undefined).identical, true);
  });

  it("keeps unknown cap names after the known ones", () => {
    const d = computeCapabilityDiff(entry(["zzz", "read"]), entry([]));
    assert.deepEqual(d.ownerCaps, ["read", "zzz"]);
  });

  it("detects a server override from either side", () => {
    assert.equal(
      computeCapabilityDiff(entry(["read"]), entry([], [rule("t", "server", "deny")]))
        .hasServerOverride,
      true,
    );
    assert.equal(
      computeCapabilityDiff(entry(["read"], [rule("o", "server", "allow")]), entry([]))
        .hasServerOverride,
      true,
    );
    assert.equal(
      computeCapabilityDiff(entry(["read"]), entry([], [rule("r", "repo", "deny")]))
        .hasServerOverride,
      false,
    );
  });

  it("ranks Server Deny > Server Allow > Repo Deny > Repo Allow and dedupes", () => {
    const d = computeCapabilityDiff(
      entry(["read"], [rule("ra", "repo", "allow"), rule("sd", "server", "deny")]),
      entry(
        [],
        [
          rule("ra", "repo", "allow"),
          rule("rd", "repo", "deny"),
          rule("sa", "server", "allow"),
        ],
      ),
    );
    assert.deepEqual(
      d.winningRules.map((r) => r.id),
      ["sd", "sa", "rd", "ra"],
    );
  });
});

describe("formatCapPlaceholder", () => {
  it("lowercases and slugs to premier_cap_v1_*_••••", () => {
    assert.equal(formatCapPlaceholder("DATABASE_URL"), "premier_cap_v1_database_url_••••");
    assert.equal(formatCapPlaceholder("Stripe-Key.live"), "premier_cap_v1_stripe_key_live_••••");
  });
});

describe("splitLineSecretRefs", () => {
  const secrets = [
    secret({ name: "DB_URL", approval: "jit" }),
    secret({ name: "DB_URL_REPLICA", canTargetUse: false }),
    secret({ name: "LOG_LEVEL", sensitivity: "public" }),
  ];

  it("returns one text segment for a plain line, including an empty one", () => {
    assert.deepEqual(splitLineSecretRefs("let x = 1;", secrets, true), [
      { kind: "text", text: "let x = 1;" },
    ]);
    assert.deepEqual(splitLineSecretRefs("", secrets, true), [{ kind: "text", text: "" }]);
  });

  it("always turns literal premier_cap_v1 tokens into placeholders", () => {
    for (const nonOwner of [false, true]) {
      const segs = splitLineSecretRefs("url=premier_cap_v1_db_url_••••;", secrets, nonOwner);
      assert.equal(segs.length, 3);
      assert.deepEqual(segs[0], { kind: "text", text: "url=" });
      assert.deepEqual(segs[1], {
        kind: "cap_placeholder",
        varName: "DB_URL",
        placeholder: "premier_cap_v1_db_url_••••",
        canUse: true,
        approval: "jit",
      });
      assert.deepEqual(segs[2], { kind: "text", text: ";" });
    }
  });

  it("treats an unknown literal token as a usable placeholder", () => {
    const [seg] = splitLineSecretRefs("premier_cap_v1_mystery", [], false);
    assert.deepEqual(seg, {
      kind: "cap_placeholder",
      varName: "mystery",
      placeholder: "premier_cap_v1_mystery",
      canUse: true,
    });
  });

  it("matches runtime hex-nonce capability tokens to the longest declared secret", () => {
    const segs = splitLineSecretRefs(
      "a=premier_cap_v1_db_url_replica_a1b2c3d4 b=premier_cap_v1_db_url_deadbeef",
      secrets,
      true,
    );
    const caps = segs.filter((s) => s.kind === "cap_placeholder");
    assert.equal(caps.length, 2);
    assert.deepEqual(caps[0], {
      kind: "cap_placeholder",
      varName: "DB_URL_REPLICA",
      placeholder: "premier_cap_v1_db_url_replica_a1b2c3d4",
      canUse: false,
    });
    assert.deepEqual(caps[1], {
      kind: "cap_placeholder",
      varName: "DB_URL",
      placeholder: "premier_cap_v1_db_url_deadbeef",
      canUse: true,
      approval: "jit",
    });
  });

  it("leaves declared names alone for the owner", () => {
    assert.deepEqual(splitLineSecretRefs("DB_URL=1", secrets, false), [
      { kind: "text", text: "DB_URL=1" },
    ]);
  });

  it("replaces whole-word declared secrets for non-owners, longest name first", () => {
    const segs = splitLineSecretRefs("a DB_URL_REPLICA b DB_URL c", secrets, true);
    assert.deepEqual(
      segs.map((s) => (s.kind === "text" ? s.text : `<${s.varName}:${s.canUse}>`)),
      ["a ", "<DB_URL_REPLICA:false>", " b ", "<DB_URL:true>", " c"],
    );
    const jit = segs.find((s) => s.kind === "cap_placeholder" && s.varName === "DB_URL");
    assert.ok(jit && jit.kind === "cap_placeholder");
    assert.equal(jit.approval, "jit");
    assert.equal(jit.placeholder, "premier_cap_v1_db_url_••••");
  });

  it("does not match inside larger identifiers or non-secret names", () => {
    assert.deepEqual(splitLineSecretRefs("MY_DB_URL DB_URL2 xDB_URL LOG_LEVEL", secrets, true), [
      { kind: "text", text: "MY_DB_URL DB_URL2 xDB_URL LOG_LEVEL" },
    ]);
  });

  it("matches restricted names and escapes regex metacharacters", () => {
    const segs = splitLineSecretRefs("use a.b+c here, axb+c not", [
      secret({ name: "a.b+c", sensitivity: "restricted" }),
    ], true);
    assert.equal(segs.filter((s) => s.kind === "cap_placeholder").length, 1);
  });
});

describe("clampSplitPct", () => {
  it("clamps to [12, 88] and defaults non-finite to 50", () => {
    assert.equal(clampSplitPct(0), 12);
    assert.equal(clampSplitPct(100), 88);
    assert.equal(clampSplitPct(37.5), 37.5);
    assert.equal(clampSplitPct(Number.NaN), 50);
    assert.equal(clampSplitPct(Number.POSITIVE_INFINITY), 50);
  });
});

describe("ghostLineWidths", () => {
  it("is deterministic, bounded to 28..84 and capped at maxLines", () => {
    const a = ghostLineWidths(100);
    assert.equal(a.length, 18);
    assert.deepEqual(a, ghostLineWidths(100));
    assert.ok(a.every((w) => w >= 28 && w <= 84));
    assert.ok(new Set(a).size > 6, "widths should vary");
    assert.equal(ghostLineWidths(5).length, 5);
    assert.equal(ghostLineWidths(100, 4).length, 4);
  });

  it("handles zero, negative and non-finite counts", () => {
    assert.deepEqual(ghostLineWidths(0), []);
    assert.deepEqual(ghostLineWidths(-3), []);
    assert.deepEqual(ghostLineWidths(Number.NaN), []);
  });

  it("is a prefix-stable function of index only", () => {
    assert.deepEqual(ghostLineWidths(6), ghostLineWidths(18).slice(0, 6));
  });
});
