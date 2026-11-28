import { test } from "node:test";
import assert from "node:assert/strict";
import type {
  AgentSessionRecord,
  AuditEvent,
  ChangeReviewRecord,
  IdentityPreset,
  PromptProvenance,
  ReviewDiffHunk,
  ReviewRound,
} from "../src/api.ts";
import {
  buildSessionTimeline,
  findStepIndexForHunk,
  primaryHunkIdForStep,
} from "../src/lib/sessionReplay.ts";

const prov = (over: Partial<PromptProvenance> = {}): PromptProvenance => ({
  session_visible: true,
  agent_profile: "claude-coder",
  model: "opus",
  prompt_summary: "Fix the login flow",
  tool_calls: [],
  session_id: "sess-1",
  egress_calls: 2,
  bytes_scrubbed: 10,
  egress_blocked: 0,
  ...over,
});

const hunk = (id: string, path: string, over: Partial<ReviewDiffHunk> = {}): ReviewDiffHunk => ({
  id,
  path,
  zone: "public",
  header: "@@ -1 +1 @@",
  allowed: true,
  lines: ["+x"],
  provenance: prov(),
  ...over,
});

const round = (hunks: ReviewDiffHunk[]): ReviewRound => ({
  round: 1,
  commit_oid: "abc",
  label: "R1",
  created_at: "2026-11-22T00:00:00Z",
  rebased_cleanly: true,
  interdiff_summary: "",
  hunks,
});

const change = {
  change_id: "c1",
  title: "t",
  branch: "b",
  author: "alice",
  session_id: "sess-1",
  visibility: "public",
  readiness: "ready",
  quarantine_flagged: false,
  comments: [],
  verdicts: {},
  rounds: [],
} as unknown as ChangeReviewRecord;

const alice: IdentityPreset = {
  id: "alice",
  label: "Alice",
  subtitle: "",
  principal: "alice",
  groups: [],
  badgeColor: "emerald",
};

const session = {
  id: "sess-1",
  principal: "alice",
  agent_profile: "claude-coder",
  command: "claude",
  bytes_scrubbed: 999,
  output_lines: ["SECRET-SESSION-LINE proxy scrubbed 999 bytes"],
} as unknown as AgentSessionRecord;

const audit: AuditEvent = {
  timestamp: "2026-11-22T00:00:01Z",
  principal: "alice",
  agent_task_id: "sess-1",
  component: "proxy",
  action: "egress",
  target: "https://api.example.com",
  decision: "exfiltration_blocked",
  reason: "SECRET-AUDIT-REASON",
  bytes_scrubbed: 0,
};

const leaks = (t: ReturnType<typeof buildSessionTimeline>) =>
  JSON.stringify(t).includes("SECRET-SESSION-LINE") || JSON.stringify(t).includes("SECRET-AUDIT-REASON");

test("collapses consecutive reads but keeps single reads and other kinds", () => {
  const h = hunk("h1", "src/a.ts", {
    provenance: prov({
      tool_calls: [
        "rg login src",
        "cat src/a.ts",
        "read src/b.ts",
        "http GET api.example.com proxy scrubbed 42 bytes",
        "grep foo",
        "cargo test -- failed then recovered",
        "panic: policy_denied",
      ],
    }),
  });
  const t = buildSessionTimeline({ round: round([h]), change, identity: alice });
  const kinds = t.steps.map((s) => s.kind);
  assert.deepEqual(kinds, ["prompt", "read", "read", "read", "egress", "read", "test", "error", "edit"]);
  assert.equal(t.steps[4].bytesScrubbed, 42);
  assert.equal(t.steps[4].prominent, true);
  assert.equal(t.steps[6].prominent, true);
  assert.deepEqual(t.steps[2].linkedHunkIds, ["h1"]);

  const types = t.displayItems.map((d) => (d.type === "step" ? d.step.kind : `${d.label}:${d.id}`));
  assert.deepEqual(types, ["prompt", "Read 3 items:reads-1", "egress", "read", "test", "error", "edit"]);
});

test("dedupes tool calls across hunks and emits one edit per allowed hunk", () => {
  const h1 = hunk("h1", "a.ts", { provenance: prov({ tool_calls: ["cat a.ts"] }) });
  const h2 = hunk("h2", "b.ts", { provenance: prov({ tool_calls: ["cat a.ts"] }) });
  const t = buildSessionTimeline({ round: round([h1, h2]), change, identity: alice });
  assert.deepEqual(t.steps.map((s) => s.kind), ["prompt", "read", "edit", "edit"]);
});

test("findStepIndexForHunk and primaryHunkIdForStep round-trip", () => {
  const h1 = hunk("h1", "a.ts", { provenance: prov({ tool_calls: ["cat a.ts"] }) });
  const h2 = hunk("h2", "b.ts");
  const t = buildSessionTimeline({ round: round([h1, h2]), change, identity: alice });
  for (const id of ["h1", "h2"]) {
    const idx = findStepIndexForHunk(t, id);
    assert.equal(t.steps[idx].kind, "edit");
    assert.equal(primaryHunkIdForStep(t.steps[idx]), id);
  }
  assert.equal(findStepIndexForHunk(t, null), 0);
  assert.equal(findStepIndexForHunk(t, "nope"), 0);
  assert.equal(primaryHunkIdForStep(undefined), null);
  assert.equal(primaryHunkIdForStep(t.steps[0]), null);
});

test("redacted timeline when session is not visible", () => {
  const h = hunk("h1", "a.ts", {
    provenance: prov({ session_visible: false, prompt_summary: "", tool_calls: [], redaction_reason: "zone policy" }),
  });
  const t = buildSessionTimeline({
    round: round([h]),
    change,
    identity: alice,
    sessions: [session],
    auditEvents: [audit],
  });
  assert.equal(t.sessionVisible, false);
  assert.equal(t.steps[0].kind, "redacted");
  assert.equal(t.steps[0].redactionReason, "zone policy");
  assert.deepEqual(t.steps.map((s) => s.kind), ["redacted", "edit", "redacted"]);
  assert.equal(t.egressCalls, 0);
  assert.equal(t.bytesScrubbed, 0);
  assert.equal(leaks(t), false);
});

test("hidden hunks never leak path or lines", () => {
  const hidden = hunk("h2", "secret/keys.ts", {
    allowed: false,
    lines: ["+PRIVATE"],
    provenance: prov({ session_visible: false, redaction_reason: "restricted zone" }),
  });
  const t = buildSessionTimeline({ round: round([hunk("h1", "a.ts"), hidden]), change, identity: alice });
  const red = t.steps.find((s) => s.linkedHunkIds.includes("h2"));
  assert.ok(red);
  assert.equal(red.kind, "redacted");
  assert.deepEqual(red.linkedPaths, []);
  assert.equal(JSON.stringify(t).includes("secret/keys.ts"), false);
  assert.equal(JSON.stringify(t).includes("PRIVATE"), false);
  assert.equal(findStepIndexForHunk(t, "h2"), red.index);
  assert.equal(t.redactedStepsCount, 1);
});

test("enriches from sessions and audit only for the owner viewing as themselves", () => {
  const r = round([hunk("h1", "a.ts")]);
  const own = buildSessionTimeline({
    round: r,
    change,
    identity: alice,
    viewerPrincipal: "alice",
    sessions: [session],
    auditEvents: [audit],
  });
  assert.equal(leaks(own), true);
  assert.equal(own.bytesScrubbed, 999);
  assert.equal(own.egressBlocked, 1);
  assert.ok(own.steps.some((s) => s.badge === "BLOCKED"));

  const bob: IdentityPreset = { ...alice, id: "bob", principal: "bob" };
  const other = buildSessionTimeline({
    round: r,
    change,
    identity: bob,
    viewerPrincipal: "alice",
    sessions: [session],
    auditEvents: [audit],
  });
  assert.equal(leaks(other), false);
  assert.equal(other.bytesScrubbed, 10);

  const agentLens: IdentityPreset = { ...alice, agentProfile: "claude-coder" };
  const agent = buildSessionTimeline({
    round: r,
    change,
    identity: agentLens,
    viewerPrincipal: "alice",
    sessions: [session],
    auditEvents: [audit],
  });
  assert.equal(leaks(agent), false);
});

test("audit events targeting hidden or unknown file paths are dropped", () => {
  const r = round([hunk("h1", "a.ts"), hunk("h2", "secret/x.ts", { allowed: false, provenance: prov({ session_visible: false }) })]);
  const ev = (target: string, reason: string): AuditEvent => ({ ...audit, action: "read denied", target, reason, decision: "denied" });
  const t = buildSessionTimeline({
    round: r,
    change,
    identity: alice,
    viewerPrincipal: "alice",
    auditEvents: [ev("secret/x.ts", "LEAK1"), ev("other/y.ts", "LEAK2"), ev("a.ts", "OK-A")],
  });
  const json = JSON.stringify(t);
  assert.equal(json.includes("LEAK1"), false);
  assert.equal(json.includes("LEAK2"), false);
  assert.equal(json.includes("secret/x.ts"), false);
  assert.equal(json.includes("OK-A"), true);
});

test("linksFor matches hunk ids and paths on token boundaries only", () => {
  const h1 = hunk("r1-h1", "README.md", {
    provenance: prov({ tool_calls: ["cat docs/README.md", "inspect r1-h10", "cat README.md"] }),
  });
  const h10 = hunk("r1-h10", "docs/README.md");
  const t = buildSessionTimeline({ round: round([h1, h10]), change, identity: alice });
  const catDocs = t.steps.find((s) => s.title === "cat docs/README.md");
  const inspectH10 = t.steps.find((s) => s.title === "inspect r1-h10");
  const catRoot = t.steps.find((s) => s.title === "cat README.md");
  assert.deepEqual(catDocs?.linkedHunkIds, ["r1-h10"]);
  assert.deepEqual(inspectH10?.linkedHunkIds, ["r1-h10"]);
  assert.deepEqual(catRoot?.linkedHunkIds, ["r1-h1"]);
});
