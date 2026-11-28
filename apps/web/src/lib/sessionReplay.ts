import type {
  AgentSessionRecord,
  AuditEvent,
  ChangeReviewRecord,
  IdentityPreset,
  ReviewDiffHunk,
  ReviewRound,
} from "../api.ts";

export type SessionStepKind =
  | "prompt"
  | "read"
  | "egress"
  | "test"
  | "edit"
  | "error"
  | "redacted";

export interface SessionStep {
  id: string;
  index: number;
  kind: SessionStepKind;
  title: string;
  detail: string;
  timestamp?: string;
  badge?: string;
  bytesScrubbed?: number;
  egressDecision?: string;
  linkedHunkIds: string[];
  linkedPaths: string[];
  redacted: boolean;
  redactionReason?: string;
  prominent: boolean;
}

export type TimelineDisplayItem =
  | { type: "step"; step: SessionStep }
  | { type: "collapsed_reads"; id: string; label: string; steps: SessionStep[] };

export interface SessionTimeline {
  steps: SessionStep[];
  displayItems: TimelineDisplayItem[];
  sessionVisible: boolean;
  agentProfile: string;
  model: string;
  promptSummary: string;
  sandbox: string | null;
  egressCalls: number;
  bytesScrubbed: number;
  egressBlocked: number;
  redactedStepsCount: number;
}

const EGRESS_RE = /proxy|egress|scrub|https?\b|exfiltrat|approval/i;
const TEST_RE = /cargo test|pnpm test|pytest|vitest|jest|\btests?\b/i;
const ERROR_RE = /error|denied|failed|panic|blocked|policy_denied/i;
const READ_RE = /\b(read|cat|rg|grep|search|ls|find|git show|git status|view|inspect)\b/i;
const DECISION_RE = /\b(exfiltration_blocked|allowed|allow|approved|approval_required|denied|deny|blocked|rate_limited|scrubbed)\b/i;

type Classified = Pick<SessionStep, "kind" | "prominent" | "bytesScrubbed" | "egressDecision" | "badge">;

// Order: egress, then test (so a failed test stays a test step), then error, then read.
function classify(line: string): Classified | null {
  if (EGRESS_RE.test(line)) {
    const bytes = /(\d+)\s*(?:B|bytes)\b/i.exec(line) ?? /scrub\w*\D{0,12}(\d+)/i.exec(line);
    const decision = DECISION_RE.exec(line)?.[1]?.toLowerCase();
    const bytesScrubbed = bytes ? Number(bytes[1]) : undefined;
    const blocked = !!decision && /block|den/.test(decision);
    return {
      kind: "egress",
      prominent: true,
      bytesScrubbed,
      egressDecision: decision,
      badge: blocked ? "BLOCKED" : bytesScrubbed ? `SCRUBBED · ${bytesScrubbed} B` : "EGRESS",
    };
  }
  if (TEST_RE.test(line)) {
    const failed = /fail|recover|panic|error/i.test(line);
    return { kind: "test", prominent: failed, badge: failed ? "RECOVERY" : "TEST" };
  }
  if (ERROR_RE.test(line)) return { kind: "error", prominent: true, badge: "ERROR" };
  if (READ_RE.test(line)) return { kind: "read", prominent: false };
  return null;
}

const visibleHunk = (h: ReviewDiffHunk) => h.allowed && !!h.provenance?.session_visible;

/** Token-boundary match so `r1-h1` never matches `r1-h10` and `README.md` never matches `docs/README.md`. */
function containsToken(haystack: string, needle: string): boolean {
  if (!needle) return false;
  let from = 0;
  while (from <= haystack.length - needle.length) {
    const idx = haystack.indexOf(needle, from);
    if (idx === -1) return false;
    const before = idx === 0 ? "" : haystack[idx - 1];
    const after = idx + needle.length >= haystack.length ? "" : haystack[idx + needle.length];
    const beforeOk = !before || !/[A-Za-z0-9_/-]/.test(before);
    const afterOk = !after || !/[A-Za-z0-9_.-]/.test(after);
    if (beforeOk && afterOk) return true;
    from = idx + 1;
  }
  return false;
}

/** A target that names a file in the repo, not an HTTP host or URL. */
function isFilePathTarget(target: string): boolean {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) return false;
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?$/i.test(target)) {
    // Bare "api.github.com" is a host; "src/main.rs" or "README.md" is a path.
    return target.includes("/") || /\.(md|rs|ts|tsx|js|jsx|json|toml|ya?ml|txt|py|go|lock|css|html|sh|env)$/i.test(target);
  }
  return target.includes("/") || target.includes(".");
}

export function buildSessionTimeline(params: {
  round: ReviewRound;
  change: ChangeReviewRecord;
  identity: IdentityPreset;
  viewerPrincipal?: string;
  sessions?: AgentSessionRecord[];
  auditEvents?: AuditEvent[];
}): SessionTimeline {
  const { round, change, identity, viewerPrincipal } = params;
  const hunks = round.hunks ?? [];
  const visible = hunks.filter(visibleHunk);
  const allowedHunks = hunks.filter((h) => h.allowed);
  const sessionVisible = visible.length > 0;
  const prov = visible[0]?.provenance;
  const hiddenReason =
    hunks.find((h) => h.provenance?.redaction_reason)?.provenance?.redaction_reason ??
    "Session details are not visible to this identity.";

  const raw: Omit<SessionStep, "index">[] = [];
  const linksFor = (line: string) => {
    const linked = allowedHunks.filter(
      (h) => containsToken(line, h.id) || (h.path && containsToken(line, h.path)),
    );
    return { linkedHunkIds: linked.map((h) => h.id), linkedPaths: linked.map((h) => h.path) };
  };

  // 1. Prompt.
  if (sessionVisible && prov) {
    raw.push({
      id: "prompt",
      kind: "prompt",
      title: "Prompt",
      detail: prov.prompt_summary,
      timestamp: prov.created_at,
      linkedHunkIds: [],
      linkedPaths: [],
      redacted: false,
      prominent: false,
    });
  } else {
    raw.push({
      id: "prompt-redacted",
      kind: "redacted",
      title: "Session redacted",
      detail: hiddenReason,
      badge: "REDACTED",
      linkedHunkIds: [],
      linkedPaths: [],
      redacted: true,
      redactionReason: hiddenReason,
      prominent: true,
    });
  }

  // 2. Tool calls from visible provenance (deduped, in order).
  const seen = new Set<string>();
  for (const h of visible) {
    for (const call of h.provenance?.tool_calls ?? []) {
      if (seen.has(call)) continue;
      seen.add(call);
      // shortcut: unrecognised tool calls are shown as reads, refine when the server types tool calls.
      const c = classify(call) ?? { kind: "read" as const, prominent: false };
      raw.push({ id: `tool-${seen.size}`, title: call, detail: call, redacted: false, ...c, ...linksFor(call) });
    }
  }

  // Enrich only for the signed-in owner viewing as themselves, never through another principal or agent lens.
  const canEnrich =
    sessionVisible &&
    (!viewerPrincipal || (identity.principal === viewerPrincipal && !identity.agentProfile));
  let sessionBytes = 0;
  let auditEgress = 0;
  let auditBlocked = 0;
  let auditBytes = 0;
  if (canEnrich) {
    const sessionIds = new Set(
      [change.session_id, ...visible.map((h) => h.provenance?.session_id)].filter((s): s is string => !!s),
    );
    const hiddenPaths = hunks.filter((h) => !h.allowed && h.path).map((h) => h.path);
    const leaksHidden = (line: string) => hiddenPaths.some((p) => line.includes(p));
    const sessions = (params.sessions ?? []).filter((s) => sessionIds.has(s.id));
    sessions.forEach((s) => {
      sessionBytes += s.bytes_scrubbed ?? 0;
      s.output_lines.forEach((line, i) => {
        if (leaksHidden(line)) return;
        const c = classify(line);
        if (!c) return;
        raw.push({ id: `out-${s.id}-${i}`, title: line, detail: `${s.command}`, redacted: false, ...c, ...linksFor(line) });
      });
    });
    const allowedPaths = new Set(allowedHunks.map((h) => h.path));
    const events = (params.auditEvents ?? [])
      .filter((e) => !!e.agent_task_id && sessionIds.has(e.agent_task_id))
      .filter((e) => !e.target || !isFilePathTarget(e.target) || allowedPaths.has(e.target))
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    events.forEach((e, i) => {
      const line = [e.component, e.action, e.target, e.decision, e.reason].filter(Boolean).join(" ");
      const c = classify(line);
      if (!c) return;
      if (c.kind === "egress") {
        auditEgress += 1;
        auditBytes += e.bytes_scrubbed ?? 0;
        c.bytesScrubbed = e.bytes_scrubbed || c.bytesScrubbed;
        c.egressDecision = e.decision;
        const blocked = e.decision === "denied" || e.decision === "exfiltration_blocked";
        if (blocked) auditBlocked += 1;
        c.badge = blocked ? "BLOCKED" : c.bytesScrubbed ? `SCRUBBED · ${c.bytesScrubbed} B` : "EGRESS";
      }
      raw.push({
        id: `audit-${i}`,
        title: `${e.action}${e.target ? ` ${e.target}` : ""}`,
        detail: e.reason,
        timestamp: e.timestamp,
        redacted: false,
        ...c,
        ...linksFor(e.target ?? ""),
      });
    });
  }

  // 3. Edits for every hunk this identity can read.
  for (const h of allowedHunks) {
    raw.push({
      id: `edit-${h.id}`,
      kind: "edit",
      title: `Edit ${h.path}`,
      detail: h.header,
      linkedHunkIds: [h.id],
      linkedPaths: [h.path],
      redacted: false,
      prominent: false,
    });
  }

  // 4. Honest redaction markers; hidden hunks never expose path or lines.
  for (const h of hunks) {
    if (h.allowed && h.provenance?.session_visible) continue;
    const reason = h.provenance?.redaction_reason ?? hiddenReason;
    raw.push({
      id: `redacted-${h.id}`,
      kind: "redacted",
      title: h.allowed ? `Session hidden · ${h.path}` : "Hidden hunk",
      detail: reason,
      badge: "REDACTED",
      linkedHunkIds: [h.id],
      linkedPaths: h.allowed ? [h.path] : [],
      redacted: true,
      redactionReason: reason,
      prominent: true,
    });
  }

  const steps: SessionStep[] = raw.map((s, index) => ({ ...s, index }));
  const maxProv = (key: "egress_calls" | "bytes_scrubbed" | "egress_blocked") =>
    Math.max(0, ...visible.map((h) => h.provenance?.[key] ?? 0));

  return {
    steps,
    displayItems: collapseReads(steps),
    sessionVisible,
    agentProfile: prov?.agent_profile ?? "redacted",
    model: prov?.model ?? "redacted",
    promptSummary: prov?.prompt_summary ?? "",
    sandbox: prov?.sandbox ?? null,
    egressCalls: Math.max(maxProv("egress_calls"), auditEgress),
    bytesScrubbed: Math.max(maxProv("bytes_scrubbed"), sessionBytes, auditBytes),
    egressBlocked: Math.max(maxProv("egress_blocked"), auditBlocked),
    redactedStepsCount: steps.filter((s) => s.redacted).length,
  };
}

function collapseReads(steps: SessionStep[]): TimelineDisplayItem[] {
  const out: TimelineDisplayItem[] = [];
  let run: SessionStep[] = [];
  const flush = () => {
    if (run.length >= 2) {
      out.push({ type: "collapsed_reads", id: `reads-${run[0].index}`, label: `Read ${run.length} items`, steps: run });
    } else {
      run.forEach((step) => out.push({ type: "step", step }));
    }
    run = [];
  };
  for (const step of steps) {
    if (step.kind === "read") {
      run.push(step);
    } else {
      flush();
      out.push({ type: "step", step });
    }
  }
  flush();
  return out;
}

export function findStepIndexForHunk(timeline: SessionTimeline, hunkId: string | null): number {
  if (!hunkId) return 0;
  const linked = timeline.steps.filter((s) => s.linkedHunkIds.includes(hunkId));
  return (linked.find((s) => s.kind === "edit" || s.kind === "redacted") ?? linked[0])?.index ?? 0;
}

export function primaryHunkIdForStep(step: SessionStep | undefined): string | null {
  return step?.linkedHunkIds[0] ?? null;
}
