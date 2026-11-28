/**
 * Pure logic for the "Two-Eyes" Glass Wall mirror: capability diffs, capability-placeholder
 * splitting and deterministic ghost geometry. No DOM/React imports, and only `import type`
 * from the API, so Node can run its tests directly (`node --test`, Node 24 type stripping).
 */
import type { MatchedRuleTrace, RepoTreeEntry } from "../api";

export const CAP_ORDER = ["traverse", "list", "read", "write", "use"] as const;
export type CapName = (typeof CAP_ORDER)[number];

export interface CapabilityDiffSummary {
  ownerCaps: string[];
  targetCaps: string[];
  /** Held by the owner, absent from the target. */
  revoked: string[];
  /** Held by the target, absent from the owner. */
  granted: string[];
  identical: boolean;
  hasServerOverride: boolean;
  /** Server Deny > Server Allow > Repo Deny > Repo Allow. */
  winningRules: MatchedRuleTrace[];
}

/** Known caps in T/L/R/W/U order (deduped), then any unknown names in their original order. */
function orderCaps(caps: readonly string[] | undefined): string[] {
  const set = new Set(caps ?? []);
  const known: string[] = CAP_ORDER.filter((c) => set.has(c));
  const extra = [...set].filter((c) => !(CAP_ORDER as readonly string[]).includes(c));
  return [...known, ...extra];
}

function ruleRank(rule: MatchedRuleTrace): number {
  return (rule.layer === "server" ? 0 : 2) + (rule.effect === "deny" ? 0 : 1);
}

export function computeCapabilityDiff(
  ownerEntry: RepoTreeEntry | null | undefined,
  targetEntry: RepoTreeEntry | null | undefined,
): CapabilityDiffSummary {
  const ownerCaps = orderCaps(ownerEntry?.effective);
  const targetCaps = orderCaps(targetEntry?.effective);
  const revoked = ownerCaps.filter((c) => !targetCaps.includes(c));
  const granted = targetCaps.filter((c) => !ownerCaps.includes(c));

  // Rule traces are owner-only on the server, so either side may carry them; merge and dedupe.
  const seen = new Set<string>();
  const rules: MatchedRuleTrace[] = [];
  for (const rule of [...(targetEntry?.matched_rules ?? []), ...(ownerEntry?.matched_rules ?? [])]) {
    const key = `${rule.layer}:${rule.effect}:${rule.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    rules.push(rule);
  }
  // Array.prototype.sort is stable, so equal ranks keep their server-reported order.
  const winningRules = rules.sort((a, b) => ruleRank(a) - ruleRank(b));

  return {
    ownerCaps,
    targetCaps,
    revoked,
    granted,
    identical: revoked.length === 0 && granted.length === 0,
    hasServerOverride: rules.some((r) => r.layer === "server"),
    winningRules,
  };
}

export interface SecretRefInfo {
  name: string;
  sensitivity: string;
  zone?: string;
  canTargetUse: boolean;
  hasEgress: boolean;
  approval?: "auto" | "jit";
}

export type LineSegment =
  | { kind: "text"; text: string }
  | {
      kind: "cap_placeholder";
      varName: string;
      placeholder: string;
      canUse: boolean;
      approval?: "auto" | "jit";
    };

const CAP_PREFIX = "premier_cap_v1_";

function slugifyVarName(varName: string): string {
  return varName.toLowerCase().replace(/[^a-z0-9]+/g, "_");
}

export function formatCapPlaceholder(varName: string): string {
  return `${CAP_PREFIX}${slugifyVarName(varName)}_••••`;
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const isSecretLike = (s: SecretRefInfo) => /^(secret|restricted)$/i.test(s.sensitivity);

/**
 * Splits one source line into text and capability-placeholder segments. Literal
 * `premier_cap_v1_*` tokens always become placeholders; declared secret/restricted variable
 * names do too, but only for a non-owner/agent reader (the owner's own view stays truthful).
 */
export function splitLineSecretRefs(
  line: string,
  secrets: SecretRefInfo[],
  isAgentOrNonOwner: boolean,
): LineSegment[] {
  const declared = secrets
    .filter(isSecretLike)
    .slice()
    .sort((a, b) => b.name.length - a.name.length);
  const names = isAgentOrNonOwner
    ? [...new Set(declared.map((s) => s.name).filter(Boolean))]
    : [];
  // Optional trailing bullets so an already-formatted placeholder re-parses as one token.
  const alternatives = [`(${CAP_PREFIX}[a-zA-Z0-9_]+•*)`];
  if (names.length > 0) {
    alternatives.push(`(?<![A-Za-z0-9_])(${names.map(escapeRegex).join("|")})(?![A-Za-z0-9_])`);
  }
  const re = new RegExp(alternatives.join("|"), "g");

  const out: LineSegment[] = [];
  let cursor = 0;
  for (const m of line.matchAll(re)) {
    const start = m.index ?? 0;
    if (start > cursor) out.push({ kind: "text", text: line.slice(cursor, start) });
    if (m[1] !== undefined) {
      // A literal token: match exact slug OR runtime `<slug>_<hex-nonce>` (longest secret name first).
      const slug = m[1].slice(CAP_PREFIX.length).replace(/_?•*$/, "");
      const info =
        declared.find((s) => slugifyVarName(s.name) === slug) ??
        declared.find((s) => slug.startsWith(`${slugifyVarName(s.name)}_`));
      out.push({
        kind: "cap_placeholder",
        varName: info?.name ?? slug,
        placeholder: m[1],
        canUse: info ? info.canTargetUse : true,
        ...(info?.approval ? { approval: info.approval } : {}),
      });
    } else {
      const info = declared.find((s) => s.name === m[2])!;
      out.push({
        kind: "cap_placeholder",
        varName: info.name,
        placeholder: formatCapPlaceholder(info.name),
        canUse: info.canTargetUse,
        ...(info.approval ? { approval: info.approval } : {}),
      });
    }
    cursor = start + m[0].length;
  }
  if (cursor < line.length || out.length === 0) out.push({ kind: "text", text: line.slice(cursor) });
  return out;
}

export function clampSplitPct(pct: number): number {
  if (!Number.isFinite(pct)) return 50;
  return Math.min(88, Math.max(12, pct));
}

/**
 * Percent widths (28..84) for the ghost outline bars behind frosted glass. Index math only:
 * a restricted file's real line lengths must never influence what is drawn.
 */
export function ghostLineWidths(lineCount: number, maxLines = 18): number[] {
  const n = Number.isFinite(lineCount) ? Math.max(0, Math.min(Math.floor(lineCount), maxLines)) : 0;
  return Array.from({ length: n }, (_, i) => 28 + ((i * 37 + i * i * 11 + 11) % 57));
}
