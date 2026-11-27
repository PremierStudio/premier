import type { AccessImpactDiff, MatchedRuleTrace } from "../api";

export type PolicyTarget =
  | { kind: "file"; path: string }
  | { kind: "dir"; path: string }
  | { kind: "zone"; zone: string };

export type PolicyIntent =
  | { kind: "shield_from_anonymous"; target: PolicyTarget; reason?: string }
  | { kind: "shield_from_all_agents"; target: PolicyTarget; reason?: string }
  | { kind: "shield_from_agent"; target: PolicyTarget; agent_profile: string; reason?: string }
  | {
      kind: "allow_agent_access";
      target: PolicyTarget;
      agent_profile: string;
      write: boolean;
      reason?: string;
    }
  | {
      kind: "restrict_to_principals";
      target: PolicyTarget;
      principals: string[];
      write: boolean;
      reason?: string;
    }
  | {
      kind: "allow_agent_secret_use";
      var_name: string;
      zone?: string;
      agent_profile: string;
      human_principals: string[];
      reason?: string;
    }
  | {
      kind: "revoke_agent_secret_use";
      var_name: string;
      zone?: string;
      agent_profile: string;
      reason?: string;
    };

export interface SecretProbeInput {
  var_name: string;
  zone?: string;
}

export interface ServerPolicyOverrideFinding {
  principal: string;
  agent_profile?: string;
  path: string;
  repo_only_effective: string[];
  effective_with_server: string[];
  server_rules: MatchedRuleTrace[];
}

export interface ServerOverrideCheck {
  passed: boolean;
  total_overrides: number;
  overrides: ServerPolicyOverrideFinding[];
}

export interface ProposePolicyIntentResponse {
  base_toml: string;
  base_sha256: string;
  proposed_toml: string;
  rule_id: string;
  summary: string;
  warnings: string[];
  validation_error?: string | null;
  server_policy_loaded: boolean;
  server_override_check: ServerOverrideCheck;
  target_paths: string[];
  secret_probes: SecretProbeInput[];
}

export interface BlastRadiusActorSummary {
  actor: string;
  capabilities: string[];
  pathCount: number;
  critical: boolean;
}

export interface BlastRadiusSummary {
  headline: string;
  revoked: BlastRadiusActorSummary[];
  granted: BlastRadiusActorSummary[];
  unchangedAgents: string[];
  serverCheckPassed: boolean;
  serverCheckLabel: string;
  totalDeltas: number;
}

export interface TomlDiffLine {
  kind: "ctx" | "add" | "del" | "gap";
  line: string;
  oldLine?: number;
  newLine?: number;
}

const CAPABILITY_ORDER = ["traverse", "list", "read", "write", "use"] as const;

function normalizeRepoPath(raw: string): string {
  return raw.trim().replace(/\\/g, "/").replace(/^\/+/, "").replace(/\/+$/, "");
}

function escapeRegexChar(ch: string): string {
  return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function globToRegExp(rawPattern: string): RegExp {
  const trimmed = rawPattern.trim().replace(/\\/g, "/").replace(/^\/+/, "");
  const isDirPrefix = trimmed.endsWith("/") && trimmed.length > 1;
  const pattern = trimmed.replace(/\/+$/, "");

  if (pattern === "**") {
    return /^.*$/;
  }
  if (pattern === "") {
    return /^$/;
  }

  let regex = "^";
  let i = 0;

  while (i < pattern.length) {
    const ch = pattern[i];

    // Escaped literal character
    if (ch === "\\" && i + 1 < pattern.length) {
      regex += escapeRegexChar(pattern[i + 1]);
      i += 2;
      continue;
    }

    // Double-star directory wildcard
    if (ch === "*" && pattern[i + 1] === "*") {
      const prev = i > 0 ? pattern[i - 1] : "";
      const next = pattern[i + 2] ?? "";

      if (i === 0 && next === "/") {
        // Leading `**/` matches zero or more directory segments
        regex += "(?:.+/)?";
        i += 3;
        continue;
      }
      if (prev === "/" && next === "/") {
        // Middle `/**/` matches `/` or `/.+/` (previous `/` was already emitted; backtrack it)
        regex = regex.slice(0, -1) + "/(?:.+/)?";
        i += 3;
        continue;
      }
      if (prev === "/" && i + 2 === pattern.length) {
        // Trailing `/**` matches both the directory itself and anything beneath it
        regex = regex.slice(0, -1) + "(?:/.*)?";
        i += 2;
        continue;
      }
      regex += ".*";
      i += 2;
      continue;
    }

    if (ch === "*") {
      regex += "[^/]*";
      i += 1;
      continue;
    }

    if (ch === "?") {
      regex += "[^/]";
      i += 1;
      continue;
    }

    if (ch === "{") {
      const close = pattern.indexOf("}", i + 1);
      if (close > i + 1) {
        const alts = pattern
          .slice(i + 1, close)
          .split(",")
          .map((alt) =>
            alt
              .split("")
              .map((c) => escapeRegexChar(c))
              .join(""),
          );
        regex += `(?:${alts.join("|")})`;
        i = close + 1;
        continue;
      }
    }

    if (ch === "[") {
      const close = pattern.indexOf("]", i + 1);
      if (close > i + 1) {
        let body = pattern.slice(i + 1, close);
        if (body.startsWith("!")) body = `^${body.slice(1)}`;
        regex += `[${body}]`;
        i = close + 1;
        continue;
      }
    }

    regex += escapeRegexChar(ch);
    i += 1;
  }

  if (isDirPrefix) {
    regex += "(?:/.*)?";
  }

  regex += "$";
  return new RegExp(regex);
}

function matchesGlobPattern(pattern: string, normalizedPath: string): boolean {
  const trimmed = pattern.trim().replace(/\\/g, "/").replace(/^\/+/, "");
  if (!trimmed) return normalizedPath === "";
  if (trimmed === "**") return true;
  if (trimmed === "*") return !normalizedPath.includes("/");
  return globToRegExp(trimmed).test(normalizedPath);
}

/**
 * Inspects `policyObj?.zones` (from `PolicySummaryResponse.policy`) and matches `path`
 * against each zone's `paths` and `exclude` globs, returning matching zone names sorted alphabetically.
 */
export function matchingZonesForPath(path: string, policyObj: unknown): string[] {
  if (!policyObj || typeof policyObj !== "object") return [];
  const zones = (policyObj as { zones?: unknown }).zones;
  if (!zones || typeof zones !== "object" || Array.isArray(zones)) return [];

  const normalized = normalizeRepoPath(path);
  const matched: string[] = [];

  for (const [zoneName, rawCfg] of Object.entries(zones as Record<string, unknown>)) {
    if (!zoneName || !rawCfg || typeof rawCfg !== "object") continue;
    const cfg = rawCfg as { paths?: unknown; exclude?: unknown };
    const includePatterns = Array.isArray(cfg.paths)
      ? cfg.paths.filter((p): p is string => typeof p === "string" && p.trim() !== "")
      : [];
    if (includePatterns.length === 0) continue;

    const excludePatterns = Array.isArray(cfg.exclude)
      ? cfg.exclude.filter((p): p is string => typeof p === "string" && p.trim() !== "")
      : [];

    const included = includePatterns.some((pattern) => matchesGlobPattern(pattern, normalized));
    if (!included) continue;

    const excluded = excludePatterns.some((pattern) => matchesGlobPattern(pattern, normalized));
    if (!excluded) {
      matched.push(zoneName);
    }
  }

  return matched.sort();
}

function sortCapabilities(caps: Iterable<string>): string[] {
  const unique = Array.from(new Set(caps));
  const order = new Map<string, number>(CAPABILITY_ORDER.map((c, idx) => [c, idx]));
  return unique.sort((a, b) => {
    const ia = order.get(a);
    const ib = order.get(b);
    if (ia !== undefined && ib !== undefined) return ia - ib;
    if (ia !== undefined) return -1;
    if (ib !== undefined) return 1;
    return a.localeCompare(b);
  });
}

function formatActor(principal: string, agentProfile?: string): string {
  return agentProfile ? `${principal} ∩ ${agentProfile}` : principal;
}

function formatTargetCount(paths: Set<string>): string {
  const count = paths.size;
  const allSecrets = count > 0 && Array.from(paths).every((p) => p.startsWith("secret:"));
  const noun = allSecrets ? (count === 1 ? "secret" : "secrets") : count === 1 ? "file" : "files";
  return `${count} ${noun}`;
}

interface ActorBucket {
  caps: Set<string>;
  paths: Set<string>;
}

/**
 * Summarizes an `AccessImpactDiff` + `ServerOverrideCheck` into a crisp, human-readable
 * blast-radius summary for direct-manipulation policy authoring.
 */
export function summarizeBlastRadius(
  diff: AccessImpactDiff | null,
  serverCheck: ServerOverrideCheck | null,
  declaredAgents?: string[],
  serverPolicyLoaded?: boolean,
): BlastRadiusSummary {
  const revokedBuckets = new Map<string, ActorBucket>();
  const grantedBuckets = new Map<string, ActorBucket>();
  const changedAgentProfiles = new Set<string>();

  const deltas = diff?.deltas ?? [];
  for (const d of deltas) {
    const actor = formatActor(d.principal, d.agent_profile);
    const hasRevoked = d.revoked.length > 0;
    const hasGranted = d.granted.length > 0;

    if (d.agent_profile && (hasRevoked || hasGranted)) {
      changedAgentProfiles.add(d.agent_profile);
    }

    if (hasRevoked) {
      let bucket = revokedBuckets.get(actor);
      if (!bucket) {
        bucket = { caps: new Set(), paths: new Set() };
        revokedBuckets.set(actor, bucket);
      }
      for (const cap of d.revoked) bucket.caps.add(cap);
      bucket.paths.add(d.path);
    }

    if (hasGranted) {
      let bucket = grantedBuckets.get(actor);
      if (!bucket) {
        bucket = { caps: new Set(), paths: new Set() };
        grantedBuckets.set(actor, bucket);
      }
      for (const cap of d.granted) bucket.caps.add(cap);
      bucket.paths.add(d.path);
    }
  }

  const toSummaries = (
    buckets: Map<string, ActorBucket>,
    markCritical: boolean,
  ): BlastRadiusActorSummary[] => {
    const items: BlastRadiusActorSummary[] = [];
    for (const [actor, bucket] of buckets.entries()) {
      const capabilities = sortCapabilities(bucket.caps);
      const critical =
        markCritical && (capabilities.includes("write") || capabilities.includes("use"));
      items.push({
        actor,
        capabilities,
        pathCount: bucket.paths.size,
        critical,
      });
    }
    items.sort((a, b) => {
      if (a.critical !== b.critical) return a.critical ? -1 : 1;
      if (a.pathCount !== b.pathCount) return b.pathCount - a.pathCount;
      return a.actor.localeCompare(b.actor);
    });
    return items;
  };

  const revoked = toSummaries(revokedBuckets, false);
  const granted = toSummaries(grantedBuckets, true);

  const uniqueDeclaredAgents = Array.from(
    new Set((declaredAgents ?? []).map((a) => a.trim()).filter(Boolean)),
  );
  const unchangedAgents =
    diff === null
      ? []
      : uniqueDeclaredAgents.filter((agent) => !changedAgentProfiles.has(agent));

  let serverCheckPassed = true;
  let serverCheckLabel: string;

  if (serverCheck) {
    serverCheckPassed = serverCheck.passed;
    if (serverCheck.passed) {
      serverCheckLabel = "Server Policy override check: ✓ passed";
    } else {
      const count = serverCheck.total_overrides || serverCheck.overrides.length;
      serverCheckLabel = `Server Policy override check: ⚠ ${count} overridden by Server Policy`;
    }
  } else if (serverPolicyLoaded === false) {
    serverCheckPassed = true;
    serverCheckLabel = "Server Policy override check: ✓ passed";
  } else {
    serverCheckPassed = true;
    serverCheckLabel = "Server Policy override check: pending";
  }

  const segments: string[] = [];

  if (diff === null) {
    segments.push("Simulating blast radius…");
  } else if (revoked.length === 0 && granted.length === 0) {
    segments.push("No effective capability changes");
  } else {
    const maxPerGroup = 2;
    for (const item of revoked.slice(0, maxPerGroup)) {
      const bucket = revokedBuckets.get(item.actor)!;
      segments.push(
        `Revokes ${item.capabilities.join(", ")} from ${item.actor} on ${formatTargetCount(bucket.paths)}`,
      );
    }
    if (revoked.length > maxPerGroup) {
      segments.push(`+${revoked.length - maxPerGroup} more tightened`);
    }

    for (const item of granted.slice(0, maxPerGroup)) {
      const bucket = grantedBuckets.get(item.actor)!;
      segments.push(
        `Grants ${item.capabilities.join(", ")} to ${item.actor} on ${formatTargetCount(bucket.paths)}`,
      );
    }
    if (granted.length > maxPerGroup) {
      segments.push(`+${granted.length - maxPerGroup} more escalated`);
    }
  }

  if (unchangedAgents.length > 0) {
    if (unchangedAgents.length <= 2) {
      segments.push(`${unchangedAgents.join(", ")} unchanged`);
    } else {
      segments.push(
        `${unchangedAgents.slice(0, 2).join(", ")} +${unchangedAgents.length - 2} agents unchanged`,
      );
    }
  }

  if (serverCheck !== null || serverPolicyLoaded !== undefined) {
    segments.push(serverCheckLabel);
  }

  return {
    headline: segments.join(" · "),
    revoked,
    granted,
    unchangedAgents,
    serverCheckPassed,
    serverCheckLabel,
    totalDeltas: deltas.length,
  };
}

function splitTomlLines(text: string): string[] {
  if (text === "") return [];
  const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const lines = normalized.split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    lines.pop();
  }
  return lines;
}

/**
 * Computes an LCS line diff between `baseToml` and `proposedToml`, collapsing long
 * unchanged sections into `"gap"` markers while keeping `contextLines` around every change.
 */
export function computeTomlLineDiff(
  baseToml: string,
  proposedToml: string,
  contextLines = 2,
): TomlDiffLine[] {
  const oldLines = splitTomlLines(baseToml);
  const newLines = splitTomlLines(proposedToml);

  const m = oldLines.length;
  const n = newLines.length;

  // Trim identical prefix & suffix so typical single-rule policy additions run in O(k).
  let prefix = 0;
  while (prefix < m && prefix < n && oldLines[prefix] === newLines[prefix]) {
    prefix += 1;
  }

  let suffix = 0;
  while (
    suffix < m - prefix &&
    suffix < n - prefix &&
    oldLines[m - 1 - suffix] === newLines[n - 1 - suffix]
  ) {
    suffix += 1;
  }

  const midOld = oldLines.slice(prefix, m - suffix);
  const midNew = newLines.slice(prefix, n - suffix);

  if (midOld.length === 0 && midNew.length === 0) {
    return [];
  }

  const raw: TomlDiffLine[] = [];

  for (let i = 0; i < prefix; i += 1) {
    raw.push({ kind: "ctx", line: oldLines[i], oldLine: i + 1, newLine: i + 1 });
  }

  const aLen = midOld.length;
  const bLen = midNew.length;

  if (aLen === 0) {
    for (let j = 0; j < bLen; j += 1) {
      raw.push({ kind: "add", line: midNew[j], newLine: prefix + j + 1 });
    }
  } else if (bLen === 0) {
    for (let i = 0; i < aLen; i += 1) {
      raw.push({ kind: "del", line: midOld[i], oldLine: prefix + i + 1 });
    }
  } else {
    // Classic bottom-up LCS table over the middle slice.
    const cols = bLen + 1;
    const dp = new Int32Array((aLen + 1) * cols);

    for (let i = aLen - 1; i >= 0; i -= 1) {
      const rowOffset = i * cols;
      const nextRowOffset = (i + 1) * cols;
      for (let j = bLen - 1; j >= 0; j -= 1) {
        if (midOld[i] === midNew[j]) {
          dp[rowOffset + j] = dp[nextRowOffset + j + 1] + 1;
        } else {
          const down = dp[nextRowOffset + j];
          const right = dp[rowOffset + j + 1];
          dp[rowOffset + j] = down >= right ? down : right;
        }
      }
    }

    let i = 0;
    let j = 0;
    while (i < aLen && j < bLen) {
      if (midOld[i] === midNew[j]) {
        raw.push({
          kind: "ctx",
          line: midOld[i],
          oldLine: prefix + i + 1,
          newLine: prefix + j + 1,
        });
        i += 1;
        j += 1;
      } else if (dp[(i + 1) * cols + j] >= dp[i * cols + (j + 1)]) {
        raw.push({
          kind: "del",
          line: midOld[i],
          oldLine: prefix + i + 1,
        });
        i += 1;
      } else {
        raw.push({
          kind: "add",
          line: midNew[j],
          newLine: prefix + j + 1,
        });
        j += 1;
      }
    }
    while (i < aLen) {
      raw.push({ kind: "del", line: midOld[i], oldLine: prefix + i + 1 });
      i += 1;
    }
    while (j < bLen) {
      raw.push({ kind: "add", line: midNew[j], newLine: prefix + j + 1 });
      j += 1;
    }
  }

  for (let s = 0; s < suffix; s += 1) {
    const oldIdx = m - suffix + s;
    const newIdx = n - suffix + s;
    raw.push({
      kind: "ctx",
      line: oldLines[oldIdx],
      oldLine: oldIdx + 1,
      newLine: newIdx + 1,
    });
  }

  const ctx = Math.max(0, Math.floor(contextLines));
  const keep = new Uint8Array(raw.length);

  for (let idx = 0; idx < raw.length; idx += 1) {
    if (raw[idx].kind === "add" || raw[idx].kind === "del") {
      const start = Math.max(0, idx - ctx);
      const end = Math.min(raw.length - 1, idx + ctx);
      for (let k = start; k <= end; k += 1) {
        keep[k] = 1;
      }
    }
  }

  const collapsed: TomlDiffLine[] = [];
  let inGap = false;
  for (let idx = 0; idx < raw.length; idx += 1) {
    if (keep[idx]) {
      inGap = false;
      collapsed.push(raw[idx]);
    } else if (!inGap) {
      inGap = true;
      collapsed.push({ kind: "gap", line: "..." });
    }
  }

  return collapsed;
}
