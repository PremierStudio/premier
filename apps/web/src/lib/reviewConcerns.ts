export type ConcernId =
  | "policy_security"
  | "schema_types"
  | "engine_server"
  | "ui_components"
  | "tests"
  | "boilerplate";

export type RiskLevel = "critical" | "high" | "medium" | "low";

export interface ConcernDefinition {
  id: ConcernId;
  order: number;
  label: string;
  shortLabel: string;
  description: string;
  defaultCollapsed: boolean;
}

export const CONCERN_DEFINITIONS: readonly ConcernDefinition[] = [
  {
    id: "policy_security",
    order: 1,
    label: "1. Policy & Security Boundaries",
    shortLabel: "Policy & Security",
    description:
      "Access policies, quarantined instruction files, secret schemas, redacted items, and sensitive security zones.",
    defaultCollapsed: false,
  },
  {
    id: "schema_types",
    order: 2,
    label: "2. Schema & Core Types",
    shortLabel: "Schema & Types",
    description: "Core data models, storage schemas, API contracts, and shared type definitions.",
    defaultCollapsed: false,
  },
  {
    id: "engine_server",
    order: 3,
    label: "3. Engine / Server Logic",
    shortLabel: "Engine & Server",
    description: "Backend crates, server handlers, and core runtime implementation.",
    defaultCollapsed: false,
  },
  {
    id: "ui_components",
    order: 4,
    label: "4. UI Components",
    shortLabel: "UI Components",
    description: "Frontend views, interactive components, styles, and visual assets.",
    defaultCollapsed: false,
  },
  {
    id: "tests",
    order: 5,
    label: "5. Tests & Verification",
    shortLabel: "Tests",
    description: "Automated test suites, specifications, and verification fixtures.",
    defaultCollapsed: false,
  },
  {
    id: "boilerplate",
    order: 6,
    label: "6. Lockfiles / Boilerplate",
    shortLabel: "Boilerplate",
    description: "Lockfiles, generated outputs, documentation, and package manifests.",
    defaultCollapsed: true,
  },
] as const;

export interface PathClassification {
  concern: ConcernId;
  risk: RiskLevel;
  riskReasons: string[];
  autoCollapsed: boolean;
  isInstructionFile: boolean;
  isPolicyFile: boolean;
  isEnvSchema: boolean;
  isSensitiveZone: boolean;
}

export interface GroupedConcernItem<T> {
  id: string;
  path: string;
  item: T;
  classification: PathClassification;
  churn: number;
  zone: string;
  allowed: boolean;
}

export interface ConcernGroup<T> {
  definition: ConcernDefinition;
  items: GroupedConcernItem<T>[];
  highestRisk: RiskLevel;
  totalChurn: number;
  defaultCollapsed: boolean;
}

export interface RiskRadarSignal {
  id: string;
  label: string;
  detail: string;
  severity: "critical" | "warn" | "info";
  kind: "policy" | "env_schema" | "quarantine" | "redacted" | "sensitive_zone";
  paths: string[];
}

const RISK_RANK: Record<RiskLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const INSTRUCTION_BASENAMES = new Set([
  "agents.md",
  "claude.md",
  ".cursorrules",
  "copilot-instructions.md",
]);

const POLICY_BASENAMES = new Set([".access.toml", "server-policy.toml"]);

const LOCKFILE_BASENAMES = new Set([
  "cargo.lock",
  "pnpm-lock.yaml",
  "package-lock.json",
  "yarn.lock",
]);

const SENSITIVE_ZONES = new Set([
  "billing",
  "secrets",
  "auth",
  "policy",
  "security",
  "admin",
  "private",
  "embargo",
]);

const SECURITY_SOURCE_TOKENS = new Set([
  "security",
  "auth",
  "acl",
  "policy",
  "proxy",
  "secret",
  "secrets",
  "sandbox",
  "cage",
  "overlay",
  "overlays",
  "billing",
]);

const SECURITY_TEST_TOKENS = new Set(["security", "auth", "acl", "policy"]);

const SCHEMA_TOKENS = new Set(["schema", "types", "models"]);

function normalizePath(path: string): string {
  return path.trim().replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/^\/+/, "");
}

function splitTokens(input: string): string[] {
  return input
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((token) => token.length > 0);
}

function compareLex(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

function isLockfileOrGenerated(baseLower: string): boolean {
  if (LOCKFILE_BASENAMES.has(baseLower)) return true;
  if (baseLower.endsWith(".lock")) return true;
  if (baseLower.endsWith(".snap")) return true;
  if (baseLower.includes(".min.")) return true;
  if (baseLower.includes(".generated.")) return true;
  return false;
}

function isTestPath(normalizedLower: string, baseLower: string): boolean {
  if (
    normalizedLower.startsWith("tests/") ||
    normalizedLower.includes("/tests/") ||
    normalizedLower.startsWith("__tests__/") ||
    normalizedLower.includes("/__tests__/") ||
    normalizedLower.startsWith("fixtures/") ||
    normalizedLower.includes("/fixtures/")
  ) {
    return true;
  }
  return /(_tests?|\.(?:test|spec))\.[^/]+$/i.test(baseLower);
}

function isDocOrConfigBoilerplate(normalizedLower: string, baseLower: string): boolean {
  if (baseLower.endsWith(".md")) return true;
  if (normalizedLower.startsWith("docs/") || normalizedLower.includes("/docs/")) return true;
  if (baseLower === ".gitignore") return true;
  if (baseLower.startsWith("license")) return true;
  if (/^tsconfig.*\.json$/i.test(baseLower)) return true;
  if (baseLower === "package.json" || baseLower === "cargo.toml") return true;
  return false;
}

function hasSensitiveZone(segmentsLower: readonly string[], zone?: string): boolean {
  if (zone && splitTokens(zone).some((t) => SENSITIVE_ZONES.has(t))) {
    return true;
  }
  return segmentsLower.some((seg) => SENSITIVE_ZONES.has(seg));
}

function isSchemaOrTypesPath(
  normalizedLower: string,
  baseLower: string,
  pathTokens: readonly string[],
): boolean {
  if (
    normalizedLower.startsWith("premier-core/") ||
    normalizedLower.includes("/premier-core/")
  ) {
    return true;
  }
  if (baseLower === "api.ts" || baseLower === "store.rs") return true;
  if (
    baseLower.endsWith(".sql") ||
    baseLower.endsWith(".proto") ||
    baseLower.endsWith(".d.ts")
  ) {
    return true;
  }
  return pathTokens.some((t) => SCHEMA_TOKENS.has(t));
}

function isUiComponentPath(normalizedLower: string, baseLower: string): boolean {
  if (
    normalizedLower.startsWith("apps/web/src/components/") ||
    normalizedLower.includes("/apps/web/src/components/")
  ) {
    return true;
  }
  return (
    baseLower.endsWith(".tsx") ||
    baseLower.endsWith(".jsx") ||
    baseLower.endsWith(".css") ||
    baseLower.endsWith(".html") ||
    baseLower.endsWith(".svg")
  );
}

export function classifyPathConcern(
  path: string,
  opts?: { allowed?: boolean; zone?: string; churn?: number },
): PathClassification {
  const allowed = opts?.allowed !== false;
  const churn = opts?.churn ?? 0;
  const normalized = normalizePath(path);
  const normalizedLower = normalized.toLowerCase();
  const segmentsLower = normalizedLower.split("/").filter((s) => s.length > 0);
  const baseLower = segmentsLower[segmentsLower.length - 1] ?? normalizedLower;

  const isInstructionFile = allowed && INSTRUCTION_BASENAMES.has(baseLower);
  const isPolicyFile = allowed && POLICY_BASENAMES.has(baseLower);
  const isEnvSchema = allowed && baseLower === ".env.schema";
  const isSensitiveZone = allowed && hasSensitiveZone(segmentsLower, opts?.zone);

  // 1. Instruction files, policy files, .env.schema, or redacted items -> critical policy_security
  if (!allowed || isInstructionFile || isPolicyFile || isEnvSchema) {
    const riskReasons: string[] = [];
    if (!allowed) riskReasons.push("Redacted under active access policy");
    if (isInstructionFile) {
      riskReasons.push("Quarantined agent instruction file (untrusted surface)");
    }
    if (isPolicyFile) riskReasons.push("Access control policy boundary file");
    if (isEnvSchema) riskReasons.push("Secret capability and egress schema (.env.schema)");
    if (isSensitiveZone) riskReasons.push("Touches sensitive access zone");
    return {
      concern: "policy_security",
      risk: "critical",
      riskReasons,
      autoCollapsed: false,
      isInstructionFile,
      isPolicyFile,
      isEnvSchema,
      isSensitiveZone,
    };
  }

  // 2. Lockfiles & generated artifacts
  if (isLockfileOrGenerated(baseLower)) {
    return {
      concern: "boilerplate",
      risk: "low",
      riskReasons: ["Lockfile or generated artifact"],
      autoCollapsed: true,
      isInstructionFile: false,
      isPolicyFile: false,
      isEnvSchema: false,
      isSensitiveZone,
    };
  }

  const pathTokens = splitTokens(normalizedLower);
  const zoneTokens = opts?.zone ? splitTokens(opts.zone) : [];

  // 3. Tests
  if (isTestPath(normalizedLower, baseLower)) {
    const securityRelated =
      pathTokens.some((t) => SECURITY_TEST_TOKENS.has(t)) ||
      zoneTokens.some((t) => SECURITY_TEST_TOKENS.has(t));
    return {
      concern: "tests",
      risk: securityRelated ? "medium" : "low",
      riskReasons: securityRelated ? ["Security, auth, ACL, or policy test coverage"] : [],
      autoCollapsed: false,
      isInstructionFile: false,
      isPolicyFile: false,
      isEnvSchema: false,
      isSensitiveZone,
    };
  }

  // 4. Security / auth / ACL / policy / proxy / secrets / sandbox / cage / overlay / billing
  //    source files or sensitive zone
  const isSecuritySource =
    !isDocOrConfigBoilerplate(normalizedLower, baseLower) &&
    pathTokens.some((t) => SECURITY_SOURCE_TOKENS.has(t));

  if (isSensitiveZone || isSecuritySource) {
    const riskReasons: string[] = [];
    if (isSensitiveZone) {
      riskReasons.push("Touches sensitive zone");
    }
    if (isSecuritySource) {
      riskReasons.push("Security, policy, secret, sandbox, or billing boundary code");
    }
    return {
      concern: "policy_security",
      risk: "high",
      riskReasons,
      autoCollapsed: false,
      isInstructionFile: false,
      isPolicyFile: false,
      isEnvSchema: false,
      isSensitiveZone,
    };
  }

  // 5. Schema & core types
  if (isSchemaOrTypesPath(normalizedLower, baseLower, pathTokens)) {
    const highChurn = churn > 120;
    const riskReasons = highChurn
      ? ["Core schema or type contract", "High churn (>120 lines)"]
      : ["Core schema or type contract"];
    return {
      concern: "schema_types",
      risk: highChurn ? "high" : "medium",
      riskReasons,
      autoCollapsed: false,
      isInstructionFile: false,
      isPolicyFile: false,
      isEnvSchema: false,
      isSensitiveZone: false,
    };
  }

  // 6. UI components
  if (isUiComponentPath(normalizedLower, baseLower)) {
    const largeUi = churn > 150;
    return {
      concern: "ui_components",
      risk: largeUi ? "medium" : "low",
      riskReasons: largeUi ? ["Large UI change (>150 lines)"] : [],
      autoCollapsed: false,
      isInstructionFile: false,
      isPolicyFile: false,
      isEnvSchema: false,
      isSensitiveZone: false,
    };
  }

  // 7. Docs & config boilerplate
  if (isDocOrConfigBoilerplate(normalizedLower, baseLower)) {
    return {
      concern: "boilerplate",
      risk: "low",
      riskReasons: [],
      autoCollapsed: true,
      isInstructionFile: false,
      isPolicyFile: false,
      isEnvSchema: false,
      isSensitiveZone: false,
    };
  }

  // 8. Engine / server logic (fallback)
  const highChurn = churn > 120;
  return {
    concern: "engine_server",
    risk: highChurn ? "high" : "medium",
    riskReasons: highChurn ? ["High churn (>120 lines) in engine/server logic"] : [],
    autoCollapsed: false,
    isInstructionFile: false,
    isPolicyFile: false,
    isEnvSchema: false,
    isSensitiveZone: false,
  };
}

export function groupItemsByConcern<T>(
  items: readonly T[],
  getMeta: (item: T) => {
    id: string;
    path: string;
    allowed?: boolean;
    zone?: string;
    churn?: number;
  },
): ConcernGroup<T>[] {
  const buckets = new Map<ConcernId, GroupedConcernItem<T>[]>();

  for (const item of items) {
    const meta = getMeta(item);
    const allowed = meta.allowed !== false;
    const churn = meta.churn ?? 0;
    const safeZone = allowed ? (meta.zone ?? "") : "";
    const classification = classifyPathConcern(meta.path, {
      allowed,
      zone: allowed ? meta.zone : undefined,
      churn,
    });
    const entry: GroupedConcernItem<T> = {
      id: meta.id,
      path: meta.path,
      item,
      classification,
      churn,
      zone: safeZone,
      allowed,
    };
    const list = buckets.get(classification.concern);
    if (list) list.push(entry);
    else buckets.set(classification.concern, [entry]);
  }

  const groups: ConcernGroup<T>[] = [];
  for (const definition of CONCERN_DEFINITIONS) {
    const grouped = buckets.get(definition.id);
    if (!grouped || grouped.length === 0) continue;

    grouped.sort((a, b) => {
      const riskDelta = RISK_RANK[b.classification.risk] - RISK_RANK[a.classification.risk];
      if (riskDelta !== 0) return riskDelta;
      if (b.churn !== a.churn) return b.churn - a.churn;
      const pathDelta = compareLex(a.path, b.path);
      if (pathDelta !== 0) return pathDelta;
      return compareLex(a.id, b.id);
    });

    const totalChurn = grouped.reduce((sum, entry) => sum + entry.churn, 0);
    groups.push({
      definition,
      items: grouped,
      highestRisk: grouped[0].classification.risk,
      totalChurn,
      defaultCollapsed: definition.defaultCollapsed,
    });
  }

  return groups;
}

function uniqueSorted(values: Iterable<string>): string[] {
  return Array.from(new Set(values)).sort(compareLex);
}

export function computeRiskRadar(
  items: ReadonlyArray<{ path: string; allowed?: boolean; zone?: string }>,
  quarantineFlagged?: boolean,
): RiskRadarSignal[] {
  const policyPaths: string[] = [];
  const envSchemaPaths: string[] = [];
  const instructionPaths: string[] = [];
  const sensitiveZonePaths: string[] = [];
  const sensitiveZoneLabels = new Set<string>();
  let redactedCount = 0;

  for (const item of items) {
    if (item.allowed === false) {
      redactedCount += 1;
      continue;
    }
    const cls = classifyPathConcern(item.path, {
      allowed: true,
      zone: item.zone,
    });
    if (cls.isPolicyFile) policyPaths.push(item.path);
    if (cls.isEnvSchema) envSchemaPaths.push(item.path);
    if (cls.isInstructionFile) instructionPaths.push(item.path);
    if (cls.isSensitiveZone) {
      sensitiveZonePaths.push(item.path);
      if (item.zone && item.zone.trim()) {
        sensitiveZoneLabels.add(item.zone.trim());
      } else {
        const firstSeg = normalizePath(item.path).split("/")[0];
        if (firstSeg) sensitiveZoneLabels.add(firstSeg);
      }
    }
  }

  const signals: RiskRadarSignal[] = [];

  if (policyPaths.length > 0) {
    const paths = uniqueSorted(policyPaths);
    signals.push({
      id: "policy",
      kind: "policy",
      severity: "critical",
      label: "Access policy modified",
      detail: `${paths.length} policy ${paths.length === 1 ? "file" : "files"} touched; verify deny-overrides-allow and server precedence.`,
      paths,
    });
  }

  if (instructionPaths.length > 0 || quarantineFlagged) {
    const paths = uniqueSorted(instructionPaths);
    signals.push({
      id: "quarantine",
      kind: "quarantine",
      severity: "critical",
      label: "Quarantined instruction surface",
      detail:
        paths.length > 0
          ? `${paths.length} agent instruction ${paths.length === 1 ? "file" : "files"} flagged; treated as untrusted code and cannot escalate agent authority.`
          : "Change is quarantine-flagged; repo instruction surfaces remain untrusted and cannot escalate agent authority.",
      paths,
    });
  }

  if (envSchemaPaths.length > 0) {
    const paths = uniqueSorted(envSchemaPaths);
    signals.push({
      id: "env_schema",
      kind: "env_schema",
      severity: "critical",
      label: "Secret schema modified",
      detail: `${paths.length} .env.schema ${paths.length === 1 ? "file" : "files"} changed; verify secret capability (use ≠ read) and egress rules.`,
      paths,
    });
  }

  if (redactedCount > 0) {
    signals.push({
      id: "redacted",
      kind: "redacted",
      severity: "warn",
      label: `${redactedCount} redacted ${redactedCount === 1 ? "item" : "items"} hidden`,
      detail:
        "Redacted files lie outside the active identity's ACL scope; paths and contents remain omitted.",
      paths: [],
    });
  }

  if (sensitiveZonePaths.length > 0) {
    const paths = uniqueSorted(sensitiveZonePaths);
    const zoneList = uniqueSorted(sensitiveZoneLabels);
    signals.push({
      id: "sensitive_zone",
      kind: "sensitive_zone",
      severity: "warn",
      label: "Sensitive zone touched",
      detail:
        zoneList.length > 0
          ? `Changes touch sensitive ${zoneList.length === 1 ? "zone" : "zones"}: ${zoneList.join(", ")}.`
          : `${paths.length} ${paths.length === 1 ? "file" : "files"} in sensitive zones modified.`,
      paths,
    });
  }

  return signals;
}

function deriveAreaFromPath(path: string): string {
  const normalized = normalizePath(path);
  const parts = normalized.split("/").filter((p) => p.length > 0);
  if (parts.length <= 1) return "root";
  if ((parts[0] === "crates" || parts[0] === "apps") && parts.length >= 2) {
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0];
}

export function extractZoneFootprint(
  items: ReadonlyArray<{ path: string; allowed?: boolean; zone?: string }>,
): { zones: string[]; redactedCount: number } {
  const zones = new Set<string>();
  let redactedCount = 0;

  for (const item of items) {
    if (item.allowed === false) {
      redactedCount += 1;
      continue;
    }
    const explicitZone = item.zone?.trim();
    if (explicitZone) {
      zones.add(explicitZone);
    } else {
      zones.add(deriveAreaFromPath(item.path));
    }
  }

  return {
    zones: Array.from(zones).sort(compareLex),
    redactedCount,
  };
}
