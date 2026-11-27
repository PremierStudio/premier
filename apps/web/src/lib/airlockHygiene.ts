export interface HygieneWarning {
  token: string;
  category: "path" | "filename" | "zone" | "branch";
  detail: string;
}

export interface CommitMessageHygieneContext {
  scrubbedPaths: string[];
  blockedPaths: string[];
  restrictedZones: string[];
  publishedPaths?: string[];
  sourceBranch?: string;
  targetBranch?: string;
  isPrivateSource: boolean;
}

const GENERIC_BRANCH_TOKENS = new Set([
  "feat",
  "feature",
  "fix",
  "bugfix",
  "hotfix",
  "priv",
  "work",
  "wip",
  "main",
  "master",
  "branch",
  "dev",
  "develop",
  "tmp",
  "temp",
  "test",
  "chore",
  "docs",
  "refactor",
  "patch",
  "draft",
  "user",
  "users",
]);

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizePath(path: string): string {
  return path.trim().replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
}

/** Case-insensitive boundary match (works cleanly for words, dotted filenames, and path segments). */
function matchesWordBoundary(text: string, token: string): boolean {
  if (!token) return false;
  const re = new RegExp(`(?:^|[^a-z0-9_])${escapeRegExp(token)}(?:$|[^a-z0-9_])`, "i");
  return re.test(text);
}

/** Case-insensitive path boundary match (prevents `a/b` matching inside `data/bar`). */
function matchesPathBoundary(text: string, path: string): boolean {
  if (!path) return false;
  const re = new RegExp(`(?:^|[^a-z0-9_./-])${escapeRegExp(path)}(?:$|[^a-z0-9_./-])`, "i");
  return re.test(text);
}

/**
 * Inspects a candidate public commit message for accidental leakage of held-back paths,
 * restricted filenames, restricted directory prefixes, zone names, or private branch names.
 */
export function analyzeCommitMessageHygiene(
  message: string,
  ctx: CommitMessageHygieneContext,
): HygieneWarning[] {
  const trimmed = message.trim();
  if (!trimmed) return [];

  const normalizedMessage = trimmed.replace(/\\/g, "/");
  const lowerMessage = normalizedMessage.toLowerCase();
  const seen = new Set<string>();
  const warnings: HygieneWarning[] = [];

  const add = (token: string, category: HygieneWarning["category"], detail: string) => {
    const clean = token.trim();
    if (!clean) return;
    const key = clean.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    warnings.push({ token: clean, category, detail });
  };

  // Directory prefixes & basenames that legitimately appear in published paths.
  const publishedDirPrefixes = new Set<string>();
  const publishedBasenames = new Set<string>();
  for (const rawPub of ctx.publishedPaths ?? []) {
    const norm = normalizePath(rawPub);
    if (!norm) continue;
    const parts = norm.split("/");
    const base = parts[parts.length - 1]?.toLowerCase();
    if (base) publishedBasenames.add(base);
    let prefix = "";
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i].toLowerCase();
      if (!seg) continue;
      prefix = prefix ? `${prefix}/${seg}` : seg;
      publishedDirPrefixes.add(prefix);
    }
  }

  const restrictedEntries: { path: string; isBlocked: boolean }[] = [];
  const seenPaths = new Set<string>();
  for (const p of ctx.blockedPaths ?? []) {
    const norm = normalizePath(p);
    if (norm && !seenPaths.has(norm.toLowerCase())) {
      seenPaths.add(norm.toLowerCase());
      restrictedEntries.push({ path: norm, isBlocked: true });
    }
  }
  for (const p of ctx.scrubbedPaths ?? []) {
    const norm = normalizePath(p);
    if (norm && !seenPaths.has(norm.toLowerCase())) {
      seenPaths.add(norm.toLowerCase());
      restrictedEntries.push({ path: norm, isBlocked: false });
    }
  }

  // 1. Full held-back or blocked path
  for (const entry of restrictedEntries) {
    if (entry.path.includes("/") && matchesPathBoundary(normalizedMessage, entry.path)) {
      add(
        entry.path,
        "path",
        entry.isBlocked
          ? `Matches blocked path "${entry.path}"`
          : `Matches held-back private path "${entry.path}"`,
      );
    }
  }

  // 2. Basename of held-back or blocked path (skip generic basenames also published publicly)
  for (const entry of restrictedEntries) {
    const parts = entry.path.split("/");
    const basename = parts[parts.length - 1] ?? "";
    if (!basename) continue;
    if (publishedBasenames.has(basename.toLowerCase())) continue;
    const hasDot = basename.includes(".");
    if (!hasDot && basename.length < 4) continue;
    if (matchesWordBoundary(trimmed, basename)) {
      add(
        basename,
        "filename",
        entry.isBlocked
          ? `Matches blocked filename "${basename}"`
          : `Matches held-back filename "${basename}"`,
      );
    }
  }

  // 3. Restricted zone names (checked before directory segments so declared zones keep "zone" category)
  for (const rawZone of ctx.restrictedZones ?? []) {
    const zone = rawZone.trim();
    if (zone.length < 2) continue;
    if (matchesWordBoundary(trimmed, zone)) {
      add(zone, "zone", `Matches restricted zone "${zone}"`);
    }
  }

  // 4. Parent directory segments of held-back or blocked paths not shared as a published prefix
  for (const entry of restrictedEntries) {
    const parts = entry.path.split("/");
    let prefix = "";
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i];
      if (!seg) continue;
      const segLower = seg.toLowerCase();
      prefix = prefix ? `${prefix}/${segLower}` : segLower;
      if (seg.length < 3) continue;
      if (publishedDirPrefixes.has(prefix)) continue;
      if (
        matchesWordBoundary(normalizedMessage, seg) ||
        lowerMessage.includes(`${segLower}/`)
      ) {
        add(seg, "path", `Matches restricted directory "${seg}/"`);
      }
    }
  }

  // 5. Private source branch name and distinct non-generic slug tokens
  if (
    ctx.isPrivateSource &&
    ctx.sourceBranch &&
    ctx.sourceBranch !== ctx.targetBranch
  ) {
    const branch = ctx.sourceBranch.trim();
    const targetTokens = new Set(
      (ctx.targetBranch ?? "")
        .toLowerCase()
        .split(/[/\-_.\s]+/)
        .filter(Boolean),
    );
    if (branch.length >= 4 && matchesWordBoundary(trimmed, branch)) {
      add(branch, "branch", `Mentions private source branch "${branch}"`);
    }
    const slugTokens = branch.split(/[/\-_.\s]+/).filter(Boolean);
    for (const tok of slugTokens) {
      const lower = tok.toLowerCase();
      if (tok.length < 4) continue;
      if (GENERIC_BRANCH_TOKENS.has(lower)) continue;
      if (targetTokens.has(lower)) continue;
      if (matchesWordBoundary(trimmed, tok)) {
        add(tok, "branch", `Matches identifier from private branch "${branch}"`);
      }
    }
  }

  return warnings;
}
