import type {
  AgentSessionRecord,
  IdentityPreset,
  PendingApproval,
  Visibility,
} from "../../api";

export type FocusTarget =
  | { kind: "session"; id: string }
  | { kind: "branch"; name: string }
  | { kind: "review"; changeId: string };

export type PresenceFilter = "all" | "agents" | "branches" | "reviews";
export type JudgmentFilter = "all" | "jit" | "quarantine" | "diffs" | "publish";

const handle = (principal: string): string => `@${principal.replace(/^(?:user:|@)/, "")}`;

/** Concise human copy for who can see a branch. */
export function visibilitySummary(vis: Visibility): string {
  switch (vis.scope) {
    case "public":
      return "public";
    case "org":
      return "org";
    case "personal": {
      const owner = Array.isArray(vis.allow) ? (vis.allow[0] ?? "") : vis.allow;
      return owner ? `personal (${handle(owner)})` : "personal";
    }
    case "restricted":
      if (vis.allow.length === 1 && vis.allow[0] === "group:owners") return "owners only";
      return vis.allow.length === 1
        ? `private · ${handle(vis.allow[0])}`
        : `private · ${vis.allow.length} people`;
  }
}

export const isPrivateVisibility = (vis: Visibility): boolean =>
  vis.scope === "restricted" || vis.scope === "personal";

/** "14s", "2m 10s", "1h 04m". */
export function formatElapsedSeconds(isoTimestamp: string, nowMs: number): string {
  const started = Date.parse(isoTimestamp);
  const secs = Number.isNaN(started) ? 0 : Math.max(0, Math.floor((nowMs - started) / 1000));
  return formatDuration(secs);
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  return `${Math.floor(secs / 3600)}h ${String(Math.floor((secs % 3600) / 60)).padStart(2, "0")}m`;
}

/** "4m 12s", or "Expired" once it reaches zero. */
export function formatCountdownSeconds(secs: number): string {
  const whole = Math.ceil(secs);
  return whole <= 0 ? "Expired" : formatDuration(whole);
}

/** Unique top-level folders of `paths` ("apps/web", "crates/premier-server"), at most `max`. */
export function summarizeZones(paths: string[], max = 2): string {
  const zones: string[] = [];
  for (const raw of paths) {
    const parts = raw.split("/").filter(Boolean);
    const zone = parts.length <= 1 ? "(root)" : parts.slice(0, Math.min(2, parts.length - 1)).join("/");
    if (!zones.includes(zone)) zones.push(zone);
  }
  const shown = zones.slice(0, max).join(", ");
  return zones.length > max ? `${shown} +${zones.length - max}` : shown;
}

/** The lens's own sessions; the owner's "self" lens sees everything, anonymous sees nothing. */
function lensMatches(
  item: { principal: string; agent_profile?: string | null },
  identity: IdentityPreset,
  owner: boolean,
): boolean {
  if (identity.principal === "anonymous") return false;
  if (owner && identity.id === "self") return true;
  if (item.principal !== identity.principal) return false;
  return !identity.agentProfile || item.agent_profile === identity.agentProfile;
}

export const filterSessionsForLens = (
  sessions: AgentSessionRecord[],
  identity: IdentityPreset,
  owner: boolean,
): AgentSessionRecord[] => sessions.filter((s) => lensMatches(s, identity, owner));

export const filterApprovalsForLens = (
  approvals: PendingApproval[],
  identity: IdentityPreset,
  owner: boolean,
): PendingApproval[] => approvals.filter((a) => lensMatches(a, identity, owner));

/** The pending approval that is probably holding this session up; an exact profile match wins. */
export function findWaitingApprovalForSession(
  session: AgentSessionRecord,
  pendingApprovals: PendingApproval[],
): PendingApproval | undefined {
  const mine = pendingApprovals.filter(
    (a) => a.status === "pending" && a.principal === session.principal,
  );
  return (
    mine.find((a) => a.agent_profile === session.agent_profile) ??
    mine.find((a) => !a.agent_profile)
  );
}

export const sessionHasUncommittedChanges = (s: AgentSessionRecord): boolean =>
  s.status !== "running" && (s.changes?.length ?? 0) > 0 && !s.commit && !s.discarded;

/** "0 B", "412 B", "1.4 KB", "2.0 MB". */
export function formatByteCount(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}
