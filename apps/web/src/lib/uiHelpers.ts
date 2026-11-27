import type { HealthResponse, KmsStatus } from "../api";

export interface SandboxBadgeInfo {
  label: string;
  tone: "mint" | "warn" | "muted";
  className: string;
  title?: string;
}

/**
 * Derives the topbar runtime sandbox status pill strictly from `health.agent_sandbox`
 * (never from `linux_bwrap_available` alone).
 */
export function getSandboxBadge(
  health: Pick<HealthResponse, "agent_sandbox" | "agent_sandbox_detail"> | null | undefined,
): SandboxBadgeInfo {
  const detail = health?.agent_sandbox_detail?.trim() || undefined;
  switch (health?.agent_sandbox) {
    case "bwrap":
      return {
        label: "bwrap sandbox",
        tone: "mint",
        className: "bg-[#67d6dc]/14 text-[#67d6dc]",
        title: detail,
      };
    case "unsandboxed-allowed":
      return {
        label: "unsandboxed",
        tone: "warn",
        className: "bg-[#f27c7c]/14 text-[#f2a37c]",
        title: detail,
      };
    default:
      return {
        label: "no sandbox (MCP/CLI proxy)",
        tone: "muted",
        className: "bg-white/[0.05] text-[#a6b5cf]",
        title: detail,
      };
  }
}

export interface ModalQueryRoot {
  querySelector(selectors: string): unknown;
}

/** Returns true when any `aria-modal="true"` dialog is currently mounted in the DOM. */
export function hasActiveModalDialog(root?: ModalQueryRoot | null): boolean {
  const target = root ?? (typeof document !== "undefined" ? document : null);
  return Boolean(target?.querySelector('[aria-modal="true"]'));
}

/** Returns true when an `aria-modal="true"` dialog other than the Command Palette is open. */
export function hasOtherModalDialog(root?: ModalQueryRoot | null): boolean {
  const target = root ?? (typeof document !== "undefined" ? document : null);
  return Boolean(target?.querySelector('[aria-modal="true"]:not([data-command-palette="true"])'));
}

/** Guard for `FloatingApprovalPopover` single-key hotkeys (`y`, `n`, `i`, `[`, `]`). */
export function canHandleApprovalHotkey(opts: {
  keysEnabled: boolean;
  hasModal: boolean;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  isEditable: boolean;
}): boolean {
  if (!opts.keysEnabled || opts.hasModal) return false;
  if (opts.metaKey || opts.ctrlKey || opts.altKey || opts.isEditable) return false;
  return true;
}

/** Guard for `Cmd/Ctrl+K`: allowed unless a non-palette modal is currently open. */
export function canToggleCommandPalette(hasOtherModal: boolean): boolean {
  return !hasOtherModal;
}

/** Guard for `Shift+L` identity-lens cycling. */
export function canCycleIdentityLens(owner: boolean, presetCount: number): boolean {
  return owner && presetCount > 1;
}

export interface TreeTruncationInfo {
  shown: number;
  totalInScope: number;
  truncated: boolean;
}

/**
 * Computes whether a repo tree listing was capped by the server below the total
 * entries in scope (`visible + traverse_only + (xray ? omitted : 0)`).
 */
export function getTreeTruncationInfo(statsTree: {
  entries: readonly unknown[];
  visible_count: number;
  traverse_only_count: number;
  omitted_count: number;
  xray?: boolean;
}): TreeTruncationInfo {
  const totalInScope =
    statsTree.visible_count +
    statsTree.traverse_only_count +
    (statsTree.xray ? statsTree.omitted_count : 0);
  const shown = statsTree.entries.length;
  return {
    shown,
    totalInScope,
    truncated: shown < totalInScope,
  };
}

/** Builds the canonical OIDC discovery endpoint URL from the issuer base URL. */
export function oidcDiscoveryUrl(issuer: string): string {
  const base = issuer.trim().replace(/\/+$/, "");
  return `${base}/.well-known/openid-configuration`;
}

/** Builds `#settings?section=github`, preserving `repo=<current>` for non-default repositories. */
export function githubSettingsHash(
  repoName?: string | null,
  isDefaultRepo = true,
): string {
  const params = new URLSearchParams();
  if (repoName && !isDefaultRepo) {
    params.set("repo", repoName);
  }
  params.set("section", "github");
  return `#settings?${params.toString()}`;
}

/** Builds the SSH `git clone` command using the published `--ssh-public-url` when available. */
export function sshCloneCommand(
  port: number,
  repoName: string,
  serverOrigin: string,
  publicUrl?: string | null,
): string {
  const repo = encodeURIComponent(repoName);
  if (typeof publicUrl === "string" && publicUrl.trim()) {
    return `git clone ${publicUrl.trim().replace(/\/+$/, "")}/${repo}.git`;
  }
  const host = new URL(serverOrigin).hostname;
  const hostPort = port === 22 ? host : `${host}:${port}`;
  return `git clone ssh://git@${hostPort}/${repo}.git`;
}

/** Validates an agent profile identifier for CLI snippets; falls back to `readonly-review`. */
export function sanitizeAgentProfile(profile: string, fallback = "readonly-review"): string {
  const trimmed = profile.trim();
  return /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(trimmed) ? trimmed : fallback;
}

/** Resolves effective env from separate preset and custom input states (never wipes `"dev-2"`). */
export function resolveEnvSelection(preset: string, customInput: string): {
  effective: string;
  isCustomActive: boolean;
} {
  const trimmed = customInput.trim();
  return trimmed
    ? { effective: trimmed, isCustomActive: true }
    : { effective: preset, isCustomActive: false };
}

/** Human-readable vault header & toast label reflecting active Envelope KMS vs Age AEAD. */
export function formatVaultHeader(kms: Pick<KmsStatus, "mode" | "provider"> | null | undefined, activeEnv: string): string {
  if (kms?.mode === "envelope") {
    return `KMS Envelope Vault · ${kms.provider} (${activeEnv})`;
  }
  return `Age AEAD Vault (${activeEnv})`;
}

export function formatVaultStoredNotice(
  kms: Pick<KmsStatus, "mode" | "provider"> | null | undefined,
  rotatedCount: number,
): string {
  if (kms?.mode === "envelope") {
    return `Encrypted in KMS Envelope Vault · ${kms.provider} (update #${rotatedCount})`;
  }
  return `Encrypted in age vault (update #${rotatedCount})`;
}

/** Computes lowercase SHA-256 hex of UTF-8 text when WebCrypto SubtleCrypto is available. */
export async function sha256Hex(text: string): Promise<string | undefined> {
  if (typeof crypto === "undefined" || !crypto.subtle) return undefined;
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}
