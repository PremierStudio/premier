import { describe, expect, it } from "vitest";
import { buildAgentConnect, sanitizeEnv } from "../components/AgentConnectModal";
import {
  canCycleIdentityLens,
  canHandleApprovalHotkey,
  canToggleCommandPalette,
  formatVaultHeader,
  formatVaultStoredNotice,
  getSandboxBadge,
  getTreeTruncationInfo,
  githubSettingsHash,
  hasActiveModalDialog,
  hasOtherModalDialog,
  oidcDiscoveryUrl,
  resolveEnvSelection,
  sanitizeAgentProfile,
  sha256Hex,
  sshCloneCommand,
} from "../lib/uiHelpers";

interface NodeFsSubset {
  readFileSync(path: URL, encoding: "utf8"): string;
}

async function readWebFile(relativeFromSrc: string): Promise<string> {
  const fsSpecifier: string = "node:fs";
  const fs = (await import(/* @vite-ignore */ fsSpecifier)) as NodeFsSubset;
  return fs.readFileSync(new URL(`../${relativeFromSrc}`, import.meta.url), "utf8");
}

describe("Studio P0 sandbox badge mapping", () => {
  it("maps bwrap to mint/cyan bwrap sandbox pill", () => {
    const badge = getSandboxBadge({
      agent_sandbox: "bwrap",
      agent_sandbox_detail: "bubblewrap active",
    });
    expect(badge.label).toBe("bwrap sandbox");
    expect(badge.tone).toBe("mint");
    expect(badge.title).toBe("bubblewrap active");
  });

  it("maps unsandboxed-allowed to warning unsandboxed pill with detail", () => {
    const badge = getSandboxBadge({
      agent_sandbox: "unsandboxed-allowed",
      agent_sandbox_detail: "PREMIER_ALLOW_UNSANDBOXED_AGENTS=1",
    });
    expect(badge.label).toBe("unsandboxed");
    expect(badge.tone).toBe("warn");
    expect(badge.title).toBe("PREMIER_ALLOW_UNSANDBOXED_AGENTS=1");
  });

  it("maps none and missing values to muted no-sandbox pill (never env-cage)", () => {
    const noneBadge = getSandboxBadge({
      agent_sandbox: "none",
      agent_sandbox_detail: "Windows host: use MCP/CLI proxy",
    });
    expect(noneBadge.label).toBe("no sandbox (MCP/CLI proxy)");
    expect(noneBadge.tone).toBe("muted");
    expect(noneBadge.title).toBe("Windows host: use MCP/CLI proxy");

    const fallback = getSandboxBadge(undefined);
    expect(fallback.label).toBe("no sandbox (MCP/CLI proxy)");
    expect(fallback.label).not.toContain("env-cage");
  });
});

describe("Studio P0 modal hotkey guards", () => {
  it("blocks approval hotkeys when keysEnabled is false, a modal is open, or target is editable", () => {
    expect(
      canHandleApprovalHotkey({
        keysEnabled: true,
        hasModal: false,
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        isEditable: false,
      }),
    ).toBe(true);

    expect(
      canHandleApprovalHotkey({
        keysEnabled: false,
        hasModal: false,
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        isEditable: false,
      }),
    ).toBe(false);

    expect(
      canHandleApprovalHotkey({
        keysEnabled: true,
        hasModal: true,
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        isEditable: false,
      }),
    ).toBe(false);

    expect(
      canHandleApprovalHotkey({
        keysEnabled: true,
        hasModal: false,
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        isEditable: true,
      }),
    ).toBe(false);
  });

  it("detects active modals and excludes Command Palette from blocking Cmd/Ctrl+K", () => {
    const noModalRoot = { querySelector: () => null };
    expect(hasActiveModalDialog(noModalRoot)).toBe(false);
    expect(hasOtherModalDialog(noModalRoot)).toBe(false);
    expect(canToggleCommandPalette(hasOtherModalDialog(noModalRoot))).toBe(true);

    const paletteOnlyRoot = {
      querySelector: (sel: string) =>
        sel === '[aria-modal="true"]' ? { role: "dialog" } : null,
    };
    expect(hasActiveModalDialog(paletteOnlyRoot)).toBe(true);
    expect(hasOtherModalDialog(paletteOnlyRoot)).toBe(false);
    expect(canToggleCommandPalette(hasOtherModalDialog(paletteOnlyRoot))).toBe(true);

    const otherModalRoot = {
      querySelector: () => ({ role: "dialog" }),
    };
    expect(hasActiveModalDialog(otherModalRoot)).toBe(true);
    expect(hasOtherModalDialog(otherModalRoot)).toBe(true);
    expect(canToggleCommandPalette(hasOtherModalDialog(otherModalRoot))).toBe(false);
  });

  it("guards Shift+L identity cycling to owners with multiple presets", () => {
    expect(canCycleIdentityLens(false, 5)).toBe(false);
    expect(canCycleIdentityLens(true, 0)).toBe(false);
    expect(canCycleIdentityLens(true, 1)).toBe(false);
    expect(canCycleIdentityLens(true, 2)).toBe(true);
  });
});

describe("Studio P1 custom environment & MCP snippet helpers", () => {
  it("preserves custom environments prefixed by a preset such as dev-2 and prod-eu", () => {
    expect(resolveEnvSelection("dev", "")).toEqual({ effective: "dev", isCustomActive: false });
    expect(resolveEnvSelection("dev", "dev")).toEqual({ effective: "dev", isCustomActive: true });
    expect(resolveEnvSelection("dev", "dev-2")).toEqual({ effective: "dev-2", isCustomActive: true });
    expect(resolveEnvSelection("prod", "prod-eu")).toEqual({
      effective: "prod-eu",
      isCustomActive: true,
    });
  });

  it("sanitizes env names and agent profiles and scopes non-default repos with cd/cwd", () => {
    expect(sanitizeEnv("dev-2")).toBe("dev-2");
    expect(sanitizeEnv("prod-eu")).toBe("prod-eu");
    expect(sanitizeEnv("bad env; rm -rf")).toBe("dev");

    expect(sanitizeAgentProfile("code-reviewer")).toBe("code-reviewer");
    expect(sanitizeAgentProfile("bad profile!")).toBe("readonly-review");

    const scoped = buildAgentConnect({ repoName: "billing", isDefaultRepo: false, env: "dev-2" });
    expect(scoped.mcpStdioCmd).toBe("cd billing\npremier mcp gateway --env dev-2");
    expect(scoped.runCmd).toBe("cd billing\npremier run --env dev-2 -- <your-agent-or-command>");
    expect(JSON.parse(scoped.mcpJson)).toEqual({
      mcpServers: {
        premier: {
          command: "premier",
          args: ["mcp", "gateway", "--env", "dev-2"],
          cwd: "<path-to>/billing",
        },
      },
    });
  });
});

describe("Studio P1 SSH clone, OIDC URL, GitHub settings, KMS, and SHA-256 helpers", () => {
  it("formats sshCloneCommand with published --ssh-public-url or origin fallback", () => {
    expect(
      sshCloneCommand(2222, "billing", "https://studio.example.com:7420", "ssh://git@git.example.com:7429/"),
    ).toBe("git clone ssh://git@git.example.com:7429/billing.git");

    expect(sshCloneCommand(2222, "billing", "https://studio.example.com:7420", null)).toBe(
      "git clone ssh://git@studio.example.com:2222/billing.git",
    );

    expect(sshCloneCommand(22, "billing", "https://studio.example.com", undefined)).toBe(
      "git clone ssh://git@studio.example.com/billing.git",
    );
  });

  it("builds canonical OIDC discovery URL and GitHub settings hash", () => {
    expect(oidcDiscoveryUrl("https://premier.example.com/")).toBe(
      "https://premier.example.com/.well-known/openid-configuration",
    );
    expect(oidcDiscoveryUrl("http://127.0.0.1:7420")).toBe(
      "http://127.0.0.1:7420/.well-known/openid-configuration",
    );

    expect(githubSettingsHash("main-repo", true)).toBe("#settings?section=github");
    expect(githubSettingsHash("billing", false)).toBe("#settings?repo=billing&section=github");
  });

  it("reflects active Envelope KMS in vault header and toast notices", () => {
    expect(formatVaultHeader({ mode: "envelope", provider: "aws-kms" }, "prod")).toBe(
      "KMS Envelope Vault · aws-kms (prod)",
    );
    expect(formatVaultHeader({ mode: "sovereign_age", provider: "local" }, "dev")).toBe(
      "Age AEAD Vault (dev)",
    );
    expect(formatVaultStoredNotice({ mode: "envelope", provider: "gcp-kms" }, 3)).toBe(
      "Encrypted in KMS Envelope Vault · gcp-kms (update #3)",
    );
  });

  it("computes SHA-256 hex digest for policy base CAS checks", async () => {
    const digest = await sha256Hex("hello");
    expect(digest).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
});

describe("Studio P1 tree truncation detection", () => {
  it("computes totalInScope with and without xray mode", () => {
    const normalExact = getTreeTruncationInfo({
      entries: new Array(12).fill(null),
      visible_count: 10,
      traverse_only_count: 2,
      omitted_count: 5,
      xray: false,
    });
    expect(normalExact).toEqual({ shown: 12, totalInScope: 12, truncated: false });

    const normalTruncated = getTreeTruncationInfo({
      entries: new Array(500).fill(null),
      visible_count: 620,
      traverse_only_count: 15,
      omitted_count: 40,
      xray: false,
    });
    expect(normalTruncated).toEqual({ shown: 500, totalInScope: 635, truncated: true });

    const xrayTruncated = getTreeTruncationInfo({
      entries: new Array(500).fill(null),
      visible_count: 450,
      traverse_only_count: 10,
      omitted_count: 60,
      xray: true,
    });
    expect(xrayTruncated).toEqual({ shown: 500, totalInScope: 520, truncated: true });
  });
});

describe("Asset hygiene, lazy Monaco workers, and --pr-* codemod", () => {
  it("removes env-cage, Pixelmator metadata, eager Monaco workers, and legacy --sf-* tokens", async () => {
    const appSrc = await readWebFile("App.tsx");
    expect(appSrc).not.toContain("env-cage");
    expect(appSrc).not.toMatch(/--sf-|\.sf-|data-sf-header/);

    const claudeSvg = await readWebFile("assets/brand-icons/claude-ai.svg");
    expect(claudeSvg).not.toContain("Pixelmator");

    const attribution = await readWebFile("assets/brand-icons/ATTRIBUTION.md");
    expect(attribution).toContain("homarr-labs/dashboard-icons");
    expect(attribution).toContain("Apache");

    const monacoSrc = await readWebFile("lib/monaco.ts");
    expect(monacoSrc).not.toContain("Promise.all([");
    expect(monacoSrc).toContain("loadLanguageWorker");

    const cssSrc = await readWebFile("index.css");
    expect(cssSrc).not.toMatch(/--sf-|\.sf-/);

    const htmlSrc = await readWebFile("../index.html");
    expect(htmlSrc).not.toMatch(/sf-shell-bg/);
    expect(htmlSrc).toContain("pr-shell-bg");
  });
});
