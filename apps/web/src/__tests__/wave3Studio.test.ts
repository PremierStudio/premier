import { describe, expect, it } from "vitest";
import type { OverlayEntry } from "../api";
import { buildAgentConnect, sanitizeEnv } from "../components/AgentConnectModal";
import { buildTraceHash, parseTraceDeepLink } from "../components/AgentTraceView";
import {
  OVERLAY_STORAGE_COPY,
  overlayEncryptionLabel,
  overlayOwnerLabel,
  overlayPayloadLabel,
} from "../components/SecretsOverlaysView";

describe("overlay metadata", () => {
  const personal: OverlayEntry = {
    kind: { kind: "personal" },
    path: ".env.scratch",
    encrypted: true,
    owner_principal: "@alice",
    has_payload: true,
  };
  const team: OverlayEntry = {
    kind: { kind: "team", name: "platform" },
    path: ".vscode/local.json",
    encrypted: false,
    team_group: "infra",
    has_payload: false,
  };

  it("labels personal overlays with their owner and team overlays with their group", () => {
    expect(overlayOwnerLabel(personal)).toBe("Personal · @alice");
    expect(overlayOwnerLabel({ ...personal, owner_principal: "bob" })).toBe("Personal · @bob");
    expect(overlayOwnerLabel({ ...personal, owner_principal: null })).toBe("Personal");
    expect(overlayOwnerLabel(team)).toBe("Team · infra");
    expect(overlayOwnerLabel({ ...team, team_group: null })).toBe("Team · platform");
  });

  it("reports the real at-rest state", () => {
    expect(overlayEncryptionLabel(personal)).toBe("AES-256-GCM");
    expect(overlayEncryptionLabel(team)).toBe("Plaintext (state dir)");
    expect(overlayPayloadLabel(personal)).toBe("payload stored");
    expect(overlayPayloadLabel(team)).toBe("no payload yet");
    expect(overlayPayloadLabel({ ...team, has_payload: undefined })).toBe("");
  });

  it("describes state-dir storage, not the working tree", () => {
    expect(OVERLAY_STORAGE_COPY).toContain("state directory");
    expect(OVERLAY_STORAGE_COPY).toContain("never written into the canonical working tree");
  });
});

describe("AgentConnectModal snippets", () => {
  it("uses the selected env instead of a hardcoded dev", () => {
    const s = buildAgentConnect({ repoName: "app", isDefaultRepo: true, env: "staging" });
    expect(s.mcpStdioCmd).toBe("premier mcp gateway --env staging");
    expect(s.runCmd).toBe("premier run --env staging -- <your-agent-or-command>");
    expect(JSON.parse(s.mcpJson).mcpServers.premier.args).toEqual([
      "mcp",
      "gateway",
      "--env",
      "staging",
    ]);
    expect(s.mcpStdioCmd).not.toContain("--env dev");
  });

  it("scopes a non-default repo and leaves the default repo bare", () => {
    const def = buildAgentConnect({ repoName: "app", isDefaultRepo: true, env: "dev" });
    expect(def.mcpStdioCmd).not.toContain("cd ");
    expect(JSON.parse(def.mcpJson).mcpServers.premier.cwd).toBeUndefined();

    const other = buildAgentConnect({ repoName: "billing", isDefaultRepo: false, env: "prod" });
    expect(other.mcpStdioCmd).toBe("cd billing\npremier mcp gateway --env prod");
    expect(other.runCmd.startsWith("cd billing\n")).toBe(true);
    expect(JSON.parse(other.mcpJson).mcpServers.premier.cwd).toBe("<path-to>/billing");
  });

  it("falls back to dev for an env the CLI could not take as one argument", () => {
    expect(sanitizeEnv("prod")).toBe("prod");
    expect(sanitizeEnv(" qa-1 ")).toBe("qa-1");
    expect(sanitizeEnv("")).toBe("dev");
    expect(sanitizeEnv("x; rm -rf /")).toBe("dev");
  });
});

describe("trace hash deep-linking", () => {
  it("keeps repo and ref next to run, span and tab", () => {
    const next = buildTraceHash("#traces?repo=billing&ref=feat%2Fx", "run-1", "span-2", "data");
    expect(next).toBe("#traces?repo=billing&ref=feat%2Fx&run=run-1&span=span-2&tab=data");
    expect(parseTraceDeepLink(next)).toEqual({
      run: "run-1",
      span: "span-2",
      tab: "data",
      repo: "billing",
      ref: "feat/x",
    });
  });

  it("replaces a previous selection without dropping repo, ref or other params", () => {
    const next = buildTraceHash(
      "#traces?run=old&span=old&tab=raw&repo=billing&ref=dev&path=a.ts",
      "run-2",
      null,
      "overview",
    );
    expect(next).toBe("#traces?repo=billing&ref=dev&path=a.ts&run=run-2");
  });

  it("restores a repo the hash lost, but never invents a ref", () => {
    expect(buildTraceHash("#traces", "r", "s", "overview", { repo: "billing" })).toBe(
      "#traces?repo=billing&run=r&span=s",
    );
    expect(buildTraceHash("#traces", null, null, "overview")).toBe("#traces");
    // The hash wins over the scope.
    expect(buildTraceHash("#traces?repo=a", "r", null, "overview", { repo: "b" })).toBe(
      "#traces?repo=a&run=r",
    );
  });
});
