import { afterEach, describe, expect, it } from "vitest";
import {
  ApiError,
  GROUP_NAME_RE,
  USERNAME_PATTERN,
  agentProfileNames,
  branchNameError,
  capMaskToNames,
  errorText,
  newFilePathError,
  repoNameError,
  repoPath,
  setCurrentRepo,
  shortOid,
} from "../api";

interface NodeFsSubset {
  readFileSync(path: URL, encoding: "utf8"): string;
}

async function readRepoFile(repoRelativePath: string): Promise<string> {
  const fsSpecifier: string = "node:fs";
  const fs = (await import(/* @vite-ignore */ fsSpecifier)) as NodeFsSubset;
  const fileUrl = new URL(`../../../../${repoRelativePath}`, import.meta.url);
  return fs.readFileSync(fileUrl, "utf8");
}

describe("api.ts pure helpers", () => {
  afterEach(() => {
    setCurrentRepo(null);
  });

  describe("newFilePathError", () => {
    it("accepts valid relative repository paths", () => {
      expect(newFilePathError("README.md")).toBeNull();
      expect(newFilePathError("src/lib/monaco.ts")).toBeNull();
      expect(newFilePathError(".access.toml")).toBeNull();
      expect(newFilePathError("billing/ledger/entry_01.rs")).toBeNull();
    });

    it("rejects empty paths", () => {
      expect(newFilePathError("")).toMatch(/Enter a file name/i);
    });

    it("rejects '..' traversal segments", () => {
      expect(newFilePathError("..")).toMatch(/\.\./);
      expect(newFilePathError("../secret.txt")).toMatch(/\.\./);
      expect(newFilePathError("src/../secret.txt")).toMatch(/\.\./);
      expect(newFilePathError("src/sub/..")).toMatch(/\.\./);
    });

    it("rejects absolute paths and backslashes", () => {
      expect(newFilePathError("/etc/passwd")).toMatch(/relative/i);
      expect(newFilePathError("\\windows\\system32")).toMatch(/relative/i);
      expect(newFilePathError("C:foo.txt")).toMatch(/relative/i);
      expect(newFilePathError("src\\file.ts")).toMatch(/Separate folders/i);
    });

    it("rejects empty or '.' path segments", () => {
      expect(newFilePathError("src//file.ts")).toMatch(/empty or "\."/i);
      expect(newFilePathError("./file.ts")).toMatch(/empty or "\."/i);
      expect(newFilePathError("src/./file.ts")).toMatch(/empty or "\."/i);
      expect(newFilePathError("src/")).toMatch(/empty or "\."/i);
    });

    it("rejects reserved .git / .premier / .premier-local components (case & trailing dot insensitive)", () => {
      expect(newFilePathError(".git/config")).toMatch(/reserved/i);
      expect(newFilePathError("sub/.GIT/HEAD")).toMatch(/reserved/i);
      expect(newFilePathError(".git./hooks")).toMatch(/reserved/i);
      expect(newFilePathError(".premier/policy.toml")).toMatch(/reserved/i);
      expect(newFilePathError(".premier-local/notes.txt")).toMatch(/reserved/i);
    });
  });

  describe("branchNameError", () => {
    it("accepts standard branch names", () => {
      expect(branchNameError("main")).toBeNull();
      expect(branchNameError("feature/zone-xray")).toBeNull();
      expect(branchNameError("release-1.0")).toBeNull();
    });

    it("rejects refs/ prefix and HEAD", () => {
      expect(branchNameError("refs/heads/main")).toMatch(/refs\//);
      expect(branchNameError("refs/premier-private/secret")).toMatch(/refs\//);
      expect(branchNameError("HEAD")).toMatch(/HEAD/);
    });

    it("mirrors server valid_branch_name (git check-ref-format --branch)", () => {
      expect(branchNameError("")).not.toBeNull();
      expect(branchNameError("@")).not.toBeNull();
      expect(branchNameError("-flag")).not.toBeNull();
      expect(branchNameError("feat..bar")).not.toBeNull();
      expect(branchNameError("my branch")).not.toBeNull();
      expect(branchNameError("feat@{1}")).not.toBeNull();
      expect(branchNameError("feat.lock")).not.toBeNull();
      expect(branchNameError("/leading")).not.toBeNull();
      expect(branchNameError("trailing/")).not.toBeNull();
      expect(branchNameError("a//b")).not.toBeNull();
      expect(branchNameError("a/.hidden")).not.toBeNull();
      expect(branchNameError("bad~name")).not.toBeNull();
    });
  });

  describe("repoNameError", () => {
    it("enforces server slug constraints", () => {
      expect(repoNameError("premier-demo")).toBeNull();
      expect(repoNameError("a")).toBeNull();
      expect(repoNameError("repo_1.0")).toBeNull();
      expect(repoNameError("")).not.toBeNull();
      expect(repoNameError("UpperCase")).not.toBeNull();
      expect(repoNameError("-leading-dash")).not.toBeNull();
      expect(repoNameError("demo.git")).toMatch(/\.git/);
      expect(repoNameError("a".repeat(64))).not.toBeNull();
    });
  });

  describe("capMaskToNames", () => {
    it("decodes capability bitmasks preserving traverse ≠ list ≠ read and use ≠ read", () => {
      expect(capMaskToNames(0)).toEqual([]);
      expect(capMaskToNames(0b00001)).toEqual(["traverse"]);
      expect(capMaskToNames(0b00010)).toEqual(["list"]);
      expect(capMaskToNames(0b00100)).toEqual(["read"]);
      expect(capMaskToNames(0b01000)).toEqual(["write"]);
      expect(capMaskToNames(0b10000)).toEqual(["use"]);
      expect(capMaskToNames(0b00111)).toEqual(["traverse", "list", "read"]);
      expect(capMaskToNames(0b10001)).toEqual(["traverse", "use"]);
      expect(capMaskToNames(0b11111)).toEqual(["traverse", "list", "read", "write", "use"]);
      expect(capMaskToNames(0b100000)).toEqual([]);
    });
  });

  describe("shortOid", () => {
    it("returns the first 7 hex characters of an OID", () => {
      expect(shortOid("0123456789abcdef0123456789abcdef01234567")).toBe("0123456");
      expect(shortOid("abc")).toBe("abc");
      expect(shortOid("")).toBe("");
    });
  });

  describe("errorText", () => {
    it("extracts structured JSON error bodies from ApiError", () => {
      const apiErr = new ApiError("400 Bad Request: {}", 400, { error: "Invalid TOML syntax" });
      expect(errorText(apiErr)).toBe("Invalid TOML syntax");
    });

    it("maps 403 without body.error to Owner only and 429 to rate-limit message", () => {
      expect(errorText(new ApiError("403 Forbidden", 403, null))).toBe("Owner only.");
      expect(errorText(new ApiError("403 Forbidden", 403, { error: "Custom denial" }))).toBe(
        "Custom denial",
      );
      expect(errorText(new ApiError("429 Too Many Requests", 429, null))).toBe(
        "Too many attempts. Try again later.",
      );
      expect(errorText(new ApiError("500 Internal Server Error: oops", 500, null))).toBe(
        "500 Internal Server Error: oops",
      );
    });

    it("handles plain Error instances and arbitrary non-Error values", () => {
      expect(errorText(new Error("Connection refused"))).toBe("Connection refused");
      expect(errorText("plain failure")).toBe("plain failure");
      expect(errorText(503)).toBe("503");
    });
  });

  describe("repoPath and identity helpers", () => {
    it("prefixes repo-scoped paths for non-default repos while keeping global paths bare", () => {
      setCurrentRepo({
        name: "billing-core",
        description: "",
        is_default: false,
        default_branch: "main",
        created_at: null,
        head_oid: null,
      });

      expect(repoPath("/v1/repo/tree?ref_name=main")).toBe(
        "/r/billing-core/v1/repo/tree?ref_name=main",
      );
      expect(repoPath("/v1/repos")).toBe("/v1/repos");
      expect(repoPath("/v1/repos/billing-core")).toBe("/v1/repos/billing-core");
      expect(repoPath("/v1/auth/status")).toBe("/v1/auth/status");
      expect(repoPath("/health")).toBe("/health");

      setCurrentRepo({
        name: "default-repo",
        description: "",
        is_default: true,
        default_branch: "main",
        created_at: null,
        head_oid: null,
      });
      expect(repoPath("/v1/repo/tree")).toBe("/v1/repo/tree");
    });

    it("extracts agent profile names safely and validates group/username patterns", () => {
      expect(
        agentProfileNames({
          policy_loaded: true,
          server_policy_loaded: false,
          repo_policy_toml: "",
          server_policy_toml: "",
          policy: { agent_profiles: [{ name: "ui-agent" }, { name: "" }, { name: "sec-bot" }] },
        }),
      ).toEqual(["ui-agent", "sec-bot"]);

      expect(
        agentProfileNames({
          policy_loaded: true,
          server_policy_loaded: false,
          repo_policy_toml: "",
          server_policy_toml: "",
          policy: null,
        }),
      ).toEqual([]);

      expect(GROUP_NAME_RE.test("billing-ops_1")).toBe(true);
      expect(GROUP_NAME_RE.test("UPPER")).toBe(false);
      const userRe = new RegExp(`^${USERNAME_PATTERN}$`);
      expect(userRe.test("alice_01")).toBe(true);
      expect(userRe.test("a")).toBe(false);
    });
  });
});

describe("URL hash deep-link contract (App.tsx)", () => {
  // Mirrors parseHash / buildHash in apps/web/src/App.tsx (non-exported internal helpers)
  const TAB_ORDER = ["code", "changes", "branches", "agents", "secrets", "policy", "settings"] as const;
  type TabId = (typeof TAB_ORDER)[number];

  function parseHashString(hash: string) {
    const raw = hash.replace(/^#/, "");
    if (!raw) return { tab: "code" as TabId | null };
    const qIdx = raw.indexOf("?");
    const tabPart = qIdx === -1 ? raw : raw.slice(0, qIdx);
    const queryPart = qIdx === -1 ? "" : raw.slice(qIdx + 1);
    const tab = (TAB_ORDER as readonly string[]).includes(tabPart) ? (tabPart as TabId) : null;
    const params = new URLSearchParams(queryPart);
    const repo = params.get("repo") || undefined;
    const ref = params.get("ref") || undefined;
    const path = params.get("path") || undefined;
    const oid = params.get("oid") || undefined;
    const change = params.get("change") || undefined;
    const section = params.get("section") || undefined;
    let lines: [number, number] | undefined;
    const linesRaw = params.get("lines");
    if (linesRaw) {
      const m = linesRaw.match(/^L?(\d+)(?:-L?(\d+))?$/i);
      if (m) {
        const a = Number(m[1]);
        const b = m[2] ? Number(m[2]) : a;
        if (a > 0 && b > 0) lines = [Math.min(a, b), Math.max(a, b)];
      }
    }
    return { tab, repo, ref, path, lines, oid, change, section };
  }

  function buildHashString(state: {
    tab: TabId;
    repo?: string;
    isDefaultRepo?: boolean;
    ref?: string;
    defaultBranch?: string | null;
    path?: string;
    lines?: [number, number] | null;
    oid?: string;
    change?: string;
    section?: string;
  }): string {
    const params = new URLSearchParams();
    if (state.repo && !state.isDefaultRepo) params.set("repo", state.repo);
    if (state.ref && state.ref !== state.defaultBranch) params.set("ref", state.ref);
    if (state.tab === "code") {
      if (state.path) params.set("path", state.path);
      if (state.lines) {
        const [a, b] = state.lines;
        params.set("lines", a === b ? `L${a}` : `L${a}-L${b}`);
      }
    } else if (state.tab === "changes") {
      if (state.change) params.set("change", state.change);
      else if (state.oid) params.set("oid", state.oid);
    } else if (state.tab === "settings") {
      if (state.section) params.set("section", state.section);
    }
    const qs = params.toString();
    return qs ? `#${state.tab}?${qs}` : `#${state.tab}`;
  }

  it("round-trips #code?path=...&lines=L1-L5 and single-line #code?path=...&lines=L7", () => {
    const built = buildHashString({
      tab: "code",
      repo: "billing",
      isDefaultRepo: false,
      ref: "feature/v2",
      defaultBranch: "main",
      path: "src/lib/monaco.ts",
      lines: [1, 5],
    });
    expect(built).toBe("#code?repo=billing&ref=feature%2Fv2&path=src%2Flib%2Fmonaco.ts&lines=L1-L5");
    expect(parseHashString(built)).toEqual({
      tab: "code",
      repo: "billing",
      ref: "feature/v2",
      path: "src/lib/monaco.ts",
      lines: [1, 5],
      oid: undefined,
      change: undefined,
      section: undefined,
    });

    const single = buildHashString({ tab: "code", path: "README.md", lines: [7, 7] });
    expect(single).toBe("#code?path=README.md&lines=L7");
    expect(parseHashString(single).lines).toEqual([7, 7]);
  });

  it("round-trips #settings?section=... and normalizes reversed line ranges", () => {
    const settingsHash = buildHashString({ tab: "settings", section: "ssh-keys" });
    expect(settingsHash).toBe("#settings?section=ssh-keys");
    expect(parseHashString(settingsHash)).toMatchObject({
      tab: "settings",
      section: "ssh-keys",
    });

    // Reversed line range L12-L4 normalizes to [4, 12]; zero lines are ignored
    expect(parseHashString("#code?path=a.rs&lines=L12-L4").lines).toEqual([4, 12]);
    expect(parseHashString("#code?path=a.rs&lines=L0-L5").lines).toBeUndefined();
    expect(parseHashString("#unknown-tab").tab).toBeNull();
    expect(parseHashString("").tab).toBe("code");
  });

  it("matches the tab list and line-range regex in apps/web/src/App.tsx", async () => {
    const appSource = (await readRepoFile("apps/web/src/App.tsx")).replace(/\r\n/g, "\n");
    expect(appSource).toContain(
      'const TAB_ORDER: TabId[] = [\n  "worktable",\n  "code",\n  "changes",\n  "branches",\n  "agents",\n  "traces",\n  "secrets",\n  "policy",\n  "settings",\n];',
    );
    expect(appSource).toContain("/^L?(\\d+)(?:-L?(\\d+))?$/i");
  });
});

describe("SSH public key validation parity (SettingsView.tsx <-> Rust auth.rs)", () => {
  it("keeps ALLOWED_SSH_KEY_TYPES and 16 KiB limit identical between frontend and server", async () => {
    const [settingsSrc, authRs] = await Promise.all([
      readRepoFile("apps/web/src/components/SettingsView.tsx"),
      readRepoFile("crates/premier-server/src/auth.rs"),
    ]);

    const extractQuotedList = (block: string): string[] =>
      Array.from(block.matchAll(/"([^"]+)"/g), (m) => m[1]);

    const tsBlock = settingsSrc.match(/const ALLOWED_SSH_KEY_TYPES = new Set\(\[([\s\S]*?)\]\);/);
    const rsBlock = authRs.match(/const ALLOWED_SSH_KEY_TYPES: &\[&str\] = &\[([\s\S]*?)\];/);

    expect(tsBlock, "SettingsView.tsx ALLOWED_SSH_KEY_TYPES").not.toBeNull();
    expect(rsBlock, "auth.rs ALLOWED_SSH_KEY_TYPES").not.toBeNull();

    const tsTypes = extractQuotedList(tsBlock![1]);
    const rsTypes = extractQuotedList(rsBlock![1]);

    expect(tsTypes).toEqual(rsTypes);
    expect(tsTypes).toContain("ssh-ed25519");
    expect(tsTypes).toContain("sk-ssh-ed25519@openssh.com");
    expect(tsTypes).not.toContain("ssh-dss");

    expect(settingsSrc).toContain("const MAX_SSH_KEY_BYTES = 16 * 1024;");
    expect(authRs).toContain("const MAX_SSH_KEY_BYTES: usize = 16 * 1024;");
  });

  it("validates OpenSSH key format regex parity against valid and invalid keys", async () => {
    const settingsSrc = await readRepoFile("apps/web/src/components/SettingsView.tsx");
    // Ensure the base64 regex in SettingsView.tsx matches what we test below
    const b64Regex = /^[A-Za-z0-9+/]+={0,2}$/;
    expect(settingsSrc).toContain("/^[A-Za-z0-9+/]+={0,2}$/");

    const validEd25519B64 = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    expect(b64Regex.test(validEd25519B64)).toBe(true);
    expect(validEd25519B64.length).toBeGreaterThanOrEqual(16);

    expect(b64Regex.test("AAAAC3NzaC1lZDI1==")).toBe(true);
    expect(b64Regex.test("not!valid@base64#")).toBe(false);
    expect(b64Regex.test("AAAAC3NzaC1===")).toBe(false);
    expect(b64Regex.test("has spaces inside")).toBe(false);
  });
});
