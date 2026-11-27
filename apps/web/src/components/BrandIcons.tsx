import githubLightUrl from "../assets/brand-icons/github-light.svg";
import gitUrl from "../assets/brand-icons/git.svg";
import gitlabUrl from "../assets/brand-icons/gitlab.svg";
import bitbucketUrl from "../assets/brand-icons/bitbucket.svg";
import giteaUrl from "../assets/brand-icons/gitea.svg";
import claudeAiUrl from "../assets/brand-icons/claude-ai.svg";
import openaiLightUrl from "../assets/brand-icons/openai-light.svg";
import googleGeminiUrl from "../assets/brand-icons/google-gemini.svg";
import githubCopilotUrl from "../assets/brand-icons/github-copilot.svg";
import vscodeUrl from "../assets/brand-icons/visual-studio-code.svg";
import dockerUrl from "../assets/brand-icons/docker.svg";
import terminalUrl from "../assets/brand-icons/terminal.svg";
import onePasswordUrl from "../assets/brand-icons/1password.svg";

/**
 * Official SVG brand marks sourced from dashboard-icons.com (homarr-labs/dashboard-icons)
 * and bundled locally so Premier works cleanly offline/air-gapped with zero CDN requests.
 */
export type BrandIconName =
  | "github"
  | "git"
  | "gitlab"
  | "bitbucket"
  | "gitea"
  | "claude"
  | "openai"
  | "gemini"
  | "copilot"
  | "vscode"
  | "docker"
  | "terminal"
  | "1password";

const BRAND_URLS: Record<BrandIconName, string> = {
  github: githubLightUrl,
  git: gitUrl,
  gitlab: gitlabUrl,
  bitbucket: bitbucketUrl,
  gitea: giteaUrl,
  claude: claudeAiUrl,
  openai: openaiLightUrl,
  gemini: googleGeminiUrl,
  copilot: githubCopilotUrl,
  vscode: vscodeUrl,
  docker: dockerUrl,
  terminal: terminalUrl,
  "1password": onePasswordUrl,
};

export function BrandIcon({
  name,
  className = "h-4 w-4",
  title,
}: {
  name: BrandIconName;
  className?: string;
  title?: string;
}) {
  return (
    <img
      src={BRAND_URLS[name]}
      alt=""
      aria-hidden="true"
      title={title}
      draggable={false}
      className={`inline-block shrink-0 select-none object-contain ${className}`}
    />
  );
}

export type GitHostBrand = "github" | "gitlab" | "bitbucket" | "gitea" | "git";

/** Detects a Git hosting provider from an HTTPS import URL to render its matching icon. */
export function detectGitHost(url: string): GitHostBrand {
  const lower = url.trim().toLowerCase();
  if (!lower) return "github";
  try {
    const host = new URL(lower).hostname;
    if (host === "github.com" || host.endsWith(".github.com")) return "github";
    if (host === "gitlab.com" || host.includes("gitlab")) return "gitlab";
    if (host === "bitbucket.org" || host.includes("bitbucket")) return "bitbucket";
    if (host.includes("gitea") || host.includes("codeberg") || host.includes("forgejo")) return "gitea";
  } catch {
    if (lower.includes("gitlab")) return "gitlab";
    if (lower.includes("bitbucket")) return "bitbucket";
    if (lower.includes("gitea")) return "gitea";
    if (lower.includes("github")) return "github";
  }
  return "git";
}

const AI_HARNESSES: { name: BrandIconName; label: string }[] = [
  { name: "claude", label: "Claude" },
  { name: "openai", label: "OpenAI / Codex" },
  { name: "gemini", label: "Gemini" },
  { name: "copilot", label: "GitHub Copilot" },
  { name: "vscode", label: "IDE / MCP Editors" },
  { name: "terminal", label: "Any CLI Agent" },
];

/** Compact visual cluster signaling multi-harness AI agent support without hardcoding one vendor. */
export function AiHarnessCluster({ compact = false }: { compact?: boolean }) {
  const items = compact ? AI_HARNESSES.slice(0, 4) : AI_HARNESSES;
  return (
    <span className="inline-flex items-center -space-x-1" aria-hidden="true">
      {items.map((item) => (
        <span
          key={item.name}
          title={item.label}
          className={`inline-flex items-center justify-center rounded-full border border-white/[0.12] bg-[#101629] shadow-sm ${
            compact ? "h-5 w-5" : "h-6 w-6"
          }`}
        >
          <BrandIcon name={item.name} className={compact ? "h-3 w-3" : "h-3.5 w-3.5"} />
        </span>
      ))}
    </span>
  );
}
