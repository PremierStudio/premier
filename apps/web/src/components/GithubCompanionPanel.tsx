import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  api,
  ApiError,
  currentRepoIsDefault,
  currentRepoName,
  errorText,
  type GithubCompanionStatus,
  type GithubPrPreviewResponse,
  type GithubPrReceipt,
  type PublishGithubPrResponse,
  type SyncDirection,
  type SyncInResponse,
  type SyncOutResponse,
  type User,
} from "../api";
import { githubSettingsHash } from "../lib/uiHelpers";
import { useModalDialog } from "../lib/useModalDialog";
import {
  ConfirmButton,
  DANGER_BTN,
  ErrorNote,
  Field,
  PRIMARY_BTN,
  SECONDARY_BTN,
  SELECT_CLASS,
  Time,
  useAction,
} from "./forms";
import { BrandIcon } from "./BrandIcons";
import {
  IconCheck,
  IconCopy,
  IconGithub,
  IconPlay,
  IconQuarantine,
  IconRefresh,
  IconShieldCheck,
  IconSync,
} from "./Icons";
import { plural } from "../lib/format";
import { SkelPill } from "./ViewSkeletons";

const LABEL = "block text-[13px] font-medium text-[#d2dbee]";
const HEADING = "font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]";
const DIRECTIONS: { value: SyncDirection; label: string }[] = [
  { value: "bidirectional", label: "Bidirectional (out and in)" },
  { value: "outbound", label: "Outbound only (Premier → GitHub)" },
  { value: "inbound", label: "Inbound only (GitHub → Premier)" },
];

// One shared status store per repo: the pill, the branch panel and Settings share one in-flight
// request and short cache per repository, so switching repos or going 0→1 repo never bleeds state.
const STATUS_TTL_MS = 30_000;

interface RepoStatusStore {
  cache: { value: GithubCompanionStatus; at: number } | null;
  failure: { err: unknown; at: number } | null;
  inflight: Promise<void> | null;
  gen: number;
  listeners: Set<(s: GithubCompanionStatus) => void>;
}

const repoStatusStores = new Map<string, RepoStatusStore>();

function getRepoStatusStore(repoKey: string): RepoStatusStore {
  let store = repoStatusStores.get(repoKey);
  if (!store) {
    store = { cache: null, failure: null, inflight: null, gen: 0, listeners: new Set() };
    repoStatusStores.set(repoKey, store);
  }
  return store;
}

/** An older server has no /v1/github/* routes; that is "unsupported", not a failure to retry. */
function isUnsupportedStatusError(err: unknown): boolean {
  return err instanceof ApiError && (err.status === 404 || err.status === 405 || err.status === 501);
}

function publishGithubStatus(value: GithubCompanionStatus, repoKey = currentRepoName()) {
  const store = getRepoStatusStore(repoKey);
  store.gen++; // supersede any older in-flight reply
  store.cache = { value, at: Date.now() };
  store.failure = null;
  store.listeners.forEach((l) => l(value));
}

/** Resolves once the store is current; rejects with the load error. `force` bypasses the cache. */
function loadGithubStatus(force: boolean, repoKey = currentRepoName()): Promise<void> {
  const store = getRepoStatusStore(repoKey);
  const now = Date.now();
  if (!force) {
    if (store.inflight) return store.inflight;
    if (store.cache && now - store.cache.at < STATUS_TTL_MS) return Promise.resolve();
    if (store.failure && now - store.failure.at < STATUS_TTL_MS) {
      return Promise.reject(store.failure.err);
    }
  }
  const gen = ++store.gen;
  const p: Promise<void> = api
    .githubStatus()
    .then((s) => {
      // A newer (forced) request supersedes this one, so a slow stale reply never overwrites it.
      if (gen === store.gen) publishGithubStatus(s, repoKey);
    })
    .catch((err: unknown) => {
      if (gen === store.gen) store.failure = { err, at: Date.now() };
      throw err;
    })
    .finally(() => {
      if (store.inflight === p) store.inflight = null;
    });
  store.inflight = p;
  return p;
}

/** Owner-only status load. Errors are swallowed: an older server has no /v1/github/* yet. */
function useGithubStatus(owner: boolean, fresh = false) {
  const repoKey = currentRepoName();
  // Seed from the repo-scoped cache so a remount shows the last status immediately instead of nothing.
  const [status, setStatus] = useState<GithubCompanionStatus | null>(() =>
    owner ? (getRepoStatusStore(repoKey).cache?.value ?? null) : null,
  );
  const [loadError, setLoadError] = useState<string | null>(null);
  const [settled, setSettled] = useState(() => !owner || getRepoStatusStore(repoKey).cache !== null);
  const [unsupported, setUnsupported] = useState(false);
  const alive = useRef(true);
  const activeRepoRef = useRef(repoKey);
  activeRepoRef.current = repoKey;
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  useEffect(() => {
    if (!owner) {
      setStatus(null);
      setLoadError(null);
      setSettled(true);
      return;
    }
    const store = getRepoStatusStore(repoKey);
    setStatus(store.cache?.value ?? null);
    setLoadError(null);
    setUnsupported(false);
    setSettled(store.cache !== null);
    const onStatus = (s: GithubCompanionStatus) => {
      setStatus(s);
      setLoadError(null);
    };
    store.listeners.add(onStatus);
    return () => {
      store.listeners.delete(onStatus);
    };
  }, [owner, repoKey]);
  const load = useCallback(
    (force: boolean): Promise<void> => {
      if (!owner) return Promise.resolve();
      const targetRepo = repoKey;
      return loadGithubStatus(force, targetRepo)
        .then(() => {
          if (alive.current && activeRepoRef.current === targetRepo) setUnsupported(false);
        })
        .catch((err: unknown) => {
          if (!alive.current || activeRepoRef.current !== targetRepo) return;
          if (isUnsupportedStatusError(err)) {
            setUnsupported(true);
            setLoadError(null);
          } else {
            setLoadError(errorText(err));
          }
        })
        .finally(() => {
          if (alive.current && activeRepoRef.current === targetRepo) setSettled(true);
        });
    },
    [owner, repoKey],
  );
  const reload = useCallback(() => load(true), [load]);
  const setRepoStatus = useCallback(
    (value: GithubCompanionStatus) => publishGithubStatus(value, repoKey),
    [repoKey],
  );
  useEffect(() => {
    void load(fresh);
  }, [load, fresh]);
  return { status, setStatus: setRepoStatus, loadError, unsupported, reload, settled };
}

/** Shared owner-only status for BranchesView (same cache as the pill and the branch panel). */
export function useGithubCompanionStatus(owner: boolean) {
  const { status, settled, reload, unsupported, loadError } = useGithubStatus(owner);
  return { status, settled, reload, unsupported, loadError };
}

/** Topbar entry point (owner-only): connected repo at a glance, or a calm "Connect GitHub" call to action. */
export function GithubTopbarPill({ user, onOpen }: { user: User; onOpen: () => void }) {
  const owner = user.role === "owner";
  const { status, settled, unsupported } = useGithubStatus(owner);
  if (!owner || unsupported) return null;
  if (!settled && !status) return <div className="pr-shimmer h-9 w-28 shrink-0 rounded-full" aria-hidden />;
  if (status?.connected && status.config) {
    return (
      <button
        type="button"
        onClick={onOpen}
        title={`GitHub Companion connected: ${status.config.full_name} · click to sync or manage`}
        className="pr-pill inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full px-2.5 font-mono text-[13px] text-[#dce4f5] hover:text-white"
      >
        <BrandIcon name="github" className="h-4 w-4 shrink-0" />
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#5bdba2]" aria-hidden />
        <span className="hidden max-w-[130px] truncate 2xl:inline">{status.config.full_name}</span>
        <span className="sr-only 2xl:hidden">GitHub connected</span>
      </button>
    );
  }
  return (
    <button
      type="button"
      onClick={onOpen}
      title="Connect a GitHub repository for bidirectional zone sync & declassified PRs"
      className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-full border border-[#7f95f8]/30 bg-[#7f95f8]/10 px-2.5 font-mono text-[13px] text-[#cfe0ff] hover:bg-[#7f95f8]/[0.18]"
    >
      <BrandIcon name="github" className="h-4 w-4 shrink-0" />
      <span className="hidden xl:inline">Connect GitHub</span>
      <span className="sr-only xl:hidden">Connect GitHub</span>
    </button>
  );
}

export function GithubCompanionModal({
  open,
  onClose,
  user,
}: {
  open: boolean;
  onClose: () => void;
  user: User;
}) {
  const { panelRef, onKeyDown } = useModalDialog({ open, onClose });
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label="GitHub Companion"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="flex max-h-[86vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-white/[0.14] bg-[#0b0f1c] shadow-2xl focus:outline-none"
      >
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.08] px-5 py-3.5">
          <h2 className="text-[14px] font-semibold text-[#f3f6fd]">
            GitHub Sync — Keep Private Folders Off GitHub
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-full text-[#d2dbee] hover:text-white"
          >
            ✕
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <GithubCompanionSettingsSection user={user} />
        </div>
      </div>
    </div>
  );
}

function Chip({ tone, children }: { tone: "ok" | "warn" | "bad" | "muted"; children: ReactNode }) {
  const cls = {
    ok: "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]",
    warn: "border border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#a8c5ff]",
    bad: "border border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f27c7c]",
    muted: "border border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]",
  }[tone];
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[12.5px] leading-4 ${cls}`}>
      {children}
    </span>
  );
}

function PathList({
  title,
  paths,
  tone,
  reasons = {},
}: {
  title: string;
  paths: string[];
  tone: string;
  reasons?: Record<string, string>;
}) {
  if (paths.length === 0) return null;
  return (
    <div className="space-y-1.5">
      <div className={HEADING}>
        {title} ({paths.length})
      </div>
      <ul className="max-h-36 space-y-1 overflow-y-auto">
        {paths.map((p) => (
          <li key={p} title={p} className={`pr-well rounded-lg px-3 py-1.5 font-mono text-[13px] ${tone}`}>
            <div className="truncate">{p}</div>
            {reasons[p] && (
              <div className="mt-0.5 font-sans text-[12.5px] leading-snug text-[#b6c3db]">{reasons[p]}</div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Oid({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <span className="font-mono text-[12.5px] text-[#a6b5cf]">
      {label} <span className="text-[#d2dbee]">{value.slice(0, 10)}</span>
    </span>
  );
}

function CopyTrailer({ trailer }: { trailer: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={trailer}
      onClick={() => {
        navigator.clipboard?.writeText(trailer).catch(() => {});
        setCopied(true);
        setTimeout(() => setCopied(false), 1600);
      }}
      className="pr-pill inline-flex items-center gap-1.5 rounded-xl px-2.5 py-1 font-mono text-[12.5px] text-[#dce4f5]"
    >
      {copied ? <IconCheck className="h-4 w-4 text-[#5bdba2]" /> : <IconCopy className="h-4 w-4 text-[#a6b5cf]" />}
      <span>Attestation</span>
    </button>
  );
}

function ReceiptRow({ r }: { r: GithubPrReceipt }) {
  // Only an https URL is ever rendered as a link.
  const safe = /^https:\/\//i.test(r.pr_url);
  return (
    <li className="pr-well flex flex-wrap items-center justify-between gap-2 rounded-xl px-3 py-2">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2 text-[14px] text-[#f3f6fd]">
          {safe ? (
            <a
              href={r.pr_url}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-[#9ec0f5] hover:underline"
            >
              #{r.pr_number}
            </a>
          ) : (
            <span className="font-mono text-[#9ec0f5]">#{r.pr_number}</span>
          )}
          <span className="truncate">{r.pr_title}</span>
        </div>
        <div className="mt-0.5 font-mono text-[12.5px] text-[#a6b5cf]">
          {r.pr_branch} → {r.base_branch} · {plural(r.published_paths.length, "path")} published ·{" "}
          {r.scrubbed_paths_count} held back · <Time value={r.created_at} />
        </div>
      </div>
      <Oid label="commit" value={r.public_commit_oid} />
    </li>
  );
}

function PatchView({ patch }: { patch: string }) {
  return (
    <pre className="pr-well max-h-64 overflow-auto rounded-lg px-3 py-2 font-mono text-[12.5px] leading-snug">
      {patch.split("\n").map((line, i) => {
        const tone = line.startsWith("@@")
          ? "text-[#9ab0ff]"
          : line.startsWith("+") && !line.startsWith("+++")
            ? "text-[#5bdba2]"
            : line.startsWith("-") && !line.startsWith("---")
              ? "text-[#f27c7c]"
              : "text-[#b6c3db]";
        return (
          <div key={i} className={tone}>
            {line || " "}
          </div>
        );
      })}
    </pre>
  );
}

// ---------------------------------------------------------------------------
// Settings: connect + bidirectional zone sync + receipts
// ---------------------------------------------------------------------------

export function GithubCompanionSettingsSection({
  user,
  hideHeader = false,
}: {
  user: User;
  hideHeader?: boolean;
}) {
  const owner = user.role !== "member";
  const { status, setStatus, loadError, reload } = useGithubStatus(owner, true);
  const [repo, setRepo] = useState("");
  const [branch, setBranch] = useState("main");
  const [zone, setZone] = useState("");
  const [direction, setDirection] = useState<SyncDirection>("bidirectional");
  const [host, setHost] = useState("github.com");
  const [apiHost, setApiHost] = useState("");
  const [token, setToken] = useState("");
  const save = useAction();
  const disconnect = useAction();

  const cfg = status?.config ?? null;
  useEffect(() => {
    if (!cfg) return;
    setRepo(cfg.full_name);
    setBranch(cfg.default_branch);
    setZone(cfg.zone ?? "");
    setDirection(cfg.sync_direction);
    setHost(cfg.host);
    setApiHost(cfg.api_host === "api.github.com" ? "" : cfg.api_host);
  }, [cfg]);

  const [squash, setSquash] = useState(true);
  const [summary, setSummary] = useState("");
  const [prNumber, setPrNumber] = useState("");
  const [upstreamRef, setUpstreamRef] = useState("");
  const [outRes, setOutRes] = useState<SyncOutResponse | null>(null);
  const [inRes, setInRes] = useState<SyncInResponse | null>(null);
  const [outBlocked, setOutBlocked] = useState<string[]>([]);
  const [inRefused, setInRefused] = useState<{
    policy_violations: SyncInResponse["policy_violations"];
    conflicts: string[];
  } | null>(null);
  const syncOut = useAction();
  const syncIn = useAction();

  if (!owner) return null;

  const enterpriseHosts = status?.enterprise_hosts_allowed ?? [];
  const zones = status?.available_zones ?? [];
  const connected = status?.connected === true;
  const prNum = prNumber.trim() === "" ? undefined : Number(prNumber);
  const prInvalid = prNum !== undefined && (!Number.isInteger(prNum) || prNum <= 0);

  const doSave = async () => {
    await save.run(async () => {
      const next = await api.githubConfigure({
        repo: repo.trim(),
        default_branch: branch.trim() || undefined,
        zone: zone || null,
        sync_direction: direction,
        host: host.trim() || undefined,
        api_host: apiHost.trim() || undefined,
        token: token || undefined,
      });
      setStatus(next);
      setToken("");
    });
  };

  const doDisconnect = async () => {
    const ok = await disconnect.run(() => api.githubDisconnect());
    if (ok) {
      setOutRes(null);
      setInRes(null);
      setOutBlocked([]);
      setInRefused(null);
      setRepo("");
      reload();
    }
  };

  const runOut = (dry: boolean) => {
    setOutRes(null);
    setOutBlocked([]);
    void syncOut.run(async () => {
      try {
        const res = await api.githubSyncOut({
          zone: cfg?.zone || undefined,
          squash,
          summary_message: summary.trim() || undefined,
          dry_run: dry,
        });
        setOutRes(res);
        if (!dry) reload();
      } catch (err) {
        if (err instanceof ApiError && err.status === 409 && Array.isArray(err.body?.blocked)) {
          setOutBlocked(err.body.blocked.filter((x): x is string => typeof x === "string"));
        }
        throw err;
      }
    });
  };

  const runIn = (dry: boolean) => {
    setInRes(null);
    setInRefused(null);
    void syncIn.run(async () => {
      try {
        const res = await api.githubSyncIn({
          pr_number: prNum,
          upstream_ref: upstreamRef.trim() || undefined,
          dry_run: dry,
        });
        setInRes(res);
        if (!dry) reload();
      } catch (err) {
        if (err instanceof ApiError && (err.status === 403 || err.status === 409) && err.body) {
          const conflicts = Array.isArray(err.body.conflicts)
            ? err.body.conflicts.filter((x): x is string => typeof x === "string")
            : [];
          const rawViolations = Array.isArray(err.body.policy_violations)
            ? err.body.policy_violations
            : [];
          const policy_violations = rawViolations.filter(
            (v): v is SyncInResponse["policy_violations"][number] =>
              !!v &&
              typeof v === "object" &&
              typeof (v as { commit_oid?: unknown }).commit_oid === "string" &&
              typeof (v as { path?: unknown }).path === "string" &&
              typeof (v as { reason?: unknown }).reason === "string",
          );
          if (conflicts.length > 0 || policy_violations.length > 0) {
            setInRefused({ policy_violations, conflicts });
          }
        }
        throw err;
      }
    });
  };

  const canOut = connected && cfg?.sync_direction !== "inbound";
  const canIn = connected && cfg?.sync_direction !== "outbound";
  const hasUnsavedChanges = Boolean(
    cfg &&
      (repo.trim() !== cfg.full_name ||
        branch.trim() !== (cfg.default_branch ?? "") ||
        zone !== (cfg.zone ?? "") ||
        direction !== cfg.sync_direction ||
        host.trim() !== cfg.host ||
        apiHost.trim() !== (cfg.api_host === "api.github.com" ? "" : cfg.api_host) ||
        token !== ""),
  );
  const pushQuestion = cfg
    ? `Push ${cfg.full_name} (${cfg.default_branch || "main"}${cfg.zone ? ` · zone ${cfg.zone}` : " · all public paths"})?`
    : "Push to GitHub?";

  return (
    <section
      aria-labelledby={hideHeader ? undefined : "gh-companion-title"}
      aria-label={hideHeader ? "GitHub Companion" : undefined}
      className="pr-surface overflow-hidden rounded-2xl"
    >
      {!hideHeader && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-3 sm:px-5">
          <h2 id="gh-companion-title" className="inline-flex items-center gap-2 text-[14.5px] font-semibold text-[#f3f6fd]">
            <IconGithub className="h-[18px] w-[18px] text-[#9ec0f5]" />
            <span>GitHub Companion</span>
          </h2>
          {status && (
            <Chip tone={connected ? "ok" : "muted"}>
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-[#5bdba2]" : "bg-[#54627c]"}`} />
              {connected ? `connected · ${cfg?.full_name}` : "disconnected"}
            </Chip>
          )}
        </div>
      )}

      <div className="space-y-4 p-4 sm:p-5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-[14px] leading-relaxed text-[#b6c3db]">
            Sync public code with GitHub; private folders stay local.
          </p>
          {hideHeader && status && (
            <Chip tone={connected ? "ok" : "muted"}>
              <span className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-[#5bdba2]" : "bg-[#54627c]"}`} />
              {connected ? `connected · ${cfg?.full_name}` : "disconnected"}
            </Chip>
          )}
        </div>
        <ErrorNote message={loadError} />

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void doSave();
          }}
          className="space-y-3"
        >
          <div className="grid gap-3 sm:grid-cols-2">
            <Field
              label="GitHub repository"
              value={repo}
              onChange={(e) => setRepo(e.target.value)}
              placeholder="acme/sdk"
              hint="owner/repo"
              required
              autoComplete="off"
              spellCheck={false}
            />
            <Field
              label="Target default branch"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
              autoComplete="off"
              spellCheck={false}
            />
            <div className="space-y-1.5">
              <label htmlFor="gh-zone" className={LABEL}>
                Zone
              </label>
              <select id="gh-zone" value={zone} onChange={(e) => setZone(e.target.value)} className={SELECT_CLASS}>
                <option value="">All public-readable paths (no zone filter)</option>
                {zones.map((z) => (
                  <option key={z} value={z}>
                    {z}
                  </option>
                ))}
                {zone && !zones.includes(zone) && <option value={zone}>{zone}</option>}
              </select>
            </div>
            <div className="space-y-1.5">
              <label htmlFor="gh-dir" className={LABEL}>
                Sync direction
              </label>
              <select
                id="gh-dir"
                value={direction}
                onChange={(e) => setDirection(e.target.value as SyncDirection)}
                className={SELECT_CLASS}
              >
                {DIRECTIONS.map((d) => (
                  <option key={d.value} value={d.value}>
                    {d.label}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {enterpriseHosts.length === 0 ? (
            <p className="text-[13px] text-[#a6b5cf]">
              Host: <span className="font-mono text-[#d2dbee]">github.com</span> · API{" "}
              <span className="font-mono text-[#d2dbee]">api.github.com</span>
            </p>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <label htmlFor="gh-host" className={LABEL}>
                  GitHub host
                </label>
                <select id="gh-host" value={host} onChange={(e) => setHost(e.target.value)} className={SELECT_CLASS}>
                  {["github.com", ...enterpriseHosts].map((h) => (
                    <option key={h} value={h}>
                      {h}
                    </option>
                  ))}
                </select>
              </div>
              <Field
                label="API host"
                value={apiHost}
                onChange={(e) => setApiHost(e.target.value)}
                placeholder="api.github.com"
                hint="Optional — defaults to host API."
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          )}

          <Field
            label="GitHub token"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={
              cfg?.token_configured ? "•••••••••••••••• (leave blank to keep existing)" : "ghp_… or github_pat_…"
            }
            autoComplete="off"
            spellCheck={false}
            hint="Write-only · encrypted in age vault, never exposed to agents."
          />
          {cfg?.token_configured && cfg.token_updated_at && (
            <p className="text-[13px] text-[#a6b5cf]">
              Token updated <Time value={cfg.token_updated_at} />
            </p>
          )}

          <ErrorNote message={save.error ?? disconnect.error} />
          <div className="flex flex-wrap items-center gap-2">
            <button type="submit" disabled={save.pending || !repo.trim()} className={PRIMARY_BTN}>
              <IconGithub className="h-4 w-4" />
              <span>{save.pending ? "Saving…" : connected ? "Save changes" : "Connect"}</span>
            </button>
            {connected && (
              <ConfirmButton
                disabled={disconnect.pending}
                question="Disconnect GitHub?"
                confirmLabel="Disconnect"
                onConfirm={() => void doDisconnect()}
                className={DANGER_BTN}
              >
                Disconnect
              </ConfirmButton>
            )}
            {connected && cfg && (
              <span className="text-[13px] text-[#a6b5cf]">
                Connected by {cfg.connected_by} · <Time value={cfg.connected_at} />
              </span>
            )}
          </div>
        </form>

        {connected && (
          <div className="space-y-4 border-t border-white/[0.06] pt-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h3 className="inline-flex items-center gap-2 text-[14px] font-semibold text-[#f3f6fd]">
                <IconSync className="h-[18px] w-[18px] text-[#9ec0f5]" />
                <span>Bidirectional zone sync</span>
              </h3>
              <div className="flex flex-wrap items-center gap-2">
                <Chip tone="muted">{plural(status?.sync_state?.mapped_commits ?? 0, "mapped commit")}</Chip>
                <Oid label="canonical" value={status?.sync_state?.last_canonical_oid} />
                <Oid label="upstream" value={status?.sync_state?.last_upstream_oid} />
              </div>
            </div>
            {status?.sync_state?.last_sync_summary && (
              <p className="text-[13px] text-[#a6b5cf]">
                Last sync: {status.sync_state.last_sync_summary}
                {status.sync_state.last_sync_out_at && (
                  <>
                    {" "}
                    · out <Time value={status.sync_state.last_sync_out_at} />
                  </>
                )}
                {status.sync_state.last_sync_in_at && (
                  <>
                    {" "}
                    · in <Time value={status.sync_state.last_sync_in_at} />
                  </>
                )}
              </p>
            )}

            {/* Sync out */}
            <div className="pr-well space-y-3 rounded-xl p-3.5">
              <div className={HEADING}>Sync out · Premier → GitHub</div>
              <label className="flex items-center gap-2 text-[14px] text-[#dce4f5]">
                <input
                  type="checkbox"
                  checked={squash}
                  onChange={(e) => setSquash(e.target.checked)}
                  className="h-4 w-4 accent-[#7f95f8]"
                />
                Squash commits (strips private history &amp; metadata)
              </label>
              {!squash && (
                <p className="text-[13px] text-[#cbd5e8]">
                  Mirrors individual public commits with scrubbed messages.
                </p>
              )}
              <Field
                label="Summary message"
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                placeholder="Optional commit summary for GitHub"
                autoComplete="off"
              />
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={syncOut.pending || !canOut}
                  title={canOut ? undefined : "Sync direction is inbound only"}
                  onClick={() => runOut(true)}
                  className={SECONDARY_BTN}
                >
                  Dry-Run Sync Out
                </button>
                <ConfirmButton
                  disabled={syncOut.pending || !canOut || hasUnsavedChanges}
                  title={
                    !canOut
                      ? "Sync direction is inbound only"
                      : hasUnsavedChanges
                        ? "Save configuration before pushing"
                        : undefined
                  }
                  question={pushQuestion}
                  confirmLabel="Push"
                  onConfirm={() => runOut(false)}
                  className={PRIMARY_BTN}
                >
                  <IconPlay className="h-4 w-4" />
                  <span>{syncOut.pending ? "Syncing…" : "Push Sync Out"}</span>
                </ConfirmButton>
                {hasUnsavedChanges && (
                  <span className="text-[13px] text-[#a8c5ff]">Save configuration before pushing</span>
                )}
              </div>
              <ErrorNote message={syncOut.error} />
              {outBlocked.length > 0 && <PathList title="Blocked" paths={outBlocked} tone="text-[#f27c7c]" />}
              {outRes && (
                <div className="space-y-2.5" role="status">
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
                    <Chip tone={outRes.dry_run ? "warn" : "ok"}>{outRes.dry_run ? "dry run" : "pushed"}</Chip>
                    {outRes.up_to_date && <Chip tone="ok">up to date</Chip>}
                    <span className="text-[#d2dbee]">
                      {outRes.source_branch} → {outRes.target_branch}
                    </span>
                    <span className="text-[#a6b5cf]">
                      {outRes.commits_projected} projected · {outRes.commits_collapsed} collapsed
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <Oid label="canonical" value={outRes.canonical_tip} />
                    <Oid label="upstream" value={outRes.upstream_tip} />
                  </div>
                  <PathList title="Published" paths={outRes.published_paths} tone="text-[#5bdba2]" />
                  <PathList title="Scrubbed (private)" paths={outRes.scrubbed_paths} tone="text-[#cbd5e8]" />
                  <PathList title="Blocked" paths={outRes.blocked} tone="text-[#f27c7c]" />
                </div>
              )}
            </div>

            {/* Sync in */}
            <div className="pr-well space-y-3 rounded-xl p-3.5">
              <div className={HEADING}>Sync in · GitHub → Premier</div>
              <div className="grid gap-3 sm:grid-cols-2">
                <Field
                  label="PR number"
                  value={prNumber}
                  onChange={(e) => setPrNumber(e.target.value)}
                  inputMode="numeric"
                  placeholder="e.g. 42"
                  autoComplete="off"
                />
                <Field
                  label="…or upstream ref"
                  value={upstreamRef}
                  onChange={(e) => setUpstreamRef(e.target.value)}
                  placeholder="main"
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              {prInvalid && <p className="text-[13px] text-[#a8c5ff]">PR number must be a positive whole number.</p>}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={syncIn.pending || !canIn || prInvalid}
                  title={canIn ? undefined : "Sync direction is outbound only"}
                  onClick={() => runIn(true)}
                  className={SECONDARY_BTN}
                >
                  Dry-Run Sync In
                </button>
                <ConfirmButton
                  disabled={syncIn.pending || !canIn || prInvalid}
                  title={canIn ? undefined : "Sync direction is outbound only"}
                  question="Pull from GitHub?"
                  confirmLabel="Pull"
                  onConfirm={() => runIn(false)}
                  className={PRIMARY_BTN}
                >
                  <IconPlay className="h-4 w-4" />
                  <span>{syncIn.pending ? "Syncing…" : "Pull Sync In"}</span>
                </ConfirmButton>
              </div>
              <ErrorNote message={syncIn.error} />
              {inRefused && inRefused.policy_violations.length > 0 && (
                <div role="alert" className="space-y-1.5">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#f27c7c]">
                    Policy violations ({inRefused.policy_violations.length})
                  </div>
                  {inRefused.policy_violations.map((v, i) => (
                    <div
                      key={`${v.commit_oid}:${v.path}:${i}`}
                      className="rounded-lg border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-1.5 text-[13px] text-[#f27c7c]"
                    >
                      <div className="flex items-center gap-1.5 font-mono">
                        <IconQuarantine className="h-4 w-4" />
                        <span>{v.commit_oid.slice(0, 10)}</span>
                        <span className="min-w-0 truncate">{v.path}</span>
                      </div>
                      <div className="mt-0.5 text-[#f6a8a8]">{v.reason}</div>
                    </div>
                  ))}
                </div>
              )}
              {inRefused && <PathList title="Conflicts" paths={inRefused.conflicts} tone="text-[#f27c7c]" />}
              {inRes && (
                <div className="space-y-2.5" role="status">
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
                    <Chip tone={inRes.dry_run ? "warn" : "ok"}>{inRes.dry_run ? "dry run" : "imported"}</Chip>
                    {inRes.up_to_date && <Chip tone="ok">up to date</Chip>}
                    <span className="text-[#d2dbee]">
                      {inRes.upstream_ref} → {inRes.target_branch}
                    </span>
                    <span className="text-[#a6b5cf]">{plural(inRes.commits_imported, "commit")} imported</span>
                    {inRes.preserved_hidden_count > 0 && (
                      <Chip tone="warn">
                        <IconShieldCheck className="h-3.5 w-3.5" />
                        {inRes.preserved_hidden_count} hidden preserved
                      </Chip>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <Oid label="upstream" value={inRes.upstream_tip} />
                    <Oid label="new canonical" value={inRes.new_canonical_tip} />
                  </div>
                  {inRes.policy_violations.length > 0 && (
                    <div role="alert" className="space-y-1.5">
                      <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#f27c7c]">
                        Policy violations ({inRes.policy_violations.length})
                      </div>
                      {inRes.policy_violations.map((v, i) => (
                        <div
                          key={`${v.commit_oid}:${v.path}:${i}`}
                          className="rounded-lg border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-1.5 text-[13px] text-[#f27c7c]"
                        >
                          <div className="flex items-center gap-1.5 font-mono">
                            <IconQuarantine className="h-4 w-4" />
                            <span>{v.commit_oid.slice(0, 10)}</span>
                            <span className="min-w-0 truncate">{v.path}</span>
                          </div>
                          <div className="mt-0.5 text-[#f6a8a8]">{v.reason}</div>
                        </div>
                      ))}
                    </div>
                  )}
                  <PathList title="Conflicts" paths={inRes.conflicts} tone="text-[#f27c7c]" />
                  <PathList title="Imported" paths={inRes.imported_paths} tone="text-[#5bdba2]" />
                </div>
              )}
            </div>

            <div className="space-y-2">
              <div className={HEADING}>Recent GitHub PR receipts</div>
              {(status?.receipts ?? []).length === 0 ? (
                <div className="font-mono text-[13px] text-[#a6b5cf]">No pull requests opened yet</div>
              ) : (
                <ul className="space-y-1.5">
                  {status?.receipts.map((r) => (
                    <ReceiptRow key={r.id} r={r} />
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// BranchesView: top-bar pill
// ---------------------------------------------------------------------------

export function GithubCompanionPill({ user }: { user: User }) {
  const owner = user.role !== "member";
  const { status, settled, loadError, unsupported, reload } = useGithubStatus(owner);
  const [retrying, setRetrying] = useState(false);
  if (!owner) return null;
  // Older servers (404/405/501) have no GitHub companion: render nothing, never a Retry chip.
  if (unsupported && !status) return null;
  // Reserve the pill's footprint while the status settles so it never pops in late.
  if (!status && !settled) return <SkelPill className="h-7 w-40" />;
  if (!status) {
    return loadError ? (
      <button
        type="button"
        disabled={retrying}
        aria-busy={retrying}
        onClick={() => {
          setRetrying(true);
          void reload().finally(() => setRetrying(false));
        }}
        title={`GitHub status failed: ${loadError}`}
        className="pr-pill inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[13px] text-[#a8c5ff] disabled:cursor-wait disabled:opacity-60"
      >
        <IconRefresh className={`h-4 w-4 ${retrying ? "animate-spin" : ""}`} />
        <span>{retrying ? "Retrying…" : "GitHub status failed · Retry"}</span>
      </button>
    ) : null;
  }
  if (status.connected && status.config) {
    return (
      <span
        title={`GitHub companion: ${status.config.full_name}`}
        className="pr-pill inline-flex max-w-full items-center gap-2 rounded-full px-3 py-1 font-mono text-[13px] text-[#dce4f5]"
      >
        <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-[#5bdba2]" />
        <span className="truncate">
          GitHub: {status.config.full_name} · {status.config.zone || "public"}
        </span>
      </span>
    );
  }
  return (
    <a
      href={githubSettingsHash(currentRepoName(), currentRepoIsDefault())}
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 font-mono text-[13px] text-[#a6b5cf] hover:text-[#9ec0f5]"
    >
      <IconGithub className="h-4 w-4" />
      <span>Connect GitHub</span>
    </a>
  );
}

// ---------------------------------------------------------------------------
// BranchesView: inspector panel
// ---------------------------------------------------------------------------

export function GithubCompanionBranchPanel({
  user,
  branchName,
  baseBranch,
  first = false,
  onPublished,
}: {
  user: User;
  branchName: string;
  baseBranch?: string;
  /** First block in its rail: no divider above it. */
  first?: boolean;
  onPublished?: () => void;
}) {
  const owner = user.role !== "member";
  const { status, reload } = useGithubStatus(owner);
  const [title, setTitle] = useState("");
  const [prBranch, setPrBranch] = useState("");
  const [body, setBody] = useState("");
  const [draft, setDraft] = useState(false);
  const [preview, setPreview] = useState<GithubPrPreviewResponse | null>(null);
  const [published, setPublished] = useState<PublishGithubPrResponse | null>(null);
  const [refused, setRefused] = useState<{ conflicts: string[]; blocked: string[] } | null>(null);
  const previewing = useAction();
  const publishing = useAction();
  // Replies for a branch the user has since left are dropped, not shown under the new branch.
  const branchRef = useRef(branchName);
  branchRef.current = branchName;

  useEffect(() => {
    setPreview(null);
    setPublished(null);
    setRefused(null);
    setTitle("");
    setPrBranch("");
    setBody("");
    setDraft(false);
    previewing.setError(null);
    publishing.setError(null);
  }, [branchName]);

  if (!owner || !status) return null;

  if (!status.connected) {
    return (
      <div className="pr-well flex items-center gap-2 rounded-xl px-3 py-2.5 text-[13px] text-[#b6c3db]">
        <IconGithub className="h-4 w-4 shrink-0 text-[#a6b5cf]" />
        <span>
          Connect GitHub in{" "}
          <a
            href={githubSettingsHash(currentRepoName(), currentRepoIsDefault())}
            className="text-[#9ec0f5] hover:underline"
          >
            Settings
          </a>{" "}
          to open clean PRs.
        </span>
      </div>
    );
  }
  const targetBase = status.config?.default_branch || baseBranch;
  if (branchName === targetBase) return null;

  const request = () => ({
    source_branch: branchName,
    base_branch: targetBase,
    pr_branch: prBranch.trim() || undefined,
    title: title.trim() || undefined,
    body: body.trim() || undefined,
  });

  const captureRefusal = (err: unknown) => {
    const b = err instanceof ApiError && err.status === 409 ? err.body : null;
    const list = (v: unknown): string[] =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
    const conflicts = list(b?.conflicts);
    const blocked = list(b?.blocked);
    setRefused(conflicts.length + blocked.length > 0 ? { conflicts, blocked } : null);
  };

  const doPreview = async () => {
    const forBranch = branchName;
    setRefused(null);
    setPublished(null);
    const ok = await previewing.run(async () => {
      try {
        const res = await api.githubPreviewPr(request());
        if (branchRef.current === forBranch) setPreview(res);
      } catch (err) {
        if (branchRef.current === forBranch) {
          setPreview(null);
          captureRefusal(err);
        }
        throw err;
      }
    });
    if (!ok && branchRef.current === forBranch) setPreview(null);
  };

  const doPublish = async () => {
    const forBranch = branchName;
    setRefused(null);
    const ok = await publishing.run(async () => {
      try {
        const res = await api.githubPublishPr({ ...request(), draft: draft || undefined });
        if (branchRef.current === forBranch) setPublished(res);
      } catch (err) {
        if (branchRef.current === forBranch) captureRefusal(err);
        throw err;
      }
    });
    if (ok) {
      reload();
      onPublished?.();
    }
  };

  const conflicts = refused?.conflicts ?? preview?.conflicts ?? [];
  const blocked = refused?.blocked ?? preview?.blocked ?? [];
  const blockReason =
    preview?.reason ||
    (blocked.length > 0
      ? "Remove the blocked files from the branch first"
      : conflicts.length > 0
        ? "Resolve the conflicts first"
        : preview && preview.published_paths.length === 0
          ? "Nothing to publish"
          : !preview?.gate_passed
            ? "Preview the pull request first"
            : undefined);
  const meta = preview?.scrubbed_metadata;
  const mine = status.receipts.filter((r) => r.source_branch === branchName);

  return (
    <div className={`space-y-3 ${first ? "" : "border-t border-white/[0.06] pt-4"}`}>
      <div className="flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-2 font-mono text-[13px] uppercase tracking-wider text-[#9ec0f5]">
          <IconGithub className="h-[18px] w-[18px]" />
          <span>GitHub pull request</span>
        </span>
        <span className="truncate font-mono text-[12.5px] text-[#a6b5cf]">{status.config?.full_name}</span>
      </div>

      <input
        value={title}
        onChange={(e) => setTitle(e.target.value)}
        aria-label="Pull request title"
        placeholder={preview?.pr_title || "Clean pull request title…"}
        className="pr-well w-full rounded-xl px-3 py-2 font-mono text-[13.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
      />
      <input
        value={prBranch}
        onChange={(e) => setPrBranch(e.target.value)}
        aria-label="Public PR branch name"
        placeholder={preview?.pr_branch || "Public PR branch (optional)"}
        spellCheck={false}
        className="pr-well w-full rounded-xl px-3 py-2 font-mono text-[13.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
      />
      <textarea
        value={body}
        onChange={(e) => setBody(e.target.value)}
        aria-label="Pull request description"
        placeholder={preview?.pr_body || "Description (optional)"}
        rows={2}
        className="pr-well w-full resize-y rounded-xl px-3 py-2 font-mono text-[13.5px] text-[#f3f6fd] placeholder:text-[#7b8ca8] focus:outline-none"
      />

      <div className="flex flex-wrap items-center gap-2">
        <label className="mr-auto flex items-center gap-1.5 text-[13.5px] text-[#dce4f5]">
          <input
            type="checkbox"
            checked={draft}
            onChange={(e) => setDraft(e.target.checked)}
            className="h-4 w-4 accent-[#7f95f8]"
          />
          Draft
        </label>
        <button
          type="button"
          disabled={previewing.pending}
          onClick={() => void doPreview()}
          className={`${SECONDARY_BTN} text-[13px]!`}
        >
          {previewing.pending ? "Previewing…" : "Preview GitHub PR"}
        </button>
        <ConfirmButton
          disabled={publishing.pending || Boolean(blockReason)}
          title={blockReason}
          question={`Open PR on ${status.config?.full_name}?`}
          confirmLabel="Publish"
          onConfirm={() => void doPublish()}
          className={`${PRIMARY_BTN} text-[13px]!`}
        >
          <IconPlay className="h-4 w-4" />
          <span>{publishing.pending ? "Publishing…" : "Publish to GitHub PR"}</span>
        </ConfirmButton>
      </div>

      <ErrorNote message={previewing.error ?? publishing.error} />

      {preview && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
            {preview.gate_passed ? (
              <Chip tone="ok">
                <IconShieldCheck className="h-4 w-4" />
                Gate OK
              </Chip>
            ) : (
              <Chip tone="bad">Blocked{preview.reason ? `: ${preview.reason}` : ""}</Chip>
            )}
            <span className="text-[#d2dbee]">
              {preview.pr_branch} → {preview.base_branch}
            </span>
            {preview.zone && <Chip tone="muted">zone {preview.zone}</Chip>}
          </div>

          {meta && (
            <ul className="pr-well space-y-1 rounded-xl px-3 py-2.5 text-[13px] text-[#d2dbee]">
              {(
                [
                  [meta.private_ancestry_stripped, "Private ancestry stripped"],
                  [meta.canonical_oids_stripped, "Canonical OIDs stripped"],
                  [meta.copyfrom_history_stripped, "Copy/rename history stripped"],
                  [meta.source_branch_name_redacted, "Source branch name redacted"],
                ] as const
              ).map(([on, label]) => (
                <li key={label} className="flex items-center gap-1.5">
                  {on ? (
                    <IconCheck className="h-4 w-4 text-[#5bdba2]" />
                  ) : (
                    <IconQuarantine className="h-4 w-4 text-[#a8c5ff]" />
                  )}
                  <span>{label}</span>
                </li>
              ))}
              <li className="text-[#b6c3db]">
                {plural(meta.commits_squashed, "commit")} squashed · {meta.omitted_paths_count} private{" "}
                {meta.omitted_paths_count === 1 ? "path" : "paths"} omitted
              </li>
            </ul>
          )}

          <PathList title="Will be published" paths={preview.published_paths} tone="text-[#5bdba2]" />
          <PathList
            title="Held back (private)"
            paths={preview.scrubbed_paths}
            tone="text-[#cbd5e8]"
            reasons={preview.held_back_reasons}
          />
        </div>
      )}

      {/* Shown for a 409 refusal too, where there is no preview. */}
      <PathList title="Blocked" paths={blocked} tone="text-[#f27c7c]" />
      <PathList title="Conflicts" paths={conflicts} tone="text-[#f27c7c]" />

      {preview && preview.diffs.length > 0 && (
        <details className="group space-y-2">
          <summary className="cursor-pointer font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
            Projected public unified diff ({plural(preview.diffs.length, "file")})
          </summary>
          <div className="mt-2 space-y-2">
            {preview.diffs.map((d) => (
              <div key={d.path} className="space-y-1">
                <div className="flex items-center justify-between gap-2 font-mono text-[12.5px]">
                  <span className="truncate text-[#dce4f5]" title={d.path}>
                    {d.path}
                  </span>
                  <span className="shrink-0">
                    <span className="text-[#5bdba2]">+{d.additions}</span>{" "}
                    <span className="text-[#f27c7c]">−{d.deletions}</span>{" "}
                    <span className="text-[#a6b5cf]">{d.status}</span>
                  </span>
                </div>
                {d.binary ? (
                  <div className="font-mono text-[12.5px] text-[#a6b5cf]">Binary file</div>
                ) : (
                  <PatchView patch={d.patch} />
                )}
                {d.truncated && <div className="font-mono text-[12.5px] text-[#cbd5e8]">Patch truncated</div>}
              </div>
            ))}
            {preview.diff_truncated && (
              <div className="font-mono text-[12.5px] text-[#cbd5e8]">More files changed than shown.</div>
            )}
          </div>
        </details>
      )}

      {published && (
        <div role="status" className="rounded-xl border border-[#5bdba2]/30 bg-[#5bdba2]/10 p-3 font-mono text-[12.5px] text-[#5bdba2]">
          <div className="flex items-center gap-1.5 font-semibold">
            <IconShieldCheck className="h-4 w-4" />
            <span>
              Opened{" "}
              {/^https:\/\//i.test(published.receipt.pr_url) ? (
                <a
                  href={published.receipt.pr_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline"
                >
                  PR #{published.receipt.pr_number}
                </a>
              ) : (
                <>PR #{published.receipt.pr_number}</>
              )}
            </span>
          </div>
          <div className="mt-1 text-[#bcefd9]">
            commit {published.receipt.public_commit_oid.slice(0, 10)} ·{" "}
            {plural(published.published_paths.length, "path")} published
            {published.scrubbed_paths.length > 0 && `, ${published.scrubbed_paths.length} held back`}
          </div>
          <div className="mt-2">
            <CopyTrailer trailer={published.receipt.attestation_trailer} />
          </div>
        </div>
      )}

      {mine.length > 0 && (
        <div className="space-y-1.5">
          <div className={HEADING}>Existing receipts for this branch</div>
          <ul className="space-y-1.5">
            {mine.map((r) => (
              <ReceiptRow key={r.id} r={r} />
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
