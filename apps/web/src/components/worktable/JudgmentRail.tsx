import { useState, type ReactNode, type RefObject } from "react";
import {
  api,
  branchNameError,
  type AgentSessionRecord,
  type GrantScope,
  type IdentityPreset,
  type PendingApproval,
  type RiskLevel,
  type SessionDiffResponse,
  type WorktableBranch,
  type WorktableQuarantineItem,
} from "../../api";
import { detectLanguage, parseUnifiedPatch, tokenClassName, tokenizeLine } from "../../lib/highlight";
import { plural } from "../../lib/format";
import { RISK_BADGE } from "../KnockApprovalCard";
import { ConfirmButton, ErrorNote, useAction } from "../forms";
import {
  IconBranchRef,
  IconIntersection,
  IconLock,
  IconQuarantine,
  IconShieldCheck,
} from "../Icons";
import {
  formatByteCount,
  formatCountdownSeconds,
  formatElapsedSeconds,
  visibilitySummary,
  type FocusTarget,
  type JudgmentFilter,
} from "./types";
import { CodeLinesSkeleton, JudgmentEmptySkeleton } from "../ViewSkeletons";

interface Props {
  owner: boolean;
  identity: IdentityPreset;
  nowMs: number;
  pendingApprovals: PendingApproval[];
  quarantineItems: WorktableQuarantineItem[];
  uncommittedSessions: AgentSessionRecord[];
  readyBranches: WorktableBranch[];
  defaultBranch: string;
  railRef?: RefObject<HTMLElement | null>;
  /** True once the worktable summary has arrived; until then counts and "Nothing waiting" are unknown. */
  loaded: boolean;
  error?: string | null;
  onRetry?: () => void;
  onApprovalDecided: () => void;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onRefreshWorktable: () => void;
  onFocus: (target: FocusTarget) => void;
  onOpenCode: (branch: string, path?: string) => void;
  onOpenReview: (changeId: string) => void;
  onOpenBranches: (branchName: string) => void;
}

const FILTERS: { id: JudgmentFilter; label: string }[] = [
  { id: "all", label: "All" },
  { id: "jit", label: "JIT" },
  { id: "quarantine", label: "Quarantine" },
  { id: "diffs", label: "Diffs" },
  { id: "publish", label: "Publish" },
];

const ROW = "pr-well pr-card-interactive space-y-2 rounded-xl px-3 py-2.5";
const MINI_BTN = "pr-pill rounded-full px-2.5 py-1 text-[13px] text-[#dce4f5] disabled:opacity-40";
const BADGE =
  "inline-flex max-w-full items-center gap-1 rounded-full bg-white/[0.06] px-2 py-0.5 font-mono text-[12.5px] text-[#d2dbee]";

function Section({
  title,
  count,
  icon,
  children,
}: {
  title: string;
  count: number;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="space-y-2" aria-label={title}>
      <h3 className="flex items-center gap-1.5 text-[12.5px] font-medium uppercase tracking-wider text-[#a6b5cf]">
        {icon}
        {title}
        <span className="rounded-full bg-white/[0.06] px-1.5 text-[12px] text-[#d2dbee]">{count}</span>
      </h3>
      <div className="space-y-2">{children}</div>
    </section>
  );
}

function BranchBadge({ name }: { name: string }) {
  return (
    <span className={BADGE} title={name}>
      <IconBranchRef className="h-3 w-3" />
      <span className="truncate">{name}</span>
    </span>
  );
}

/** Shared by the rail and the focus drawer so both send the same explicit grant_scope contract. */
export function ApprovalRow({
  ap,
  owner,
  nowMs,
  onDecided,
}: {
  ap: PendingApproval;
  owner: boolean;
  nowMs: number;
  onDecided: () => void;
}) {
  const { pending, error, run } = useAction();
  const decide = (approved: boolean, scope?: GrantScope, ttl?: number) =>
    void run(async () => {
      if (approved) {
        await api.decideApproval(ap.id, true, ttl, { grant_scope: scope ?? "once" });
      } else {
        await api.decideApproval(ap.id, false);
      }
      onDecided();
    });
  const expiresMs = ap.expires_at
    ? Date.parse(ap.expires_at)
    : Date.parse(ap.created_at) + ap.ttl_secs * 1000;
  const expired = !Number.isNaN(expiresMs) && expiresMs <= nowMs;
  const risk: RiskLevel =
    ap.risk_level ?? (ap.method.toUpperCase() === "GET" ? "read_only" : "state_mutation");
  const badge = RISK_BADGE[risk];
  const target = `${ap.host}${ap.concrete_path ?? ap.path}`;
  return (
    <div className={ROW} data-judgment-item>
      <div className="flex flex-wrap items-center gap-2">
        <span className="pr-presence-dot bg-[#7f95f8]" aria-hidden="true" />
        <span className="font-mono text-[13.5px] text-[#f3f6fd]">{ap.var_name}</span>
        <span className={BADGE}>{ap.method}</span>
        <span className={`rounded-full border px-2 py-0.5 font-mono text-[12px] ${badge.cls}`}>
          {badge.label}
        </span>
      </div>
      <div className="break-all font-mono text-[13px] text-[#d2dbee]" title={target}>
        {target}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-[#a6b5cf]">
        <span className="font-mono">
          {ap.principal}
          {ap.agent_profile ? ` ∩ ${ap.agent_profile}` : ""}
        </span>
        <span>waiting {formatElapsedSeconds(ap.created_at, nowMs)}</span>
        {!Number.isNaN(expiresMs) && <span>{formatCountdownSeconds((expiresMs - nowMs) / 1000)}</span>}
      </div>
      {owner ? (
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            disabled={pending || expired}
            onClick={() => decide(true, "once")}
            className="pr-action-btn rounded-full px-3 py-1 text-[13px] disabled:opacity-40"
          >
            Allow once
          </button>
          <button
            type="button"
            disabled={pending || expired}
            onClick={() => decide(true, "exact_path", 300)}
            title="Allow this exact method + path for 5 minutes"
            className="pr-pill rounded-full px-2.5 py-1 text-[13px] text-[#dce4f5] disabled:opacity-40"
          >
            Allow 5m
          </button>
          <ConfirmButton
            disabled={pending || expired}
            confirmLabel="Deny"
            question="Deny this request?"
            onConfirm={() => decide(false)}
            className="pr-pill rounded-full px-2.5 py-1 text-[13px] text-[#f27c7c] disabled:opacity-40"
          >
            Deny
          </ConfirmButton>
        </div>
      ) : (
        <p className="text-[13px] text-[#a6b5cf]">Owner approval required</p>
      )}
      <ErrorNote message={error} />
    </div>
  );
}

function QuarantineRow({
  item,
  onFocus,
  onOpenCode,
  onOpenReview,
}: {
  item: WorktableQuarantineItem;
  onFocus: (target: FocusTarget) => void;
  onOpenCode: (branch: string, path?: string) => void;
  onOpenReview: (changeId: string) => void;
}) {
  return (
    <div className={ROW} data-judgment-item>
      <div className="flex flex-wrap items-center gap-2">
        <IconQuarantine className="h-4 w-4 text-[#a8c5ff]" />
        <span className="min-w-0 truncate font-mono text-[13.5px] text-[#f3f6fd]" title={item.path}>
          {item.path}
        </span>
        <BranchBadge name={item.branch} />
      </div>
      <p className="text-[12.5px] text-[#a6b5cf]">
        {item.author} · {item.title} · Instruction surface modified
      </p>
      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          className={MINI_BTN}
          onClick={() =>
            onFocus(
              item.change_id
                ? { kind: "review", changeId: item.change_id }
                : { kind: "branch", name: item.branch },
            )
          }
        >
          Focus
        </button>
        <button type="button" className={MINI_BTN} onClick={() => onOpenCode(item.branch, item.path)}>
          Inspect
        </button>
        {item.change_id && (
          <button
            type="button"
            className={MINI_BTN}
            onClick={() => onOpenReview(item.change_id as string)}
          >
            Review
          </button>
        )}
      </div>
    </div>
  );
}

/** Compact syntax-highlighted hunks of a session's diff, fetched on first open. */
function QuickDiff({ data }: { data: SessionDiffResponse }) {
  return (
    <div className="pr-well max-h-52 overflow-auto rounded-lg font-mono text-[12.5px] leading-[1.55]">
      {data.truncated && (
        <div className="px-2.5 py-1 text-[12.5px] text-[#cbd5e8]">Diff truncated by the server.</div>
      )}
      {data.files.map((file) => {
        const parsed = !file.binary && file.patch ? parseUnifiedPatch(file.patch) : null;
        const lang = detectLanguage(file.path);
        return (
          <div key={file.path} className="border-b border-white/[0.05] last:border-b-0">
            <div className="flex items-center justify-between gap-2 bg-white/[0.03] px-2.5 py-1 text-[12.5px]">
              <span className="truncate text-[#dce4f5]" title={file.path}>
                {file.path}
              </span>
              {parsed && (
                <span className="shrink-0">
                  <span className="text-[#5bdba2]">+{parsed.additions}</span>{" "}
                  <span className="text-[#f27c7c]">-{parsed.deletions}</span>
                </span>
              )}
            </div>
            {file.binary ? (
              <div className="px-2.5 py-1 text-[#a6b5cf]">Binary file ({formatByteCount(file.size)})</div>
            ) : (
              parsed?.lines.map((dl, i) => {
                if (dl.kind === "meta") return null;
                if (dl.kind === "hunk") {
                  return (
                    <div key={i} className="bg-[#7f95f8]/10 px-2.5 text-[12px] text-[#9ec0f5]">
                      {dl.body}
                    </div>
                  );
                }
                const bg = dl.kind === "add" ? "bg-[#5bdba2]/10" : dl.kind === "del" ? "bg-[#f27c7c]/10" : "";
                const sigil =
                  dl.kind === "add" ? "text-[#5bdba2]" : dl.kind === "del" ? "text-[#f27c7c]" : "text-[#a6b5cf]";
                return (
                  <div key={i} className={`flex px-2 ${bg}`}>
                    <span className={`w-3.5 shrink-0 select-none ${sigil}`}>{dl.sigil}</span>
                    <span className="whitespace-pre">
                      {tokenizeLine(dl.body, lang).map((tok, ti) => (
                        <span key={ti} className={tokenClassName(tok.kind)}>
                          {tok.text}
                        </span>
                      ))}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        );
      })}
    </div>
  );
}

function SessionRow({
  session,
  owner,
  identity,
  onSessionChange,
  onRefreshWorktable,
  onFocus,
  onOpenReview,
}: {
  session: AgentSessionRecord;
  owner: boolean;
  identity: IdentityPreset;
  onSessionChange: (rec: AgentSessionRecord) => void;
  onRefreshWorktable: () => void;
  onFocus: (target: FocusTarget) => void;
  onOpenReview: (changeId: string) => void;
}) {
  const [diffOpen, setDiffOpen] = useState(false);
  const [diff, setDiff] = useState<SessionDiffResponse | null>(null);
  const diffAction = useAction();
  const [mode, setMode] = useState<"commit" | "branch">("commit");
  const [message, setMessage] = useState("");
  const [newBranch, setNewBranch] = useState(`agent/${session.id.slice(0, 8)}`);
  const [formError, setFormError] = useState<string | null>(null);
  const act = useAction();

  const changes = session.changes ?? [];
  const busy = act.pending;

  const toggleDiff = () => {
    const next = !diffOpen;
    setDiffOpen(next);
    if (next && !diff) void diffAction.run(async () => setDiff(await api.sessionDiff(session.id)));
  };

  const commit = () => {
    setFormError(null);
    const msg = message.trim() || undefined;
    if (mode === "commit") {
      void act.run(async () => {
        const res = await api.commitSession(session.id, msg);
        onSessionChange({ ...session, commit: res.commit });
        onRefreshWorktable();
      });
      return;
    }
    const target = newBranch.trim();
    const nameErr = target ? branchNameError(target) : "Enter a branch name.";
    if (nameErr) {
      setFormError(nameErr);
      return;
    }
    void act.run(async () => {
      const res = await api.commitSession(session.id, msg, { new_branch: target });
      const branch = res.branch || target;
      const review = await api.createReview({
        title: msg || `Agent session ${session.id.slice(0, 8)}`,
        branch,
        base_ref: session.branch || undefined,
        author: identity.principal === "anonymous" ? session.principal : identity.principal,
        delegated_agent: session.agent_profile || null,
        session_id: session.id,
      });
      onSessionChange({ ...session, commit: res.commit, branch });
      onRefreshWorktable();
      onOpenReview(review.change_id);
    });
  };

  const discard = () =>
    void act.run(async () => {
      onSessionChange(await api.discardSession(session.id));
      onRefreshWorktable();
    });

  return (
    <div className={ROW} data-judgment-item>
      <div className="flex flex-wrap items-center gap-2">
        <IconIntersection className="h-4 w-4 text-[#9ec0f5]" />
        <span className="font-mono text-[13px] text-[#d2dbee]">
          {session.principal}
          {session.agent_profile ? ` ∩ ${session.agent_profile}` : ""}
        </span>
        {session.branch && <BranchBadge name={session.branch} />}
      </div>
      <p className="truncate font-mono text-[13px] text-[#f3f6fd]" title={session.command}>
        $ {session.command}
      </p>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-[#a6b5cf]">
        <span>{plural(changes.length, "file")}</span>
        {session.bytes_scrubbed > 0 && <span>{formatByteCount(session.bytes_scrubbed)} scrubbed</span>}
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <button type="button" onClick={toggleDiff} className={diffOpen ? "pr-pill-active rounded-full px-2.5 py-1 text-[13px]" : MINI_BTN}>
          {diffOpen ? "Hide Diff" : "Quick Diff"}
        </button>
        <button type="button" className={MINI_BTN} onClick={() => onFocus({ kind: "session", id: session.id })}>
          Focus
        </button>
      </div>
      {diffOpen && (
        <div className="space-y-1.5">
          {diffAction.pending && (
            <div className="pr-well h-24 overflow-hidden rounded-lg">
              <CodeLinesSkeleton />
            </div>
          )}
          <ErrorNote message={diffAction.error} />
          {diff && <QuickDiff data={diff} />}
          <button
            type="button"
            className="text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd]"
            onClick={() => onFocus({ kind: "session", id: session.id })}
          >
            Full focus →
          </button>
        </div>
      )}

      {owner && (
        <div className="space-y-2 border-t border-white/[0.06] pt-2">
          <div className="flex flex-wrap items-center gap-2">
            <div
              role="group"
              aria-label="Commit target"
              className="inline-flex rounded-full border border-white/[0.08] bg-black/30 p-0.5 text-[12.5px]"
            >
              {(
                [
                  ["commit", "Commit"],
                  ["branch", "Branch + Review"],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  disabled={busy}
                  aria-pressed={mode === id}
                  onClick={() => setMode(id)}
                  className={`rounded-full px-2.5 py-0.5 transition disabled:opacity-50 ${
                    mode === id ? "bg-[#7f95f8]/25 text-[#f3f6fd]" : "text-[#a6b5cf] hover:text-white"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            {mode === "branch" && (
              <input
                value={newBranch}
                onChange={(e) => setNewBranch(e.target.value)}
                disabled={busy}
                aria-label="New branch name"
                className="pr-well min-w-[120px] flex-1 rounded-xl px-2.5 py-1 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-50"
              />
            )}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <input
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              disabled={busy}
              aria-label="Commit message"
              placeholder={`Agent session ${session.id.slice(0, 8)}`}
              className="pr-well min-w-[120px] flex-1 rounded-xl px-2.5 py-1 text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none disabled:opacity-50"
            />
            <button
              type="button"
              disabled={busy || session.changes_truncated}
              title={session.changes_truncated ? "The change set is too large to commit" : undefined}
              onClick={commit}
              className="pr-action-btn rounded-full px-3 py-1 text-[13px] disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? "Working…" : mode === "branch" ? "Commit & Open Review" : "Commit"}
            </button>
            <ConfirmButton
              disabled={busy}
              confirmLabel="Discard"
              onConfirm={discard}
              className={MINI_BTN}
            >
              Discard
            </ConfirmButton>
          </div>
          <ErrorNote message={formError ?? act.error} />
        </div>
      )}
    </div>
  );
}

function BranchRow({
  branch,
  owner,
  defaultBranch,
  onFocus,
  onOpenBranches,
}: {
  branch: WorktableBranch;
  owner: boolean;
  defaultBranch: string;
  onFocus: (target: FocusTarget) => void;
  onOpenBranches: (branchName: string) => void;
}) {
  const files = branch.private_paths_touched.length;
  return (
    <div className={ROW} data-judgment-item>
      <div className="flex flex-wrap items-center gap-2">
        <IconLock className="h-4 w-4 text-[#a8c5ff]" />
        <span className="min-w-0 truncate font-mono text-[13.5px] text-[#f3f6fd]" title={branch.name}>
          {branch.name}
        </span>
        <span className={BADGE}>{visibilitySummary(branch.visibility)}</span>
        <span className="font-mono text-[12.5px] text-[#5bdba2]">+{branch.ahead_commits}</span>
        {files > 0 && <span className="text-[12.5px] text-[#a6b5cf]">{plural(files, "file")}</span>}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {owner ? (
          <>
            <button
              type="button"
              className="pr-action-btn rounded-full px-3 py-1 text-[13px]"
              onClick={() => onFocus({ kind: "branch", name: branch.name })}
            >
              Preview &amp; Publish
            </button>
            <button type="button" className={MINI_BTN} onClick={() => onOpenBranches(branch.name)}>
              Branches →
            </button>
          </>
        ) : (
          <>
            <span className="text-[13px] text-[#a6b5cf]">Ready · owner publishes to {defaultBranch}</span>
            <button type="button" className={MINI_BTN} onClick={() => onFocus({ kind: "branch", name: branch.name })}>
              Focus
            </button>
          </>
        )}
      </div>
    </div>
  );
}

/** The prioritized "Action Required" rail: JIT requests, quarantine, uncommitted diffs, publishes. */
export function JudgmentRail({
  owner,
  identity,
  nowMs,
  pendingApprovals,
  quarantineItems,
  uncommittedSessions,
  readyBranches,
  defaultBranch,
  railRef,
  loaded,
  error,
  onRetry,
  onApprovalDecided,
  onSessionChange,
  onRefreshWorktable,
  onFocus,
  onOpenCode,
  onOpenReview,
  onOpenBranches,
}: Props) {
  const [filter, setFilter] = useState<JudgmentFilter>("all");
  const total =
    pendingApprovals.length +
    quarantineItems.length +
    uncommittedSessions.length +
    readyBranches.length;
  // Approvals and quarantine are the only items that warrant the gold "needs attention" tone.
  const urgent = pendingApprovals.length + quarantineItems.length;
  const show = (f: JudgmentFilter) => filter === "all" || filter === f;
  const shown =
    (show("jit") ? pendingApprovals.length : 0) +
    (show("quarantine") ? quarantineItems.length : 0) +
    (show("diffs") ? uncommittedSessions.length : 0) +
    (show("publish") ? readyBranches.length : 0);

  return (
    <section
      ref={railRef}
      aria-label="Action Required"
      className="pr-surface flex flex-col overflow-hidden rounded-2xl"
    >
      <header className="space-y-2 border-b border-white/[0.06] px-3.5 py-2.5">
        <h2 className="flex items-center gap-2 text-[14px] font-semibold text-[#f3f6fd]">
          Action Required
          <span
            className={`rounded-full px-2 py-0.5 font-mono text-[12.5px] font-normal ${
              !loaded
                ? "bg-white/[0.06] text-[#a6b5cf]"
                : urgent > 0
                  ? "bg-[#7f95f8]/15 text-[#a8c5ff]"
                  : total > 0
                    ? "bg-[#7f95f8]/15 text-[#9ec0f5]"
                    : "bg-[#5bdba2]/15 text-[#5bdba2]"
            }`}
          >
            {loaded ? total : "–"}
          </span>
        </h2>
        <div className="flex gap-1 overflow-x-auto" role="group" aria-label="Judgment filter">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              aria-pressed={filter === f.id}
              onClick={() => setFilter(f.id)}
              className={`shrink-0 rounded-full px-2 py-0.5 text-[12.5px] transition ${
                filter === f.id ? "pr-pill-active" : "pr-pill text-[#9ec0f5] hover:text-[#f3f6fd]"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </header>

      <div className="flex min-h-0 flex-1 flex-col space-y-3.5 overflow-y-auto p-2.5">
        {loaded && shown === 0 && (
          <div className="flex flex-1 flex-col items-center justify-center gap-1.5 py-6 text-center">
            <IconShieldCheck className="h-8 w-8 text-[#5bdba2]" />
            <p className="text-[14px] font-medium text-[#f3f6fd]">Nothing waiting</p>
            <p className="max-w-[240px] text-[13px] text-[#a6b5cf]">
              {total === 0
                ? "No approvals, blocked edits, or pending publishes."
                : "Nothing waiting in this category."}
            </p>
          </div>
        )}

        {!loaded && error && (
          <div role="alert" className="flex flex-col items-center gap-2 py-6 text-center">
            <IconQuarantine className="h-7 w-7 text-[#f27c7c]" />
            <p className="text-[14px] font-medium text-[#f3f6fd]">Couldn&apos;t load judgment items</p>
            <p className="max-w-[260px] break-words text-[13px] text-[#a6b5cf]">{error}</p>
            {onRetry && (
              <button type="button" onClick={onRetry} className={MINI_BTN}>
                Retry
              </button>
            )}
          </div>
        )}

        {show("jit") && pendingApprovals.length > 0 && (
          <Section
            title="Approvals"
            count={pendingApprovals.length}
            icon={<IconLock className="h-3.5 w-3.5 text-[#a8c5ff]" />}
          >
            {pendingApprovals.map((ap) => (
              <ApprovalRow key={ap.id} ap={ap} owner={owner} nowMs={nowMs} onDecided={onApprovalDecided} />
            ))}
          </Section>
        )}

        {show("quarantine") && quarantineItems.length > 0 && (
          <Section
            title="Quarantine"
            count={quarantineItems.length}
            icon={<IconQuarantine className="h-3.5 w-3.5 text-[#a8c5ff]" />}
          >
            {quarantineItems.map((item) => (
              <QuarantineRow
                key={item.id}
                item={item}
                onFocus={onFocus}
                onOpenCode={onOpenCode}
                onOpenReview={onOpenReview}
              />
            ))}
          </Section>
        )}

        {show("diffs") && uncommittedSessions.length > 0 && (
          <Section
            title="Uncommitted diffs"
            count={uncommittedSessions.length}
            icon={<IconIntersection className="h-3.5 w-3.5 text-[#9ec0f5]" />}
          >
            {uncommittedSessions.map((s) => (
              <SessionRow
                key={s.id}
                session={s}
                owner={owner}
                identity={identity}
                onSessionChange={onSessionChange}
                onRefreshWorktable={onRefreshWorktable}
                onFocus={onFocus}
                onOpenReview={onOpenReview}
              />
            ))}
          </Section>
        )}

        {show("publish") && readyBranches.length > 0 && (
          <Section
            title="Ready to Publish"
            count={readyBranches.length}
            icon={<IconLock className="h-3.5 w-3.5 text-[#a8c5ff]" />}
          >
            {readyBranches.map((b) => (
              <BranchRow
                key={b.name}
                branch={b}
                owner={owner}
                defaultBranch={defaultBranch}
                onFocus={onFocus}
                onOpenBranches={onOpenBranches}
              />
            ))}
          </Section>
        )}

        {!loaded && !error && <JudgmentEmptySkeleton />}
      </div>
    </section>
  );
}
