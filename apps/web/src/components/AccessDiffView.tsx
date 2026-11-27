import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import {
  api,
  ApiError,
  errorText,
  shortOid,
  type AccessImpactDiff,
  type DeclassificationReport,
  type FirewallFinding,
  type FirewallSeverity,
  type IdentityPreset,
  type PendingQuarantineEdit,
  type QuarantineFileStatus,
  type QuarantineOverviewResponse,
} from "../api";
import { formatTime, isoTime, plural } from "../lib/format";
import { validateAccessToml } from "../lib/monaco";
import { sha256Hex } from "../lib/uiHelpers";
import { CodeBlock } from "./CodeBlock";
import {
  IconAmbientPulse,
  IconBlock,
  IconChanges,
  IconCheck,
  IconChevron,
  IconClock,
  IconClose,
  IconLock,
  IconPolicy,
  IconQuarantine,
  IconRefresh,
  IconShieldCheck,
  IconTerminal,
} from "./Icons";

// Monaco is heavy: load it on demand so the Policy tab paints (toolbar, impact diff) immediately.
const MonacoCodeEditor = lazy(() =>
  import("./MonacoCodeEditor").then((m) => ({ default: m.MonacoCodeEditor })),
);
const MonacoDiffViewer = lazy(() =>
  import("./MonacoDiffViewer").then((m) => ({ default: m.MonacoDiffViewer })),
);

import { CodeLinesSkeleton, PanelRowsSkeleton } from "./ViewSkeletons";

function MonacoSkeleton() {
  return <CodeLinesSkeleton className="bg-[#080b16]" />;
}

function severityBadgeClass(severity: FirewallSeverity): string {
  switch (severity) {
    case "critical":
      return "border border-[#f27c7c]/45 bg-[#f27c7c]/20 text-[#f27c7c]";
    case "high":
      return "border border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f7a49c]";
    case "warning":
      return "border border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#a8c5ff]";
    case "info":
      return "border border-[#9ec0f5]/30 bg-[#9ec0f5]/12 text-[#9ec0f5]";
  }
}

function fileStatusClass(status: QuarantineFileStatus["status"]): string {
  switch (status) {
    case "pinned":
      return "border border-[#9ec0f5]/30 bg-[#9ec0f5]/14 text-[#9ec0f5]";
    case "approved":
      return "border border-[#5bdba2]/30 bg-[#5bdba2]/14 text-[#5bdba2]";
    case "flagged":
      return "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]";
    case "unverified":
      return "border border-[#9ec0f5]/35 bg-[#7f95f8]/14 text-[#a8c5ff]";
  }
}

function FindingCard({ finding }: { finding: FirewallFinding }) {
  const loc = finding.line != null ? `${finding.location}:${finding.line}` : finding.location;
  return (
    <div className="rounded-lg border border-white/[0.06] bg-black/25 px-2.5 py-2 space-y-1">
      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[12px]">
        <span className={`rounded-full px-2 py-0.5 uppercase ${severityBadgeClass(finding.severity)}`}>
          {finding.severity}
        </span>
        <span className="rounded-full border border-white/[0.08] bg-white/[0.04] px-2 py-0.5 text-[#b6c3db]">
          {finding.category}
        </span>
        {finding.blocking && (
          <span className="rounded-full bg-[#f27c7c]/16 px-2 py-0.5 text-[#f27c7c]">blocking</span>
        )}
      </div>
      <div title={loc} className="truncate font-mono text-[12.5px] text-[#dce4f5]">
        {loc}
      </div>
      <p className="text-[12.5px] leading-snug text-[#d2dbee]">{finding.summary}</p>
      {finding.owner_detail && (
        <div className="rounded border border-white/[0.06] bg-black/30 px-2 py-1 font-mono text-[12.5px] leading-snug text-[#b6c3db]">
          {finding.owner_detail}
        </div>
      )}
    </div>
  );
}

export interface PolicyDraftRule {
  zoneName: string;
  pathGlob: string;
  target: string;
  tomlSnippet: string;
}

interface Props {
  identity: IdentityPreset;
  /** False for members: owner-only actions are disabled rather than left to 403. */
  owner: boolean;
  /** Optional proposed TOML handed off from the direct-manipulation Policy Intent Composer. */
  draftToml?: string | null;
  onClearDraftToml?: () => void;
  /** Called after a save, so the app can reload what it derives from the policy (agent profiles). */
  onPolicySaved?: () => void;
  /** Optional ambient hygiene draft rule to append & diff immediately once base policy loads. */
  draftRule?: PolicyDraftRule | null;
  onConsumeDraft?: () => void;
}

export function AccessDiffView({
  identity,
  owner,
  draftToml,
  onClearDraftToml,
  onPolicySaved,
  draftRule,
  onConsumeDraft,
}: Props) {
  const [baseToml, setBaseToml] = useState("");
  const [headToml, setHeadToml] = useState("");
  const [serverToml, setServerToml] = useState("");
  const [editorLayer, setEditorLayer] = useState<"repo" | "diff" | "server">("repo");
  const [diffSplit, setDiffSplit] = useState(true);
  const [draftNoticeVisible, setDraftNoticeVisible] = useState(Boolean(draftToml));
  const [policyLoaded, setPolicyLoaded] = useState(false);
  const [draftBanner, setDraftBanner] = useState<{ zoneName: string; pathGlob: string } | null>(
    null,
  );
  const computeSeqRef = useRef(0);

  // Customizable probes
  const [probesOpen, setProbesOpen] = useState(false);
  const probesRef = useRef<HTMLDivElement>(null);
  // Probed principals default to the directory (plus anonymous), loaded with the policy below.
  const [defaultPrincipals, setDefaultPrincipals] = useState<string[]>(["anonymous"]);
  const [principals, setPrincipals] = useState<string[]>(["anonymous"]);
  // Empty path list instructs the server to evaluate all repository paths (up to 250).
  const [paths, setPaths] = useState<string[]>([]);
  const [newPrincipal, setNewPrincipal] = useState("");
  const [newPath, setNewPath] = useState("");

  const [diff, setDiff] = useState<AccessImpactDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [applying, setApplying] = useState(false);
  const [appliedBanner, setAppliedBanner] = useState<string | null>(null);
  const [copiedCli, setCopiedCli] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Server-side flag, so the warning survives a reload (unlike the post-import notice).
  const [importedPending, setImportedPending] = useState(false);

  // Right-hand inspector tab & Quarantine/Firewall state
  const [inspectorTab, setInspectorTab] = useState<"diff" | "quarantine">("diff");
  const [quarantine, setQuarantine] = useState<QuarantineOverviewResponse | null>(null);
  const [quarantineLoading, setQuarantineLoading] = useState(false);
  const [quarantineError, setQuarantineError] = useState<string | null>(null);
  const [quarantineNotice, setQuarantineNotice] = useState<string | null>(null);
  const [scanReport, setScanReport] = useState<DeclassificationReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [copiedScanCli, setCopiedScanCli] = useState(false);

  // Per-pending-edit approval/rejection controls
  const [expandedEdits, setExpandedEdits] = useState<Record<string, boolean>>({});
  const [editReasons, setEditReasons] = useState<Record<string, string>>({});
  const [editAcks, setEditAcks] = useState<Record<string, boolean>>({});
  const [busyEditId, setBusyEditId] = useState<string | null>(null);

  // Inline action for tracked instruction files
  const [activeFileAction, setActiveFileAction] = useState<{
    path: string;
    mode: "approve" | "revoke";
  } | null>(null);
  const [fileReason, setFileReason] = useState("");
  const [fileAck, setFileAck] = useState(false);
  const [busyFilePath, setBusyFilePath] = useState<string | null>(null);

  const loadQuarantine = async () => {
    if (!owner) return;
    setQuarantineLoading(true);
    setQuarantineError(null);
    try {
      const res = await api.quarantineOverview();
      setQuarantine(res);
    } catch (err: unknown) {
      setQuarantineError(errorText(err));
    } finally {
      setQuarantineLoading(false);
    }
  };

  const compute = async (opts?: {
    base?: string;
    head?: string;
    nextPrincipals?: string[];
    nextPaths?: string[];
  }) => {
    const b = opts?.base ?? baseToml;
    const h = opts?.head ?? headToml;
    const pr = opts?.nextPrincipals ?? principals;
    const pa = opts?.nextPaths ?? paths;
    // An empty base is valid: the very first rule on a fresh policy still diffs against nothing.
    if (!h.trim()) return;
    const seq = ++computeSeqRef.current;
    setLoading(true);
    setError(null);
    try {
      const res = await api.policyDiff({
        base_toml: b,
        head_toml: h,
        principals: pr,
        paths: pa,
        include_agent_profiles: true,
        changed_files: [],
      });
      if (seq === computeSeqRef.current) setDiff(res);
    } catch (err: unknown) {
      if (seq === computeSeqRef.current) setError(errorText(err));
    } finally {
      if (seq === computeSeqRef.current) setLoading(false);
    }
  };

  useEffect(() => {
    Promise.all([
      api.policySummary(),
      api.directory().catch(() => null),
    ])
      .then(([res, directory]) => {
        const probed = ["anonymous", ...(directory?.principals.map((p) => p.principal) ?? [])];
        setDefaultPrincipals(probed);
        setPrincipals(probed);
        setPaths([]);
        setImportedPending(res.imported_policy_pending === true);
        setBaseToml(res.repo_policy_toml);
        const initialHead = draftToml ?? res.repo_policy_toml;
        setHeadToml(initialHead);
        setDraftNoticeVisible(Boolean(draftToml));
        setServerToml(res.server_policy_toml);
        setPolicyLoaded(true);
        void compute({
          base: res.repo_policy_toml,
          head: initialHead,
          nextPrincipals: probed,
          nextPaths: [],
        });
      })
      .catch((err: unknown) => setError(errorText(err)));
  }, []);

  useEffect(() => {
    if (!owner) return;
    // Only feeds the tab badge: let the policy summary + first diff paint first.
    const t = window.setTimeout(() => void loadQuarantine(), 350);
    return () => window.clearTimeout(t);
  }, [owner]);

  // Opening the Quarantine tab before the deferred load fires should not wait for it.
  useEffect(() => {
    if (inspectorTab === "quarantine" && owner && !quarantine && !quarantineLoading) {
      void loadQuarantine();
    }
  }, [inspectorTab]);

  useEffect(() => {
    if (!probesOpen) return;
    const onDown = (e: MouseEvent) => {
      if (!probesRef.current?.contains(e.target as Node)) setProbesOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setProbesOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [probesOpen]);

  const pendingEdits = useMemo(
    () => (quarantine?.pending_edits ?? []).filter((e) => e.status === "pending"),
    [quarantine],
  );
  const flaggedFilesCount = useMemo(
    () => (quarantine?.tracked_files ?? []).filter((f) => f.status === "flagged").length,
    [quarantine],
  );
  const quarantineBadgeCount = pendingEdits.length + flaggedFilesCount;

  const showQuarantineNotice = (msg: string) => {
    setQuarantineNotice(msg);
    setTimeout(() => setQuarantineNotice((cur) => (cur === msg ? null : cur)), 4000);
  };

  const runFirewallScan = async () => {
    setScanning(true);
    setQuarantineError(null);
    try {
      const report = await api.accessScan({});
      setScanReport(report);
    } catch (err: unknown) {
      setQuarantineError(errorText(err));
    } finally {
      setScanning(false);
    }
  };

  const handleApprovePendingEdit = async (edit: PendingQuarantineEdit) => {
    const reason = (editReasons[edit.id] ?? "").trim();
    if (!reason || !editAcks[edit.id]) return;
    setBusyEditId(edit.id);
    setQuarantineError(null);
    try {
      const res = await api.quarantineApprove({
        pending_id: edit.id,
        reason,
        acknowledge_diff: true,
        apply_commit: true,
      });
      setEditReasons((prev) => ({ ...prev, [edit.id]: "" }));
      setEditAcks((prev) => ({ ...prev, [edit.id]: false }));
      showQuarantineNotice(
        res.commit
          ? `Approved ${res.path} · committed ${shortOid(res.commit)}`
          : `Approved ${res.path}`,
      );
      await loadQuarantine();
    } catch (err: unknown) {
      setQuarantineError(errorText(err));
    } finally {
      setBusyEditId(null);
    }
  };

  const handleRejectPendingEdit = async (edit: PendingQuarantineEdit) => {
    const reason = (editReasons[edit.id] ?? "").trim();
    if (!reason) return;
    setBusyEditId(edit.id);
    setQuarantineError(null);
    try {
      await api.quarantineReject({
        pending_id: edit.id,
        reason,
      });
      setEditReasons((prev) => ({ ...prev, [edit.id]: "" }));
      setEditAcks((prev) => ({ ...prev, [edit.id]: false }));
      showQuarantineNotice(`Rejected edit to ${edit.path}`);
      await loadQuarantine();
    } catch (err: unknown) {
      setQuarantineError(errorText(err));
    } finally {
      setBusyEditId(null);
    }
  };

  const handleApproveTrackedFile = async (file: QuarantineFileStatus) => {
    const reason = fileReason.trim();
    if (!reason || !fileAck) return;
    setBusyFilePath(file.path);
    setQuarantineError(null);
    try {
      const res = await api.quarantineApprove({
        path: file.path,
        sha256: file.sha256,
        reason,
        acknowledge_diff: true,
        apply_commit: false,
      });
      setActiveFileAction(null);
      setFileReason("");
      setFileAck(false);
      showQuarantineNotice(`Approved ${res.path} (${res.sha256.slice(0, 12)})`);
      await loadQuarantine();
    } catch (err: unknown) {
      setQuarantineError(errorText(err));
    } finally {
      setBusyFilePath(null);
    }
  };

  const handleRevokeTrackedFile = async (file: QuarantineFileStatus) => {
    const reason = fileReason.trim();
    if (!reason) return;
    setBusyFilePath(file.path);
    setQuarantineError(null);
    try {
      await api.quarantineReject({
        path: file.path,
        reason,
      });
      setActiveFileAction(null);
      setFileReason("");
      setFileAck(false);
      showQuarantineNotice(`Revoked approval for ${file.path}`);
      await loadQuarantine();
    } catch (err: unknown) {
      setQuarantineError(errorText(err));
    } finally {
      setBusyFilePath(null);
    }
  };

  // Load any draft TOML sent later while the Policy tab is already mounted.
  useEffect(() => {
    if (!draftToml || !baseToml) return;
    setEditorLayer("repo");
    setHeadToml(draftToml);
    setDraftNoticeVisible(true);
    void compute({ base: baseToml, head: draftToml });
  }, [draftToml]);

  // Apply an ambient-hygiene draft rule once the base policy has loaded.
  useEffect(() => {
    if (!policyLoaded || !draftRule) return;
    const snippet = draftRule.tomlSnippet.trim();
    const currentHead = headToml || baseToml;
    const nextHead =
      snippet && !currentHead.includes(snippet)
        ? `${currentHead.trimEnd()}${currentHead.trim() ? "\n\n" : ""}${snippet}\n`
        : currentHead;
    const cleanTarget = draftRule.target.replace(/^\/+|\/+$/g, "");
    const probePath = cleanTarget ? `${cleanTarget}/example` : "";
    const nextPaths = probePath ? Array.from(new Set([...paths, probePath])) : paths;

    setEditorLayer("repo");
    setHeadToml(nextHead);
    setPaths(nextPaths);
    setDraftBanner({ zoneName: draftRule.zoneName, pathGlob: draftRule.pathGlob });
    void compute({
      base: baseToml,
      head: nextHead,
      nextPrincipals: principals,
      nextPaths,
    });
    onConsumeDraft?.();
  }, [policyLoaded, draftRule]);

  const isDirty = headToml !== baseToml;

  const policyMarkers = useMemo(() => validateAccessToml(headToml, error), [headToml, error]);
  const markerSummary = useMemo(() => {
    let errors = 0;
    let warnings = 0;
    for (const m of policyMarkers) {
      if (m.severity === "error") errors += 1;
      else if (m.severity === "warning") warnings += 1;
    }
    return { errors, warnings };
  }, [policyMarkers]);

  const summary = useMemo(() => {
    if (!diff) return { granted: 0, revoked: 0, quarantine: 0 };
    let granted = 0;
    let revoked = 0;
    for (const d of diff.deltas) {
      granted += d.granted.length;
      revoked += d.revoked.length;
    }
    for (const md of diff.mcp_deltas ?? []) {
      if (md.escalated) granted += 1;
      else revoked += 1;
    }
    return { granted, revoked, quarantine: diff.quarantine_alerts.length };
  }, [diff]);

  const cliCommand = useMemo(() => {
    const parts = ["premier access diff .access.toml .access.proposed.toml"];
    if (serverToml.trim()) parts.push("--server-policy .access.server.toml");
    for (const p of principals) parts.push(`--principal ${p}`);
    for (const pa of paths) parts.push(`--path ${pa}`);
    return parts.join(" ");
  }, [serverToml, principals, paths]);

  const reset = () => {
    setHeadToml(baseToml);
    setPrincipals(defaultPrincipals);
    setPaths([]);
    setDraftNoticeVisible(false);
    setDraftBanner(null);
    onClearDraftToml?.();
    void compute({ head: baseToml, nextPrincipals: defaultPrincipals, nextPaths: [] });
  };

  const addPrincipal = (e: React.FormEvent) => {
    e.preventDefault();
    const val = newPrincipal.trim();
    if (!val) return;
    const next = Array.from(new Set([...principals, val]));
    setPrincipals(next);
    setNewPrincipal("");
    void compute({ nextPrincipals: next });
  };

  const addPath = (e: React.FormEvent) => {
    e.preventDefault();
    const val = newPath.trim();
    if (!val) return;
    const next = Array.from(new Set([...paths, val]));
    setPaths(next);
    setNewPath("");
    void compute({ nextPaths: next });
  };

  const [policyConflict, setPolicyConflict] = useState(false);

  const reloadLatestPolicy = async () => {
    setLoading(true);
    setError(null);
    setPolicyConflict(false);
    try {
      const res = await api.policySummary();
      setImportedPending(res.imported_policy_pending === true);
      setBaseToml(res.repo_policy_toml);
      setHeadToml(res.repo_policy_toml);
      setServerToml(res.server_policy_toml);
      await compute({ base: res.repo_policy_toml, head: res.repo_policy_toml });
    } catch (err: unknown) {
      setError(errorText(err));
    } finally {
      setLoading(false);
    }
  };

  const applyAndReload = async () => {
    setApplying(true);
    setError(null);
    setPolicyConflict(false);
    setAppliedBanner(null);
    try {
      const expectedBaseSha256 = await sha256Hex(baseToml);
      const res = await api.updateRepoPolicy(headToml, identity.principal, expectedBaseSha256);
      setBaseToml(headToml);
      setDraftNoticeVisible(false);
      setDraftBanner(null);
      onClearDraftToml?.();
      onPolicySaved?.();
      setAppliedBanner(
        res.commit
          ? `Committed ${shortOid(res.commit)} · ${plural(res.rule_count, "rule")} live`
          : `Hot-reloaded (${plural(res.rule_count, "rule")})`,
      );
      await compute({ base: headToml, head: headToml });
      if (owner) void loadQuarantine();
      setTimeout(() => setAppliedBanner(null), 4000);
      // Ask the server rather than assume the apply cleared the pending flag.
      api
        .policySummary()
        .then((s) => setImportedPending(s.imported_policy_pending === true))
        .catch(() => {});
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 409) {
        setPolicyConflict(true);
        setError(
          "Policy changed on the server since you loaded it. Reload the latest .access.toml to avoid overwriting concurrent edits.",
        );
      } else {
        setError(errorText(err));
      }
    } finally {
      setApplying(false);
    }
  };

  const layerBtn = (layer: "repo" | "diff" | "server", icon: React.ReactNode, label: string, dirty: boolean) => (
    <button
      type="button"
      onClick={() => setEditorLayer(layer)}
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 transition ${
        editorLayer === layer ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#dce4f5]"
      }`}
    >
      {icon}
      <span>{label}</span>
      {dirty && <span className="h-1.5 w-1.5 rounded-full bg-[#9ec0f5]" />}
    </button>
  );

  const hasStatus = importedPending || draftNoticeVisible || appliedBanner || draftBanner || error;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto p-2.5 sm:p-3 lg:overflow-hidden xl:p-4">
      {/* One unified workbench toolbar: layer switch · diff layout · validity | probes · reset · CLI · compute · apply */}
      <div className="pr-surface relative z-30 flex shrink-0 flex-wrap items-center justify-between gap-x-3 gap-y-1.5 rounded-xl px-2.5 py-1.5 lg:flex-nowrap">
        <div className="flex min-w-0 flex-wrap items-center gap-2 font-mono text-[12.5px] lg:flex-nowrap">
          <div className="inline-flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5">
            {layerBtn("repo", <IconPolicy className="h-3.5 w-3.5 text-[#9ec0f5]" />, ".access.toml", isDirty)}
            {layerBtn("diff", <IconChanges className="h-3.5 w-3.5 text-[#67d6dc]" />, "Diff vs Live", isDirty)}
            {layerBtn("server", <IconLock className="h-3.5 w-3.5 text-[#9ec0f5]" />, "Server Policy", false)}
          </div>

          {editorLayer === "diff" && (
            <div
              role="group"
              aria-label="Diff view layout"
              className="inline-flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 text-[12.5px]"
            >
              <button
                type="button"
                onClick={() => setDiffSplit(true)}
                className={`rounded-full px-2.5 py-0.5 transition ${
                  diffSplit ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#dce4f5]"
                }`}
              >
                Split
              </button>
              <button
                type="button"
                onClick={() => setDiffSplit(false)}
                className={`rounded-full px-2.5 py-0.5 transition ${
                  !diffSplit ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#dce4f5]"
                }`}
              >
                Inline
              </button>
            </div>
          )}

          {editorLayer === "server" ? (
            <span className="text-[#a6b5cf]">read-only ceiling</span>
          ) : policyMarkers.length === 0 ? (
            <span
              title="No syntax or policy diagnostics"
              className="inline-flex items-center gap-1.5 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/14 px-2.5 py-0.5 text-[12.5px] text-[#5bdba2]"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-[#5bdba2]" />
              <span>Valid</span>
            </span>
          ) : (
            <div
              className="flex items-center gap-1.5"
              title={policyMarkers
                .slice(0, 4)
                .map((m) => `L${m.startLineNumber}: ${m.message}`)
                .join("\n")}
            >
              {markerSummary.errors > 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/16 px-2.5 py-0.5 text-[12.5px] text-[#f27c7c]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#f27c7c]" />
                  <span>{plural(markerSummary.errors, "error")}</span>
                </span>
              )}
              {markerSummary.warnings > 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[#9ec0f5]/35 bg-[#7f95f8]/15 px-2.5 py-0.5 text-[12.5px] text-[#a8c5ff]">
                  <span className="h-1.5 w-1.5 rounded-full bg-[#7f95f8]" />
                  <span>{plural(markerSummary.warnings, "warning")}</span>
                </span>
              )}
              {markerSummary.errors === 0 && markerSummary.warnings === 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[#9ec0f5]/30 bg-[#9ec0f5]/12 px-2.5 py-0.5 text-[12.5px] text-[#9ec0f5]">
                  <span>{plural(policyMarkers.length, "notice")}</span>
                </span>
              )}
            </div>
          )}
          <span
            title="* matches within one path segment; ** matches across folders. Server policy overrides repo policy."
            className="hidden cursor-help whitespace-nowrap text-[#a6b5cf] 2xl:inline"
          >
            Server &gt; Repo
          </span>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-1.5 whitespace-nowrap font-mono text-[12.5px] lg:flex-nowrap">
          <div ref={probesRef} className="relative">
            <button
              type="button"
              aria-expanded={probesOpen}
              onClick={() => setProbesOpen((o) => !o)}
              title={`${plural(principals.length, "principal")} · ${
                paths.length === 0 ? "all paths" : plural(paths.length, "path")
              }`}
              className={`rounded-full px-2.5 py-1 transition ${
                probesOpen ? "pr-pill-active" : "pr-pill text-[#b6c3db]"
              }`}
            >
              Probes ({principals.length}·{paths.length === 0 ? "all" : paths.length})
            </button>
            {/* Opaque popover (no layout shift, no bleed-through) */}
            {probesOpen && (
              <div className="pr-elevated absolute top-full left-0 z-40 mt-1.5 grid w-[min(680px,calc(100vw-2rem))] gap-3 rounded-2xl bg-[#0b0f1c]! p-4 md:grid-cols-2 sm:left-auto sm:right-0">
                <div className="space-y-2">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Principals
                  </div>
                  <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                    {principals.map((p) => (
                      <span
                        key={p}
                        className="pr-well inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[12.5px] text-[#dce4f5]"
                      >
                        <span>{p}</span>
                        <button
                          type="button"
                          onClick={() => {
                            const next = principals.filter((x) => x !== p);
                            setPrincipals(next);
                            void compute({ nextPrincipals: next });
                          }}
                          aria-label={`Remove ${p}`}
                          className="text-[#a6b5cf] hover:text-white"
                        >
                          <IconClose className="h-4 w-4" />
                        </button>
                      </span>
                    ))}
                  </div>
                  <form onSubmit={addPrincipal} className="flex gap-2">
                    <input
                      value={newPrincipal}
                      onChange={(e) => setNewPrincipal(e.target.value)}
                      aria-label="Add a principal to probe"
                      placeholder="Add @user…"
                      className="pr-well min-w-0 flex-1 rounded-xl px-2.5 py-1.5 font-mono text-[13px] text-[#f3f6fd] focus:outline-none"
                    />
                    <button type="submit" className="pr-pill rounded-xl px-3 py-1.5 font-mono text-[12.5px]">
                      Add
                    </button>
                  </form>
                </div>

                <div className="space-y-2">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Paths {paths.length === 0 ? "(all repo paths, up to 250)" : `(${paths.length} custom)`}
                  </div>
                  <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                    {paths.length === 0 && (
                      <span className="font-mono text-[12.5px] text-[#a6b5cf]">
                        Probing all repo paths. Add paths below to filter.
                      </span>
                    )}
                    {paths.map((pa) => (
                      <span
                        key={pa}
                        className="pr-well inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 font-mono text-[12.5px] text-[#dce4f5]"
                      >
                        <span>{pa}</span>
                        <button
                          type="button"
                          onClick={() => {
                            const next = paths.filter((x) => x !== pa);
                            setPaths(next);
                            void compute({ nextPaths: next });
                          }}
                          aria-label={`Remove ${pa}`}
                          className="text-[#a6b5cf] hover:text-white"
                        >
                          <IconClose className="h-4 w-4" />
                        </button>
                      </span>
                    ))}
                  </div>
                  <form onSubmit={addPath} className="flex gap-2">
                    <input
                      value={newPath}
                      onChange={(e) => setNewPath(e.target.value)}
                      aria-label="Add a path to probe"
                      placeholder={paths.length === 0 ? "Add a file path to probe, e.g. README.md" : "Add path/to/file…"}
                      className="pr-well min-w-0 flex-1 rounded-xl px-2.5 py-1.5 font-mono text-[13px] text-[#f3f6fd] focus:outline-none"
                    />
                    <button type="submit" className="pr-pill rounded-xl px-3 py-1.5 font-mono text-[12.5px]">
                      Add
                    </button>
                  </form>
                </div>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={reset}
            className="pr-pill rounded-full px-2.5 py-1 text-[#a6b5cf] hover:text-[#dce4f5]"
          >
            Reset
          </button>

          <button
            type="button"
            onClick={() => {
              navigator.clipboard?.writeText(cliCommand).catch(() => {});
              setCopiedCli(true);
              setTimeout(() => setCopiedCli(false), 1500);
            }}
            title={`Copy: ${cliCommand}`}
            aria-label="Copy premier access diff command"
            className="pr-pill inline-flex h-[26px] items-center gap-1.5 rounded-full px-2.5 text-[#d2dbee]"
          >
            {copiedCli ? (
              <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
            ) : (
              <IconTerminal className="h-3.5 w-3.5 text-[#9ec0f5]" />
            )}
            <span className="hidden 2xl:inline">premier access diff</span>
          </button>

          <button
            type="button"
            disabled={loading}
            onClick={() => void compute()}
            title="Compute impact diff (Ctrl/⌘S in the editor)"
            className="pr-pill rounded-full px-3 py-1 text-[#dce4f5] disabled:opacity-50"
          >
            {loading ? "Previewing…" : "Preview Changes"}
          </button>

          <button
            type="button"
            // A pending imported policy is applied as shown, so it needs no edit first.
            disabled={!owner || applying || (!isDirty && !importedPending) || editorLayer === "server"}
            onClick={() => void applyAndReload()}
            title={
              owner
                ? "Compile against Server Policy, commit .access.toml to the default branch, and hot-reload the server"
                : "Owner only"
            }
            className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3.5 py-1 text-[13px] disabled:opacity-40"
          >
            <IconCheck className="h-3.5 w-3.5" />
            <span>{applying ? "Saving…" : "Save Rules"}</span>
          </button>
        </div>
      </div>

      {/* All transient banners collapse into one compact status strip (no stacked chrome bars) */}
      {hasStatus && (
        <div className="shrink-0 divide-y divide-white/[0.06] overflow-hidden rounded-xl border border-white/[0.08] bg-[#0b0f1c]/97 font-mono text-[13px]">
          {importedPending && (
            <div role="alert" className="flex items-center gap-2 bg-[#7f95f8]/8 px-3 py-1.5 text-[#a8c5ff]">
              <IconQuarantine className="h-3.5 w-3.5 shrink-0" />
              <span className="min-w-0 flex-1 truncate" title="Only owners have access until you review and apply it.">
                Imported policy not yet enforced — save to apply.
              </span>
            </div>
          )}
          {draftNoticeVisible && (
            <div role="status" className="flex items-center gap-2 bg-[#7f95f8]/10 px-3 py-1.5 text-[#cfe0ff]">
              <IconAmbientPulse className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
              <span className="min-w-0 flex-1 truncate">
                Draft loaded from Policy Composer — review diff and save.
              </span>
              <button
                type="button"
                onClick={() => {
                  setDraftNoticeVisible(false);
                  onClearDraftToml?.();
                }}
                aria-label="Dismiss proposed policy notice"
                className="shrink-0 rounded-md p-0.5 text-[#9ec0f5] hover:bg-white/[0.08] hover:text-white"
              >
                <IconClose className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
          {draftBanner && (
            <div role="status" className="flex items-center gap-2 bg-[#7f95f8]/10 px-3 py-1.5 text-[#cfe0ff]">
              <IconAmbientPulse className="h-3.5 w-3.5 shrink-0 text-[#9ec0f5]" />
              <span className="min-w-0 flex-1 truncate">
                Drafted zone <strong className="text-[#f3f6fd]">{draftBanner.zoneName}</strong> (
                {draftBanner.pathGlob}) — review diff before saving.
              </span>
              <button
                type="button"
                onClick={() => setDraftBanner(null)}
                aria-label="Dismiss draft banner"
                className="shrink-0 rounded-md p-0.5 text-[#9ec0f5] hover:bg-white/[0.08] hover:text-white"
              >
                <IconClose className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
          {appliedBanner && (
            <div role="status" className="flex items-center gap-2 bg-[#5bdba2]/12 px-3 py-1.5 text-[#5bdba2]">
              <IconCheck className="h-3.5 w-3.5 shrink-0" />
              <span className="min-w-0 flex-1 truncate">{appliedBanner}</span>
            </div>
          )}
          {error && (
            <div role="alert" className="flex items-center gap-2 bg-[#f27c7c]/10 px-3 py-1.5 text-[#f27c7c]">
              <IconBlock className="h-3.5 w-3.5 shrink-0" />
              <span className="min-w-0 flex-1 break-words">{error}</span>
              {policyConflict && (
                <button
                  type="button"
                  onClick={() => void reloadLatestPolicy()}
                  disabled={loading}
                  className="pr-pill shrink-0 rounded-full px-2.5 py-0.5 text-[12px] text-[#f3f6fd] hover:text-white disabled:opacity-50"
                >
                  Reload latest
                </button>
              )}
            </div>
          )}
        </div>
      )}

      {/* Split: 3-Mode Policy Workbench + Structured Impact Deltas */}
      <div className="flex min-h-0 flex-1 flex-col gap-3 lg:flex-row">
        <section className="pr-surface flex min-w-0 shrink-0 flex-col overflow-hidden rounded-2xl lg:min-h-0 lg:flex-1 lg:shrink">
          <div className="relative flex min-h-[340px] flex-1 flex-col lg:min-h-0">
            <div className="absolute inset-0 flex min-h-0 flex-1 flex-col">
              <Suspense fallback={<MonacoSkeleton />}>
                {editorLayer === "repo" ? (
                  <MonacoCodeEditor
                    key="repo-policy"
                    language="premier-access-toml"
                    path=".access.toml"
                    value={headToml}
                    onChange={setHeadToml}
                    readOnly={false}
                    minimap={false}
                    stickyScroll={true}
                    wordWrap={false}
                    markers={policyMarkers}
                    onSave={() => {
                      if (!loading) void compute();
                    }}
                    ariaLabel="Repository policy (.access.toml)"
                    minHeight={0}
                    className="h-full min-h-0 w-full flex-1"
                  />
                ) : editorLayer === "diff" ? (
                  <MonacoDiffViewer
                    original={baseToml}
                    modified={headToml}
                    language="premier-access-toml"
                    path=".access.toml"
                    readOnly={false}
                    onModifiedChange={setHeadToml}
                    renderSideBySide={diffSplit}
                    collapseUnchanged={false}
                    autoHeight={false}
                    markers={policyMarkers}
                    onSave={() => {
                      if (!loading) void compute();
                    }}
                    ariaLabel="Diff repository policy (.access.toml) against live policy"
                    minHeight={0}
                    className="h-full min-h-0 w-full flex-1"
                  />
                ) : (
                  <MonacoCodeEditor
                    key="server-policy"
                    language="premier-access-toml"
                    path=".access.server.toml"
                    value={serverToml || "# No server policy override configured\n"}
                    readOnly={true}
                    minimap={false}
                    stickyScroll={true}
                    ariaLabel="Server policy (read-only)"
                    minHeight={0}
                    className="h-full min-h-0 w-full flex-1"
                  />
                )}
              </Suspense>
            </div>
          </div>
        </section>

        <aside className="pr-surface flex shrink-0 flex-col overflow-hidden rounded-2xl lg:w-[404px] xl:w-[452px] 2xl:w-[504px]">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-1.5">
            <div
              role="tablist"
              aria-label="Policy inspector view"
              className="inline-flex rounded-full border border-white/[0.08] bg-white/[0.03] p-0.5 font-mono text-[12.5px]"
            >
              <button
                type="button"
                role="tab"
                aria-selected={inspectorTab === "diff"}
                onClick={() => setInspectorTab("diff")}
                className={`rounded-full px-2.5 py-1 transition ${
                  inspectorTab === "diff" ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#e6ecf8]"
                }`}
              >
                Permission Diff
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={inspectorTab === "quarantine"}
                onClick={() => setInspectorTab("quarantine")}
                className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 transition ${
                  inspectorTab === "quarantine"
                    ? "pr-pill-active"
                    : "text-[#a6b5cf] hover:text-[#e6ecf8]"
                }`}
              >
                <IconQuarantine
                  className={`h-3.5 w-3.5 ${quarantineBadgeCount > 0 ? "text-[#a8c5ff]" : "text-[#9ec0f5]"}`}
                />
                <span>Blocked Edits</span>
                {quarantineBadgeCount > 0 && (
                  <span className="rounded-full bg-[#f27c7c]/22 px-1.5 py-0.5 text-[12px] font-semibold text-[#f27c7c]">
                    {quarantineBadgeCount}
                  </span>
                )}
              </button>
            </div>

            {inspectorTab === "diff" ? (
              <div className="flex items-center gap-1.5 font-mono text-[12.5px]">
                <span
                  className={`rounded-full px-2 py-0.5 ${
                    summary.granted > 0
                      ? "bg-[#9ec0f5]/14 text-[#9ec0f5]"
                      : "bg-white/[0.04] text-[#a6b5cf]"
                  }`}
                >
                  +{summary.granted}
                </span>
                <span
                  className={`rounded-full px-2 py-0.5 ${
                    summary.revoked > 0
                      ? "bg-[#5bdba2]/15 text-[#5bdba2]"
                      : "bg-white/[0.04] text-[#a6b5cf]"
                  }`}
                >
                  -{summary.revoked}
                </span>
                {summary.quarantine > 0 && (
                  <span className="rounded-full bg-[#f27c7c]/18 px-2 py-0.5 text-[#f27c7c]">
                    {plural(summary.quarantine, "alert")}
                  </span>
                )}
              </div>
            ) : (
              owner && (
                <button
                  type="button"
                  disabled={quarantineLoading}
                  onClick={() => void loadQuarantine()}
                  title="Refresh quarantine status"
                  aria-label="Refresh quarantine status"
                  className="pr-pill inline-flex h-7 w-7 items-center justify-center rounded-full text-[#a6b5cf] hover:text-[#f3f6fd] disabled:opacity-40"
                >
                  <IconRefresh
                    className={`h-3.5 w-3.5 ${quarantineLoading ? "animate-spin" : ""}`}
                  />
                </button>
              )
            )}
          </div>

          {inspectorTab === "diff" ? (
            <div
              aria-busy={loading}
              className={`min-h-0 flex-1 space-y-3 overflow-y-auto p-4 transition-opacity ${
                loading && diff ? "opacity-60" : ""
              }`}
            >
              {!diff && !error && (loading || !policyLoaded) && <PanelRowsSkeleton rows={3} className="p-0!" />}
              {!diff && policyLoaded && !loading && !error && (
                <div className="py-8 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                  Edit .access.toml to preview who gains or loses access.
                </div>
              )}
              {diff?.quarantine_alerts.map((al) => (
                <div
                  key={al.path}
                  className="flex items-start gap-2.5 rounded-xl border border-[#9ec0f5]/35 bg-[#7f95f8]/10 p-3.5 font-mono text-[13px] text-[#a8c5ff]"
                >
                  <IconQuarantine className="mt-0.5 h-[18px] w-[18px]" />
                  <div className="min-w-0">
                    <div className="font-semibold">{al.path}</div>
                    <div className="mt-0.5 text-[#d6e2f8]">{al.message}</div>
                  </div>
                </div>
              ))}

              {diff &&
                diff.deltas.length === 0 &&
                (diff.mcp_deltas?.length ?? 0) === 0 &&
                diff.quarantine_alerts.length === 0 && (
                  <div className="space-y-1 py-8 text-center font-mono text-[13.5px] text-[#a6b5cf]">
                    <div>No effective capability changes</div>
                    <div className="text-[12.5px]">
                      Evaluated {plural(principals.length, "principal")} ·{" "}
                      {paths.length === 0 ? "all paths" : plural(paths.length, "path")}
                    </div>
                  </div>
                )}

              {diff?.deltas.map((d, i) => (
                <div key={`${d.principal}-${d.path}-${i}`} className="pr-well rounded-xl p-3.5 font-mono">
                  <div className="flex items-center justify-between gap-2 text-[13.5px]">
                    <span className="font-medium text-[#f3f6fd]">
                      {d.principal}
                      {d.agent_profile ? ` ∩ ${d.agent_profile}` : ""}
                    </span>
                    <span
                      className={`shrink-0 rounded-full px-2 py-0.5 text-[12px] uppercase ${
                        d.granted.length > 0
                          ? d.granted.some((g) => g === "write" || g === "use")
                            ? "bg-[#f27c7c]/14 text-[#f27c7c]"
                            : "bg-[#9ec0f5]/12 text-[#9ec0f5]"
                          : "bg-[#5bdba2]/12 text-[#5bdba2]"
                      }`}
                    >
                      {d.granted.length > 0 ? "▲ escalation" : "▼ tightened"}
                    </span>
                  </div>
                  <div className="mt-1 break-all text-[13px] text-[#a6b5cf]">{d.path}</div>
                  <div className="mt-2.5 flex flex-wrap gap-1.5 text-[12.5px]">
                    {/* Security-correct colors: escalations (+) in slate-ice/coral warning, revocations (-) in mint */}
                    {d.granted.map((g) => {
                      const critical = g === "write" || g === "use";
                      return (
                        <span
                          key={`+${g}`}
                          className={`rounded-full px-2.5 py-0.5 ${
                            critical
                              ? "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]"
                              : "border border-[#9ec0f5]/30 bg-[#9ec0f5]/12 text-[#9ec0f5]"
                          }`}
                        >
                          +{g}
                        </span>
                      );
                    })}
                    {d.revoked.map((r) => (
                      <span
                        key={`-${r}`}
                        className="rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/14 px-2.5 py-0.5 text-[#5bdba2]"
                      >
                        -{r}
                      </span>
                    ))}
                  </div>
                </div>
              ))}

              {diff?.mcp_deltas?.map((md, i) => {
                const beforeLabel = md.before_allowed ? `allow (${md.before_approval})` : "deny";
                const afterLabel = md.after_allowed ? `allow (${md.after_approval})` : "deny";
                const criticalEscalation = md.escalated && md.after_approval === "auto";
                return (
                  <div
                    key={`mcp-${md.principal}-${md.agent_profile ?? ""}-${md.tool}-${i}`}
                    className="pr-well rounded-xl p-3.5 font-mono"
                  >
                    <div className="flex items-center justify-between gap-2 text-[13.5px]">
                      <span className="min-w-0 truncate font-medium text-[#f3f6fd]">
                        {md.principal}
                        {md.agent_profile ? ` ∩ ${md.agent_profile}` : ""}
                      </span>
                      <span
                        className={`shrink-0 text-[12.5px] uppercase ${
                          md.escalated
                            ? criticalEscalation
                              ? "text-[#f27c7c]"
                              : "text-[#a8c5ff]"
                            : "text-[#5bdba2]"
                        }`}
                      >
                        {md.escalated ? "escalation" : "tightened"}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-1.5 break-all text-[13px] text-[#a6b5cf]">
                      <span className="shrink-0 rounded-full bg-[#7f95f8]/16 px-2 py-0.5 text-[12px] text-[#9ec0f5]">
                        MCP
                      </span>
                      <span>{md.tool}</span>
                    </div>
                    <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[12.5px]">
                      <span className="rounded-full bg-white/[0.06] px-2.5 py-0.5 text-[#b6c3db]">
                        {beforeLabel}
                      </span>
                      <span className="text-[#a6b5cf]">→</span>
                      <span
                        className={`rounded-full px-2.5 py-0.5 ${
                          md.escalated
                            ? criticalEscalation
                              ? "border border-[#f27c7c]/35 bg-[#f27c7c]/16 text-[#f27c7c]"
                              : "border border-[#9ec0f5]/35 bg-[#7f95f8]/15 text-[#a8c5ff]"
                            : "border border-[#5bdba2]/30 bg-[#5bdba2]/14 text-[#5bdba2]"
                        }`}
                      >
                        {afterLabel}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : !owner ? (
            <div className="min-h-0 flex-1 overflow-y-auto p-4">
              <div className="pr-well flex flex-col items-center gap-2 rounded-2xl p-6 text-center">
                <IconLock className="h-6 w-6 text-[#a8c5ff]" />
                <div className="font-mono text-[14px] font-semibold text-[#f3f6fd]">
                  Owner-only Blocked Edits
                </div>
                <p className="text-[13.5px] leading-relaxed text-[#b6c3db]">
                  Firewall scans, quarantined edits, and overrides require owner access.
                </p>
              </div>
            </div>
          ) : (
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
              {quarantineError && (
                <div
                  role="alert"
                  className="rounded-xl border border-[#f27c7c]/25 bg-[#f27c7c]/10 px-3 py-2 font-mono text-[12.5px] text-[#f27c7c]"
                >
                  {quarantineError}
                </div>
              )}

              {quarantineNotice && (
                <div
                  role="status"
                  className="flex items-center gap-2 rounded-xl border border-[#5bdba2]/30 bg-[#5bdba2]/12 px-3 py-2 font-mono text-[12.5px] text-[#5bdba2]"
                >
                  <IconCheck className="h-4 w-4" />
                  <span>{quarantineNotice}</span>
                </div>
              )}

              {/* 1. Live Firewall Scan Bar */}
              <div className="pr-well space-y-2.5 rounded-xl p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5]">
                    Live Firewall Scan
                  </span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard?.writeText("premier access scan").catch(() => {});
                        setCopiedScanCli(true);
                        setTimeout(() => setCopiedScanCli(false), 1500);
                      }}
                      title="premier access scan"
                      className="pr-pill inline-flex items-center gap-1 rounded-full px-2.5 py-1 font-mono text-[12.5px] text-[#d2dbee]"
                    >
                      {copiedScanCli ? (
                        <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                      ) : (
                        <IconTerminal className="h-3.5 w-3.5 text-[#9ec0f5]" />
                      )}
                      <span>premier access scan</span>
                    </button>
                    <button
                      type="button"
                      disabled={scanning}
                      onClick={() => void runFirewallScan()}
                      className="pr-action-btn inline-flex items-center gap-1.5 rounded-full px-3 py-1 font-mono text-[12.5px] disabled:opacity-50"
                    >
                      <IconShieldCheck className="h-3.5 w-3.5" />
                      <span>{scanning ? "Scanning…" : "Run Scan"}</span>
                    </button>
                  </div>
                </div>

                {scanReport && (
                  <div className="space-y-2 border-t border-white/[0.06] pt-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px]">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {scanReport.passed ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-[#5bdba2]/30 bg-[#5bdba2]/14 px-2 py-0.5 text-[#5bdba2]">
                            <IconShieldCheck className="h-3.5 w-3.5" />
                            <span>Firewall Passed</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full border border-[#f27c7c]/35 bg-[#f27c7c]/16 px-2 py-0.5 text-[#f27c7c]">
                            <IconBlock className="h-3.5 w-3.5" />
                            <span>{plural(scanReport.blocking_count, "blocker")}</span>
                          </span>
                        )}
                        {scanReport.warning_count > 0 && (
                          <span className="rounded-full border border-[#9ec0f5]/30 bg-[#7f95f8]/12 px-2 py-0.5 text-[#a8c5ff]">
                            {plural(scanReport.warning_count, "warning")}
                          </span>
                        )}
                      </div>
                      {scanReport.report_digest && (
                        <span className="text-[#a6b5cf]">
                          digest {scanReport.report_digest.slice(0, 12)}
                        </span>
                      )}
                    </div>

                    {scanReport.findings.length === 0 ? (
                      <div className="font-mono text-[12.5px] text-[#5bdba2]">
                        No firewall findings detected.
                      </div>
                    ) : (
                      <div className="max-h-56 space-y-1.5 overflow-y-auto">
                        {scanReport.findings.map((f) => (
                          <FindingCard key={f.id} finding={f} />
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* 2. Pending Quarantined Edits Queue */}
              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Pending Quarantined Edits ({quarantine ? pendingEdits.length : "…"})
                  </span>
                  {quarantine && (
                    <span
                      className={`rounded-full px-2 py-0.5 font-mono text-[12px] ${
                        quarantine.enforced
                          ? "border border-[#5bdba2]/30 bg-[#5bdba2]/12 text-[#5bdba2]"
                          : "border border-white/[0.11] bg-white/[0.04] text-[#9eb0cc]"
                      }`}
                    >
                      {quarantine.enforced ? "enforced" : "advisory"}
                    </span>
                  )}
                </div>

                {!quarantine && !quarantineError ? (
                  <PanelRowsSkeleton rows={2} className="p-0!" />
                ) : pendingEdits.length === 0 ? (
                  <div className="pr-well rounded-xl px-3 py-3 text-center font-mono text-[12.5px] text-[#a6b5cf]">
                    No pending quarantined edits
                  </div>
                ) : (
                  <div className="space-y-2.5">
                    {pendingEdits.map((edit) => {
                      const expanded = Boolean(expandedEdits[edit.id]);
                      const reason = editReasons[edit.id] ?? "";
                      const ack = Boolean(editAcks[edit.id]);
                      const busy = busyEditId === edit.id;
                      return (
                        <div
                          key={edit.id}
                          className="pr-well space-y-2 rounded-xl border border-[#9ec0f5]/25 p-3"
                        >
                          <div className="flex flex-wrap items-start justify-between gap-2">
                            <div className="min-w-0">
                              <div className="truncate font-mono text-[13.5px] font-medium text-[#f3f6fd]">
                                {edit.path}
                              </div>
                              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[12.5px] text-[#a6b5cf]">
                                <span>
                                  {edit.proposed_by}
                                  {edit.agent_profile ? ` ∩ ${edit.agent_profile}` : ""}
                                </span>
                                <span className="text-[#9ec0f5]">{edit.branch}</span>
                                <span className="text-[#a6b5cf]">
                                  {edit.proposed_sha256.slice(0, 12)}
                                </span>
                              </div>
                            </div>
                            <span
                              title={isoTime(edit.created_at)}
                              className="inline-flex shrink-0 items-center gap-1 font-mono text-[12px] text-[#a6b5cf]"
                            >
                              <IconClock className="h-3 w-3" />
                              {formatTime(edit.created_at)}
                            </span>
                          </div>

                          {edit.commit_message && (
                            <div className="rounded-lg bg-black/25 px-2.5 py-1.5 font-mono text-[12.5px] text-[#d2dbee]">
                              {edit.commit_message}
                            </div>
                          )}

                          {edit.findings.length > 0 && (
                            <div className="space-y-1.5">
                              {edit.findings.map((f) => (
                                <FindingCard key={f.id} finding={f} />
                              ))}
                            </div>
                          )}

                          <button
                            type="button"
                            onClick={() =>
                              setExpandedEdits((prev) => ({ ...prev, [edit.id]: !prev[edit.id] }))
                            }
                            aria-expanded={expanded}
                            className="inline-flex items-center gap-1 font-mono text-[12.5px] text-[#9ec0f5] hover:text-white"
                          >
                            <IconChevron
                              direction={expanded ? "up" : "down"}
                              className="h-3.5 w-3.5"
                            />
                            <span>{expanded ? "Hide proposed content" : "Inspect proposed content"}</span>
                          </button>

                          {expanded && (
                            <CodeBlock
                              code={edit.proposed_content}
                              filePath={edit.path}
                              label={edit.path}
                              showLineNumbers
                              compact
                              maxHeightClass="max-h-56"
                            />
                          )}

                          <div className="space-y-2 border-t border-white/[0.06] pt-2">
                            <input
                              value={reason}
                              onChange={(e) =>
                                setEditReasons((prev) => ({ ...prev, [edit.id]: e.target.value }))
                              }
                              aria-label={`Audit reason for ${edit.path}`}
                              placeholder="Audit reason (required)…"
                              className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                            />
                            <label className="flex cursor-pointer items-start gap-2 text-[12.5px] leading-snug text-[#d2dbee]">
                              <input
                                type="checkbox"
                                checked={ack}
                                onChange={(e) =>
                                  setEditAcks((prev) => ({ ...prev, [edit.id]: e.target.checked }))
                                }
                                className="mt-0.5 accent-[#5bdba2]"
                              />
                              <span>
                                I reviewed the proposed diff for{" "}
                                <code className="font-mono text-[#f3f6fd]">
                                  {edit.proposed_sha256.slice(0, 12)}
                                </code>
                              </span>
                            </label>
                            <div className="flex flex-wrap items-center gap-2">
                              <button
                                type="button"
                                disabled={busy || !ack || !reason.trim()}
                                onClick={() => void handleApprovePendingEdit(edit)}
                                className="inline-flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-[#5bdba2]/35 bg-[#5bdba2]/16 px-2.5 py-1.5 font-mono text-[12.5px] font-medium text-[#5bdba2] transition hover:bg-[#5bdba2]/24 disabled:cursor-not-allowed disabled:opacity-40"
                              >
                                <IconCheck className="h-3.5 w-3.5" />
                                <span>{busy ? "Working…" : "Approve & Commit"}</span>
                              </button>
                              <button
                                type="button"
                                disabled={busy || !reason.trim()}
                                onClick={() => void handleRejectPendingEdit(edit)}
                                className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-[#f27c7c]/35 bg-[#f27c7c]/14 px-3 py-1.5 font-mono text-[12.5px] font-medium text-[#f27c7c] transition hover:bg-[#f27c7c]/22 disabled:cursor-not-allowed disabled:opacity-40"
                              >
                                <IconClose className="h-3.5 w-3.5" />
                                <span>Reject</span>
                              </button>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* 3. Tracked Instruction Files */}
              <div className="space-y-2">
                <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                  Tracked Instruction Files ({quarantine ? quarantine.tracked_files.length : "…"})
                </div>

                {!quarantine && !quarantineError ? (
                  <PanelRowsSkeleton rows={2} className="p-0!" />
                ) : !quarantine || quarantine.tracked_files.length === 0 ? (
                  <div className="pr-well rounded-xl px-3 py-3 text-center font-mono text-[12.5px] text-[#a6b5cf]">
                    No tracked instruction files
                  </div>
                ) : (
                  <div className="space-y-2">
                    {quarantine.tracked_files.map((file) => {
                      const isActionOpen = activeFileAction?.path === file.path;
                      const actionMode = isActionOpen ? activeFileAction.mode : null;
                      const busy = busyFilePath === file.path;
                      return (
                        <div key={file.path} className="pr-well space-y-2 rounded-xl p-3">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span
                              title={file.path}
                              className="min-w-0 truncate font-mono text-[13px] font-medium text-[#f3f6fd]"
                            >
                              {file.path}
                            </span>
                            <span
                              className={`rounded-full px-2 py-0.5 font-mono text-[12px] uppercase ${fileStatusClass(
                                file.status,
                              )}`}
                            >
                              {file.status}
                            </span>
                          </div>

                          <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[12.5px] text-[#a6b5cf]">
                            <span>sha256 {file.sha256.slice(0, 12)}</span>
                            {file.approved_by && (
                              <span title={isoTime(file.approved_at)}>
                                by {file.approved_by}
                                {file.approved_at ? ` · ${formatTime(file.approved_at)}` : ""}
                              </span>
                            )}
                          </div>

                          {file.findings.length > 0 && (
                            <div className="space-y-1.5">
                              {file.findings.map((f) => (
                                <FindingCard key={f.id} finding={f} />
                              ))}
                            </div>
                          )}

                          <div className="flex flex-wrap items-center gap-1.5">
                            {file.status !== "pinned" && (
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => {
                                  if (actionMode === "approve") {
                                    setActiveFileAction(null);
                                  } else {
                                    setActiveFileAction({ path: file.path, mode: "approve" });
                                    setFileReason("");
                                    setFileAck(false);
                                  }
                                }}
                                className="pr-pill inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-mono text-[12.5px] text-[#5bdba2] hover:text-white disabled:opacity-40"
                              >
                                <IconCheck className="h-3.5 w-3.5" />
                                <span>Approve Version</span>
                              </button>
                            )}
                            {file.status === "approved" && (
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => {
                                  if (actionMode === "revoke") {
                                    setActiveFileAction(null);
                                  } else {
                                    setActiveFileAction({ path: file.path, mode: "revoke" });
                                    setFileReason("");
                                    setFileAck(false);
                                  }
                                }}
                                className="pr-pill inline-flex items-center gap-1 rounded-lg px-2.5 py-1 font-mono text-[12.5px] text-[#f27c7c] hover:text-white disabled:opacity-40"
                              >
                                <IconClose className="h-3.5 w-3.5" />
                                <span>Revoke</span>
                              </button>
                            )}
                          </div>

                          {isActionOpen && actionMode && (
                            <div className="space-y-2 border-t border-white/[0.06] pt-2">
                              <input
                                value={fileReason}
                                onChange={(e) => setFileReason(e.target.value)}
                                aria-label={`Audit reason for ${file.path}`}
                                placeholder={
                                  actionMode === "approve"
                                    ? "Approval audit reason…"
                                    : "Revocation reason…"
                                }
                                className="w-full rounded-lg border border-white/[0.08] bg-black/30 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:outline-none"
                              />
                              {actionMode === "approve" && (
                                <label className="flex cursor-pointer items-start gap-2 text-[12.5px] leading-snug text-[#d2dbee]">
                                  <input
                                    type="checkbox"
                                    checked={fileAck}
                                    onChange={(e) => setFileAck(e.target.checked)}
                                    className="mt-0.5 accent-[#5bdba2]"
                                  />
                                  <span>
                                    I reviewed{" "}
                                    <code className="font-mono text-[#f3f6fd]">
                                      {file.sha256.slice(0, 12)}
                                    </code>{" "}
                                    and approve this instruction file version
                                  </span>
                                </label>
                              )}
                              <div className="flex items-center gap-2">
                                {actionMode === "approve" ? (
                                  <button
                                    type="button"
                                    disabled={busy || !fileAck || !fileReason.trim()}
                                    onClick={() => void handleApproveTrackedFile(file)}
                                    className="inline-flex items-center gap-1 rounded-lg border border-[#5bdba2]/35 bg-[#5bdba2]/16 px-3 py-1 font-mono text-[12.5px] text-[#5bdba2] disabled:cursor-not-allowed disabled:opacity-40"
                                  >
                                    <IconCheck className="h-3.5 w-3.5" />
                                    <span>{busy ? "Approving…" : "Confirm Approval"}</span>
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    disabled={busy || !fileReason.trim()}
                                    onClick={() => void handleRevokeTrackedFile(file)}
                                    className="inline-flex items-center gap-1 rounded-lg border border-[#f27c7c]/35 bg-[#f27c7c]/14 px-3 py-1 font-mono text-[12.5px] text-[#f27c7c] disabled:cursor-not-allowed disabled:opacity-40"
                                  >
                                    <IconClose className="h-3.5 w-3.5" />
                                    <span>{busy ? "Revoking…" : "Confirm Revoke"}</span>
                                  </button>
                                )}
                                <button
                                  type="button"
                                  onClick={() => setActiveFileAction(null)}
                                  className="font-mono text-[12.5px] text-[#a6b5cf] hover:text-white"
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* 4. Recent Audited Overrides */}
              {quarantine && quarantine.recent_overrides.length > 0 && (
                <div className="space-y-2">
                  <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
                    Recent Audited Overrides ({quarantine.recent_overrides.length})
                  </div>
                  <div className="space-y-1.5">
                    {quarantine.recent_overrides.map((ov) => (
                      <div key={ov.id} className="pr-well space-y-1 rounded-xl px-3 py-2 font-mono">
                        <div className="flex flex-wrap items-center justify-between gap-1.5 text-[12.5px]">
                          <span className="font-medium text-[#cbd5e8]">{ov.owner}</span>
                          <span
                            title={isoTime(ov.created_at)}
                            className="text-[12px] text-[#a6b5cf]"
                          >
                            {formatTime(ov.created_at)}
                          </span>
                        </div>
                        <div className="truncate text-[12.5px] text-[#dce4f5]" title={ov.target}>
                          {ov.target}
                        </div>
                        <div className="font-sans text-[12.5px] leading-snug text-[#d2dbee]">
                          {ov.reason}
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-[12px] text-[#a6b5cf]">
                          <span>digest {ov.report_digest.slice(0, 12)}</span>
                          {ov.finding_ids.length > 0 && (
                            <span>{plural(ov.finding_ids.length, "finding")}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}
