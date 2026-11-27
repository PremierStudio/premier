import { useCallback, useEffect, useId, useRef, useState, type FormEvent } from "react";
import {
  api,
  currentRepoName,
  errorText,
  type IdentityPreset,
  type IssuedWorkloadToken,
  type KmsStatus,
  type OidcDiscoveryDocument,
  type RotationReceipt,
  type RotationStatus,
  type VarSpec,
  type VerifyOidcResponse,
} from "../api";
import {
  IconCheck,
  IconChevron,
  IconCopy,
  IconLock,
  IconQuarantine,
  IconRefresh,
  IconShieldCheck,
  IconVault,
} from "./Icons";
import { ConfirmButton, ErrorNote, OwnerOnly, Time } from "./forms";
import { SettingsRowsSkeleton } from "./ViewSkeletons";
import { oidcDiscoveryUrl } from "../lib/uiHelpers";

interface Props {
  owner: boolean;
  identity: IdentityPreset;
  activeEnv: string;
  selectedVar: { name: string; spec: VarSpec } | null;
  varNames: string[];
  onVaultChanged?: () => void;
}

const ROTATION_STATUS_CLASS: Record<RotationStatus, string> = {
  committed: "bg-[#5bdba2]/14 text-[#5bdba2]",
  rolled_back: "bg-[#7f95f8]/14 text-[#a8c5ff]",
  manual_required: "bg-[#7f95f8]/14 text-[#a8c5ff]",
  failed: "bg-[#f27c7c]/14 text-[#f27c7c]",
};

function SectionToggle({
  open,
  onToggle,
  children,
}: {
  open: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-expanded={open}
      onClick={onToggle}
      className="inline-flex items-center gap-1.5 text-[12.5px] uppercase tracking-wider text-[#9ec0f5] hover:text-[#f3f6fd]"
    >
      <IconChevron direction={open ? "down" : "right"} className="h-3.5 w-3.5 text-[#a6b5cf]" />
      {children}
    </button>
  );
}

// Survives tab switches: the discovery document is static per server.
let discoveryCache: OidcDiscoveryDocument | null = null;
// Stale-while-revalidate keyed by repo so switching repos never flashes another repo's KMS/rotation state.
const kmsCache = new Map<string, KmsStatus>();
const receiptsCache = new Map<string, RotationReceipt[]>();

const FIELD_CLASS =
  "w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none";
const SELECT_CLASS = `${FIELD_CLASS} bg-[#0d1222]! [color-scheme:dark]`;
const NO_SPIN = "[appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none";

function formatUnixTime(sec: number): string {
  try {
    return new Date(sec * 1000).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
    });
  } catch {
    return String(sec);
  }
}

function shortHash(hash: string): string {
  if (hash.length <= 16) return hash;
  return `${hash.slice(0, 10)}…${hash.slice(-6)}`;
}

export function SecretLifecyclePanel({
  owner,
  identity,
  activeEnv,
  selectedVar,
  varNames,
  onVaultChanged,
}: Props) {
  const repoKey = currentRepoName();
  const activeRepoRef = useRef(repoKey);
  activeRepoRef.current = repoKey;

  // 1. KMS & Key Transparency (owner-only)
  const [kms, setKmsState] = useState<KmsStatus | null>(() => kmsCache.get(repoKey) ?? null);
  const [kmsLoading, setKmsLoading] = useState(false);
  const [kmsError, setKmsError] = useState<string | null>(null);
  const [kmsBusy, setKmsBusy] = useState<"migrate" | "rotate" | null>(null);
  const [kmsNotice, setKmsNotice] = useState<string | null>(null);
  const [ktExpanded, setKtExpanded] = useState(false);

  // 2. Dual-Phase Rotation (owner-only)
  const [receipts, setReceiptsState] = useState<RotationReceipt[] | null>(
    () => receiptsCache.get(repoKey) ?? null,
  );
  const [rotTarget, setRotTarget] = useState(selectedVar?.name ?? varNames[0] ?? "");
  const [rotReason, setRotReason] = useState("");
  const [rotNewValue, setRotNewValue] = useState("");
  const [rotBusy, setRotBusy] = useState(false);
  const [rotError, setRotError] = useState<string | null>(null);
  const [rotNotice, setRotNotice] = useState<string | null>(null);

  // Sections open by default for owners; the OIDC minter (and its fetch) waits until opened.
  const [openSec, setOpenSec] = useState({ kms: owner, rot: owner, oidc: !owner });
  const toggleSec = (k: "kms" | "rot" | "oidc") =>
    setOpenSec((o) => ({ ...o, [k]: !o[k] }));

  // 3. Keyless OIDC / SVID Minter (all authenticated users)
  const [discovery, setDiscovery] = useState<OidcDiscoveryDocument | null>(discoveryCache);
  const [oidcError, setOidcError] = useState<string | null>(null);
  const [audienceInput, setAudienceInput] = useState("https://sts.amazonaws.com");
  const [branchInput, setBranchInput] = useState("main");
  const [ttlInput, setTtlInput] = useState("300");
  const [principalInput, setPrincipalInput] = useState(identity.principal);
  const [profileInput, setProfileInput] = useState(identity.agentProfile ?? "");
  const [taskIdInput, setTaskIdInput] = useState("");
  const [mintBusy, setMintBusy] = useState(false);
  const [issued, setIssued] = useState<IssuedWorkloadToken | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [copiedOidcKey, setCopiedOidcKey] = useState<string | null>(null);
  const copyOidcValue = (key: string, value: string) => {
    navigator.clipboard
      ?.writeText(value)
      .then(() => {
        setCopiedOidcKey(key);
        window.setTimeout(() => setCopiedOidcKey((cur) => (cur === key ? null : cur)), 1500);
      })
      .catch(() => {});
  };
  const [verifyAudience, setVerifyAudience] = useState("");
  const [verifyBusy, setVerifyBusy] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyOidcResponse | null>(null);
  const uid = useId();
  const fid = (k: string) => `${uid}-${k}`;

  const setKms = useCallback((next: KmsStatus | null, targetRepo = activeRepoRef.current) => {
    if (next) kmsCache.set(targetRepo, next);
    if (activeRepoRef.current === targetRepo) setKmsState(next);
  }, []);

  const setReceipts = useCallback(
    (
      next:
        | RotationReceipt[]
        | null
        | ((prev: RotationReceipt[] | null) => RotationReceipt[] | null),
      targetRepo = activeRepoRef.current,
    ) => {
      const resolved =
        typeof next === "function" ? next(receiptsCache.get(targetRepo) ?? null) : next;
      if (resolved) receiptsCache.set(targetRepo, resolved);
      if (activeRepoRef.current === targetRepo) setReceiptsState(resolved);
    },
    [],
  );

  useEffect(() => {
    setKmsState(kmsCache.get(repoKey) ?? null);
    setReceiptsState(receiptsCache.get(repoKey) ?? null);
  }, [repoKey]);

  useEffect(() => {
    if (selectedVar?.name) {
      setRotTarget(selectedVar.name);
    } else if (!rotTarget && varNames.length > 0) {
      setRotTarget(varNames[0]);
    }
  }, [selectedVar?.name, varNames]);

  useEffect(() => {
    setPrincipalInput(identity.principal);
    setProfileInput(identity.agentProfile ?? "");
  }, [identity.principal, identity.agentProfile]);

  const loadKmsAndReceipts = useCallback(() => {
    if (!owner) return;
    const targetRepo = repoKey;
    setKmsLoading(true);
    setKmsError(null);
    api
      .kmsStatus()
      .then((s) => {
        setKms(s, targetRepo);
        if (activeRepoRef.current === targetRepo) setKmsError(null);
      })
      .catch((err: unknown) => {
        if (activeRepoRef.current === targetRepo) setKmsError(errorText(err));
      })
      .finally(() => {
        if (activeRepoRef.current === targetRepo) setKmsLoading(false);
      });

    api
      .rotationReceipts()
      .then((r) => setReceipts(r, targetRepo))
      .catch(() => setReceipts((prev) => prev ?? [], targetRepo));
  }, [owner, repoKey, setKms, setReceipts]);

  useEffect(() => {
    loadKmsAndReceipts();
  }, [loadKmsAndReceipts]);

  useEffect(() => {
    if (!openSec.oidc) return;
    if (discoveryCache) {
      if (discoveryCache.token_ttl_default_secs > 0) setTtlInput(String(discoveryCache.token_ttl_default_secs));
      return;
    }
    api
      .oidcDiscovery()
      .then((doc) => {
        discoveryCache = doc;
        setDiscovery(doc);
        if (doc.token_ttl_default_secs > 0) {
          setTtlInput(String(doc.token_ttl_default_secs));
        }
      })
      .catch((err: unknown) => setOidcError(errorText(err)));
  }, [openSec.oidc]);

  const handleMigrateEnvelope = async () => {
    setKmsBusy("migrate");
    setKmsError(null);
    setKmsNotice(null);
    try {
      const res = await api.migrateToEnvelope();
      setKms(res.status);
      setKmsNotice(
        res.already_migrated
          ? "Vault is already using Envelope KMS."
          : `Migrated ${res.migrated_entries} ${res.migrated_entries === 1 ? "entry" : "entries"} to Envelope KMS.`,
      );
      onVaultChanged?.();
    } catch (err: unknown) {
      setKmsError(errorText(err));
    } finally {
      setKmsBusy(null);
    }
  };

  const handleRotateDek = async () => {
    setKmsBusy("rotate");
    setKmsError(null);
    setKmsNotice(null);
    try {
      const res = await api.rotateDek();
      setKms(res.status);
      setKmsNotice(`Rotated vault DEK to v${res.dek_version}.`);
      onVaultChanged?.();
    } catch (err: unknown) {
      setKmsError(errorText(err));
    } finally {
      setKmsBusy(null);
    }
  };

  const handleRotateSecret = async (e: FormEvent) => {
    e.preventDefault();
    const key = rotTarget.trim();
    if (!key) return;
    const rawNewValue = rotNewValue;
    // Clear secret input immediately so plaintext never lingers in component state.
    setRotNewValue("");
    setRotBusy(true);
    setRotError(null);
    setRotNotice(null);
    try {
      const receipt = await api.rotateSecret(key, {
        env: activeEnv,
        reason: rotReason.trim() || undefined,
        new_value: rawNewValue || undefined,
      });
      setReceipts((prev) => [receipt, ...(prev ?? []).filter((r) => r.id !== receipt.id)]);
      setRotReason("");
      setRotNotice(
        `${receipt.var_name} (${receipt.env}): ${receipt.status.replace(/_/g, " ")} at ${receipt.phase_reached}`,
      );
      onVaultChanged?.();
    } catch (err: unknown) {
      setRotError(errorText(err));
    } finally {
      setRotBusy(false);
    }
  };

  const handleMintOidc = async (e: FormEvent) => {
    e.preventDefault();
    const audiences = audienceInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (audiences.length === 0) {
      setOidcError("Enter at least one audience URI.");
      return;
    }
    const parsedTtl = ttlInput.trim() ? Number(ttlInput.trim()) : undefined;
    if (parsedTtl !== undefined && (!Number.isFinite(parsedTtl) || parsedTtl <= 0)) {
      setOidcError("TTL must be a positive number of seconds.");
      return;
    }
    setMintBusy(true);
    setOidcError(null);
    setVerifyResult(null);
    try {
      const res = await api.mintOidcToken({
        principal: owner && principalInput.trim() ? principalInput.trim() : undefined,
        agent_profile: owner && profileInput.trim() ? profileInput.trim() : null,
        task_id: owner && taskIdInput.trim() ? taskIdInput.trim() : null,
        audience: audiences,
        branch: branchInput.trim() || undefined,
        ttl_secs: parsedTtl,
      });
      setIssued(res);
      setVerifyAudience(res.claims.aud[0] ?? audiences[0]);
      setCopiedToken(false);
    } catch (err: unknown) {
      setOidcError(errorText(err));
    } finally {
      setMintBusy(false);
    }
  };

  const handleVerifyToken = async () => {
    if (!issued) return;
    const aud = verifyAudience.trim() || issued.claims.aud[0] || "";
    if (!aud) return;
    setVerifyBusy(true);
    setOidcError(null);
    try {
      const res = await api.verifyOidcToken(issued.token, aud);
      setVerifyResult(res);
    } catch (err: unknown) {
      setOidcError(errorText(err));
    } finally {
      setVerifyBusy(false);
    }
  };

  const copyToken = () => {
    if (!issued) return;
    navigator.clipboard
      ?.writeText(issued.token)
      .then(() => {
        setCopiedToken(true);
        window.setTimeout(() => setCopiedToken(false), 1800);
      })
      .catch(() => {});
  };

  const activeRotationSpec =
    selectedVar && selectedVar.name === rotTarget ? selectedVar.spec.rotation : null;

  return (
    <div className="min-h-0 flex-1 space-y-2.5 overflow-y-auto p-3 font-mono text-[13px]">
      {/* 1. KMS & Key Transparency Health Card */}
      <div className="pr-well space-y-3 rounded-xl p-3">
        <div className="flex items-center justify-between gap-2">
          <SectionToggle open={openSec.kms} onToggle={() => toggleSec("kms")}>
            <IconVault className="h-4 w-4" />
            <span>Encryption &amp; Key Storage</span>
          </SectionToggle>
          {owner && (
            <button
              type="button"
              disabled={kmsLoading}
              onClick={loadKmsAndReceipts}
              aria-label="Refresh KMS status"
              title="Refresh KMS status"
              className="pr-pill inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[12px] text-[#b6c3db] hover:text-[#f3f6fd] disabled:opacity-45"
            >
              <IconRefresh className={`h-3.5 w-3.5 ${kmsLoading ? "animate-spin" : ""}`} />
              <span>Refresh</span>
            </button>
          )}
        </div>

        {openSec.kms && (!owner ? (
          <OwnerOnly className="rounded-lg bg-black/25 py-3!" />
        ) : (
          <>
            <ErrorNote message={kmsError} />
            {kms ? (
              <div className="space-y-2.5">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span
                    className={`rounded-full px-2 py-0.5 text-[12px] font-medium ${
                      kms.mode === "envelope"
                        ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                        : "bg-white/[0.07] text-[#d2dbee]"
                    }`}
                  >
                    {kms.mode}
                  </span>
                  <span className="rounded-full bg-[#7f95f8]/15 px-2 py-0.5 text-[12px] text-[#9ec0f5]">
                    DEK v{kms.dek_version}
                  </span>
                  <span
                    className={`rounded-full px-2 py-0.5 text-[12px] ${
                      kms.kek_separated
                        ? "bg-[#5bdba2]/14 text-[#5bdba2]"
                        : "bg-[#7f95f8]/14 text-[#a8c5ff]"
                    }`}
                  >
                    {kms.kek_separated ? "KEK separated" : "KEK co-located"}
                  </span>
                  <span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12px] text-[#d2dbee]">
                    {kms.entry_count} {kms.entry_count === 1 ? "secret" : "secrets"}
                  </span>
                </div>

                <div className="space-y-1 text-[12.5px]">
                  <div className="flex justify-between gap-2">
                    <span className="text-[#a6b5cf]">provider</span>
                    <span className="truncate text-[#dce4f5]">{kms.provider}</span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#a6b5cf]">key_id</span>
                    <span className="truncate text-[#dce4f5]" title={kms.key_id}>
                      {kms.key_id}
                    </span>
                  </div>
                  <div className="flex justify-between gap-2">
                    <span className="text-[#a6b5cf]">envelope</span>
                    <span className="text-[#dce4f5]">v{kms.envelope_version}</span>
                  </div>
                </div>

                {/* Key Transparency Health */}
                <div
                  className={`rounded-xl border p-2.5 ${
                    !kms.kt_enabled
                      ? "border-white/[0.06] bg-black/25 text-[#b6c3db]"
                      : kms.kt_valid
                        ? "border-[#5bdba2]/25 bg-[#5bdba2]/8 text-[#5bdba2]"
                        : "border-[#f27c7c]/35 bg-[#f27c7c]/10 text-[#f27c7c]"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 text-[12.5px] font-medium">
                      {!kms.kt_enabled ? (
                        <IconLock className="h-3.5 w-3.5 text-[#a6b5cf]" />
                      ) : kms.kt_valid ? (
                        <IconShieldCheck className="h-4 w-4" />
                      ) : (
                        <IconQuarantine className="h-4 w-4" />
                      )}
                      <span>
                        Key Transparency:{" "}
                        {!kms.kt_enabled
                          ? "disabled"
                          : kms.kt_valid
                            ? "verified"
                            : "tamper detected"}
                      </span>
                    </span>
                    <span className="text-[12px] opacity-85">{kms.kt_entries} entries</span>
                  </div>
                  {kms.kt_error && (
                    <div role="alert" className="mt-1.5 break-words text-[12.5px] text-[#f9b4b4]">
                      {kms.kt_error}
                    </div>
                  )}
                  {kms.kt_recent_entries && kms.kt_recent_entries.length > 0 && (
                    <div className="mt-2 border-t border-white/[0.08] pt-2">
                      <button
                        type="button"
                        aria-expanded={ktExpanded}
                        onClick={() => setKtExpanded((o) => !o)}
                        className="flex w-full items-center justify-between text-[12.5px] text-[#dce4f5] hover:text-white"
                      >
                        <span>Recent KT log ({kms.kt_recent_entries.length})</span>
                        <IconChevron
                          direction={ktExpanded ? "up" : "down"}
                          className="h-3.5 w-3.5 text-[#a6b5cf]"
                        />
                      </button>
                      {ktExpanded && (
                        <ul className="mt-2 max-h-44 space-y-1.5 overflow-y-auto">
                          {kms.kt_recent_entries.map((entry) => (
                            <li
                              key={`${entry.seq}-${entry.entry_hash}`}
                              className="rounded-lg bg-black/35 px-2.5 py-1.5 text-[12px] text-[#d2dbee]"
                            >
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-semibold text-[#f3f6fd]">
                                  #{entry.seq} {entry.event}
                                </span>
                                <span className="text-[#a6b5cf]">
                                  <Time value={entry.timestamp} />
                                </span>
                              </div>
                              <div className="mt-0.5 flex flex-wrap items-center justify-between gap-1 text-[#b6c3db]">
                                <span>actor: {entry.actor}</span>
                                <span title={entry.entry_hash} className="text-[#9ec0f5]">
                                  {shortHash(entry.entry_hash)}
                                </span>
                              </div>
                              {entry.recipients.length > 0 && (
                                <div className="mt-0.5 truncate text-[#a6b5cf]">
                                  recipients: {entry.recipients.join(", ")}
                                </div>
                              )}
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  )}
                </div>

                {/* KMS Owner Actions */}
                <div className="flex flex-wrap items-center gap-2 pt-0.5">
                  {kms.mode === "sovereign_age" && (
                    <ConfirmButton
                      disabled={kmsBusy !== null}
                      confirmLabel="Migrate"
                      question="Migrate vault to Envelope KMS?"
                      onConfirm={() => void handleMigrateEnvelope()}
                      className="pr-action-btn rounded-lg px-3 py-1.5 font-sans text-[13px] disabled:opacity-45"
                    >
                      {kmsBusy === "migrate" ? "Migrating…" : "Migrate to Envelope KMS"}
                    </ConfirmButton>
                  )}
                  {kms.mode === "envelope" && (
                    <ConfirmButton
                      disabled={kmsBusy !== null}
                      confirmLabel="Rotate DEK"
                      question="Re-wrap all vault entries with a new DEK?"
                      onConfirm={() => void handleRotateDek()}
                      className="pr-pill rounded-lg border-[#9ec0f5]/30 px-3 py-1.5 font-sans text-[13px] text-[#9ec0f5] hover:text-[#f3f6fd] disabled:opacity-45"
                    >
                      {kmsBusy === "rotate" ? "Rotating DEK…" : "Rotate DEK"}
                    </ConfirmButton>
                  )}
                </div>

                {kmsNotice && (
                  <div role="status" className="flex items-center gap-1.5 text-[12.5px] text-[#5bdba2]">
                    <IconCheck className="h-3.5 w-3.5 shrink-0" />
                    <span>{kmsNotice}</span>
                  </div>
                )}
              </div>
            ) : (
              !kmsError && <SettingsRowsSkeleton rows={2} />
            )}
          </>
        ))}
      </div>

      {/* 2. Dual-Phase Rotation Controls & Receipts */}
      <div className="pr-well space-y-3 rounded-xl p-3">
        <div className="flex items-center justify-between gap-2">
          <SectionToggle open={openSec.rot} onToggle={() => toggleSec("rot")}>
            <span>Key Rotation ({activeEnv})</span>
          </SectionToggle>
          {owner && receipts && receipts.length > 0 && (
            <span className="text-[12px] text-[#a6b5cf]">{receipts.length} receipts</span>
          )}
        </div>

        {openSec.rot && (!owner ? (
          <OwnerOnly className="rounded-lg bg-black/25 py-3!" />
        ) : (
          <>
            {activeRotationSpec && (
              <div className="space-y-1 rounded-lg border border-white/[0.06] bg-black/30 p-2.5 text-[12.5px]">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#a6b5cf]">provider</span>
                  <span className="text-[#dce4f5]">
                    {activeRotationSpec.provider || "webhook"}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[#a6b5cf]">webhook</span>
                  <span
                    className="truncate text-[#9ec0f5]"
                    title={activeRotationSpec.webhook_url}
                  >
                    {activeRotationSpec.webhook_url}
                  </span>
                </div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[#a6b5cf]">policy</span>
                  <span className="flex flex-wrap items-center gap-1.5">
                    {activeRotationSpec.schedule && (
                      <span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12px] text-[#dce4f5]">
                        {activeRotationSpec.schedule}
                      </span>
                    )}
                    {activeRotationSpec.max_age_days != null && (
                      <span className="rounded-full bg-white/[0.06] px-2 py-0.5 text-[12px] text-[#dce4f5]">
                        max {activeRotationSpec.max_age_days}d
                      </span>
                    )}
                    <span
                      className={`rounded-full px-2 py-0.5 text-[12px] ${
                        activeRotationSpec.revoke_on_offboard
                          ? "bg-[#f27c7c]/14 text-[#f27c7c]"
                          : "bg-white/[0.06] text-[#a6b5cf]"
                      }`}
                    >
                      {activeRotationSpec.revoke_on_offboard
                        ? "offboard-rotate"
                        : "manual-offboard"}
                    </span>
                  </span>
                </div>
              </div>
            )}

            <form onSubmit={(e) => void handleRotateSecret(e)} className="space-y-2">
              {varNames.length > 0 ? (
                <select
                  value={rotTarget}
                  onChange={(e) => setRotTarget(e.target.value)}
                  aria-label="Secret variable to rotate"
                  className={`${SELECT_CLASS} font-mono text-[13px]`}
                >
                  {varNames.map((vn) => (
                    <option key={vn} value={vn}>
                      {vn}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  value={rotTarget}
                  onChange={(e) => setRotTarget(e.target.value)}
                  aria-label="Secret key name to rotate"
                  placeholder="SECRET_KEY_NAME"
                  className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                />
              )}

              <input
                value={rotReason}
                onChange={(e) => setRotReason(e.target.value)}
                aria-label="Rotation reason"
                placeholder="Reason (optional, e.g. Scheduled rotation)"
                className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-sans text-[13px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
              />

              <div className="flex items-center gap-2">
                <input
                  type="password"
                  autoComplete="new-password"
                  value={rotNewValue}
                  onChange={(e) => setRotNewValue(e.target.value)}
                  aria-label="Manual replacement secret value (optional)"
                  placeholder="Optional manual value (leave blank for webhook)"
                  className="min-w-0 flex-1 rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={rotBusy || !rotTarget.trim()}
                  className="pr-action-btn shrink-0 rounded-lg px-3 py-1.5 font-sans text-[12.5px] disabled:opacity-45"
                >
                  {rotBusy ? "Rotating…" : "Rotate"}
                </button>
              </div>
            </form>

            {rotNotice && (
              <div role="status" className="flex items-center gap-1.5 text-[12.5px] text-[#5bdba2]">
                <IconCheck className="h-3.5 w-3.5 shrink-0" />
                <span>{rotNotice}</span>
              </div>
            )}
            <ErrorNote message={rotError} />

            {/* Recent Rotation Receipts */}
            {receipts === null ? (
              <SettingsRowsSkeleton rows={2} />
            ) : receipts.length > 0 ? (
              <ul className="max-h-52 space-y-1.5 overflow-y-auto pt-1">
                {receipts.slice(0, 12).map((r) => (
                  <li
                    key={r.id}
                    className="space-y-1 rounded-lg border border-white/[0.05] bg-black/30 px-2.5 py-2 text-[12.5px]"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-1.5">
                      <span className="truncate font-semibold text-[#f3f6fd]">
                        {r.var_name}{" "}
                        <span className="font-normal text-[#a6b5cf]">({r.env})</span>
                      </span>
                      <span
                        className={`rounded-full px-2 py-0.5 text-[12px] ${ROTATION_STATUS_CLASS[r.status]}`}
                      >
                        {r.status.replace(/_/g, " ")}
                      </span>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-[#b6c3db]">
                      <span>{r.provider}</span>
                      <span>· phase: {r.phase_reached}</span>
                      {r.http_status != null && <span>· HTTP {r.http_status}</span>}
                      {r.rollback_sent && (
                        <span className="rounded-full bg-[#7f95f8]/14 px-1.5 py-0.2 text-[#a8c5ff]">
                          rollback sent
                        </span>
                      )}
                      {r.triggered_by_offboard && (
                        <span className="rounded-full bg-[#f27c7c]/14 px-1.5 py-0.2 text-[#f27c7c]">
                          offboard
                        </span>
                      )}
                    </div>
                    <div className="flex items-center justify-between gap-2 text-[12px] text-[#a6b5cf]">
                      <span className="truncate">
                        {r.actor} · {r.reason}
                      </span>
                      <span className="shrink-0">
                        <Time value={r.timestamp} />
                      </span>
                    </div>
                    {r.error && (
                      <div className="break-words text-[12px] text-[#f27c7c]">{r.error}</div>
                    )}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-[12.5px] text-[#a6b5cf]">No rotation receipts recorded yet.</div>
            )}
          </>
        ))}
      </div>

      {/* 3. Keyless OIDC / SVID Workload Token Minter (all authenticated users) */}
      <div className="pr-well space-y-3 rounded-xl p-3">
        <div className="flex items-center justify-between gap-2">
          <SectionToggle open={openSec.oidc} onToggle={() => toggleSec("oidc")}>
            <IconShieldCheck className="h-4 w-4" />
            <span>Short-Lived Cloud Credentials (OIDC)</span>
          </SectionToggle>
          {discovery && (
            <span className="rounded-full bg-[#5bdba2]/14 px-2 py-0.5 text-[12px] text-[#5bdba2]">
              {discovery.id_token_signing_alg_values_supported[0] ?? "EdDSA"}
            </span>
          )}
        </div>

        {openSec.oidc && (
        <div className="space-y-3">
        {discovery && (() => {
          const openidConfigUrl = oidcDiscoveryUrl(discovery.issuer);
          return (
            <div className="space-y-1.5 rounded-lg bg-black/30 p-2.5 text-[12.5px]">
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">issuer</span>
                <span className="truncate text-[#dce4f5]" title={discovery.issuer}>
                  {discovery.issuer}
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="shrink-0 text-[#a6b5cf]">openid-config</span>
                <span className="inline-flex min-w-0 items-center gap-1.5">
                  <span className="truncate text-[#dce4f5]" title={openidConfigUrl}>
                    {openidConfigUrl}
                  </span>
                  <button
                    type="button"
                    onClick={() => copyOidcValue("openid-config", openidConfigUrl)}
                    aria-label="Copy OpenID configuration URL"
                    title="Copy OpenID configuration URL"
                    className="shrink-0 rounded p-0.5 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white"
                  >
                    {copiedOidcKey === "openid-config" ? (
                      <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                    ) : (
                      <IconCopy className="h-3.5 w-3.5" />
                    )}
                  </button>
                </span>
              </div>
              {discovery.jwks_uri && (
                <div className="flex items-center justify-between gap-2">
                  <span className="shrink-0 text-[#a6b5cf]">jwks_uri</span>
                  <span className="inline-flex min-w-0 items-center gap-1.5">
                    <span className="truncate text-[#dce4f5]" title={discovery.jwks_uri}>
                      {discovery.jwks_uri}
                    </span>
                    <button
                      type="button"
                      onClick={() => copyOidcValue("jwks_uri", discovery.jwks_uri)}
                      aria-label="Copy JWKS URI"
                      title="Copy JWKS URI"
                      className="shrink-0 rounded p-0.5 text-[#a6b5cf] hover:bg-white/[0.06] hover:text-white"
                    >
                      {copiedOidcKey === "jwks_uri" ? (
                        <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                      ) : (
                        <IconCopy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </span>
                </div>
              )}
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">kid</span>
                <span className="truncate text-[#9ec0f5]">{discovery.kid}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">ttl max</span>
                <span className="text-[#dce4f5]">{discovery.token_ttl_max_secs}s</span>
              </div>
            </div>
          );
        })()}

        <form onSubmit={(e) => void handleMintOidc(e)} className="space-y-2">
          <div className="space-y-1">
            <label htmlFor={fid("aud")} className="block text-[12px] uppercase tracking-wider text-[#a6b5cf]">
              Audience (comma-separated)
            </label>
            <input
              id={fid("aud")}
              value={audienceInput}
              onChange={(e) => setAudienceInput(e.target.value)}
              required
              placeholder="https://sts.amazonaws.com"
              className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div className="space-y-1">
              <label htmlFor={fid("branch")} className="block text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                Branch
              </label>
              <input
                id={fid("branch")}
                value={branchInput}
                onChange={(e) => setBranchInput(e.target.value)}
                placeholder="main"
                className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor={fid("ttl")} className="block text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                TTL (secs)
              </label>
              <input
                id={fid("ttl")}
                type="number"
                min={1}
                max={discovery?.token_ttl_max_secs ?? 3600}
                step={1}
                value={ttlInput}
                onChange={(e) => setTtlInput(e.target.value)}
                className={`${NO_SPIN} w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none`}
              />
            </div>
          </div>

          {owner ? (
            <div className="grid grid-cols-2 gap-2">
              <div className="space-y-1">
                <label htmlFor={fid("principal")} className="block text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                  Principal
                </label>
                <input
                  id={fid("principal")}
                  value={principalInput}
                  onChange={(e) => setPrincipalInput(e.target.value)}
                  placeholder="@owner"
                  className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                />
              </div>
              <div className="space-y-1">
                <label htmlFor={fid("profile")} className="block text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                  Agent Profile
                </label>
                <input
                  id={fid("profile")}
                  value={profileInput}
                  onChange={(e) => setProfileInput(e.target.value)}
                  placeholder="optional"
                  className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                />
              </div>
              <div className="col-span-2 space-y-1">
                <label htmlFor={fid("task")} className="block text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                  Task ID (optional)
                </label>
                <input
                  id={fid("task")}
                  value={taskIdInput}
                  onChange={(e) => setTaskIdInput(e.target.value)}
                  placeholder="task-123"
                  className="w-full rounded-lg border border-white/[0.08] bg-black/35 px-2.5 py-1.5 font-mono text-[12.5px] text-[#f3f6fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/45 focus:outline-none"
                />
              </div>
            </div>
          ) : (
            <div className="text-[12.5px] text-[#a6b5cf]">
              Minting short-lived workload token as{" "}
              <span className="text-[#dce4f5]">{identity.principal}</span>
            </div>
          )}

          <button
            type="submit"
            disabled={mintBusy || !audienceInput.trim()}
            className="pr-action-btn w-full rounded-lg px-3 py-1.5 font-sans text-[13px] disabled:opacity-45"
          >
            {mintBusy ? "Minting…" : "Mint Workload Token"}
          </button>
        </form>

        <ErrorNote message={oidcError} />

        {issued && (
          <div className="space-y-2.5 rounded-xl border border-[#7f95f8]/30 bg-black/35 p-3">
            <div className="flex items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
                <span className="rounded-full bg-[#5bdba2]/14 px-2 py-0.5 text-[#5bdba2]">
                  {issued.alg}
                </span>
                <span className="text-[#a6b5cf]">kid: {issued.kid}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={copyToken}
                  className="pr-pill inline-flex items-center gap-1 rounded-lg px-2 py-1 text-[12.5px] text-[#dce4f5]"
                >
                  {copiedToken ? (
                    <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
                  ) : (
                    <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
                  )}
                  <span>{copiedToken ? "Copied" : "Copy JWT"}</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setIssued(null);
                    setVerifyResult(null);
                  }}
                  className="text-[12.5px] text-[#a6b5cf] hover:text-[#f3f6fd]"
                >
                  Clear
                </button>
              </div>
            </div>

            <code className="block max-h-20 select-all overflow-y-auto break-all rounded-lg border border-white/[0.06] bg-black/45 p-2 text-[12px] text-[#9ec0f5]">
              {issued.token}
            </code>

            {/* Decoded WorkloadClaims Preview */}
            <div className="space-y-1 text-[12.5px]">
              <div className="text-[12px] uppercase tracking-wider text-[#a6b5cf]">
                Decoded Claims
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">sub</span>
                <span className="truncate text-[#f3f6fd]">{issued.claims.sub}</span>
              </div>
              {issued.claims.act && (
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">act</span>
                  <span className="truncate text-[#9ec0f5]">
                    {issued.claims.act.profile} · {issued.claims.act.task_id}
                  </span>
                </div>
              )}
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">aud</span>
                <span className="truncate text-[#dce4f5]">{issued.claims.aud.join(", ")}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">repo / branch</span>
                <span className="truncate text-[#dce4f5]">
                  {issued.claims.repo} · {issued.claims.branch}
                </span>
              </div>
              {issued.claims.scope.length > 0 && (
                <div className="flex flex-wrap items-center justify-between gap-1.5">
                  <span className="text-[#a6b5cf]">scope</span>
                  <span className="flex flex-wrap justify-end gap-1">
                    {issued.claims.scope.map((sc) => (
                      <span
                        key={sc}
                        className="rounded-full bg-[#7f95f8]/15 px-1.5 py-0.5 text-[12px] text-[#9ec0f5]"
                      >
                        {sc}
                      </span>
                    ))}
                  </span>
                </div>
              )}
              {issued.claims.groups.length > 0 && (
                <div className="flex justify-between gap-2">
                  <span className="text-[#a6b5cf]">groups</span>
                  <span className="truncate text-[#dce4f5]">{issued.claims.groups.join(", ")}</span>
                </div>
              )}
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">exp</span>
                <span className="text-[#dce4f5]">{formatUnixTime(issued.claims.exp)}</span>
              </div>
              <div className="flex justify-between gap-2">
                <span className="text-[#a6b5cf]">jti</span>
                <span className="truncate text-[#a6b5cf]" title={issued.claims.jti}>
                  {issued.claims.jti}
                </span>
              </div>
            </div>

            {/* Verify Token Check */}
            <div className="flex items-center gap-2 border-t border-white/[0.06] pt-2">
              <input
                value={verifyAudience}
                onChange={(e) => setVerifyAudience(e.target.value)}
                aria-label="Audience to verify against"
                placeholder="Audience to verify"
                className="min-w-0 flex-1 rounded-lg border border-white/[0.08] bg-black/35 px-2 py-1 font-mono text-[12.5px] text-[#f3f6fd] focus:border-[#9ec0f5]/45 focus:outline-none"
              />
              <button
                type="button"
                disabled={verifyBusy || !verifyAudience.trim()}
                onClick={() => void handleVerifyToken()}
                className="pr-pill shrink-0 rounded-lg px-2.5 py-1 font-sans text-[12.5px] text-[#9ec0f5] hover:text-[#f3f6fd] disabled:opacity-45"
              >
                {verifyBusy ? "Verifying…" : "Verify Token"}
              </button>
            </div>

            {verifyResult && (
              <div
                role="status"
                className={`flex items-start gap-1.5 rounded-lg border px-2.5 py-1.5 text-[12.5px] ${
                  verifyResult.valid
                    ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#5bdba2]"
                    : "border-[#f27c7c]/30 bg-[#f27c7c]/10 text-[#f27c7c]"
                }`}
              >
                {verifyResult.valid ? (
                  <IconShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                ) : (
                  <IconQuarantine className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                )}
                <span className="min-w-0 break-words">
                  {verifyResult.valid
                    ? `Signature & audience verified for ${verifyResult.claims?.sub ?? issued.claims.sub}`
                    : verifyResult.error || "Verification failed"}
                </span>
              </div>
            )}
          </div>
        )}
        </div>
        )}
      </div>
    </div>
  );
}
