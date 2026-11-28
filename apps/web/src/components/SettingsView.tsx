import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ComponentType,
  type FormEvent,
  type ReactNode,
} from "react";
import { CodeBlock } from "./CodeBlock";
import { SettingsRowsSkeleton } from "./ViewSkeletons";
import {
  api,
  ApiError,
  authApi,
  currentRepoIsDefault,
  currentRepoName,
  errorText,
  getServerOrigin,
  GROUP_NAME_RE,
  repoPath,
  USERNAME_PATTERN,
  type AccessToken,
  type Directory,
  type DirectoryPrincipal,
  type HealthResponse,
  type OffboardReceipt,
  type Repo,
  type Role,
  type RotationStatus,
  type SshKey,
  type TotpEnrollment,
  type User,
  type UserRow,
} from "../api";
import { buildAgentConnect, sanitizeEnv } from "./AgentConnectModal";
import { sanitizeAgentProfile, sshCloneCommand } from "../lib/uiHelpers";
import {
  CodeField,
  ConfirmButton,
  DANGER_BTN,
  ErrorNote,
  Field,
  INPUT_CLASS,
  PRIMARY_BTN,
  SECONDARY_BTN,
  SELECT_CLASS,
  Time,
  useAction,
} from "./forms";
import { BrandIcon } from "./BrandIcons";
import { GithubCompanionSettingsSection } from "./GithubCompanionPanel";
import { formatTime } from "../lib/format";
import { desktopNotificationsOn, setDesktopNotifications } from "../lib/notify";
import {
  IconCage,
  IconCheck,
  IconClock,
  IconCode,
  IconCopy,
  IconDownload,
  IconEdit,
  IconGear,
  IconLock,
  IconPanel,
  IconPlus,
  IconPolicy,
  IconQuarantine,
  IconRefresh,
  IconShieldCheck,
  IconTerminal,
  IconTrash,
  IconUser,
  IconVault,
  type IconProps,
} from "./Icons";

function GithubNavIcon({ className }: IconProps) {
  return <BrandIcon name="github" className={className} />;
}

export type SettingsSectionId =
  | "profile"
  | "security"
  | "sessions"
  | "tokens"
  | "ssh-keys"
  | "users"
  | "offboarding"
  | "directory"
  | "repositories"
  | "workspace"
  | "mcp"
  | "github"
  | "activity"
  | "about";

interface NavItemDef {
  id: SettingsSectionId;
  label: string;
  shortLabel: string;
  subtitle: string;
  icon: ComponentType<IconProps>;
  ownerOnly?: boolean;
  requiresRepo?: boolean;
}

interface NavGroupDef {
  title: string;
  ownerOnly?: boolean;
  items: NavItemDef[];
}

const SETTINGS_NAV_GROUPS: NavGroupDef[] = [
  {
    title: "Account",
    items: [
      {
        id: "profile",
        label: "Profile & Preferences",
        shortLabel: "Profile",
        subtitle: "Name, identity, and preferences",
        icon: IconUser,
      },
      {
        id: "security",
        label: "Password & 2FA",
        shortLabel: "Password & 2FA",
        subtitle: "Password and two-factor auth",
        icon: IconShieldCheck,
      },
      {
        id: "sessions",
        label: "Active Sessions",
        shortLabel: "Sessions",
        subtitle: "Signed-in devices",
        icon: IconPanel,
      },
    ],
  },
  {
    title: "Access & Credentials",
    items: [
      {
        id: "tokens",
        label: "Access Tokens",
        shortLabel: "Tokens",
        subtitle: "Personal API & Git tokens",
        icon: IconTerminal,
      },
      {
        id: "ssh-keys",
        label: "SSH Keys",
        shortLabel: "SSH Keys",
        subtitle: "Public keys for Git over SSH",
        icon: IconVault,
      },
    ],
  },
  {
    title: "Administration",
    ownerOnly: true,
    items: [
      {
        id: "users",
        label: "Users & Roles",
        shortLabel: "Users",
        subtitle: "Accounts and roles",
        icon: IconUser,
        ownerOnly: true,
      },
      {
        id: "offboarding",
        label: "Offboarding & Kill-Switch",
        shortLabel: "Offboarding",
        subtitle: "Revoke a user immediately",
        icon: IconQuarantine,
        ownerOnly: true,
      },
      {
        id: "directory",
        label: "Directory & Groups",
        shortLabel: "Directory",
        subtitle: "Groups and principal mapping",
        icon: IconPolicy,
        ownerOnly: true,
      },
      {
        id: "repositories",
        label: "Repositories",
        shortLabel: "Repos",
        subtitle: "Manage hosted repositories",
        icon: IconCode,
        ownerOnly: true,
      },
      {
        id: "workspace",
        label: "Audit & Backup",
        shortLabel: "Backup",
        subtitle: "Retention and server backups",
        icon: IconDownload,
        ownerOnly: true,
      },
    ],
  },
  {
    title: "Integrations",
    items: [
      {
        id: "mcp",
        label: "MCP & AI Agents",
        shortLabel: "MCP & Agents",
        subtitle: "Connect any AI coding agent",
        icon: IconCage,
        requiresRepo: true,
      },
      {
        id: "github",
        label: "GitHub Sync",
        shortLabel: "GitHub",
        subtitle: "Sync and publish PRs",
        icon: GithubNavIcon,
        ownerOnly: true,
        requiresRepo: true,
      },
    ],
  },
  {
    title: "Diagnostics",
    items: [
      {
        id: "activity",
        label: "Security Activity",
        shortLabel: "Activity",
        subtitle: "Account security log",
        icon: IconClock,
      },
      {
        id: "about",
        label: "Server & Host",
        shortLabel: "Server",
        subtitle: "Server runtime and host capabilities",
        icon: IconGear,
      },
    ],
  },
];

const ALL_SECTION_IDS = new Set<string>(
  SETTINGS_NAV_GROUPS.flatMap((g) => g.items.map((i) => i.id)),
);

const OWNER_ONLY_SECTIONS = new Set<string>(
  SETTINGS_NAV_GROUPS.flatMap((g) =>
    g.items.filter((i) => g.ownerOnly || i.ownerOnly).map((i) => i.id),
  ),
);

function resolveSection(
  requested: string | undefined,
  owner: boolean,
): SettingsSectionId {
  if (!requested || !ALL_SECTION_IDS.has(requested)) return "profile";
  if (!owner && OWNER_ONLY_SECTIONS.has(requested)) return "profile";
  return requested as SettingsSectionId;
}

interface Props {
  user: User;
  health: HealthResponse | null;
  /** True when loading /health failed, so About shows an error instead of an endless skeleton. */
  healthError?: boolean;
  onRetryHealth?: () => void;
  repos: Repo[];
  onReposReload: () => Promise<void>;
  onAddRepo?: () => void;
  onUserChange: (user: User) => void;
  onDirectoryChange: (directory: Directory) => void;
  requestedSection?: string;
  onSelectSection?: (section: string) => void;
}

// Stale-while-revalidate cache for this Settings visit: revisiting a section paints instantly, then
// refetches. Cleared when SettingsView unmounts so one account's data never reaches the next sign-in.
const loadCache = new Map<unknown, unknown>();

function useLoad<T>(fetcher: () => Promise<T>) {
  const [data, setDataState] = useState<T | null>(
    () => (loadCache.get(fetcher) as T | undefined) ?? null,
  );
  const [error, setError] = useState<string | null>(null);
  const setData = useCallback(
    (d: T | null) => {
      if (d === null) loadCache.delete(fetcher);
      else loadCache.set(fetcher, d);
      setDataState(d);
    },
    [fetcher],
  );
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);
  const reload = useCallback(() => {
    fetcher()
      .then((d) => {
        if (!alive.current) return;
        setData(d);
        setError(null);
      })
      .catch((err: unknown) => {
        if (alive.current) setError(errorText(err));
      });
  }, [fetcher, setData]);
  useEffect(reload, [reload]);
  return { data, error, reload, setData };
}

/** True while a settings page holds a single card: its title already shows in the page header. */
const SoloCardContext = createContext(false);
const SOLO_CARD_SECTIONS = new Set<string>([
  "sessions",
  "tokens",
  "ssh-keys",
  "users",
  "offboarding",
  "directory",
  "repositories",
  "mcp",
  "github",
  "activity",
  "about",
]);

function formatUserAgent(ua: string | null | undefined): string {
  const raw = ua?.trim();
  if (!raw) return "Unknown client";
  const lower = raw.toLowerCase();
  if (lower.includes("premier")) return "Premier CLI";
  if (lower.startsWith("git/")) return "Git CLI";
  if (
    /^(curl|wget|httpie|python-|go-http-client|node|undici|axios|reqwest|okhttp|insomnia|postman)/i.test(
      raw,
    )
  ) {
    return "CLI / API";
  }

  let browser = "";
  if (/Edg(?:A|iOS)?\//i.test(raw)) browser = "Edge";
  else if (/OPR\/|Opera/i.test(raw)) browser = "Opera";
  else if (/Vivaldi\//i.test(raw)) browser = "Vivaldi";
  else if (/Firefox\/|FxiOS\//i.test(raw)) browser = "Firefox";
  else if (/Chrome\/|CriOS\//i.test(raw)) browser = "Chrome";
  else if (/Chromium\//i.test(raw)) browser = "Chromium";
  else if (/Safari\//i.test(raw)) browser = "Safari";

  let os = "";
  if (/iPhone|iPad|iPod/i.test(raw)) os = "iOS";
  else if (/Android/i.test(raw)) os = "Android";
  else if (/Windows/i.test(raw)) os = "Windows";
  else if (/Mac OS X|Macintosh/i.test(raw)) os = "macOS";
  else if (/CrOS/i.test(raw)) os = "ChromeOS";
  else if (/Linux/i.test(raw)) os = "Linux";

  if (browser && os) return `${browser} · ${os}`;
  if (browser) return browser;
  if (os) return os;
  if (!raw.startsWith("Mozilla/")) return "CLI / API";
  return raw;
}
const NO_SPIN =
  "[appearance:textfield] [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none";

function Section({
  title,
  description,
  icon: Icon,
  aside,
  children,
}: {
  title: string;
  description?: ReactNode;
  icon: ComponentType<IconProps>;
  aside?: ReactNode;
  children: ReactNode;
}) {
  const id = useId();
  const solo = useContext(SoloCardContext);
  return (
    <section aria-labelledby={id} className="pr-surface overflow-hidden rounded-2xl [backdrop-filter:none]!">
      {solo && !aside ? (
        <h2 id={id} className="sr-only">
          {title}
        </h2>
      ) : (
        <div className="flex min-h-[44px] flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-4 py-2.5">
          <h2 id={id} className="inline-flex items-center gap-2 text-[15px] font-semibold text-[#f5f7fd]">
            <Icon className="h-4 w-4 text-[#9ec0f5]" />
            <span>{title}</span>
          </h2>
          {aside}
        </div>
      )}
      <div className="space-y-3 p-4">
        {description && <div className="text-[13.5px] leading-relaxed text-[#b6c3db]">{description}</div>}
        {children}
      </div>
    </section>
  );
}

function Notice({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="status" className="flex items-center gap-1.5 text-[13.5px] text-[#5bdba2]">
      <IconCheck className="h-4 w-4" />
      <span>{message}</span>
    </div>
  );
}

/** Loading / error / empty placeholder shared by the list sections. */
function ListState({
  data,
  error,
  empty,
}: {
  data: unknown[] | null;
  error: string | null;
  empty: string;
}) {
  if (error) return <ErrorNote message={error} />;
  if (!data) return <SettingsRowsSkeleton rows={3} />;
  if (data.length === 0) return <p className="font-mono text-[13.5px] text-[#a6b5cf]">{empty}</p>;
  return null;
}

function Badge({
  tone,
  children,
}: {
  tone: "mint" | "info" | "coral" | "muted";
  children: ReactNode;
}) {
  const cls =
    tone === "mint"
      ? "border-[#5bdba2]/30 bg-[#5bdba2]/10 text-[#5bdba2]"
      : tone === "info"
        ? "border-[#9ec0f5]/30 bg-[#7f95f8]/12 text-[#a8c5ff]"
        : tone === "coral"
          ? "border-[#f27c7c]/30 bg-[#f27c7c]/12 text-[#f27c7c]"
          : "border-white/[0.12] bg-white/[0.045] text-[#b2c0d8]";
  return (
    <span className={`rounded-full border px-2 py-0.5 font-mono text-[12.5px] leading-4 ${cls}`}>
      {children}
    </span>
  );
}

function ProfileSection({ user, onUserChange }: Pick<Props, "user" | "onUserChange">) {
  const [displayName, setDisplayName] = useState(user.display_name);
  const [saved, setSaved] = useState(false);
  const [notify, setNotify] = useState(desktopNotificationsOn);
  const action = useAction();
  const notifyAction = useAction();
  const notifyId = useId();
  const trimmed = displayName.trim();

  useEffect(() => {
    setDisplayName(user.display_name);
  }, [user.display_name]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setSaved(false);
    void action
      .run(async () => onUserChange(await authApi.updateProfile(trimmed)))
      .then(setSaved);
  };

  return (
    <div className="space-y-4">
      <Section title="Profile" icon={IconUser}>
        <form onSubmit={submit} className="space-y-3.5">
          <div className="grid gap-3.5 sm:grid-cols-2">
            <Field
              label="Username"
              value={user.username}
              readOnly
              disabled
              hint={`Created ${formatTime(user.created_at)}`}
              className="font-mono"
            />
            <Field
              label="Display name"
              name="display_name"
              autoComplete="name"
              required
              maxLength={64}
              value={displayName}
              onChange={(e) => {
                setDisplayName(e.target.value);
                setSaved(false);
              }}
            />
          </div>
          <ErrorNote message={action.error} />
          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              disabled={action.pending || !trimmed || trimmed === user.display_name}
              className={PRIMARY_BTN}
            >
              {action.pending ? "Saving…" : "Save profile"}
            </button>
            <Notice message={saved ? "Profile saved" : null} />
          </div>
        </form>
      </Section>

      <Section title="Notifications" icon={IconGear}>
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <label
              htmlFor={notifyId}
              className="block cursor-pointer text-[14px] font-medium text-[#dce4f5]"
            >
              Desktop notifications (this browser)
            </label>
            <p className="mt-0.5 text-[13px] text-[#98a8c4]">
              Alert when an agent needs approval.
            </p>
          </div>
          <button
            id={notifyId}
            type="button"
            role="switch"
            aria-checked={notify}
            disabled={notifyAction.pending}
            onClick={() => {
              const next = !notify;
              void notifyAction.run(async () => setNotify(await setDesktopNotifications(next)));
            }}
            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#9ec0f5]/60 disabled:cursor-not-allowed disabled:opacity-40 ${
              notify
                ? "border-[#5bdba2]/50 bg-[#5bdba2]/25"
                : "border-white/[0.14] bg-white/[0.08]"
            }`}
          >
            <span
              aria-hidden="true"
              className={`pointer-events-none inline-block h-4 w-4 rounded-full transition-transform ${
                notify ? "translate-x-[22px] bg-[#5bdba2]" : "translate-x-1 bg-[#a6b5cf]"
              }`}
            />
          </button>
        </div>
        <ErrorNote message={notifyAction.error} />
      </Section>
    </div>
  );
}

function PasswordSection({ user }: Pick<Props, "user">) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState(false);
  const action = useAction();
  const canSubmit = current.length > 0 && next.length >= 10 && confirm.length >= 10;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setDone(false);
    if (next !== confirm) {
      action.setError("The two new passwords don't match.");
      return;
    }
    void action
      .run(async () => {
        await authApi.changePassword(current, next);
        setCurrent("");
        setNext("");
        setConfirm("");
      })
      .then(setDone);
  };

  return (
    <Section title="Password" icon={IconLock}>
      <form onSubmit={submit} className="space-y-3.5">
        {/* Lets password managers attach the new password to the right account. */}
        <input type="text" name="username" autoComplete="username" value={user.username} readOnly hidden />
        <Field
          label="Current password"
          name="current-password"
          type="password"
          maxLength={1024}
          autoComplete="current-password"
          required
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field
            label="New password"
            name="new-password"
            type="password"
            maxLength={1024}
            autoComplete="new-password"
            required
            minLength={10}
            hint="Min 10 characters"
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
          <Field
            label="Confirm new password"
            name="confirm-password"
            type="password"
            maxLength={1024}
            autoComplete="new-password"
            required
            minLength={10}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <ErrorNote message={action.error} />
        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" disabled={action.pending || !canSubmit} className={PRIMARY_BTN}>
            {action.pending ? "Changing…" : "Change password"}
          </button>
          <Notice message={done ? "Password updated. Other sessions signed out." : null} />
        </div>
      </form>
    </Section>
  );
}

/** One-time display of fresh recovery codes; stays until the user says they saved them. */
function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const copyAll = () => {
    setCopyError(false);
    if (!navigator.clipboard?.writeText) {
      setCopyError(true);
      return;
    }
    navigator.clipboard
      .writeText(codes.join("\n"))
      .then(() => {
        setCopied(true);
        setCopyError(false);
      })
      .catch(() => {
        setCopied(false);
        setCopyError(true);
      });
  };
  return (
    <div role="status" className="space-y-3 rounded-xl border border-[#9ec0f5]/25 bg-[#7f95f8]/[0.08] p-3.5">
      <div className="text-[14px] font-medium text-[#a8c5ff]">
        Save these recovery codes — each works once and won&apos;t be shown again.
      </div>
      <ul className="pr-well grid select-all grid-cols-2 gap-x-4 gap-y-1.5 rounded-xl px-3 py-2.5 font-mono text-[14px] text-[#f3f6fd]">
        {codes.map((c) => (
          <li key={c} className="break-all">
            {c}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={copyAll} className={SECONDARY_BTN}>
          {copied ? (
            <IconCheck className="h-4 w-4 text-[#5bdba2]" />
          ) : (
            <IconCopy className="h-4 w-4 text-[#a6b5cf]" />
          )}
          <span>{copied ? "Copied" : "Copy all"}</span>
        </button>
        <button type="button" onClick={onDone} className={PRIMARY_BTN}>
          I&apos;ve saved them
        </button>
      </div>
      {copyError && (
        <p role="alert" className="text-[13px] text-[#f2a67c]">
          Clipboard copy failed — select and copy the recovery codes manually above.
        </p>
      )}
    </div>
  );
}

function TotpSection({ user, onUserChange }: Pick<Props, "user" | "onUserChange">) {
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const action = useAction();

  const begin = () => void action.run(async () => setEnrollment(await authApi.totpBegin()));

  const enable = (e: FormEvent) => {
    e.preventDefault();
    void action.run(async () => {
      const { recovery_codes } = await authApi.totpEnable(code);
      setEnrollment(null);
      setCode("");
      setRecoveryCodes(recovery_codes);
      onUserChange({ ...user, totp_enabled: true, recovery_codes_left: recovery_codes.length });
    });
  };

  const regenerate = () =>
    void action.run(async () => {
      const { recovery_codes } = await authApi.newRecoveryCodes(password);
      setPassword("");
      setRecoveryCodes(recovery_codes);
      onUserChange({ ...user, recovery_codes_left: recovery_codes.length });
    });

  const disable = () => {
    void action.run(async () => {
      await authApi.totpDisable(password);
      setPassword("");
      setRecoveryCodes(null);
      onUserChange({ ...user, totp_enabled: false, recovery_codes_left: 0 });
    });
  };

  return (
    <Section
      title="Two-factor authentication"
      icon={IconShieldCheck}
      aside={<Badge tone={user.totp_enabled ? "mint" : "muted"}>{user.totp_enabled ? "on" : "off"}</Badge>}
    >
      {recoveryCodes && (
        <RecoveryCodes codes={recoveryCodes} onDone={() => setRecoveryCodes(null)} />
      )}
      {user.totp_enabled ? (
        <form onSubmit={(e) => e.preventDefault()} className="space-y-3.5">
          <p className="text-[13.5px] text-[#b6c3db]">
            {user.recovery_codes_left ?? 0} recovery{" "}
            {user.recovery_codes_left === 1 ? "code" : "codes"} left. Generating new codes
            invalidates all previous recovery codes.
          </p>
          <input type="text" name="username" autoComplete="username" value={user.username} readOnly hidden />
          <Field
            label="Current password"
            name="current-password"
            type="password"
            maxLength={1024}
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <ErrorNote message={action.error} />
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={regenerate}
              disabled={action.pending || !password}
              className={SECONDARY_BTN}
            >
              Generate new codes
            </button>
            <ConfirmButton
              disabled={action.pending || !password}
              confirmLabel="Turn off 2FA"
              question="Disable two-factor authentication?"
              onConfirm={disable}
              className={DANGER_BTN}
            >
              Turn off two-factor
            </ConfirmButton>
          </div>
        </form>
      ) : enrollment ? (
        <form onSubmit={enable} className="space-y-3.5">
          <div className="flex flex-col gap-4 sm:flex-row">
            {/* <img> + data URL keeps server SVG out of the DOM; white plate so it scans on the dark theme. */}
            <img
              src={`data:image/svg+xml;utf8,${encodeURIComponent(enrollment.qr_svg)}`}
              alt="QR code to scan with your authenticator app"
              className="h-44 w-44 shrink-0 self-center rounded-xl bg-white p-2 sm:self-start"
            />
            <div className="min-w-0 flex-1 space-y-3">
              <p className="text-[13.5px] text-[#b6c3db]">
                Scan with your authenticator app, then enter the 6-digit code.
              </p>
              <div>
                <div className="text-[13px] text-[#a6b5cf]">Manual key</div>
                <code className="pr-well mt-1 block select-all break-all rounded-xl px-3 py-2 text-[13.5px] text-[#e6ecf8]">
                  {enrollment.secret}
                </code>
              </div>
              <CodeField
                name="totp_code"
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              />
            </div>
          </div>
          <ErrorNote message={action.error} />
          <div className="flex flex-wrap gap-2">
            <button type="submit" disabled={action.pending || code.length !== 6} className={PRIMARY_BTN}>
              {action.pending ? "Verifying…" : "Turn on two-factor"}
            </button>
            <button
              type="button"
              disabled={action.pending}
              onClick={() => {
                setEnrollment(null);
                setCode("");
                action.setError(null);
              }}
              className={SECONDARY_BTN}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <>
          <p className="text-[13.5px] text-[#b6c3db]">
            Use an authenticator app to generate 6-digit verification codes.
          </p>
          <ErrorNote message={action.error} />
          <button type="button" onClick={begin} disabled={action.pending} className={PRIMARY_BTN}>
            {action.pending ? "Preparing…" : "Set up two-factor"}
          </button>
        </>
      )}
    </Section>
  );
}

function SessionsSection() {
  const { data, error, reload } = useLoad(authApi.sessions);
  const action = useAction();
  const others = data?.filter((s) => !s.current).length ?? 0;

  const revoke = (fn: () => Promise<void>) => void action.run(fn).then(reload);

  return (
    <Section title="Active Sessions" icon={IconPanel}>
      <ErrorNote message={action.error} />
      <ListState data={data} error={error} empty="No sessions." />
      {data && data.length > 0 && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-[12.5px] text-[#a6b5cf]">
              {data.length} active {data.length === 1 ? "session" : "sessions"}
            </span>
            {others > 0 ? (
              <ConfirmButton
                disabled={action.pending}
                confirmLabel="Sign out all"
                question={`Sign out ${others} other ${others === 1 ? "session" : "sessions"}?`}
                onConfirm={() => revoke(authApi.revokeOtherSessions)}
                className={`${DANGER_BTN} px-3! py-1.5! text-[13px]!`}
              >
                Sign out all others
              </ConfirmButton>
            ) : (
              <span className="text-[13px] text-[#98a8c4]">Signed in on 1 device</span>
            )}
          </div>
          <ul className="space-y-2">
            {data.map((s) => (
              <li
                key={s.id}
                className="pr-well flex items-center justify-between gap-3 rounded-xl px-3.5 py-2.5"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[13.5px] text-[#e6ecf8]">{s.ip ?? "unknown address"}</span>
                    {s.current && <Badge tone="mint">this session</Badge>}
                  </div>
                  <div
                    className="mt-0.5 truncate text-[13px] text-[#b6c3db]"
                    title={s.user_agent ?? undefined}
                  >
                    {formatUserAgent(s.user_agent)}
                  </div>
                  <div className="mt-0.5 font-mono text-[12.5px] text-[#a6b5cf]">
                    started <Time value={s.created_at} /> · last seen <Time value={s.last_seen_at} />
                  </div>
                </div>
                {!s.current && (
                  <ConfirmButton
                    disabled={action.pending}
                    confirmLabel="Sign out"
                    question="Sign out this session?"
                    onConfirm={() => revoke(() => authApi.revokeSession(s.id))}
                    title="Sign out this session"
                    aria-label={`Sign out session from ${s.ip ?? "unknown address"}`}
                    className="pr-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[#f27c7c] disabled:opacity-40"
                  >
                    <IconTrash className="h-4 w-4" />
                  </ConfirmButton>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </Section>
  );
}

function TokensSection() {
  const { data, error, reload } = useLoad(authApi.tokens);
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("30");
  const [created, setCreated] = useState<(AccessToken & { token: string }) | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState(false);
  const createAction = useAction();
  const revokeAction = useAction();
  const expiryId = useId();

  const create = (e: FormEvent) => {
    e.preventDefault();
    if (created) return;
    const days = expiry && expiry !== "never" ? Number(expiry) : undefined;
    void createAction
      .run(async () => {
        setCreated(await authApi.createToken(name.trim(), days));
        setCopied(false);
        setCopyError(false);
        setName("");
      })
      .then(reload);
  };

  const copy = () => {
    if (!created) return;
    setCopyError(false);
    if (!navigator.clipboard?.writeText) {
      setCopyError(true);
      return;
    }
    navigator.clipboard
      .writeText(created.token)
      .then(() => {
        setCopied(true);
        setCopyError(false);
      })
      .catch(() => {
        setCopied(false);
        setCopyError(true);
      });
  };

  return (
    <Section title="Access Tokens" icon={IconTerminal}>
      {created && (
        <div
          role="status"
          className="space-y-3 rounded-xl border border-[#9ec0f5]/25 bg-[#7f95f8]/[0.08] p-3.5"
        >
          <div className="text-[13.5px] font-medium text-[#a8c5ff]">
            Copy “{created.name}” now — it won&apos;t be shown again.
          </div>
          <div className="flex items-center gap-2">
            <code className="pr-well min-w-0 flex-1 select-all break-all rounded-xl px-3 py-2 text-[13.5px] text-[#f3f6fd]">
              {created.token}
            </code>
            <button type="button" onClick={copy} autoFocus className={`${SECONDARY_BTN} shrink-0`}>
              {copied ? (
                <IconCheck className="h-4 w-4 text-[#5bdba2]" />
              ) : (
                <IconCopy className="h-4 w-4 text-[#a6b5cf]" />
              )}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>
          </div>
          {copyError && (
            <p role="alert" className="text-[13px] text-[#f2a67c]">
              Clipboard copy failed — select and copy the token manually above.
            </p>
          )}
          <button
            type="button"
            onClick={() => {
              setCreated(null);
              setCopied(false);
              setCopyError(false);
            }}
            className={PRIMARY_BTN}
          >
            I&apos;ve saved this token
          </button>
        </div>
      )}

      <form onSubmit={create} className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="min-w-0 flex-1">
          <Field
            label="Token name"
            name="token_name"
            autoComplete="off"
            required
            maxLength={64}
            placeholder="laptop git"
            disabled={Boolean(created)}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div className="space-y-1.5 sm:w-40">
          <label htmlFor={expiryId} className="block text-[13px] font-medium text-[#d2dbee]">
            Expires
          </label>
          <select
            id={expiryId}
            value={expiry}
            disabled={Boolean(created)}
            onChange={(e) => setExpiry(e.target.value)}
            className={SELECT_CLASS}
          >
            <option value="30">In 30 days</option>
            <option value="90">In 90 days</option>
            <option value="365">In 1 year</option>
            <option value="never">Never</option>
          </select>
        </div>
        <button
          type="submit"
          disabled={createAction.pending || Boolean(created) || !name.trim()}
          className={`${PRIMARY_BTN} h-10 shrink-0`}
        >
          <IconPlus className="h-4 w-4" />
          <span>{createAction.pending ? "Creating…" : "Create token"}</span>
        </button>
      </form>
      <ErrorNote message={createAction.error ?? revokeAction.error} />

      <div className="border-t border-white/[0.06] pt-3">
        <ListState data={data} error={error} empty="No access tokens yet." />
        {data && data.length > 0 && (
          <ul className="space-y-2">
            {data.map((t) => (
              <li
                key={t.id}
                className="pr-well flex items-center justify-between gap-3 rounded-xl px-3.5 py-2.5"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-[14px] font-medium text-[#e6ecf8]">{t.name}</span>
                    <span className="font-mono text-[12.5px] text-[#a6b5cf]">{t.prefix}…</span>
                  </div>
                  <div className="mt-0.5 font-mono text-[12.5px] text-[#a6b5cf]">
                    created <Time value={t.created_at} /> · last used <Time value={t.last_used_at} /> ·{" "}
                    {t.expires_at ? (
                      <>
                        expires <Time value={t.expires_at} />
                      </>
                    ) : (
                      "no expiry"
                    )}
                  </div>
                </div>
                <ConfirmButton
                  disabled={revokeAction.pending}
                  confirmLabel="Revoke"
                  onConfirm={() =>
                    void revokeAction
                      .run(async () => {
                        await authApi.revokeToken(t.id);
                        // The "copy it now" banner is for a token that no longer exists.
                        setCreated((c) => (c?.id === t.id ? null : c));
                      })
                      .then(reload)
                  }
                  title="Revoke token: clients using it stop working"
                  aria-label={`Revoke token ${t.name}`}
                  className="pr-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[#f27c7c] disabled:opacity-40"
                >
                  <IconTrash className="h-4 w-4" />
                </ConfirmButton>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}

/** Matches Rust server's `ALLOWED_SSH_KEY_TYPES` (explicitly excludes weak `ssh-dss`). */
const ALLOWED_SSH_KEY_TYPES = new Set([
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "ssh-rsa",
  "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
]);

const MAX_SSH_KEY_BYTES = 16 * 1024;

async function loadSshKeys(): Promise<SshKey[]> {
  try {
    return await authApi.sshKeys();
  } catch (err: unknown) {
    if (err instanceof ApiError && err.status === 404) return [];
    throw err;
  }
}

function validateSshPublicKey(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return "Paste an OpenSSH public key.";
  if (/PRIVATE KEY/i.test(trimmed)) {
    return "That looks like a private key. Paste your public key (.pub), starting with ssh-ed25519 or similar.";
  }
  if (/[\r\n]/.test(trimmed)) {
    return "Enter a single OpenSSH public key on one line.";
  }
  const [keyType, keyData] = trimmed.split(/\s+/);
  if (!keyType || !keyData) {
    return "Paste a valid OpenSSH public key (for example: ssh-ed25519 AAAA... comment).";
  }
  if (!ALLOWED_SSH_KEY_TYPES.has(keyType)) {
    return `Unsupported SSH key type "${keyType}". Allowed: ssh-ed25519, ecdsa-sha2-nistp256/384/521, ssh-rsa, sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com.`;
  }
  if (keyData.length > Math.floor((MAX_SSH_KEY_BYTES * 4) / 3) + 8) {
    return "SSH public key exceeds maximum size (16 KiB).";
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(keyData) || keyData.length < 16) {
    return "Invalid base64 key data in OpenSSH public key.";
  }
  const decodedBytes = Math.floor((keyData.replace(/=+$/, "").length * 3) / 4);
  if (decodedBytes > MAX_SSH_KEY_BYTES) {
    return "SSH public key exceeds maximum size (16 KiB).";
  }
  return null;
}

function SshKeysSection({
  health,
  hasRepos,
}: {
  health: HealthResponse | null;
  hasRepos: boolean;
}) {
  const { data, error, reload } = useLoad(loadSshKeys);
  const [name, setName] = useState("");
  const [publicKey, setPublicKey] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const addAction = useAction();
  const revokeAction = useAction();
  const keyId = useId();
  const sshEnabled = health?.ssh_enabled;
  const sshPort = health?.ssh_port ?? 2222;
  const [sshPublicUrl, setSshPublicUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!hasRepos) return;
    api
      .settings()
      .then((st) => setSshPublicUrl(st?.ssh_public_url ?? null))
      .catch(() => {});
  }, [hasRepos]);
  const cloneCmd = hasRepos
    ? sshCloneCommand(sshPort, currentRepoName(), getServerOrigin(), sshPublicUrl)
    : "";

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const copyClone = () => {
    navigator.clipboard
      ?.writeText(cloneCmd)
      .then(() => setCopied(true))
      .catch(() => {});
  };

  const add = (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    const trimmedName = name.trim();
    const trimmedKey = publicKey.trim();
    if (!trimmedName) {
      addAction.setError("Enter a name for this key.");
      return;
    }
    const keyError = validateSshPublicKey(trimmedKey);
    if (keyError) {
      addAction.setError(keyError);
      return;
    }
    void addAction
      .run(async () => {
        const added = await authApi.addSshKey(trimmedName, trimmedKey);
        setName("");
        setPublicKey("");
        setNotice(`Added “${added.name}”`);
      })
      .then((ok) => {
        if (ok) reload();
      });
  };

  return (
    <Section title="SSH Keys" icon={IconVault}>
      {sshEnabled === false && (
        <p className="text-[13px] text-[#98a8c4]">
          SSH listener is off — keys added now activate automatically once SSH is enabled.
        </p>
      )}
      {sshEnabled !== false && hasRepos && (
        <div className="pr-well space-y-1.5 rounded-xl px-3.5 py-2.5">
          <div className="text-[12.5px] font-medium text-[#a6b5cf]">
            Clone over SSH {health?.ssh_port ? `(port ${health.ssh_port})` : ""}
          </div>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 select-all break-all font-mono text-[13.5px] text-[#e6ecf8]">
              {cloneCmd}
            </code>
            <button
              type="button"
              onClick={copyClone}
              className={`${SECONDARY_BTN} shrink-0 px-2.5! py-1.5! text-[13px]!`}
            >
              {copied ? (
                <IconCheck className="h-3.5 w-3.5 text-[#5bdba2]" />
              ) : (
                <IconCopy className="h-3.5 w-3.5 text-[#a6b5cf]" />
              )}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>
          </div>
        </div>
      )}

      <form onSubmit={add} className="space-y-3.5">
        <Field
          label="Key name"
          name="ssh_key_name"
          autoComplete="off"
          required
          maxLength={64}
          placeholder="laptop"
          value={name}
          onChange={(e) => {
            setName(e.target.value);
            setNotice(null);
            if (addAction.error) addAction.setError(null);
          }}
        />
        <div className="space-y-1.5">
          <label htmlFor={keyId} className="block text-[13px] font-medium text-[#d2dbee]">
            Public key
          </label>
          <textarea
            id={keyId}
            name="ssh_public_key"
            rows={3}
            required
            spellCheck={false}
            autoCapitalize="none"
            placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... you@laptop"
            aria-describedby={`${keyId}-hint`}
            className={`${INPUT_CLASS} resize-y font-mono text-[13.5px]`}
            value={publicKey}
            onChange={(e) => {
              setPublicKey(e.target.value);
              setNotice(null);
              if (addAction.error) addAction.setError(null);
            }}
          />
          <p id={`${keyId}-hint`} className="text-[13px] text-[#98a8c4]">
            Paste your public key (e.g.{" "}
            <code className="font-mono text-[#b6c3db]">~/.ssh/id_ed25519.pub</code>)
          </p>
        </div>
        <ErrorNote message={addAction.error ?? revokeAction.error} />
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="submit"
            disabled={addAction.pending || !name.trim() || !publicKey.trim()}
            className={PRIMARY_BTN}
          >
            <IconPlus className="h-4 w-4" />
            <span>{addAction.pending ? "Adding…" : "Add SSH key"}</span>
          </button>
          <Notice message={notice} />
        </div>
      </form>

      <div className="border-t border-white/[0.06] pt-3">
        <ListState data={data} error={error} empty="No SSH keys yet." />
        {data && data.length > 0 && (
          <ul className="space-y-2">
            {data.map((k) => (
              <li
                key={k.id}
                className="pr-well flex items-center justify-between gap-3 rounded-xl px-3.5 py-2.5"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-[14px] font-medium text-[#e6ecf8]">{k.name}</span>
                    <Badge tone="muted">{k.key_type}</Badge>
                  </div>
                  <div className="mt-0.5 break-all font-mono text-[12.5px] text-[#b6c3db]">
                    {k.fingerprint}
                  </div>
                  <div className="mt-0.5 font-mono text-[12.5px] text-[#a6b5cf]">
                    added <Time value={k.created_at} />
                  </div>
                </div>
                <ConfirmButton
                  disabled={revokeAction.pending}
                  confirmLabel="Revoke"
                  onConfirm={() => {
                    setNotice(null);
                    void revokeAction
                      .run(async () => {
                        await authApi.revokeSshKey(k.id);
                        setNotice(`Revoked “${k.name}”`);
                      })
                      .then((ok) => {
                        if (ok) reload();
                      });
                  }}
                  title="Revoke SSH key: clients using it can no longer authenticate"
                  aria-label={`Revoke SSH key ${k.name}`}
                  className="pr-pill inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[#f27c7c] disabled:opacity-40"
                >
                  <IconTrash className="h-4 w-4" />
                </ConfirmButton>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Section>
  );
}

const ROTATION_TONE: Record<RotationStatus, "mint" | "info" | "coral"> = {
  committed: "mint",
  rolled_back: "info",
  manual_required: "info",
  failed: "coral",
};

type OffboardReceiptWithErrors = OffboardReceipt & { persist_errors?: string[] };

function offboardReceiptIssues(receipt: OffboardReceiptWithErrors) {
  const persistErrors = Array.isArray(receipt.persist_errors)
    ? receipt.persist_errors.filter(Boolean)
    : [];
  const failedRotations = receipt.rotations.filter((r) => r.status === "failed").length;
  const attentionRotations = receipt.rotations.filter(
    (r) => r.status === "manual_required" || r.status === "rolled_back",
  ).length;
  const oidcNotRevoked = !receipt.oidc_revoked;
  const hasPartialFailure =
    persistErrors.length > 0 || failedRotations > 0 || attentionRotations > 0 || oidcNotRevoked;
  const hasHardFailure = persistErrors.length > 0 || failedRotations > 0;
  return {
    persistErrors,
    failedRotations,
    attentionRotations,
    oidcNotRevoked,
    hasPartialFailure,
    hasHardFailure,
  };
}

function OffboardReceiptCard({
  receipt,
  highlighted = false,
}: {
  receipt: OffboardReceiptWithErrors;
  highlighted?: boolean;
}) {
  const issues = offboardReceiptIssues(receipt);
  const surfaceClass = highlighted
    ? issues.hasHardFailure
      ? "border border-[#f27c7c]/35 bg-[#f27c7c]/[0.06]"
      : issues.hasPartialFailure
        ? "border border-[#f2a67c]/35 bg-[#f2a67c]/[0.06]"
        : "border border-[#5bdba2]/30 bg-[#5bdba2]/[0.05]"
    : issues.hasHardFailure
      ? "pr-well border border-[#f27c7c]/25"
      : "pr-well";

  return (
    <div className={`space-y-2.5 rounded-xl p-3.5 ${surfaceClass}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[14px] font-semibold text-[#f3f6fd]">
            {receipt.principal}
          </span>
          {receipt.account_deleted ? (
            <Badge tone="coral">account deleted</Badge>
          ) : receipt.account_disabled ? (
            <Badge tone="muted">account disabled</Badge>
          ) : (
            <Badge tone="muted">policy principal</Badge>
          )}
          <Badge tone={receipt.oidc_revoked ? "mint" : "coral"}>
            OIDC {receipt.oidc_revoked ? "revoked" : "not revoked"}
          </Badge>
          {issues.hasPartialFailure && (
            <Badge tone={issues.hasHardFailure ? "coral" : "info"}>
              {issues.hasHardFailure ? "partial failure" : "attention required"}
            </Badge>
          )}
        </div>
        <span className="font-mono text-[12.5px] text-[#a6b5cf]">
          <Time value={receipt.timestamp} />
        </span>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2 text-[13px] text-[#b6c3db]">
        <span className="break-words">{receipt.reason}</span>
        <span className="font-mono text-[12.5px] text-[#a6b5cf]">
          by {receipt.actor} · {receipt.id}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-1.5 font-mono text-[12.5px] sm:grid-cols-5">
        <div className="rounded-lg bg-black/30 px-2.5 py-1.5">
          <div className="text-[#a6b5cf]">Sessions</div>
          <div className="text-[#f3f6fd]">{receipt.sessions_revoked} revoked</div>
        </div>
        <div className="rounded-lg bg-black/30 px-2.5 py-1.5">
          <div className="text-[#a6b5cf]">Tokens</div>
          <div className="text-[#f3f6fd]">{receipt.tokens_revoked} revoked</div>
        </div>
        <div className="rounded-lg bg-black/30 px-2.5 py-1.5">
          <div className="text-[#a6b5cf]">SSH keys</div>
          <div className="text-[#f3f6fd]">{receipt.ssh_keys_revoked} revoked</div>
        </div>
        <div className="rounded-lg bg-black/30 px-2.5 py-1.5">
          <div className="text-[#a6b5cf]">JIT approvals</div>
          <div className="text-[#f3f6fd]">{receipt.approvals_revoked} revoked</div>
        </div>
        <div className="rounded-lg bg-black/30 px-2.5 py-1.5">
          <div className="text-[#a6b5cf]">Agent cages</div>
          <div className="text-[#f3f6fd]">{receipt.agent_sessions_terminated} stopped</div>
        </div>
      </div>

      {issues.persistErrors.length > 0 && (
        <div
          role="alert"
          className="space-y-1 rounded-lg border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-2 text-[12.5px] text-[#f27c7c]"
        >
          <div className="font-mono font-semibold uppercase tracking-wider">
            Persistence errors ({issues.persistErrors.length})
          </div>
          <ul className="list-disc space-y-0.5 pl-4 font-mono">
            {issues.persistErrors.map((err, i) => (
              <li key={`${err}-${i}`} className="break-words">
                {err}
              </li>
            ))}
          </ul>
        </div>
      )}

      {receipt.rotations.length > 0 && (
        <div className="space-y-1.5 border-t border-white/[0.06] pt-2">
          <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
            Secret Rotations ({receipt.rotations.length})
          </div>
          <ul className="space-y-1">
            {receipt.rotations.map((rot) => (
              <li
                key={rot.id}
                className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-black/30 px-2.5 py-1.5 font-mono text-[12.5px]"
              >
                <span className="min-w-0 truncate text-[#dce4f5]">
                  {rot.var_name}{" "}
                  <span className="text-[#a6b5cf]">
                    ({rot.env} · {rot.provider} · {rot.phase_reached})
                  </span>
                </span>
                <span className="flex shrink-0 items-center gap-1.5">
                  {rot.http_status != null && (
                    <span className="text-[#a6b5cf]">HTTP {rot.http_status}</span>
                  )}
                  {rot.rollback_sent && <Badge tone="info">rollback</Badge>}
                  <Badge tone={ROTATION_TONE[rot.status]}>
                    {rot.status.replace(/_/g, " ")}
                  </Badge>
                </span>
                {rot.error && (
                  <div className="w-full break-words text-[12.5px] text-[#f27c7c]">{rot.error}</div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function OffboardingSection({
  user,
  hasRepos,
  syncEpoch,
  onOffboarded,
}: {
  user: User;
  hasRepos: boolean;
  syncEpoch: number;
  onOffboarded: () => void;
}) {
  const { data: dirData, reload: reloadDir } = useLoad(api.directory);
  const { data: usersData, reload: reloadUsers } = useLoad(api.users);
  const {
    data: receipts,
    error: receiptsError,
    reload: reloadReceipts,
  } = useLoad(api.offboardReceipts);

  useEffect(() => {
    if (syncEpoch === 0) return;
    reloadDir();
    reloadUsers();
  }, [syncEpoch, reloadDir, reloadUsers]);

  const [selectedPrincipal, setSelectedPrincipal] = useState("");
  const [customPrincipal, setCustomPrincipal] = useState("");
  const [reason, setReason] = useState("Offboarding revocation");
  const [env, setEnv] = useState("prod");
  const [rotateSecrets, setRotateSecrets] = useState(true);
  const [deleteAccount, setDeleteAccount] = useState(false);
  const [latestReceipt, setLatestReceipt] = useState<OffboardReceiptWithErrors | null>(null);
  const action = useAction();

  const selectId = useId();
  const envId = useId();

  // Only supported @user accounts can be offboarded; exclude bot:*, service:*, spiffe://*, and self.
  const selfSet = new Set([user.principal.toLowerCase(), `@${user.username}`.toLowerCase()]);
  const candidateMap = new Map<string, string>();
  for (const p of dirData?.principals ?? []) {
    if (!p.principal.startsWith("@")) continue;
    if (selfSet.has(p.principal.toLowerCase())) continue;
    candidateMap.set(p.principal, `${p.principal} (${p.display_name})`);
  }
  for (const u of usersData ?? []) {
    if (!u.principal.startsWith("@")) continue;
    if (selfSet.has(u.principal.toLowerCase()) || u.username === user.username) continue;
    if (!candidateMap.has(u.principal)) {
      candidateMap.set(u.principal, `${u.principal} (${u.display_name})`);
    }
  }
  const candidates = [...candidateMap.entries()].sort((a, b) => a[0].localeCompare(b[0]));

  const hasCandidates = candidates.length > 0;
  const showManualInput = !hasCandidates || selectedPrincipal === "__custom__";
  const rawTarget = showManualInput ? customPrincipal.trim() : selectedPrincipal.trim();
  const normalizedTarget = rawTarget ? rawTarget.replace(/^@?/, "@") : "";
  const isSelfTarget = normalizedTarget !== "" && selfSet.has(normalizedTarget.toLowerCase());
  const effectiveRotate = hasRepos && rotateSecrets;
  const confirmQuestion = `Offboard ${normalizedTarget || "principal"} (revoke sessions/tokens/keys${
    deleteAccount ? ", delete account" : ""
  }${effectiveRotate ? ", rotate secrets" : ""})?`;

  const executeOffboard = () => {
    if (!normalizedTarget) {
      action.setError("Select or enter a @user account to offboard.");
      return;
    }
    if (isSelfTarget) {
      action.setError("You cannot offboard your own signed-in owner account.");
      return;
    }
    void action.run(async () => {
      const receipt = (await api.offboardPrincipal({
        principal: normalizedTarget,
        reason: reason.trim() || undefined,
        env,
        rotate_secrets: effectiveRotate,
        delete_account: deleteAccount,
      })) as OffboardReceiptWithErrors;
      setLatestReceipt(receipt);
      setSelectedPrincipal("");
      setCustomPrincipal("");
      reloadReceipts();
      reloadDir();
      reloadUsers();
      onOffboarded();
    });
  };

  const latestIssues = latestReceipt ? offboardReceiptIssues(latestReceipt) : null;

  return (
    <Section
      title="Emergency Offboarding Kill-Switch"
      icon={IconQuarantine}
      description={
        hasRepos
          ? "Revoke sessions, tokens, SSH keys, active cages, and rotate secrets immediately."
          : "Revoke sessions, tokens, and SSH keys immediately."
      }
    >
      <div className="space-y-3.5 rounded-xl border border-[#f27c7c]/20 bg-[#f27c7c]/[0.04] p-4">
        <div className={hasRepos ? "grid gap-3.5 sm:grid-cols-2" : "space-y-3.5"}>
          {hasCandidates ? (
            <div className="space-y-1.5">
              <label htmlFor={selectId} className="block text-[13px] font-medium text-[#d2dbee]">
                Target user
              </label>
              <select
                id={selectId}
                value={selectedPrincipal}
                onChange={(e) => {
                  setSelectedPrincipal(e.target.value);
                  action.setError(null);
                }}
                className={`${SELECT_CLASS} font-mono`}
              >
                <option value="">Select a user…</option>
                {candidates.map(([principal, label]) => (
                  <option key={principal} value={principal}>
                    {label}
                  </option>
                ))}
                <option value="__custom__">Enter @username manually…</option>
              </select>
            </div>
          ) : (
            <Field
              label="Target @username"
              name="offboard_custom_principal"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="@alice"
              className="font-mono"
              value={customPrincipal}
              onChange={(e) => {
                setCustomPrincipal(e.target.value);
                action.setError(null);
              }}
            />
          )}

          {hasRepos && (
            <div className="space-y-1.5">
              <label htmlFor={envId} className="block text-[13px] font-medium text-[#d2dbee]">
                Rotation environment
              </label>
              <select
                id={envId}
                value={env}
                disabled={!rotateSecrets}
                onChange={(e) => setEnv(e.target.value)}
                className={`${SELECT_CLASS} font-mono`}
              >
                <option value="prod">prod</option>
                <option value="staging">staging</option>
                <option value="preview">preview</option>
                <option value="dev">dev</option>
              </select>
            </div>
          )}
        </div>

        {hasCandidates && selectedPrincipal === "__custom__" && (
          <Field
            label="Manual @username"
            name="offboard_custom_principal"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="@alice"
            className="font-mono"
            value={customPrincipal}
            onChange={(e) => {
              setCustomPrincipal(e.target.value);
              action.setError(null);
            }}
          />
        )}

        <Field
          label="Reason"
          name="offboard_reason"
          autoComplete="off"
          placeholder="Offboarding revocation"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />

        <div className="flex flex-col gap-2 text-[14px] text-[#dce4f5]">
          {hasRepos && (
            <label className="inline-flex cursor-pointer items-center gap-2.5">
              <input
                type="checkbox"
                className="h-4 w-4 accent-[#7f95f8]"
                checked={rotateSecrets}
                onChange={(e) => setRotateSecrets(e.target.checked)}
              />
              <span>Rotate exposed secrets</span>
            </label>
          )}
          <label className="inline-flex cursor-pointer items-center gap-2.5 text-[#f9b4b4]">
            <input
              type="checkbox"
              className="h-4 w-4 accent-[#f27c7c]"
              checked={deleteAccount}
              onChange={(e) => setDeleteAccount(e.target.checked)}
            />
            <span>Delete user account</span>
          </label>
        </div>

        <ErrorNote message={action.error} />

        <div className="flex flex-wrap items-center gap-3">
          <ConfirmButton
            key={`${normalizedTarget}:${deleteAccount}:${effectiveRotate}`}
            disabled={action.pending || !normalizedTarget || isSelfTarget}
            confirmLabel={`Offboard ${normalizedTarget || "user"}`}
            question={confirmQuestion}
            onConfirm={executeOffboard}
            className={DANGER_BTN}
          >
            <IconQuarantine className="h-4 w-4" />
            <span>
              {action.pending
                ? "Executing Kill-Switch…"
                : `Offboard ${normalizedTarget || "User"}`}
            </span>
          </ConfirmButton>
        </div>
        {isSelfTarget && (
          <div
            role="alert"
            className="flex items-start gap-2 rounded-xl border border-[#9ec0f5]/25 bg-[#7f95f8]/8 px-3 py-2 text-[13px] text-[#dce4f5]"
          >
            <IconQuarantine className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[#a8c5ff]" />
            <span>You can&apos;t offboard your own account.</span>
          </div>
        )}
      </div>

      {latestReceipt && latestIssues && (
        <div role="status" className="space-y-2">
          {latestIssues.hasPartialFailure ? (
            <div
              className={`flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider ${
                latestIssues.hasHardFailure ? "text-[#f27c7c]" : "text-[#f2a67c]"
              }`}
            >
              <IconQuarantine className="h-4 w-4" />
              <span>
                {latestIssues.hasHardFailure
                  ? "Kill-Switch Partial Failure — Review Receipt"
                  : "Kill-Switch Completed with Warnings — Review Receipt"}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 font-mono text-[12.5px] uppercase tracking-wider text-[#5bdba2]">
              <IconCheck className="h-4 w-4" />
              <span>Kill-Switch Executed — Receipt</span>
            </div>
          )}
          <OffboardReceiptCard receipt={latestReceipt} highlighted />
        </div>
      )}

      <div className="space-y-2 border-t border-white/[0.06] pt-3.5">
        <div className="font-mono text-[12.5px] uppercase tracking-wider text-[#a6b5cf]">
          Offboarding History ({receipts?.length ?? 0})
        </div>
        <ListState
          data={receipts}
          error={receiptsError}
          empty="No offboarding receipts recorded yet."
        />
        {receipts && receipts.length > 0 && (
          <div className="max-h-96 space-y-2 overflow-y-auto">
            {receipts.map((r) => (
              <OffboardReceiptCard key={r.id} receipt={r as OffboardReceiptWithErrors} />
            ))}
          </div>
        )}
      </div>
    </Section>
  );
}

const ROW_BTN = `${SECONDARY_BTN} px-2.5! py-1.5! text-[13px]!`;

function RoleSelect({
  value,
  onChange,
  ...rest
}: {
  value: Role;
  onChange: (role: Role) => void;
  id?: string;
  disabled?: boolean;
  title?: string;
  "aria-label"?: string;
  className?: string;
}) {
  return (
    <select
      {...rest}
      value={value}
      onChange={(e) => onChange(e.target.value as Role)}
      className={`${SELECT_CLASS} ${rest.className ?? ""}`}
    >
      <option value="member">Member</option>
      <option value="owner">Owner</option>
    </select>
  );
}

function UsersSection({
  user,
  onChanged,
  onSelectSection,
}: {
  user: User;
  onChanged: () => void;
  onSelectSection?: (section: SettingsSectionId) => void;
}) {
  const { data, error, reload } = useLoad(api.users);
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("member");
  /** Username whose "set password" form is open. */
  const [resetFor, setResetFor] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const addAction = useAction();
  const rowAction = useAction();
  const roleId = useId();

  // Accounts and directory principals move together, so Directory & groups and "View as" reload too.
  const refresh = () => {
    reload();
    onChanged();
  };

  const mutate = (done: string, fn: () => Promise<unknown>) => {
    setNotice(null);
    void rowAction.run(fn).then((ok) => {
      if (ok) setNotice(done);
      refresh();
    });
  };

  const add = (e: FormEvent) => {
    e.preventDefault();
    setNotice(null);
    const name = username.trim();
    void addAction
      .run(async () => {
        await api.createUser({
          username: name,
          password,
          display_name: displayName.trim() || undefined,
          role,
        });
        setUsername("");
        setDisplayName("");
        setPassword("");
        setRole("member");
        setNotice(`Added @${name}`);
      })
      .then(refresh);
  };

  const setUserPassword = (e: FormEvent, u: UserRow) => {
    e.preventDefault();
    setNotice(null);
    void rowAction
      .run(async () => {
        await api.updateUser(u.username, { password: newPassword });
        setResetFor(null);
        setNewPassword("");
        setNotice(`New password set for @${u.username}`);
      })
      .then(refresh);
  };

  return (
    <Section
      title="Users & Roles"
      icon={IconUser}
      description="Owners manage workspace settings and secrets; members access repositories."
    >
      <ErrorNote message={rowAction.error} />
      <Notice message={notice} />
      <ListState data={data} error={error} empty="No accounts." />
      {data && data.length > 0 && (
        <ul className="space-y-2">
          {data.map((u) => {
            const self = u.username === user.username;
            return (
              <li key={u.username} className="pr-well space-y-2.5 rounded-xl px-3.5 py-2.5">
                <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="truncate text-[14px] font-medium text-[#e6ecf8]">
                        {u.display_name}
                      </span>
                      <span className="break-all font-mono text-[12.5px] text-[#a6b5cf]">@{u.username}</span>
                      <Badge tone={u.role === "owner" ? "mint" : "muted"}>{u.role}</Badge>
                      <Badge tone={u.totp_enabled ? "mint" : "muted"}>
                        2FA {u.totp_enabled ? "on" : "off"}
                      </Badge>
                      {u.disabled && <Badge tone="muted">disabled</Badge>}
                      {self && <Badge tone="muted">you</Badge>}
                    </div>
                    <div className="mt-1 font-mono text-[12.5px] text-[#a6b5cf]">
                      last sign-in <Time value={u.last_login_at} />
                    </div>
                  </div>
                  {self ? (
                    <div className="flex shrink-0 items-center gap-2.5">
                      <span className="text-[13px] text-[#98a8c4]">Current account</span>
                      {onSelectSection && (
                        <button
                          type="button"
                          onClick={() => onSelectSection("security")}
                          className={ROW_BTN}
                        >
                          Password &amp; 2FA →
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="flex shrink-0 flex-wrap items-center gap-1.5">
                      <RoleSelect
                        value={u.role}
                        disabled={rowAction.pending}
                        aria-label={`Role for ${u.username}`}
                        className="w-auto! py-1.5! text-[13px]!"
                        onChange={(next) =>
                          mutate(`@${u.username} is now ${next === "owner" ? "an owner" : "a member"}`, () =>
                            api.updateUser(u.username, { role: next }),
                          )
                        }
                      />
                      <button
                        type="button"
                        disabled={rowAction.pending}
                        aria-expanded={resetFor === u.username}
                        onClick={() => {
                          setResetFor(resetFor === u.username ? null : u.username);
                          setNewPassword("");
                        }}
                        className={ROW_BTN}
                      >
                        Set password
                      </button>
                      <button
                        type="button"
                        disabled={rowAction.pending}
                        onClick={() =>
                          mutate(`@${u.username} ${u.disabled ? "enabled" : "disabled"}`, () =>
                            api.updateUser(u.username, { disabled: !u.disabled }),
                          )
                        }
                        className={ROW_BTN}
                      >
                        {u.disabled ? "Enable" : "Disable"}
                      </button>
                      <ConfirmButton
                        disabled={rowAction.pending}
                        confirmLabel="Delete"
                        onConfirm={() => mutate(`Deleted @${u.username}`, () => api.deleteUser(u.username))}
                        title="Delete account: they can no longer sign in"
                        aria-label={`Delete account ${u.username}`}
                        className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#f27c7c] disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        <IconTrash className="h-4 w-4" />
                      </ConfirmButton>
                    </div>
                  )}
                </div>
                {resetFor === u.username && !self && (
                  <form
                    onSubmit={(e) => setUserPassword(e, u)}
                    className="flex flex-col gap-2.5 border-t border-white/[0.06] pt-2.5 sm:flex-row sm:items-end"
                  >
                    {/* Tells password managers which account this password belongs to. */}
                    <input type="text" name="username" autoComplete="username" value={u.username} readOnly hidden />
                    <div className="min-w-0 flex-1">
                      <Field
                        label={`New password for @${u.username}`}
                        name="new-password"
                        type="password"
                        maxLength={1024}
                        autoComplete="new-password"
                        required
                        minLength={10}
                        autoFocus
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                      />
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="submit"
                        disabled={rowAction.pending || newPassword.length < 10}
                        className={PRIMARY_BTN}
                      >
                        {rowAction.pending ? "Saving…" : "Save password"}
                      </button>
                      <button
                        type="button"
                        disabled={rowAction.pending}
                        onClick={() => setResetFor(null)}
                        className={SECONDARY_BTN}
                      >
                        Cancel
                      </button>
                    </div>
                  </form>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <form onSubmit={add} className="space-y-3.5 border-t border-white/[0.06] pt-3.5">
        <h3 className="text-[14px] font-semibold text-[#f3f6fd]">Add user</h3>
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field
            label="Username"
            name="new_username"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            required
            pattern={USERNAME_PATTERN}
            maxLength={32}
            placeholder="alice"
            hint="a–z, 0–9, - or _"
            className="font-mono"
            value={username}
            onChange={(e) => setUsername(e.target.value.toLowerCase())}
          />
          <Field
            label="Display name"
            name="new_display_name"
            autoComplete="off"
            maxLength={64}
            placeholder="Optional"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <Field
            label="Initial password"
            name="new-password"
            type="password"
            maxLength={1024}
            autoComplete="new-password"
            required
            minLength={10}
            hint="Min 10 characters"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <div className="space-y-1.5">
            <label htmlFor={roleId} className="block text-[13px] font-medium text-[#d2dbee]">
              Role
            </label>
            <RoleSelect id={roleId} value={role} onChange={setRole} />
          </div>
        </div>
        <ErrorNote message={addAction.error} />
        <button
          type="submit"
          disabled={addAction.pending || !username.trim() || password.length < 10}
          className={PRIMARY_BTN}
        >
          <IconPlus className="h-4 w-4" />
          <span>{addAction.pending ? "Adding…" : "Add user"}</span>
        </button>
      </form>
    </Section>
  );
}

function RepositoriesSection({
  repos,
  onReposReload,
  onAddRepo,
}: Pick<Props, "repos" | "onReposReload" | "onAddRepo">) {
  /** The one row form that is open: description edit or delete confirmation. */
  const [open, setOpen] = useState<{ name: string; mode: "edit" | "delete" } | null>(null);
  const [text, setText] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const action = useAction();

  const toggle = (name: string, mode: "edit" | "delete", initial: string) => {
    setOpen(open?.name === name && open.mode === mode ? null : { name, mode });
    setText(initial);
    action.setError(null);
  };

  const submit = (e: FormEvent, r: Repo, mode: "edit" | "delete") => {
    e.preventDefault();
    setNotice(null);
    void action.run(async () => {
      if (mode === "edit") await api.updateRepo(r.name, text.trim());
      else await api.deleteRepo(r.name);
      setOpen(null);
      setNotice(mode === "edit" ? `Saved ${r.name}` : `Deleted ${r.name}`);
      // Deleting the repo you are in drops the Studio back to the default one.
      await onReposReload();
    });
  };

  return (
    <Section title="Repositories" icon={IconCode}>
      <Notice message={notice} />
      {repos.length === 0 ? (
        <div className="flex flex-col items-start gap-3 py-1 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-0.5">
            <div className="text-[14px] font-medium text-[#e6ecf8]">No repositories yet.</div>
            <p className="text-[13.5px] text-[#b6c3db]">
              Add a repository to enable Git, sync, and agents.
            </p>
          </div>
          {onAddRepo && (
            <button type="button" onClick={onAddRepo} className={`${PRIMARY_BTN} shrink-0`}>
              <IconPlus className="h-4 w-4" />
              <span>Add repository</span>
            </button>
          )}
        </div>
      ) : (
      <>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-mono text-[12.5px] text-[#a6b5cf]">
            {repos.length} {repos.length === 1 ? "repository" : "repositories"}
          </span>
          {onAddRepo && (
            <button type="button" onClick={onAddRepo} className={`${PRIMARY_BTN} px-3! py-1.5! text-[13px]!`}>
              <IconPlus className="h-4 w-4" />
              <span>Add repository</span>
            </button>
          )}
        </div>
        <ul className="space-y-2">
          {repos.map((r) => {
            const mode = open?.name === r.name ? open.mode : null;
            return (
              <li key={r.name} className="pr-well space-y-2.5 rounded-xl px-3.5 py-2.5">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="break-all font-mono text-[14px] font-medium text-[#e6ecf8]">
                        {r.name}
                      </span>
                      {r.is_default && <Badge tone="mint">default</Badge>}
                      {!r.head_oid && <Badge tone="muted">empty</Badge>}
                    </div>
                    <div className="mt-0.5 break-words text-[13px] text-[#b6c3db]">
                      {r.description || "No description"}
                    </div>
                  </div>
                  <div className="flex shrink-0 gap-1.5">
                    <button
                      type="button"
                      disabled={action.pending}
                      aria-expanded={mode === "edit"}
                      onClick={() => toggle(r.name, "edit", r.description)}
                      title="Edit description"
                      aria-label={`Edit description of ${r.name}`}
                      className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#9ec0f5] disabled:opacity-40"
                    >
                      <IconEdit className="h-4 w-4" />
                    </button>
                    <button
                      type="button"
                      disabled={r.is_default || action.pending}
                      aria-expanded={mode === "delete"}
                      onClick={() => toggle(r.name, "delete", "")}
                      title={r.is_default ? "The default repository can't be deleted" : "Delete repository"}
                      aria-label={`Delete repository ${r.name}`}
                      className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#f27c7c] disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      <IconTrash className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                {mode && (
                  <form
                    onSubmit={(e) => submit(e, r, mode)}
                    className="space-y-2.5 border-t border-white/[0.06] pt-2.5"
                  >
                    <div className="flex flex-col gap-2.5 sm:flex-row sm:items-end">
                      <div className="min-w-0 flex-1">
                        {mode === "edit" ? (
                          <Field
                            label="Description"
                            name="repo_description"
                            autoComplete="off"
                            maxLength={500}
                            autoFocus
                            value={text}
                            onChange={(e) => setText(e.target.value)}
                          />
                        ) : (
                          <Field
                            label={`Type ${r.name} to permanently delete`}
                            name="repo_confirm"
                            autoComplete="off"
                            autoCapitalize="none"
                            spellCheck={false}
                            autoFocus
                            className="font-mono"
                            value={text}
                            onChange={(e) => setText(e.target.value)}
                          />
                        )}
                      </div>
                      <div className="flex gap-2">
                        {mode === "edit" ? (
                          <button
                            type="submit"
                            disabled={action.pending || text.trim() === r.description}
                            className={PRIMARY_BTN}
                          >
                            {action.pending ? "Saving…" : "Save"}
                          </button>
                        ) : (
                          <button
                            type="submit"
                            disabled={action.pending || text !== r.name}
                            className={DANGER_BTN}
                          >
                            {action.pending ? "Deleting…" : "Delete repository"}
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={action.pending}
                          onClick={() => setOpen(null)}
                          className={SECONDARY_BTN}
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                    <ErrorNote message={action.error} />
                  </form>
                )}
              </li>
            );
          })}
        </ul>
      </>
      )}
    </Section>
  );
}

/** Validates `@user`, `bot:*`, `service:*`, and `spiffe://*` directory principals. */
function isValidDirectoryPrincipal(raw: string): boolean {
  if (!raw || raw.length > 128 || /\s/.test(raw)) return false;
  if (raw.startsWith("@")) return /^@[^\s@/]+$/.test(raw);
  if (raw.startsWith("bot:") || raw.startsWith("service:")) {
    return /^(?:bot|service):[A-Za-z0-9._-]+$/.test(raw);
  }
  if (raw.startsWith("spiffe://")) {
    return /^spiffe:\/\/[A-Za-z0-9._-]+\/[A-Za-z0-9._/-]+$/.test(raw);
  }
  return false;
}

function PeopleSection({ onDirectoryChange }: Pick<Props, "onDirectoryChange">) {
  const { data, error, setData } = useLoad(api.directory);
  /** Principal being edited, or null while the form adds a new one. */
  const [editing, setEditing] = useState<string | null>(null);
  const [principal, setPrincipal] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [groups, setGroups] = useState("");
  const groupsRef = useRef<HTMLInputElement>(null);
  const saveAction = useAction();
  const deleteAction = useAction();

  // Keeps the header's "View as" list in step with every load and edit.
  useEffect(() => {
    if (data) onDirectoryChange(data);
  }, [data, onDirectoryChange]);

  const reset = () => {
    setEditing(null);
    setPrincipal("");
    setDisplayName("");
    setGroups("");
    saveAction.setError(null);
  };

  const startEdit = (p: DirectoryPrincipal) => {
    setEditing(p.principal);
    setPrincipal(p.principal);
    setDisplayName(p.display_name);
    // The owner's `owners` group is implicit, so it isn't offered for editing.
    setGroups(p.groups.filter((g) => !(p.is_owner && g === "owners")).join(", "));
    saveAction.setError(null);
    requestAnimationFrame(() => {
      groupsRef.current?.focus();
      groupsRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const name = principal.trim();
    const list = [...new Set(groups.split(",").map((g) => g.trim()).filter(Boolean))];
    const bad = list.find((g) => !GROUP_NAME_RE.test(g));
    if (!isValidDirectoryPrincipal(name)) {
      saveAction.setError(
        "Use @user, bot:<name>, service:<name>, or spiffe://<domain>/<path> (no spaces).",
      );
    } else if (bad !== undefined) {
      saveAction.setError(`“${bad}” isn't a valid group. Use 1–32 of a–z, 0–9, "-" or "_".`);
    } else if (!editing && data?.principals.some((p) => p.principal === name)) {
      saveAction.setError(`${name} already exists. Use its edit button to change it.`);
    } else {
      void saveAction.run(async () => {
        setData(await api.saveDirectoryPrincipal(name, displayName.trim(), list));
        reset();
      });
    }
  };

  const remove = (p: DirectoryPrincipal) => {
    void deleteAction.run(async () => {
      setData(await api.deleteDirectoryPrincipal(p.principal));
      if (editing === p.principal) reset();
    });
  };

  return (
    <Section
      title="Directory & Groups"
      icon={IconPolicy}
      description={
        <>
          Principals and groups used in <code className="text-[#dce4f5]">.access.toml</code> rules.
        </>
      }
    >
      <ErrorNote message={deleteAction.error} />
      <ListState data={data?.principals ?? null} error={error} empty="No principals yet." />
      {data && data.principals.length > 0 && (
        <ul className="space-y-2">
          {data.principals.map((p) => (
            <li
              key={p.principal}
              className="pr-well flex items-center justify-between gap-3 rounded-xl px-3.5 py-2.5"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                  <span className="truncate text-[14px] font-medium text-[#e6ecf8]">{p.display_name}</span>
                  <span className="break-all font-mono text-[12.5px] text-[#a6b5cf]">{p.principal}</span>
                  {p.is_owner && <Badge tone="mint">owner</Badge>}
                  {p.has_account && <Badge tone="muted">account</Badge>}
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  {p.groups.length === 0 ? (
                    <span className="font-mono text-[12.5px] text-[#a6b5cf]">no groups</span>
                  ) : (
                    p.groups.map((g) => (
                      <Badge key={g} tone="muted">
                        {g}
                      </Badge>
                    ))
                  )}
                </div>
              </div>
              <div className="flex shrink-0 gap-1.5">
                <button
                  type="button"
                  onClick={() => startEdit(p)}
                  title="Edit"
                  aria-label={`Edit ${p.principal}`}
                  className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#9ec0f5]"
                >
                  <IconEdit className="h-4 w-4" />
                </button>
                {/* A principal with an account goes away by deleting the user under Users. */}
                {!p.has_account && (
                  <ConfirmButton
                    disabled={p.is_owner || deleteAction.pending}
                    confirmLabel="Remove"
                    onConfirm={() => remove(p)}
                    title={
                      p.is_owner
                        ? "The owner can't be removed"
                        : "Remove: rules naming it stop matching anyone"
                    }
                    aria-label={`Remove ${p.principal}`}
                    className="pr-pill inline-flex h-8 w-8 items-center justify-center rounded-lg text-[#f27c7c] disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <IconTrash className="h-4 w-4" />
                  </ConfirmButton>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}

      <form onSubmit={submit} className="space-y-3.5 border-t border-white/[0.06] pt-3.5">
        <h3 className="text-[14px] font-semibold text-[#f3f6fd]">
          {editing === null ? "Add principal" : `Editing ${editing}`}
        </h3>
        <div className="grid gap-3.5 sm:grid-cols-2">
          <Field
            label="Principal"
            name="principal"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            required
            maxLength={128}
            placeholder="@alice, bot:ci, spiffe://..."
            readOnly={editing !== null}
            disabled={editing !== null}
            className="font-mono"
            value={principal}
            onChange={(e) => setPrincipal(e.target.value)}
          />
          <Field
            label="Display name"
            name="directory_display_name"
            autoComplete="off"
            required
            maxLength={64}
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
        </div>
        <Field
          ref={groupsRef}
          label="Groups"
          name="groups"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          placeholder="core, security"
          hint={data && data.groups.length > 0 ? `In use: ${data.groups.join(", ")}` : undefined}
          className="font-mono"
          value={groups}
          onChange={(e) => setGroups(e.target.value)}
        />
        <ErrorNote message={saveAction.error} />
        <div className="flex flex-wrap gap-2">
          <button
            type="submit"
            disabled={saveAction.pending || !principal.trim() || !displayName.trim()}
            className={PRIMARY_BTN}
          >
            {editing === null && <IconPlus className="h-4 w-4" />}
            <span>
              {saveAction.pending ? "Saving…" : editing === null ? "Add principal" : `Save ${editing}`}
            </span>
          </button>
          {editing !== null && (
            <button type="button" disabled={saveAction.pending} onClick={reset} className={SECONDARY_BTN}>
              Cancel
            </button>
          )}
        </div>
      </form>
    </Section>
  );
}

function WorkspaceSection({ hasRepos }: { hasRepos: boolean }) {
  const { data, error, setData } = useLoad(api.settings);
  const [days, setDays] = useState(data?.audit_retention_days?.toString() ?? "");
  const [forever, setForever] = useState(data ? data.audit_retention_days === null : true);
  const [saved, setSaved] = useState(false);
  const action = useAction();
  // Set once the user edits the form, so a background cache revalidation never clobbers their typing.
  const dirtyRef = useRef(false);

  useEffect(() => {
    if (!data || dirtyRef.current) return;
    setForever(data.audit_retention_days === null);
    setDays(data.audit_retention_days?.toString() ?? "");
  }, [data]);

  const savedDays = data?.audit_retention_days ?? null;
  const parsedDays = forever ? null : days.trim() === "" ? NaN : Number(days);
  const validRetention =
    forever ||
    (parsedDays !== null && Number.isInteger(parsedDays) && parsedDays >= 1 && parsedDays <= 3650);
  const isDirty = Boolean(data) && validRetention && parsedDays !== savedDays;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!isDirty) return;
    setSaved(false);
    void action
      .run(async () => {
        const res = await api.updateSettings({ audit_retention_days: forever ? null : Number(days) });
        dirtyRef.current = false; // the saved value is now the truth: let it sync into the form
        setData(res);
      })
      .then(setSaved);
  };

  const restoreCmd =
    "premier restore premier-backup-YYYY-MM-DD.tar.gz --into /path/to/workspace\ncd /path/to/workspace && premier serve";

  return (
    <div className="space-y-4">
      <Section title="Audit Retention" icon={IconClock}>
        <ErrorNote message={error} />
        {!data && !error ? (
          <SettingsRowsSkeleton rows={2} />
        ) : (
        <form onSubmit={submit} className="space-y-3.5">
          <div className="grid gap-3.5 sm:grid-cols-2 sm:items-end">
            <Field
              label="Keep audit events for (days)"
              name="audit_retention_days"
              type="number"
              inputMode="numeric"
              min={1}
              max={3650}
              step={1}
              required={!forever}
              disabled={forever || !data}
              placeholder={forever ? "" : "90"}
              className={NO_SPIN}
              value={forever ? "" : days}
              onChange={(e) => {
                dirtyRef.current = true;
                setDays(e.target.value);
                setSaved(false);
              }}
            />
            <label className="flex cursor-pointer items-center gap-2.5 pb-2 text-[14px] text-[#dce4f5]">
              <input
                type="checkbox"
                className="h-4 w-4 accent-[#7f95f8]"
                disabled={!data}
                checked={forever}
                onChange={(e) => {
                  dirtyRef.current = true;
                  setForever(e.target.checked);
                  setSaved(false);
                }}
              />
              <span>Keep forever</span>
            </label>
          </div>
          {!forever && (
            <p className="text-[13px] text-[#98a8c4]">
              Audit events older than the configured retention window will be pruned on save.
            </p>
          )}
          <ErrorNote message={action.error} />
          <div className="flex flex-wrap items-center gap-3">
            <button type="submit" disabled={action.pending || !data || !isDirty} className={PRIMARY_BTN}>
              {action.pending ? "Saving…" : "Save retention"}
            </button>
            <Notice message={saved ? "Retention saved" : null} />
          </div>
        </form>
        )}
      </Section>

      <Section
        title={hasRepos ? "Download backup archive & Audit Export" : "Download backup archive"}
        icon={IconDownload}
      >
        <div className="flex flex-wrap gap-2">
          <a href={repoPath("/v1/backup")} download className={PRIMARY_BTN}>
            <IconDownload className="h-4 w-4" />
            <span>Download backup archive</span>
          </a>
          {hasRepos && (
            <a href={repoPath("/v1/audit/export")} download className={SECONDARY_BTN}>
              <IconDownload className="h-4 w-4 text-[#a6b5cf]" />
              <span>Export audit log (NDJSON)</span>
            </a>
          )}
        </div>
        <p className="rounded-xl border border-white/[0.12] bg-white/[0.045] px-3.5 py-2.5 text-[13px] leading-relaxed text-[#b2c0d8]">
          {hasRepos
            ? `Repository "${currentRepoName()}" + server state (includes vault data — store securely).`
            : "Server & account state (accounts, tokens, SSH keys, and server policies — store securely)."}
        </p>

        <details className="pr-well group rounded-xl">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3.5 py-2.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5] select-none [&::-webkit-details-marker]:hidden">
            <span className="inline-flex items-center gap-2">
              <span
                aria-hidden="true"
                className="inline-block text-[11px] transition-transform group-open:rotate-90"
              >
                ▸
              </span>
              <span>Restore Guide</span>
            </span>
            <span className="text-[12.5px] normal-case tracking-normal text-[#a6b5cf] group-open:hidden">
              Show steps
            </span>
            <span className="hidden text-[12.5px] normal-case tracking-normal text-[#a6b5cf] group-open:inline">
              Hide steps
            </span>
          </summary>
          <div className="space-y-2 border-t border-white/[0.06] px-3.5 pb-3.5 pt-2.5">
            <ol className="list-decimal space-y-1 pl-5 text-[13.5px] text-[#d2dbee]">
              <li>Stop the running Premier server.</li>
              <li>
                Restore with <code className="font-mono text-[#dce4f5]">premier restore</code>.
              </li>
              <li>Restart Premier and rotate any exposed credentials.</li>
            </ol>
            <CodeBlock code={restoreCmd} label="Restore command" language="shell" compact />
          </div>
        </details>
      </Section>
    </div>
  );
}

type McpSetupTab = "mcp-json" | "mcp-stdio" | "cli-wrapper";

function McpAgentsSection({ user }: { user: User }) {
  const [activeTab, setActiveTab] = useState<McpSetupTab>("mcp-json");
  const [envName, setEnvName] = useState("dev");
  const [profile, setProfile] = useState("readonly-review");

  const repoName = currentRepoName();
  const isDefaultRepo = currentRepoIsDefault();
  const effectiveEnv = sanitizeEnv(envName);
  const effectiveProfile = sanitizeAgentProfile(profile);
  const { mcpJson, mcpStdioCmd, runCmd } = buildAgentConnect({
    repoName,
    isDefaultRepo,
    env: effectiveEnv,
  });
  const cdPrefix = !isDefaultRepo && repoName ? `cd ${repoName}\n` : "";

  const tabs: Record<McpSetupTab, { label: string; header: string; snippet: string }> = {
    "mcp-json": {
      label: "MCP Config (JSON)",
      header: ".mcp.json",
      snippet: mcpJson,
    },
    "mcp-stdio": {
      label: "MCP Stdio Command",
      header: "stdio transport",
      snippet: `# Secret-brokering MCP gateway\n${mcpStdioCmd}\n\n# Read/write repository MCP server\n${cdPrefix}premier mcp serve --agent-profile ${effectiveProfile}`,
    },
    "cli-wrapper": {
      label: "CLI Wrapper",
      header: "shell wrapper",
      snippet: runCmd,
    },
  };

  const activeCfg = tabs[activeTab];

  return (
    <Section
      title="Connect Any MCP or CLI Agent"
      icon={IconCage}
      description="Use secrets and repository tools without exposing raw secret values."
    >
      <div
        className={`grid gap-3 ${activeTab === "mcp-stdio" ? "sm:grid-cols-2" : "sm:max-w-xs"}`}
      >
        <Field
          label="Environment"
          name="mcp_env_name"
          value={envName}
          onChange={(e) => setEnvName(e.target.value)}
          placeholder="dev"
          className="font-mono"
        />
        {activeTab === "mcp-stdio" && (
          <Field
            label="Agent profile"
            name="mcp_agent_profile"
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            placeholder="readonly-review"
            className="font-mono"
            hint={`Authority: ${user.principal} ∩ ${effectiveProfile}`}
          />
        )}
      </div>

      <div
        role="tablist"
        aria-label="MCP and CLI setup"
        className="inline-flex flex-wrap rounded-full border border-white/[0.08] bg-black/30 p-1 font-mono text-[13px]"
      >
        {(["mcp-json", "mcp-stdio", "cli-wrapper"] as McpSetupTab[]).map((tabKey) => (
          <button
            key={tabKey}
            type="button"
            role="tab"
            aria-selected={activeTab === tabKey}
            onClick={() => setActiveTab(tabKey)}
            className={`rounded-full px-3.5 py-1 transition ${
              activeTab === tabKey ? "pr-pill-active" : "text-[#a6b5cf] hover:text-[#f3f6fd]"
            }`}
          >
            {tabs[tabKey].label}
          </button>
        ))}
      </div>

      <CodeBlock
        code={activeCfg.snippet}
        label={activeCfg.header}
        language={activeTab === "mcp-json" ? "json" : "shell"}
        showLineNumbers={activeCfg.snippet.includes("\n")}
      />
    </Section>
  );
}

const SECURITY_EVENT_META: Record<
  string,
  { label: string; tone: "mint" | "info" | "coral" | "muted" }
> = {
  login_ok: { label: "Signed in", tone: "mint" },
  login_failed: { label: "Sign-in failed", tone: "coral" },
  logout: { label: "Signed out", tone: "muted" },
  owner_created: { label: "Owner created", tone: "mint" },
  password_changed: { label: "Password changed", tone: "info" },
  totp_enabled: { label: "2FA enabled", tone: "mint" },
  totp_disabled: { label: "2FA disabled", tone: "coral" },
  recovery_code_used: { label: "Recovery code used", tone: "info" },
  recovery_codes_regenerated: { label: "Recovery codes regenerated", tone: "info" },
  token_created: { label: "Access token created", tone: "info" },
  token_revoked: { label: "Access token revoked", tone: "muted" },
  ssh_key_added: { label: "SSH key added", tone: "info" },
  ssh_key_revoked: { label: "SSH key revoked", tone: "muted" },
  session_revoked: { label: "Session signed out", tone: "muted" },
  user_created: { label: "User created", tone: "mint" },
  user_updated: { label: "User updated", tone: "info" },
  user_deleted: { label: "User deleted", tone: "coral" },
  user_offboarded: { label: "User offboarded", tone: "coral" },
};

function formatSecurityEventMeta(kind: string): {
  label: string;
  tone: "mint" | "info" | "coral" | "muted";
} {
  if (SECURITY_EVENT_META[kind]) return SECURITY_EVENT_META[kind];
  const label = kind.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
  if (kind.includes("fail") || kind.includes("delete") || kind.includes("offboard")) {
    return { label, tone: "coral" };
  }
  return { label, tone: "muted" };
}

function EventsSection() {
  const { data, error, reload } = useLoad(authApi.events);
  return (
    <Section title="Security Activity" icon={IconClock}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="font-mono text-[12.5px] text-[#a6b5cf]">Latest 50 events</span>
        <button
          type="button"
          onClick={reload}
          className={`${SECONDARY_BTN} px-2.5! py-1! text-[12.5px]!`}
        >
          <IconRefresh className="h-3.5 w-3.5 text-[#a6b5cf]" />
          <span>Refresh</span>
        </button>
      </div>
      <ListState data={data} error={error} empty="No activity recorded yet." />
      {data && data.length > 0 && (
        <ul className="pr-well max-h-[480px] divide-y divide-white/[0.05] overflow-y-auto rounded-xl">
          {data.map((ev, i) => {
            const meta = formatSecurityEventMeta(ev.kind);
            return (
              <li key={`${ev.at}-${i}`} className="px-3.5 py-2.5">
                <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={meta.tone}>{meta.label}</Badge>
                    {ev.username && (
                      <span className="font-mono text-[13px] text-[#9ec0f5]">@{ev.username}</span>
                    )}
                  </div>
                  <span className="font-mono text-[12.5px] text-[#a6b5cf]">
                    <Time value={ev.at} />
                  </span>
                </div>
                {ev.detail && (
                  <div className="mt-1 break-words text-[13px] text-[#b6c3db]">{ev.detail}</div>
                )}
                <div
                  className="mt-1 truncate font-mono text-[12.5px] text-[#a6b5cf]"
                  title={ev.user_agent ?? undefined}
                >
                  {ev.ip || "unknown address"}
                  {ev.user_agent ? ` · ${formatUserAgent(ev.user_agent)}` : ""}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Section>
  );
}

function AboutSection({
  health,
  healthError,
  onRetryHealth,
  hasRepos,
}: Pick<Props, "health" | "healthError" | "onRetryHealth"> & { hasRepos: boolean }) {
  // Members get no workspace path, host capabilities or sandbox detail: those rows are left out.
  const caps = health?.host_capabilities;
  if (!health) {
    return (
      <Section title="Server & Host" icon={IconGear}>
        {healthError ? (
          <div role="alert" className="flex flex-wrap items-center gap-3 text-[14px] text-[#dce4f5]">
            <span>Server details unavailable</span>
            {onRetryHealth && (
              <button type="button" onClick={onRetryHealth} className={SECONDARY_BTN}>
                Retry
              </button>
            )}
          </div>
        ) : (
          <SettingsRowsSkeleton rows={2} />
        )}
      </Section>
    );
  }
  const sshStatus =
    health.ssh_enabled === true
      ? `Enabled (port ${health.ssh_port ?? 2222})`
      : health.ssh_enabled === false
        ? "Off"
        : undefined;
  const hostValue = caps ? `${caps.os}/${caps.arch}` : health.os;
  const rows: [string, string | undefined][] = [
    ["Version", `v${health.version}`],
    ["Status", health.status],
    ["Host", hostValue],
    ["Workspace", health.workspace_root],
    ["SSH listener", sshStatus],
    ["Agent sandbox", health.agent_sandbox],
    // Why it is not bwrap; left out when the sandbox works.
    ...(health.agent_sandbox !== "bwrap" && health.agent_sandbox_detail
      ? [["Sandbox detail", health.agent_sandbox_detail] satisfies [string, string]]
      : []),
  ];

  const configFlags: [string, boolean | undefined][] = [
    ...(hasRepos
      ? ([
          ["Repo policy", health.policy_loaded],
          [".env.schema", health.schema_loaded],
        ] as [string, boolean | undefined][])
      : []),
    ["Server policy", health.server_policy_loaded],
  ];
  const visibleConfigFlags = configFlags.filter(
    (f): f is [string, boolean] => typeof f[1] === "boolean",
  );

  const hostOs = (caps?.os ?? health.os ?? "").toLowerCase();
  const isWindows = hostOs.includes("win");
  const isLinux = hostOs.includes("linux");
  const isMac = hostOs.includes("mac") || hostOs.includes("darwin");

  const platformCaps: [string, boolean | undefined][] = [
    ...(!isWindows ? ([["POSIX FIFO", caps?.posix_fifo_supported]] as [string, boolean | undefined][]) : []),
    ...(isLinux || (!isWindows && !isMac)
      ? ([
          ["bwrap", caps?.linux_bwrap_available],
          ["unshare", caps?.linux_unshare_available],
          ["FUSE3", caps?.linux_fuse3_available],
        ] as [string, boolean | undefined][])
      : []),
    ...(isWindows || (!isLinux && !isMac)
      ? ([["ProjFS", caps?.windows_projfs_available]] as [string, boolean | undefined][])
      : []),
  ];
  const visiblePlatformCaps = platformCaps.filter(
    (f): f is [string, boolean] => typeof f[1] === "boolean",
  );

  return (
    <Section title="Server & Host" icon={IconGear}>
      <dl className="pr-well space-y-2 rounded-xl p-3.5 font-mono text-[13px]">
        {rows
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k} className="flex justify-between gap-3">
              <dt className="shrink-0 text-[#a6b5cf]">{k}</dt>
              <dd className="min-w-0 break-all text-right text-[#dce4f5]">{v}</dd>
            </div>
          ))}
      </dl>
      {visibleConfigFlags.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {visibleConfigFlags.map(([label, on]) => (
            <Badge key={label} tone={on ? "mint" : "muted"}>
              {label}: {on ? "Available" : "Off"}
            </Badge>
          ))}
        </div>
      )}
      {visiblePlatformCaps.length > 0 && (
        <details className="pr-well group rounded-xl">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-2 px-3.5 py-2.5 font-mono text-[12.5px] uppercase tracking-wider text-[#9ec0f5] select-none [&::-webkit-details-marker]:hidden">
            <span className="inline-flex items-center gap-2">
              <span
                aria-hidden="true"
                className="inline-block text-[11px] transition-transform group-open:rotate-90"
              >
                ▸
              </span>
              <span>Platform capabilities</span>
            </span>
            <span className="text-[12.5px] normal-case tracking-normal text-[#a6b5cf]">
              {visiblePlatformCaps.filter(([, on]) => on).length}/{visiblePlatformCaps.length} available
            </span>
          </summary>
          <div className="space-y-2 border-t border-white/[0.06] px-3.5 py-2.5">
            {visiblePlatformCaps.map(([label, on]) => (
              <div key={label} className="flex items-center justify-between gap-3 font-mono text-[13px]">
                <span className="text-[#d2dbee]">{label}</span>
                <Badge tone={on ? "mint" : "muted"}>{on ? "Available" : "Unavailable"}</Badge>
              </div>
            ))}
          </div>
        </details>
      )}
    </Section>
  );
}

function RepoPrerequisiteCard({
  title,
  description,
  icon: Icon,
  onAddRepo,
}: {
  title: string;
  description: string;
  icon: ComponentType<IconProps>;
  onAddRepo?: () => void;
}) {
  return (
    <Section title={title} icon={Icon}>
      <div className="flex flex-col items-start gap-4 py-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/[0.08] bg-white/[0.04] text-[#9ec0f5]">
            <IconLock className="h-4 w-4" />
          </div>
          <div className="space-y-1">
            <div className="text-[14.5px] font-medium text-[#f3f6fd]">
              Add a repository to unlock {title}
            </div>
            <p className="text-[13.5px] leading-relaxed text-[#a6b5cf]">{description}</p>
          </div>
        </div>
        {onAddRepo && (
          <button type="button" onClick={onAddRepo} className={`${PRIMARY_BTN} shrink-0`}>
            <IconPlus className="h-4 w-4" />
            <span>Add repository</span>
          </button>
        )}
      </div>
    </Section>
  );
}

export function SettingsView({
  user,
  health,
  healthError,
  onRetryHealth,
  repos,
  onReposReload,
  onAddRepo,
  onUserChange,
  onDirectoryChange,
  requestedSection,
  onSelectSection,
}: Props) {
  // Members get 403 on users, directory edits, settings and backup, so Administration is owner-only.
  const owner = user.role !== "member";
  const hasRepos = repos.length > 0;
  const [activeSection, setActiveSection] = useState<SettingsSectionId>(() =>
    resolveSection(requestedSection, owner),
  );
  // Bumped after a user or offboarding change to keep People & groups and Offboarding synced.
  const [directoryEpoch, setDirectoryEpoch] = useState(0);
  const [usersEpoch, setUsersEpoch] = useState(0);

  useEffect(() => () => loadCache.clear(), []);

  useEffect(() => {
    if (requestedSection === undefined) return;
    setActiveSection(resolveSection(requestedSection, owner));
  }, [requestedSection, owner]);

  const visibleGroups = useMemo(
    () =>
      SETTINGS_NAV_GROUPS.filter((g) => !g.ownerOnly || owner)
        .map((g) => ({
          ...g,
          items: g.items.filter((item) => !item.ownerOnly || owner),
        }))
        .filter((g) => g.items.length > 0),
    [owner],
  );

  const visibleItems = useMemo(
    () => visibleGroups.flatMap((g) => g.items),
    [visibleGroups],
  );

  const activeItem =
    visibleItems.find((item) => item.id === activeSection) ?? visibleItems[0];

  const selectSection = (id: SettingsSectionId) => {
    setActiveSection(id);
    onSelectSection?.(id);
  };

  return (
    <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain [scrollbar-gutter:stable]">
      <div className="mx-auto flex w-full max-w-[1120px] flex-1 flex-col gap-4 px-4 py-6 lg:flex-row lg:gap-6 lg:px-6">
        {/* Mobile / Tablet Responsive Section Selector Bar (< lg) */}
        <nav
          aria-label="Settings sections"
          className="pr-surface flex shrink-0 items-center gap-1.5 overflow-x-auto rounded-2xl p-2 lg:hidden"
        >
          {visibleItems.map((item) => {
            const Icon = item.icon;
            const locked = Boolean(item.requiresRepo && !hasRepos);
            const active = activeSection === item.id;
            return (
              <button
                key={item.id}
                type="button"
                title={locked ? "Requires a repository" : undefined}
                aria-current={active ? "page" : undefined}
                onClick={() => selectSection(item.id)}
                className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1.5 text-[13.5px] font-medium whitespace-nowrap transition ${
                  active
                    ? "pr-pill-active"
                    : locked
                      ? "text-[#98a8c4] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
                      : "text-[#b2c0d8] hover:bg-white/[0.05] hover:text-[#f3f6fd]"
                }`}
              >
                <Icon className={`h-4 w-4 ${active ? "text-[#9ec0f5]" : "opacity-80"}`} />
                <span>{item.shortLabel}</span>
                {locked && <IconLock className="h-3.5 w-3.5 shrink-0 text-[#7f8ea8]" aria-hidden="true" />}
              </button>
            );
          })}
        </nav>

        {/* Persistent GitHub-Style Obsidian Glassmorphic Left Sidebar (lg+) */}
        <aside className="pr-surface hidden w-[252px] shrink-0 self-start flex-col overflow-hidden rounded-2xl lg:sticky lg:top-6 lg:flex lg:max-h-[calc(100vh-7rem)]">
          <div className="border-b border-white/[0.06] px-4 py-2.5">
            <div className="truncate text-[14px] font-semibold text-[#f3f6fd]">
              {user.display_name}
            </div>
            <div className="mt-0.5 flex items-center gap-2 font-mono text-[12.5px] text-[#a6b5cf]">
              <span className="truncate">{user.principal}</span>
              <Badge tone={owner ? "mint" : "muted"}>{user.role}</Badge>
            </div>
          </div>
          <nav
            aria-label="Settings navigation"
            className="min-h-0 flex-1 space-y-3 overflow-y-auto overscroll-contain p-2.5"
          >
            {visibleGroups.map((group) => (
              <div key={group.title} className="space-y-1">
                <div className="px-2.5 pb-0.5 font-mono text-[12.5px] font-semibold uppercase tracking-[0.08em] text-[#a6b5cf]">
                  {group.title}
                </div>
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const locked = Boolean(item.requiresRepo && !hasRepos);
                  const active = activeSection === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      title={locked ? "Requires a repository" : undefined}
                      aria-current={active ? "page" : undefined}
                      onClick={() => selectSection(item.id)}
                      className={`flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left text-[14px] font-medium transition ${
                        active
                          ? "bg-[#7f95f8]/18 text-[#f3f6fd] shadow-[inset_2px_0_0_0_rgba(158,192,245,0.9)]"
                          : locked
                            ? "text-[#98a8c4] hover:bg-white/[0.045] hover:text-[#f3f6fd]"
                            : "text-[#b4c2dc] hover:bg-white/[0.045] hover:text-[#f3f6fd]"
                      }`}
                    >
                      <Icon
                        className={`h-[17px] w-[17px] shrink-0 ${
                          active ? "text-[#9ec0f5]" : locked ? "text-[#7f8ea8]" : "text-[#a6b5cf]"
                        }`}
                      />
                      <span className="min-w-0 flex-1 truncate">{item.label}</span>
                      {locked && (
                        <IconLock className="h-3.5 w-3.5 shrink-0 text-[#7f8ea8]" aria-hidden="true" />
                      )}
                    </button>
                  );
                })}
              </div>
            ))}
          </nav>
        </aside>

        {/* Main Active Settings Pane */}
        <div className="min-w-0 flex-1 max-w-3xl pb-6">
          <SoloCardContext.Provider value={SOLO_CARD_SECTIONS.has(activeSection)}>
            <div className="space-y-4">
              {activeItem && (
                <header className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1.5 px-0.5">
                  <div className="min-w-0">
                    <h1 className="text-[20px] font-semibold tracking-[-0.02em] text-[#f5f7fd]">
                      {activeItem.label}
                    </h1>
                    <p className="mt-0.5 text-[13.5px] text-[#98a8c4]">{activeItem.subtitle}</p>
                  </div>
                  {activeSection === "ssh-keys" && health?.ssh_enabled !== undefined && (
                    <Badge tone={health.ssh_enabled ? "mint" : "muted"}>
                      {health.ssh_enabled ? `SSH :${health.ssh_port ?? 2222}` : "SSH listener off"}
                    </Badge>
                  )}
                  {activeSection === "mcp" && hasRepos && <Badge tone="mint">use ≠ read</Badge>}
                </header>
              )}

              {activeSection === "profile" && (
                <ProfileSection user={user} onUserChange={onUserChange} />
              )}
              {activeSection === "security" && (
                <div className="space-y-4">
                  <PasswordSection user={user} />
                  <TotpSection user={user} onUserChange={onUserChange} />
                </div>
              )}
              {activeSection === "sessions" && <SessionsSection />}
              {activeSection === "tokens" && <TokensSection />}
              {activeSection === "ssh-keys" && (
                <SshKeysSection health={health} hasRepos={hasRepos} />
              )}
              {activeSection === "users" && owner && (
                <UsersSection
                  key={`users-${usersEpoch}`}
                  user={user}
                  onChanged={() => setDirectoryEpoch((n) => n + 1)}
                  onSelectSection={selectSection}
                />
              )}
              {activeSection === "offboarding" && owner && (
                <OffboardingSection
                  user={user}
                  hasRepos={hasRepos}
                  syncEpoch={directoryEpoch}
                  onOffboarded={() => {
                    setDirectoryEpoch((n) => n + 1);
                    setUsersEpoch((n) => n + 1);
                  }}
                />
              )}
              {activeSection === "directory" && owner && (
                <PeopleSection key={directoryEpoch} onDirectoryChange={onDirectoryChange} />
              )}
              {activeSection === "repositories" && owner && (
                <RepositoriesSection
                  repos={repos}
                  onReposReload={onReposReload}
                  onAddRepo={onAddRepo}
                />
              )}
              {activeSection === "workspace" && owner && <WorkspaceSection hasRepos={hasRepos} />}
              {activeSection === "mcp" &&
                (hasRepos ? (
                  <McpAgentsSection user={user} />
                ) : (
                  <RepoPrerequisiteCard
                    title="MCP & AI Agents"
                    description="Create or import a repository to generate scoped .mcp.json configs, stdio commands, and secret-brokering CLI wrappers for AI coding agents."
                    icon={IconCage}
                    onAddRepo={onAddRepo}
                  />
                ))}
              {activeSection === "github" &&
                owner &&
                (hasRepos ? (
                  <GithubCompanionSettingsSection user={user} hideHeader />
                ) : (
                  <RepoPrerequisiteCard
                    title="GitHub Sync"
                    description="Create or import a repository to configure GitHub remotes, mirror sync, and pull request publishing."
                    icon={GithubNavIcon}
                    onAddRepo={onAddRepo}
                  />
                ))}
              {activeSection === "activity" && <EventsSection />}
              {activeSection === "about" && (
                <AboutSection
                  health={health}
                  healthError={healthError}
                  onRetryHealth={onRetryHealth}
                  hasRepos={hasRepos}
                />
              )}
            </div>
          </SoloCardContext.Provider>
        </div>
      </div>
    </div>
  );
}
