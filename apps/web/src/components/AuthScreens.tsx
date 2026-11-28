import { useEffect, useId, useRef, useState, type FormEvent, type InputHTMLAttributes, type ReactNode, type Ref } from "react";
import { ApiError, authApi, type AuthStatus } from "../api";
import { ErrorNote, Field, INPUT_CLASS, PRIMARY_BTN, SECONDARY_BTN, useAction } from "./forms";
import { IconRefresh, PremierMark } from "./Icons";

function AuthShell({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children?: ReactNode;
}) {
  return (
    <div className="pr-stage-backdrop flex min-h-[100dvh] items-center justify-center overflow-y-auto px-4 py-10 text-[#f3f6fd]">
      <main className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center space-y-2.5 text-center">
          <div className="pr-icon-tile flex h-12 w-12 items-center justify-center rounded-2xl">
            <PremierMark className="h-7 w-7" />
          </div>
          <span className="text-[15px] font-semibold tracking-[-0.02em] text-[#eef3fc]">
            Premier
          </span>
        </div>
        <div className="pr-elevated relative overflow-hidden rounded-2xl p-5 sm:p-6">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-[#cfe0ff]/30 to-transparent"
          />
          <h1 className="bg-gradient-to-b from-white via-[#eef3fc] to-[#a7b6d2] bg-clip-text text-[19px] font-semibold tracking-[-0.02em] text-transparent">
            {title}
          </h1>
          <p className="mt-1 text-[14px] leading-relaxed text-[#b6c3db]">{subtitle}</p>
          {children && <div className="mt-5">{children}</div>}
        </div>
      </main>
    </div>
  );
}

/** Shown while the first status call is in flight, or when the server cannot be reached. */
export function AuthLoadingScreen({ error, onRetry }: { error: string | null; onRetry: () => void }) {
  // Fast boots resolve well inside 200ms; showing the card only after that avoids a one-frame flash.
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = window.setTimeout(() => setVisible(true), 200);
    return () => window.clearTimeout(t);
  }, []);
  if (!error && !visible) return <div aria-hidden="true" className="min-h-[100dvh]" />;
  return (
    <AuthShell
      title={error ? "Can't reach the server" : "Connecting…"}
      subtitle={error ? "The Premier server did not answer." : "Checking your session."}
    >
      {error ? (
        <div className="space-y-3">
          <ErrorNote message={error} />
          <button type="button" onClick={onRetry} className={`${SECONDARY_BTN} w-full`}>
            <IconRefresh className="h-4 w-4" />
            <span>Try again</span>
          </button>
        </div>
      ) : (
        <div
          role="status"
          aria-live="polite"
          aria-label="Connecting to server"
          className="space-y-2.5"
        >
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06]">
            <div className="pr-shimmer h-full w-full rounded-full" />
          </div>
          <div className="flex items-center gap-2">
            <div className="pr-shimmer h-2.5 w-2/5 rounded-full" />
            <div className="pr-shimmer h-2.5 w-1/4 rounded-full opacity-70" />
          </div>
        </div>
      )}
    </AuthShell>
  );
}

/** Password input with a show/hide toggle. */
function PasswordField({
  label,
  hint,
  ref,
  ...input
}: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  label: string;
  hint?: string;
  ref?: Ref<HTMLInputElement>;
}) {
  const id = useId();
  const [shown, setShown] = useState(false);
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-[13.5px] font-medium text-[#d2dbee]">
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          ref={ref}
          type={shown ? "text" : "password"}
          maxLength={1024}
          aria-describedby={hint ? `${id}-hint` : undefined}
          className={`${INPUT_CLASS} pr-16`}
          {...input}
        />
        <button
          type="button"
          onClick={() => setShown((v) => !v)}
          aria-pressed={shown}
          aria-label={shown ? "Hide password" : "Show password"}
          className="absolute inset-y-0 right-1.5 my-auto h-7 rounded-lg px-2 text-[13px] text-[#9ec0f5] hover:bg-white/[0.06] hover:text-[#f3f6fd]"
        >
          {shown ? "Hide" : "Show"}
        </button>
      </div>
      {hint && (
        <p id={`${id}-hint`} className="text-[13px] text-[#98a8c4]">
          {hint}
        </p>
      )}
    </div>
  );
}

export function SetupScreen({ onDone }: { onDone: (status: AuthStatus) => void }) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const confirmRef = useRef<HTMLInputElement>(null);
  const action = useAction();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (password !== confirm) {
      action.setError("The two passwords don't match.");
      confirmRef.current?.select();
      return;
    }
    void action.run(async () =>
      onDone(
        await authApi.setup({
          username,
          password,
          display_name: displayName.trim() || undefined,
        }),
      ),
    );
  };

  return (
    <AuthShell
      title="Create the owner account"
      subtitle="This server has no account yet. The owner controls policy, secrets, and access tokens."
    >
      <form onSubmit={submit} className="space-y-3.5">
        <Field
          label="Username"
          name="username"
          autoComplete="username"
          autoCapitalize="none"
          spellCheck={false}
          autoFocus
          required
          pattern="[a-z0-9_\-]{2,32}"
          title="2–32 characters: lowercase letters, digits, _ or -"
          hint="2–32 characters: lowercase letters, digits, _ or -"
          value={username}
          onChange={(e) => setUsername(e.target.value.toLowerCase())}
          className="font-mono"
        />
        <Field
          label="Display name (optional)"
          name="display_name"
          autoComplete="name"
          maxLength={64}
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
        />
        <PasswordField
          label="Password"
          name="new-password"
          autoComplete="new-password"
          required
          minLength={10}
          hint="At least 10 characters."
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <PasswordField
          ref={confirmRef}
          label="Confirm password"
          name="confirm-password"
          autoComplete="new-password"
          required
          minLength={10}
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        <ErrorNote message={action.error} />
        <button type="submit" disabled={action.pending} className={`${PRIMARY_BTN} w-full`}>
          {action.pending ? "Creating account…" : "Create account"}
        </button>
      </form>
    </AuthShell>
  );
}

export function SignInScreen({
  onDone,
  reason,
}: {
  onDone: (status: AuthStatus) => void;
  /** "expired": the session ended while the app was open. */
  reason?: "expired";
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [code, setCode] = useState("");
  const passwordRef = useRef<HTMLInputElement>(null);
  const codeRef = useRef<HTMLInputElement>(null);
  const action = useAction();

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void action.run(async () => {
      try {
        onDone(
          await authApi.login({
            username: username.trim().toLowerCase(),
            password,
            totp_code: needTotp ? code : undefined,
          }),
        );
      } catch (err: unknown) {
        const totpRequired =
          err instanceof ApiError && err.status === 401 && err.body?.totp_required === true;
        if (totpRequired && !needTotp) {
          // Password accepted; the code field autofocuses when it mounts.
          setNeedTotp(true);
          return;
        }
        if (needTotp) {
          setCode("");
          codeRef.current?.focus();
        } else {
          passwordRef.current?.select();
        }
        throw err;
      }
    });
  };

  const backToPassword = () => {
    setNeedTotp(false);
    setCode("");
    action.setError(null);
  };

  return (
    <AuthShell
      title={needTotp ? "Two-factor code" : "Sign in"}
      subtitle={
        needTotp
          ? "Enter the 6-digit code from your authenticator app, or a recovery code."
          : reason === "expired"
            ? "Your session expired. Sign in to continue."
            : "Use your Premier account to continue."
      }
    >
      <form onSubmit={submit} className="space-y-3.5">
        {/* Kept mounted (hidden) on the code step so password managers still see one login form. */}
        <div className={needTotp ? "hidden" : "space-y-3.5"}>
          <Field
            label="Username"
            name="username"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value.toLowerCase())}
            className="font-mono"
          />
          <PasswordField
            ref={passwordRef}
            label="Password"
            name="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        {needTotp && (
          <Field
            ref={codeRef}
            label="6-digit code or a recovery code"
            name="totp_code"
            autoComplete="one-time-code"
            autoCapitalize="none"
            spellCheck={false}
            autoFocus
            required
            value={code}
            onChange={(e) => setCode(e.target.value.trim())}
            className="font-mono"
          />
        )}
        <ErrorNote message={action.error} />
        <button type="submit" disabled={action.pending} className={`${PRIMARY_BTN} w-full`}>
          {action.pending ? "Signing in…" : needTotp ? "Verify" : "Sign in"}
        </button>
        {needTotp && (
          <button
            type="button"
            onClick={backToPassword}
            disabled={action.pending}
            className={`${SECONDARY_BTN} w-full`}
          >
            Back
          </button>
        )}
      </form>
    </AuthShell>
  );
}
