import {
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type Ref,
} from "react";
import { errorText } from "../api";
import { formatTime, isoTime } from "../lib/format";
import { IconLock, IconQuarantine } from "./Icons";

export const INPUT_CLASS =
  "h-10 w-full rounded-xl border border-white/[0.11] bg-black/35 px-3.5 py-2 text-[14px] text-[#f5f7fd] placeholder:text-[#8e9eb8] focus:border-[#9ec0f5]/50 focus:outline-none focus-visible:border-[#9ec0f5]/70 focus-visible:ring-2 focus-visible:ring-[#9ec0f5]/45 disabled:opacity-60";

export const SELECT_CLASS =
  "h-10 w-full rounded-xl border border-white/[0.11] bg-[#0d1224] [color-scheme:dark] px-3.5 py-2 text-[14px] text-[#f5f7fd] focus:border-[#9ec0f5]/50 focus:outline-none focus-visible:border-[#9ec0f5]/70 focus-visible:ring-2 focus-visible:ring-[#9ec0f5]/45 disabled:opacity-60";

export const PRIMARY_BTN =
  "pr-action-btn inline-flex h-10 items-center justify-center gap-1.5 rounded-xl px-4 py-2 text-[13.5px] disabled:cursor-not-allowed disabled:bg-none disabled:bg-white/[0.06] disabled:text-[#7c8ca8] disabled:border-white/[0.08] disabled:shadow-none disabled:filter-none";

export const SECONDARY_BTN =
  "pr-pill inline-flex h-10 items-center justify-center gap-1.5 rounded-xl px-3.5 py-2 text-[13.5px] text-[#dce4f5] disabled:cursor-not-allowed disabled:opacity-45";

export const DANGER_BTN =
  "inline-flex h-10 items-center justify-center gap-1.5 rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3.5 py-2 text-[13.5px] text-[#f27c7c] transition hover:bg-[#f27c7c]/18 disabled:cursor-not-allowed disabled:border-white/[0.08] disabled:bg-white/[0.05] disabled:text-[#7c8ca8]";

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: string;
  ref?: Ref<HTMLInputElement>;
}

/** Labelled input; the label is always a real <label> bound by id. */
export function Field({ label, hint, className, ...input }: FieldProps) {
  const id = useId();
  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-[13px] font-medium text-[#d2dbee]">
        {label}
      </label>
      <input
        id={id}
        aria-describedby={hint ? `${id}-hint` : undefined}
        className={`${INPUT_CLASS} ${className ?? ""}`}
        {...input}
      />
      {hint && (
        <p id={`${id}-hint`} className="text-[12px] text-[#8e9eb8]">
          {hint}
        </p>
      )}
    </div>
  );
}

/** Six-digit authenticator code input. */
export function CodeField(props: Omit<FieldProps, "label"> & { label?: string }) {
  return (
    <Field
      label="6-digit code"
      inputMode="numeric"
      autoComplete="one-time-code"
      pattern="[0-9]{6}"
      maxLength={6}
      placeholder="000000"
      required
      {...props}
      className={`font-mono tracking-[0.3em] ${props.className ?? ""}`}
    />
  );
}

export function ErrorNote({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/10 px-3 py-2 text-[13.5px] text-[#f27c7c]"
    >
      <IconQuarantine className="mt-px h-4 w-4" />
      <span className="min-w-0 break-words">{message}</span>
    </div>
  );
}

/** Stand-in for a panel whose data only owners may load. */
export function OwnerOnly({ className = "" }: { className?: string }) {
  return (
    <div
      className={`flex items-center justify-center gap-2 p-4 text-center text-[13.5px] text-[#98a8c4] ${className}`}
    >
      <IconLock className="h-4 w-4 shrink-0" />
      <span>Only owners can view this</span>
    </div>
  );
}

/** A timestamp in the app's one format, with the full ISO value on hover. */
export function Time({ value }: { value: string | null | undefined }) {
  const iso = isoTime(value);
  return (
    <time dateTime={iso} title={iso}>
      {formatTime(value)}
    </time>
  );
}

/** Button that swaps in place for "Are you sure? [Cancel] [Confirm]"; no modal. */
export function ConfirmButton({
  onConfirm,
  confirmLabel = "Confirm",
  question = "Are you sure?",
  children,
  ...button
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  onConfirm: () => void;
  confirmLabel?: string;
  question?: string;
}) {
  const [asking, setAsking] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef(false);

  useEffect(() => {
    if (button.disabled && asking) {
      setAsking(false);
    }
  }, [button.disabled, asking]);

  useEffect(() => {
    if (!asking && restoreFocusRef.current) {
      restoreFocusRef.current = false;
      triggerRef.current?.focus();
    }
  }, [asking]);

  if (!asking) {
    return (
      <button
        ref={triggerRef}
        type="button"
        {...button}
        onClick={() => {
          if (!button.disabled) setAsking(true);
        }}
      >
        {children}
      </button>
    );
  }
  return (
    <span
      role="group"
      aria-label={button["aria-label"]}
      className="inline-flex shrink-0 flex-wrap items-center justify-end gap-1.5 text-[13px] text-[#d2dbee]"
    >
      <span>{question}</span>
      <button
        type="button"
        autoFocus
        onClick={() => {
          restoreFocusRef.current = true;
          setAsking(false);
        }}
        className={`${SECONDARY_BTN} px-2.5! py-1.5! text-[13px]!`}
      >
        Cancel
      </button>
      <button
        type="button"
        disabled={button.disabled}
        onClick={() => {
          if (button.disabled) return;
          setAsking(false);
          onConfirm();
        }}
        className={`${DANGER_BTN} px-2.5! py-1.5! text-[13px]!`}
      >
        {confirmLabel}
      </button>
    </span>
  );
}

/** Pending/error state for one async action; `run` resolves true on success. */
export function useAction() {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (fn: () => Promise<unknown>): Promise<boolean> => {
    setPending(true);
    setError(null);
    try {
      await fn();
      return true;
    } catch (err: unknown) {
      setError(errorText(err));
      return false;
    } finally {
      setPending(false);
    }
  };
  return { pending, error, setError, run };
}
