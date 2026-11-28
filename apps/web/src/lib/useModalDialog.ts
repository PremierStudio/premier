import {
  useCallback,
  useEffect,
  useRef,
  type KeyboardEvent as ReactKeyboardEvent,
  type RefObject,
} from "react";

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

export interface UseModalDialogOptions {
  open: boolean;
  onClose: () => void;
  /** Optional element inside the dialog to focus on open; defaults to first focusable or panel. */
  initialFocusRef?: RefObject<HTMLElement | null>;
  /** When false, Escape does not dismiss the dialog (e.g. while an irreversible request runs). */
  closeOnEscape?: boolean;
}

/**
 * Shared accessible modal hook:
 * - Restores focus to the opener element when the modal closes or unmounts.
 * - Moves initial focus into the dialog if nothing inside it is already focused.
 * - Traps Tab / Shift+Tab cycling within the dialog panel.
 * - Stops keydown propagation so global Studio shortcuts never fire behind the modal.
 * - Handles Escape dismissal consistently.
 */
export function useModalDialog({
  open,
  onClose,
  initialFocusRef,
  closeOnEscape = true,
}: UseModalDialogOptions) {
  const panelRef = useRef<HTMLDivElement>(null);
  const openerRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return;
    openerRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;

    const panel = panelRef.current;
    if (panel) {
      const active = document.activeElement;
      if (!active || !panel.contains(active)) {
        const target =
          initialFocusRef?.current ??
          panel.querySelector<HTMLElement>(FOCUSABLE_SELECTOR) ??
          panel;
        target.focus();
      }
    }

    const onWindowKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && closeOnEscape) {
        e.preventDefault();
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", onWindowKeyDown);

    return () => {
      window.removeEventListener("keydown", onWindowKeyDown);
      const opener = openerRef.current;
      openerRef.current = null;
      if (opener && opener.isConnected) {
        opener.focus();
      }
    };
  }, [open, onClose, closeOnEscape, initialFocusRef]);

  const onKeyDown = useCallback(
    (e: ReactKeyboardEvent) => {
      e.stopPropagation();
      e.nativeEvent.stopPropagation();
      if (e.key === "Escape") {
        if (closeOnEscape) {
          e.preventDefault();
          onClose();
        }
        return;
      }
      if (e.key !== "Tab") return;
      const panel = panelRef.current;
      if (!panel) return;
      const items = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement,
      );
      if (items.length === 0) {
        e.preventDefault();
        panel.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey) {
        if (!active || active === first || !panel.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else {
        if (!active || active === last || !panel.contains(active)) {
          e.preventDefault();
          first.focus();
        }
      }
    },
    [closeOnEscape, onClose],
  );

  return { panelRef, onKeyDown };
}
