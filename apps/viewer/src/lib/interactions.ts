export interface FocusTrapOptions {
  enabled?: boolean;
  initialFocus?: string;
  onEscape?: () => void;
}

const focusableSelector = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])'
].join(',');

export function focusTrap(node: HTMLElement, options: FocusTrapOptions = {}) {
  let current = options;
  let previousFocus: HTMLElement | null = null;
  let active = false;

  const focusables = () => [...node.querySelectorAll<HTMLElement>(focusableSelector)]
    .filter((element) => !element.hidden && element.getAttribute('aria-hidden') !== 'true');

  const focusInitial = () => {
    const requested = current.initialFocus ? node.querySelector<HTMLElement>(current.initialFocus) : null;
    const target = requested && !requested.hasAttribute('disabled') ? requested : focusables()[0] ?? node;
    target.focus({ preventScroll: true });
  };

  const enable = () => {
    if (active || current.enabled === false) return;
    active = true;
    previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    queueMicrotask(focusInitial);
  };

  const disable = (restore = true) => {
    if (!active) return;
    active = false;
    const restoreTarget = previousFocus;
    if (restore && restoreTarget) queueMicrotask(() => {
      if (restoreTarget.isConnected) restoreTarget.focus({ preventScroll: true });
    });
    previousFocus = null;
  };

  const keydown = (event: KeyboardEvent) => {
    if (!active) return;
    if (event.key === 'Escape' && current.onEscape) {
      event.preventDefault();
      event.stopPropagation();
      current.onEscape();
      return;
    }
    if (event.key !== 'Tab') return;
    const items = focusables();
    if (!items.length) {
      event.preventDefault();
      node.focus();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  node.addEventListener('keydown', keydown);
  enable();

  return {
    update(next: FocusTrapOptions) {
      current = next;
      if (next.enabled === false) disable();
      else enable();
    },
    destroy() {
      node.removeEventListener('keydown', keydown);
      disable();
    }
  };
}

/** Move an overlay to the document root so transformed/backdrop-filter ancestors cannot offset it. */
export function portal(node: HTMLElement) {
  document.body.appendChild(node);
  return { destroy: () => node.remove() };
}
