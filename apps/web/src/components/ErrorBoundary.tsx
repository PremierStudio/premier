import { Component, Fragment, type ErrorInfo, type ReactNode } from "react";

export interface ErrorBoundaryProps {
  children?: ReactNode;
  /** Human-readable scope shown in the fallback card (e.g., "Premier Studio", "Traces"). */
  scope?: string;
  /** Render full-viewport centered fallback (used at the root app boundary). */
  fullScreen?: boolean;
  /** Changing this key clears a caught error automatically (e.g., repo switch). */
  resetKey?: string | number;
  /** Optional hook called when the user clicks "Reload tab". */
  onReset?: () => void;
}

interface ErrorBoundaryState {
  error: Error | null;
  retryNonce: number;
}

const CHUNK_ERROR_RE =
  /Failed to fetch dynamically imported module|Importing a module script failed|Loading chunk|ChunkLoadError|error loading dynamically imported module/i;

export function isChunkLoadError(error: Error | null): boolean {
  if (!error) return false;
  return CHUNK_ERROR_RE.test(error.name) || CHUNK_ERROR_RE.test(error.message);
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = {
    error: null,
    retryNonce: 0,
  };

  static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(`[ErrorBoundary:${this.props.scope ?? "Studio"}]`, error, info.componentStack);
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps): void {
    if (this.state.error && prevProps.resetKey !== this.props.resetKey) {
      this.setState((prev) => ({ error: null, retryNonce: prev.retryNonce + 1 }));
    }
  }

  private handleReloadTab = (): void => {
    this.props.onReset?.();
    this.setState((prev) => ({ error: null, retryNonce: prev.retryNonce + 1 }));
  };

  private handleHardReload = (): void => {
    if (typeof window !== "undefined") {
      window.location.reload();
    }
  };

  render(): ReactNode {
    const { error, retryNonce } = this.state;
    if (!error) {
      return <Fragment key={retryNonce}>{this.props.children}</Fragment>;
    }

    const scopeLabel = this.props.scope ?? "Studio";
    const chunkError = isChunkLoadError(error);
    const detail = error.message?.trim() || "An unexpected rendering error occurred.";

    return (
      <div
        role="alert"
        className={
          this.props.fullScreen
            ? "pr-shell-bg flex min-h-[100dvh] w-full items-center justify-center p-6 text-[#f5f7fd]"
            : "flex min-h-0 flex-1 items-center justify-center p-6 text-[#f5f7fd]"
        }
      >
        <div className="pr-elevated w-full max-w-lg rounded-2xl p-6">
          <div className="flex items-start gap-3">
            <span
              aria-hidden="true"
              className="mt-0.5 inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-[#f27c7c]/30 bg-[#f27c7c]/12 font-mono text-[14px] font-semibold text-[#f27c7c]"
            >
              !
            </span>
            <div className="min-w-0 flex-1 space-y-1.5">
              <p className="font-mono text-[12px] uppercase tracking-wider text-[#f27c7c]">
                {chunkError ? "Bundle Update Needed" : "View Crashed"} · {scopeLabel}
              </p>
              <h2 className="text-[16px] font-semibold tracking-[-0.015em] text-[#f5f7fd]">
                {chunkError
                  ? `Couldn't load the ${scopeLabel} module`
                  : `${scopeLabel} ran into an unexpected error`}
              </h2>
              <p className="text-[13.5px] leading-relaxed text-[#a6b5cf]">
                {chunkError
                  ? "The server may have been updated while this tab was open. Reload the tab or run a hard reload to fetch the latest bundle."
                  : "Other tabs remain unaffected. You can retry rendering this view or hard reload Premier Studio."}
              </p>
            </div>
          </div>

          <pre className="pr-well mt-4 max-h-36 overflow-auto rounded-xl px-3.5 py-2.5 font-mono text-[12px] leading-relaxed text-[#d2dbee] whitespace-pre-wrap break-words">
            {detail}
          </pre>

          <div className="mt-5 flex flex-wrap items-center justify-end gap-2">
            <button
              type="button"
              onClick={this.handleReloadTab}
              className="pr-pill inline-flex h-9 items-center justify-center rounded-full px-4 text-[13.5px] font-medium text-[#dce4f5] transition hover:text-white"
            >
              Reload tab
            </button>
            <button
              type="button"
              onClick={this.handleHardReload}
              className="pr-action-btn inline-flex h-9 items-center justify-center rounded-full px-4 text-[13.5px] font-medium"
            >
              Hard reload
            </button>
          </div>
        </div>
      </div>
    );
  }
}
