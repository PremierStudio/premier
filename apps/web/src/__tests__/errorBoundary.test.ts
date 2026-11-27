import { createElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary, type ErrorBoundaryProps, isChunkLoadError } from "../components/ErrorBoundary";

// The vitest environment is `node` (no jsdom / testing-library), so the boundary is driven the way
// React drives it: getDerivedStateFromError -> state -> render(), plus its lifecycle methods called
// directly. Rendering goes through react-dom/server.

type Internals = {
  state: { error: Error | null; retryNonce: number };
  props: ErrorBoundaryProps;
  setState: (u: unknown) => void;
  handleReloadTab: () => void;
  handleHardReload: () => void;
};

type Boundary = Pick<ErrorBoundary, "render" | "componentDidCatch" | "componentDidUpdate"> & Internals;

/** An ErrorBoundary instance whose setState applies synchronously, like React's batched flush. */
function makeBoundary(props: ErrorBoundaryProps = {}): Boundary {
  const b = new ErrorBoundary(props) as unknown as Boundary;
  b.setState = (u: unknown) => {
    const next = typeof u === "function" ? (u as (s: Internals["state"]) => object)(b.state) : u;
    b.state = { ...b.state, ...(next as object) };
  };
  return b;
}

function crash(b: Boundary, error: Error): void {
  b.state = { ...b.state, ...ErrorBoundary.getDerivedStateFromError(error) } as Internals["state"];
}

const html = (b: Pick<ErrorBoundary, "render">): string =>
  renderToStaticMarkup(createElement(() => b.render() as ReactNode));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("isChunkLoadError", () => {
  it.each([
    "Failed to fetch dynamically imported module: /assets/Files-abc.js",
    "Importing a module script failed.",
    "error loading dynamically imported module: /assets/x.js",
    "Loading chunk 7 failed.",
  ])("matches %s", (message) => {
    expect(isChunkLoadError(new Error(message))).toBe(true);
  });

  it("matches by error name and rejects ordinary errors", () => {
    const named = new Error("x");
    named.name = "ChunkLoadError";
    expect(isChunkLoadError(named)).toBe(true);
    expect(isChunkLoadError(new TypeError("undefined is not a function"))).toBe(false);
    expect(isChunkLoadError(new Error(""))).toBe(false);
  });
});

describe("ErrorBoundary fallback rendering", () => {
  it("passes children through untouched while healthy", () => {
    const b = makeBoundary({ children: createElement("main", null, "Studio body") });
    expect(html(b)).toBe("<main>Studio body</main>");
  });

  it("scopes the fallback copy and falls back to 'Studio' without a scope", () => {
    const scoped = makeBoundary({ scope: "Branches" });
    crash(scoped, new Error("kaboom"));
    const scopedHtml = html(scoped);
    expect(scopedHtml).toContain('role="alert"');
    expect(scopedHtml).toContain("View Crashed");
    expect(scopedHtml).toContain("Branches ran into an unexpected error");
    expect(scopedHtml).toContain("kaboom");
    expect(scopedHtml).toContain("Other tabs remain unaffected");

    const bare = makeBoundary();
    crash(bare, new Error("x"));
    expect(html(bare)).toContain("Studio ran into an unexpected error");
  });

  it("uses a generic detail when the error has no message", () => {
    const b = makeBoundary({ scope: "Traces" });
    crash(b, new Error("   "));
    expect(html(b)).toContain("An unexpected rendering error occurred.");
  });

  it("explains a stale bundle for chunk-load failures instead of a crash", () => {
    const b = makeBoundary({ scope: "Files" });
    crash(b, new TypeError("Failed to fetch dynamically imported module: /assets/Files.js"));
    const out = html(b);
    expect(out).toContain("Bundle Update Needed");
    expect(out).toContain("load the Files module");
    expect(out).toContain("server may have been updated");
    expect(out).not.toContain("View Crashed");
  });

  it("escapes error text (no HTML injection through error messages)", () => {
    const b = makeBoundary();
    crash(b, new Error('<img src=x onerror="alert(1)">'));
    const out = html(b);
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img");
  });

  it("renders a full-viewport shell only for the root boundary", () => {
    const root = makeBoundary({ fullScreen: true });
    const pane = makeBoundary();
    crash(root, new Error("a"));
    crash(pane, new Error("a"));
    expect(html(root)).toContain("min-h-[100dvh]");
    expect(html(pane)).not.toContain("min-h-[100dvh]");
  });
});

describe("ErrorBoundary recovery", () => {
  it("getDerivedStateFromError captures the error", () => {
    const err = new Error("boom");
    expect(ErrorBoundary.getDerivedStateFromError(err)).toEqual({ error: err });
  });

  it("logs the crash with its scope and component stack", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const b = makeBoundary({ scope: "Secrets" });
    const err = new Error("boom");
    b.componentDidCatch(err, { componentStack: "\n  at Secrets" });
    expect(spy).toHaveBeenCalledWith("[ErrorBoundary:Secrets]", err, "\n  at Secrets");
  });

  it("'Reload tab' clears the error, bumps the retry key and calls onReset", () => {
    const onReset = vi.fn();
    const b = makeBoundary({ onReset });
    crash(b, new Error("boom"));
    b.handleReloadTab();
    expect(onReset).toHaveBeenCalledTimes(1);
    expect(b.state.error).toBeNull();
    expect(b.state.retryNonce).toBe(1);
    b.handleReloadTab();
    expect(b.state.retryNonce).toBe(2);
  });

  it("'Hard reload' reloads the window and is a no-op without one", () => {
    const reload = vi.fn();
    vi.stubGlobal("window", { location: { reload } });
    makeBoundary().handleHardReload();
    expect(reload).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
    expect(() => makeBoundary().handleHardReload()).not.toThrow();
  });

  it("clears a caught error when resetKey changes (repo or tab switch), and only then", () => {
    const b = makeBoundary({ resetKey: "repoA:code" });
    crash(b, new Error("boom"));

    b.componentDidUpdate({ resetKey: "repoA:code" });
    expect(b.state.error).not.toBeNull();

    b.props = { ...b.props, resetKey: "repoB:code" };
    b.componentDidUpdate({ resetKey: "repoA:code" });
    expect(b.state.error).toBeNull();
    expect(b.state.retryNonce).toBe(1);
  });

  it("does not bump the retry key on a resetKey change when nothing crashed", () => {
    const b = makeBoundary({ resetKey: 1 });
    b.props = { ...b.props, resetKey: 2 };
    b.componentDidUpdate({ resetKey: 1 });
    expect(b.state.retryNonce).toBe(0);
  });
});
