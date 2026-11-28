import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  api,
  authApi,
  errorText,
  invalidateApiCache,
  onUnauthorized,
  setCurrentRepo,
  type Repo,
} from "../api";

// How the Studio's fetch layer behaves when the server is slow, down, restarted, or rejects a
// session. `fetch` is stubbed, so this runs offline with no server.

function reply(status: number, body: string, statusText = ""): Response {
  return new Response(status === 204 ? null : body, { status, statusText });
}
const json = (value: unknown, status = 200): Response => reply(status, JSON.stringify(value));

const repo = (over: Partial<Repo>): Repo => ({
  name: "premier",
  description: "",
  is_default: true,
  default_branch: "main",
  created_at: null,
  head_oid: null,
  ...over,
});

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  invalidateApiCache();
  setCurrentRepo(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCurrentRepo(null);
  invalidateApiCache();
});

describe("error responses", () => {
  it("turns a JSON error body into an ApiError carrying status and body", async () => {
    fetchMock.mockResolvedValueOnce(json({ error: "branch is protected" }, 409));
    const err = await api.branches().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(409);
    expect((err as ApiError).body).toEqual({ error: "branch is protected" });
    expect(errorText(err)).toBe("branch is protected");
  });

  it("keeps a non-JSON 5xx page (proxy error) readable and body-less", async () => {
    fetchMock.mockResolvedValueOnce(reply(502, "<html>Bad Gateway</html>", "Bad Gateway"));
    const err = (await api.repos().catch((e: unknown) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(502);
    expect(err.body).toBeNull();
    expect(err.message).toContain("502 Bad Gateway");
  });

  it("ignores a JSON error body that is not an object", async () => {
    fetchMock.mockResolvedValueOnce(reply(500, "null"));
    const err = (await api.repos().catch((e: unknown) => e)) as ApiError;
    expect(err.body).toBeNull();
  });

  it("propagates a network failure instead of swallowing it", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError("Failed to fetch"));
    await expect(api.health()).rejects.toThrow("Failed to fetch");
    expect(errorText(new TypeError("Failed to fetch"))).toBe("Failed to fetch");
  });

  it("answers 204 with undefined rather than a JSON parse error", async () => {
    fetchMock.mockResolvedValueOnce(reply(204, ""));
    await expect(authApi.logout()).resolves.toBeUndefined();
  });

  it("explains 403 and 429 for inline forms", () => {
    expect(errorText(new ApiError("403", 403, null))).toBe("Owner only.");
    expect(errorText(new ApiError("403", 403, { error: "needs 2fa" }))).toBe("needs 2fa");
    expect(errorText(new ApiError("429", 429, null))).toBe("Too many attempts. Try again later.");
  });
});

describe("session expiry (401)", () => {
  it("notifies the single unauthorized listener, and unsubscribing stops it", async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    fetchMock.mockImplementation(async () => reply(401, "{}"));

    await expect(api.repos()).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);

    off();
    await expect(api.repos()).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("does not treat a wrong password on an auth mutation as an expired session", async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    fetchMock.mockResolvedValueOnce(json({ error: "invalid credentials" }, 401));
    await expect(authApi.login({ username: "a", password: "b" })).rejects.toBeInstanceOf(ApiError);
    expect(listener).not.toHaveBeenCalled();
    off();
  });

  it("still signs out on a 401 from a GET under /v1/auth/", async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    fetchMock.mockResolvedValueOnce(reply(401, "{}"));
    await expect(authApi.sessions()).rejects.toBeInstanceOf(ApiError);
    expect(listener).toHaveBeenCalledTimes(1);
    off();
  });

  it("keeps the session on 403 (owner-only call)", async () => {
    const listener = vi.fn();
    const off = onUnauthorized(listener);
    fetchMock.mockResolvedValueOnce(reply(403, "{}"));
    await expect(api.repos()).rejects.toBeInstanceOf(ApiError);
    expect(listener).not.toHaveBeenCalled();
    off();
  });
});

describe("read cache", () => {
  it("serves a repeated cacheable GET from cache, and a failure is not cached", async () => {
    fetchMock
      .mockResolvedValueOnce(reply(503, "down"))
      .mockResolvedValueOnce(json([{ name: "main" }]));
    await expect(api.branches()).rejects.toBeInstanceOf(ApiError);
    await expect(api.branches()).resolves.toEqual([{ name: "main" }]);
    await expect(api.branches()).resolves.toEqual([{ name: "main" }]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("shares one in-flight request between concurrent callers", async () => {
    fetchMock.mockImplementation(async () => json([]));
    await Promise.all([api.branches(), api.branches(), api.branches()]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("drops cached reads after a mutation so the Studio never shows stale data", async () => {
    fetchMock.mockImplementation(async () => json([]));
    await api.branches();
    await api.branches();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await authApi.revokeSession("abc");
    await api.branches();
    expect(fetchMock).toHaveBeenCalledTimes(3); // revoke + refetch
  });

  it("invalidateApiCache forces the next read to the network (SSE resync)", async () => {
    fetchMock.mockImplementation(async () => json([]));
    await api.branches();
    invalidateApiCache();
    await api.branches();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("repo scoping", () => {
  it("routes non-default repositories through /r/<name> and leaves the default bare", async () => {
    fetchMock.mockImplementation(async () => json([]));
    setCurrentRepo(repo({ name: "team/app", is_default: false }));
    await api.branches();
    expect(fetchMock.mock.calls[0]?.[0]).toBe("/r/team%2Fapp/v1/branches");

    setCurrentRepo(repo({}));
    invalidateApiCache();
    await api.branches();
    expect(fetchMock.mock.calls[1]?.[0]).toBe("/v1/branches");
  });
});
