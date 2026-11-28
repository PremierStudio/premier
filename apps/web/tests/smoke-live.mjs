#!/usr/bin/env node
// Live smoke test for a running Premier server. Zero dependencies, read-only GET requests only.
//
//   node tests/smoke-live.mjs [--url http://127.0.0.1:7420]
//   PREMIER_URL=https://git.example.com pnpm test:smoke
//
// Not part of `test:all` (that suite is offline). Exits 0 when every check passes, 1 otherwise.

const argv = process.argv.slice(2);
const urlFlag = argv.findIndex((a) => a === "--url" || a.startsWith("--url="));
const flagValue =
  urlFlag === -1 ? undefined : argv[urlFlag].includes("=") ? argv[urlFlag].split("=")[1] : argv[urlFlag + 1];
const BASE = (flagValue || process.env.PREMIER_URL || "http://127.0.0.1:7420").replace(/\/+$/, "");
const TIMEOUT_MS = Number(process.env.PREMIER_SMOKE_TIMEOUT_MS) || 10_000;

// /metrics is served on the loopback listener and hidden by the public proxy.
function isLoopbackUrl(base) {
  let hostname;
  try {
    hostname = new URL(base).hostname;
  } catch {
    return false;
  }
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

const LOOPBACK = isLoopbackUrl(BASE);

/** @type {{ name: string, ok: boolean, detail: string }[]} */
const results = [];

async function get(path) {
  const res = await fetch(`${BASE}${path}`, {
    redirect: "manual",
    signal: AbortSignal.timeout(TIMEOUT_MS),
    headers: { accept: "*/*" },
  });
  return { res, text: await res.text() };
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`body is not JSON: ${text.slice(0, 80)}`);
  }
}

function expect(cond, message) {
  if (!cond) throw new Error(message);
}

async function check(name, fn) {
  try {
    const detail = (await fn()) ?? "ok";
    results.push({ name, ok: true, detail: String(detail) });
  } catch (err) {
    const cause = err instanceof Error && err.cause ? ` (${err.cause.code ?? err.cause.message})` : "";
    results.push({ name, ok: false, detail: `${err instanceof Error ? err.message : err}${cause}` });
  }
}

const jsonEndpoint = (path) => async () => {
  const { res, text } = await get(path);
  expect(res.status === 200, `expected 200, got ${res.status}`);
  expect((res.headers.get("content-type") ?? "").includes("json"), `content-type is ${res.headers.get("content-type")}`);
  const body = parseJson(text);
  expect(body !== null && typeof body === "object", "body is not a JSON object");
  return `200 ${Object.keys(body).slice(0, 4).join(",")}`;
};

let indexHtml = "";

await check("GET /health", jsonEndpoint("/health"));
await check("GET /livez", jsonEndpoint("/livez"));
await check("GET /readyz", jsonEndpoint("/readyz"));

await check("GET /metrics", async () => {
  const { res, text } = await get("/metrics");
  if (LOOPBACK) {
    expect(res.status === 200, `expected 200, got ${res.status}`);
    expect((res.headers.get("content-type") ?? "").startsWith("text/plain"), `content-type is ${res.headers.get("content-type")}`);
    expect(text.includes("# HELP"), "no '# HELP' line");
    expect(/^premier_/m.test(text), "no premier_* series");
    return `200 ${text.split("\n").filter((l) => l.startsWith("premier_")).length} premier_* samples`;
  }
  expect(res.status === 404 || res.status === 403, `expected 404 or 403, got ${res.status}`);
  return `${res.status} metrics hidden on public origin`;
});

await check("GET /.well-known/openid-configuration", async () => {
  const { res, text } = await get("/.well-known/openid-configuration");
  expect(res.status === 200, `expected 200, got ${res.status}`);
  const doc = parseJson(text);
  expect(typeof doc.jwks_uri === "string" && doc.jwks_uri.length > 0, "missing jwks_uri");
  expect(JSON.stringify(doc).includes("EdDSA"), "EdDSA not advertised");
  return `200 jwks_uri=${doc.jwks_uri}`;
});

await check("GET /.well-known/jwks.json", async () => {
  const { res, text } = await get("/.well-known/jwks.json");
  expect(res.status === 200, `expected 200, got ${res.status}`);
  const doc = parseJson(text);
  expect(Array.isArray(doc.keys) && doc.keys.length > 0, "keys is not a non-empty array");
  const key = doc.keys.find((k) => k.kty === "OKP" && k.crv === "Ed25519");
  expect(key, "no OKP/Ed25519 key");
  expect(typeof key.x === "string" && key.x.length > 0, "Ed25519 key has no public value x");
  expect(!("d" in key), "JWK exposes a private key component (d)");
  const cache = res.headers.get("cache-control");
  expect(cache, "missing Cache-Control header");
  return `200 ${doc.keys.length} key(s), cache-control: ${cache}`;
});

await check("Security headers", async () => {
  const { res } = await get("/health");
  const h = (n) => res.headers.get(n);
  expect(h("x-content-type-options")?.toLowerCase() === "nosniff", `x-content-type-options: ${h("x-content-type-options")}`);
  expect(h("x-frame-options")?.toUpperCase() === "DENY", `x-frame-options: ${h("x-frame-options")}`);
  expect(h("referrer-policy"), "missing referrer-policy");
  const csp = h("content-security-policy") ?? "";
  expect(csp, "missing content-security-policy");
  const scriptSrc = csp.split(";").map((part) => part.trim()).find((part) => part.startsWith("script-src "));
  expect(scriptSrc === "script-src 'self'", `CSP script-src: ${scriptSrc ?? "missing"}`);
  expect(h("x-request-id"), "missing x-request-id");
  return `x-request-id=${h("x-request-id")}`;
});

await check("GET / (Studio HTML)", async () => {
  const { res, text } = await get("/");
  expect(res.status === 200, `expected 200, got ${res.status}`);
  expect((res.headers.get("content-type") ?? "").includes("text/html"), `content-type is ${res.headers.get("content-type")}`);
  expect(/id=["']root["']/.test(text), 'no <div id="root"> mount point');
  expect(/<script[^>]+src=/.test(text), "no <script src> bundle reference");
  indexHtml = text;
  return `200 ${text.length} bytes`;
});

await check("SPA JS/CSS assets", async () => {
  expect(indexHtml, "skipped: index.html unavailable");
  const refs = [
    ...indexHtml.matchAll(/<script[^>]+src=["']([^"']+)["']/g),
    ...indexHtml.matchAll(/<link[^>]+rel=["']stylesheet["'][^>]+href=["']([^"']+)["']/g),
  ].map((m) => m[1]).filter((u) => u.startsWith("/") && !u.startsWith("//"));
  expect(refs.length > 0, "index.html references no local assets");
  for (const ref of refs) {
    const { res, text } = await get(ref);
    expect(res.status === 200, `${ref}: expected 200, got ${res.status}`);
    expect(!(res.headers.get("content-type") ?? "").includes("text/html"), `${ref}: served as HTML (SPA fallback?), asset is missing`);
    expect(text.length > 0, `${ref}: empty body`);
  }
  return `${refs.length} asset(s) fetched`;
});

const width = Math.max(...results.map((r) => r.name.length));
console.log(`\nPremier live smoke: ${BASE}\n`);
for (const r of results) {
  console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name.padEnd(width)}  ${r.detail}`);
}
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} passed${failed ? `, ${failed} FAILED` : ""}`);
process.exit(failed ? 1 : 0);
