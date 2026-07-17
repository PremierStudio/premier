import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';

// Rehearses scripts/preflight-npm-trusted-publishing.mjs against a stub GitHub
// OIDC issuer and a stub npm registry, proving the release gate succeeds only
// when every published package has a trusted publisher, fails with remediation
// output when one is missing, and refuses to run outside GitHub Actions —
// all without contacting npmjs.com.

const root = resolve(import.meta.dirname, '../..');
const preflight = join(root, 'scripts', 'preflight-npm-trusted-publishing.mjs');

// The publish job is the source of truth for what the preflight must cover.
const releaseWorkflow = readFileSync(join(root, '.github', 'workflows', 'release.yml'), 'utf8');
const publishedPackages = [...releaseWorkflow.matchAll(/publish_if_missing (\S+) \S+/g)].map((match) => match[1]);
assert.equal(publishedPackages.length, 6, 'release.yml must publish six npm packages');

const issuedAudiences = [];
const exchangedPackages = [];
let trustedPackages = new Set();

const stub = createServer((request, response) => {
  const url = new URL(request.url, 'http://stub');
  if (request.method === 'GET' && url.pathname === '/oidc-token') {
    assert.equal(request.headers.authorization, 'Bearer runner-request-token');
    issuedAudiences.push(url.searchParams.get('audience'));
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ value: 'stub-github-id-token' }));
    return;
  }
  if (request.method === 'POST' && url.pathname.startsWith('/-/npm/v1/oidc/token/exchange/package/')) {
    assert.equal(request.headers.authorization, 'Bearer stub-github-id-token');
    const name = decodeURIComponent(url.pathname.split('/package/')[1]);
    exchangedPackages.push(name);
    response.setHeader('content-type', 'application/json');
    if (trustedPackages.has(name)) {
      response.end(JSON.stringify({ token: `stub-publish-token-for-${name}` }));
    } else {
      response.statusCode = 404;
      response.end(JSON.stringify({ message: `${name} has no GitHub Actions trusted publisher for this workflow` }));
    }
    return;
  }
  response.statusCode = 500;
  response.end('unexpected request');
});
await new Promise((ready) => stub.listen(0, '127.0.0.1', ready));
const port = stub.address().port;

// The child fetches from the stub, so the parent event loop must stay free to
// answer — an async spawn, never spawnSync.
async function runPreflight(environment) {
  const result = await promisify(execFile)(process.execPath, [preflight], {
    cwd: root,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, ...environment },
  }).catch((error) => error);
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  return { ...result, status: result.code ?? 0 };
}

const actionsEnvironment = {
  ACTIONS_ID_TOKEN_REQUEST_URL: `http://127.0.0.1:${port}/oidc-token?api-version=2.0`,
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-request-token',
  PREMIER_NPM_REGISTRY: `http://127.0.0.1:${port}`,
};

try {
  process.stdout.write('› every package trusted: preflight must pass\n');
  trustedPackages = new Set(publishedPackages);
  const accepted = await runPreflight(actionsEnvironment);
  assert.equal(accepted.status, 0, 'preflight must succeed when all trusted publishers exist');
  for (const name of publishedPackages) {
    assert.ok(accepted.stdout.includes(`${name}: trusted publisher accepted this workflow`));
  }
  assert.deepEqual(new Set(exchangedPackages), new Set(publishedPackages),
    'preflight must exercise exactly the packages the publish job publishes');
  assert.deepEqual([...new Set(issuedAudiences)], ['npm:127.0.0.1'],
    'OIDC audience must be derived from PREMIER_NPM_REGISTRY so rehearsal tokens cannot reach npmjs.com');

  process.stdout.write('\n› missing trusted publishers: preflight must fail with remediation\n');
  trustedPackages = new Set(publishedPackages.slice(2));
  const rejected = await runPreflight(actionsEnvironment);
  assert.equal(rejected.status, 1, 'preflight must fail when any trusted publisher is missing');
  assert.ok(rejected.stderr.includes('rejected 2 of 6 packages'));
  for (const name of publishedPackages.slice(0, 2)) {
    assert.ok(rejected.stderr.includes(`${name}: HTTP 404`));
  }
  assert.ok(rejected.stderr.includes('give each package a GitHub Actions trusted publisher'));

  process.stdout.write('\n› outside GitHub Actions: preflight must refuse to guess\n');
  const guarded = await runPreflight({ PREMIER_NPM_REGISTRY: `http://127.0.0.1:${port}` });
  assert.equal(guarded.status, 1, 'preflight must fail without GitHub OIDC credentials');
  assert.ok(guarded.stderr.includes('Run this inside GitHub Actions'));

  process.stdout.write('\nnpm trusted-publishing preflight rehearsal passed\n');
} finally {
  stub.close();
}
