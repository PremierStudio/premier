import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

// Proves that npmjs.com trusted publishing will accept this workflow for every
// package the release publishes, without publishing anything. It performs the
// same GitHub OIDC id-token request and registry token exchange as
// `npm publish` (npm/cli lib/utils/oidc.js); npm itself treats a failed
// exchange as a silent fallback that only surfaces halfway through a release.
// PREMIER_NPM_REGISTRY exists so a rehearsal can point at a stub registry; the
// OIDC audience is derived from that hostname, so a rehearsal token is useless
// against the real registry.

const root = resolve(import.meta.dirname, '..');
const registry = new URL(process.env.PREMIER_NPM_REGISTRY ?? 'https://registry.npmjs.org');

const packageDirectories = [
  'packages/premier-cli',
  'sdk/js',
  ...readdirSync(join(root, 'npm', 'platforms'), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `npm/platforms/${entry.name}`),
];
const packageNames = packageDirectories.map(
  (directory) => JSON.parse(readFileSync(join(root, directory, 'package.json'), 'utf8')).name,
);

const idTokenRequestUrl = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
const idTokenRequestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
if (!idTokenRequestUrl || !idTokenRequestToken) {
  process.stderr.write(
    'GitHub OIDC credentials are unavailable. Run this inside GitHub Actions with `id-token: write` permission.\n',
  );
  process.exit(1);
}

const idTokenUrl = new URL(idTokenRequestUrl);
idTokenUrl.searchParams.append('audience', `npm:${registry.hostname}`);
const idTokenResponse = await fetch(idTokenUrl, {
  headers: { accept: 'application/json', authorization: `Bearer ${idTokenRequestToken}` },
});
const idToken = idTokenResponse.ok ? (await idTokenResponse.json()).value : undefined;
if (!idToken) {
  process.stderr.write(`GitHub did not issue an OIDC id token (HTTP ${idTokenResponse.status}).\n`);
  process.exit(1);
}

const failures = [];
for (const name of packageNames) {
  const exchangeUrl = new URL(`/-/npm/v1/oidc/token/exchange/package/${name.replace('/', '%2f')}`, registry);
  const response = await fetch(exchangeUrl, {
    method: 'POST',
    headers: { accept: 'application/json', authorization: `Bearer ${idToken}` },
  });
  const body = await response.json().catch(() => ({}));
  if (response.ok && body.token) {
    process.stdout.write(`${name}: trusted publisher accepted this workflow\n`);
  } else {
    failures.push(`${name}: HTTP ${response.status} ${body.message ?? response.statusText}`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`\nnpm trusted publishing rejected ${failures.length} of ${packageNames.length} packages:\n`);
  for (const failure of failures) {
    process.stderr.write(`  ${failure}\n`);
  }
  process.stderr.write(
    '\nOn npmjs.com, give each package a GitHub Actions trusted publisher for\n' +
      'PremierStudio/premier, workflow release.yml, environment release,\n' +
      'then re-run this preflight before pushing a release tag.\n',
  );
  process.exit(1);
}

process.stdout.write(`npm trusted publishing verified for ${packageNames.length} packages on ${registry.host}\n`);
