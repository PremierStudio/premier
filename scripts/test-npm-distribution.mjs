import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const target = `${process.platform}-${process.arch}`;
const platformDirectories = {
  'darwin-arm64': 'darwin-arm64',
  'darwin-x64': 'darwin-x64',
  'linux-arm64': 'linux-arm64-gnu',
  'linux-x64': 'linux-x64-gnu',
};
const platformDirectory = platformDirectories[target];
assert.ok(platformDirectory, `npm distribution smoke is unsupported on ${target}`);

function run(command, args, options = {}) {
  return execFileSync(command, args, {
    cwd: options.cwd ?? root,
    encoding: 'utf8',
    env: { ...process.env, npm_config_audit: 'false', npm_config_fund: 'false' },
    stdio: options.stdio ?? ['ignore', 'pipe', 'pipe'],
  });
}

function pack(directory, destination) {
  const result = JSON.parse(run('npm', ['pack', directory, '--pack-destination', destination, '--json']));
  if (Array.isArray(result)) return result[0];
  if (result.files) return result;
  return Object.values(result)[0];
}

const cargo = JSON.parse(run('cargo', ['metadata', '--format-version', '1', '--no-deps']));
run('cargo', ['build', '--locked', '-p', 'premier-cli']);
const binary = join(cargo.target_directory, 'debug', process.platform === 'win32' ? 'premier.exe' : 'premier');
const work = mkdtempSync(join(tmpdir(), 'premier-npm-distribution-'));

try {
  const stagedPlatform = join(work, 'platform');
  const stagedLauncher = join(work, 'launcher');
  cpSync(join(root, 'npm', 'platforms', platformDirectory), stagedPlatform, { recursive: true });
  cpSync(join(root, 'packages', 'premier-cli'), stagedLauncher, { recursive: true });
  cpSync(join(root, 'LICENSE'), join(stagedPlatform, 'LICENSE'));
  cpSync(join(root, 'LICENSE'), join(stagedLauncher, 'LICENSE'));
  mkdirSync(join(stagedPlatform, 'bin'), { recursive: true });
  cpSync(binary, join(stagedPlatform, 'bin', 'premier'));
  chmodSync(join(stagedPlatform, 'bin', 'premier'), 0o755);

  const platformManifest = JSON.parse(readFileSync(join(stagedPlatform, 'package.json'), 'utf8'));
  const launcherManifest = JSON.parse(readFileSync(join(stagedLauncher, 'package.json'), 'utf8'));
  assert.equal(platformManifest.scripts, undefined, 'platform package must not run lifecycle scripts');
  assert.equal(launcherManifest.scripts?.preinstall, undefined);
  assert.equal(launcherManifest.scripts?.install, undefined);
  assert.equal(launcherManifest.scripts?.postinstall, undefined);
  const expectedVersion = launcherManifest.version;
  assert.equal(platformManifest.version, expectedVersion, 'platform and launcher versions must match');
  for (const [name, pinned] of Object.entries(launcherManifest.optionalDependencies ?? {})) {
    assert.equal(pinned, expectedVersion, `${name} must be pinned to the launcher version`);
  }

  const platformPack = pack(stagedPlatform, work);
  const launcherPack = pack(stagedLauncher, work);
  assert.ok(platformPack.files.some((file) => file.path === 'bin/premier'));
  assert.ok(platformPack.files.some((file) => file.path === 'LICENSE'));
  assert.ok(launcherPack.files.some((file) => file.path === 'bin/premier.js'));
  assert.ok(launcherPack.files.some((file) => file.path === 'LICENSE'));

  const consumer = join(work, 'consumer');
  mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ name: 'premier-clean-install', private: true }, null, 2));
  const platformTarball = join(work, basename(platformPack.filename));
  const launcherTarball = join(work, basename(launcherPack.filename));
  run('npm', ['install', '--ignore-scripts', platformTarball], { cwd: consumer });
  run('npm', ['install', '--ignore-scripts', '--omit=optional', launcherTarball], { cwd: consumer });
  const output = run(join(consumer, 'node_modules', '.bin', 'premier'), ['--version'], { cwd: consumer });
  assert.equal(output.trim(), `premier ${expectedVersion}`);
  process.stdout.write(`script-free npm install verified with ${platformManifest.name}\n`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
