#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const { join } = require('node:path');

const PLATFORM_PACKAGES = Object.freeze({
  'darwin-arm64': '@premierstudio/premier-darwin-arm64',
  'darwin-x64': '@premierstudio/premier-darwin-x64',
  'linux-arm64': '@premierstudio/premier-linux-arm64-gnu',
  'linux-x64': '@premierstudio/premier-linux-x64-gnu',
});

function packageFor(platform, arch, report = process.report) {
  if (platform === 'linux') {
    const header = report && typeof report.getReport === 'function' ? report.getReport().header : {};
    if (!header.glibcVersionRuntime) {
      throw new Error('Premier currently supports glibc Linux; musl packages are not published yet.');
    }
  }
  const name = PLATFORM_PACKAGES[`${platform}-${arch}`];
  if (!name) throw new Error(`Premier does not publish a binary for ${platform}-${arch}.`);
  return name;
}

function resolveBinary(platform = process.platform, arch = process.arch) {
  const packageName = packageFor(platform, arch);
  let manifest;
  try {
    manifest = require.resolve(`${packageName}/package.json`);
  } catch (error) {
    const message = [
      `The optional package ${packageName} is missing.`,
      'Reinstall @premierstudio/premier without omitting optional dependencies.',
      `Original resolution error: ${error.message}`,
    ].join('\n');
    throw new Error(message);
  }
  return join(manifest, '..', 'bin', 'premier');
}

function main() {
  let binary;
  try {
    binary = resolveBinary();
  } catch (error) {
    process.stderr.write(`premier: ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  const result = spawnSync(binary, process.argv.slice(2), { stdio: 'inherit' });
  if (result.error) {
    process.stderr.write(`premier: unable to launch ${binary}: ${result.error.message}\n`);
    process.exitCode = 1;
    return;
  }
  if (result.signal) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.status ?? 1;
}

if (require.main === module) main();

module.exports = { PLATFORM_PACKAGES, packageFor, resolveBinary };
