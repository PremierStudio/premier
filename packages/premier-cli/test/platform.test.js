'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { packageFor } = require('../bin/premier.js');

const glibc = { getReport: () => ({ header: { glibcVersionRuntime: '2.39' } }) };
const musl = { getReport: () => ({ header: {} }) };

test('selects every published platform package', () => {
  assert.equal(packageFor('darwin', 'arm64'), '@premierstudio/premier-darwin-arm64');
  assert.equal(packageFor('darwin', 'x64'), '@premierstudio/premier-darwin-x64');
  assert.equal(packageFor('linux', 'arm64', glibc), '@premierstudio/premier-linux-arm64-gnu');
  assert.equal(packageFor('linux', 'x64', glibc), '@premierstudio/premier-linux-x64-gnu');
});

test('rejects unsupported operating systems and architectures', () => {
  assert.throws(() => packageFor('win32', 'x64'), /does not publish/);
  assert.throws(() => packageFor('darwin', 'riscv64'), /does not publish/);
});

test('rejects musl rather than installing a glibc binary', () => {
  assert.throws(() => packageFor('linux', 'x64', musl), /musl packages are not published/);
});
