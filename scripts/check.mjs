import { spawnSync } from 'node:child_process';

const steps = [
  ['cargo', ['fmt', '--all', '--', '--check']],
  ['cargo', ['clippy', '--workspace', '--all-targets', '--', '-D', 'warnings']],
  ['cargo', ['test', '--workspace']],
  ['npm', ['run', 'check', '--workspace', '@premier/viewer']],
  ['npm', ['run', 'test', '--workspace', '@premier/viewer']],
  ['npm', ['run', 'test:coverage', '--workspace', '@premier/viewer']],
  ['npm', ['run', 'build', '--workspace', '@premier/viewer']],
  ['npm', ['run', 'build', '--workspace', '@premierstudio/trace']],
  ['npm', ['run', 'test', '--workspace', '@premierstudio/trace']],
  ['node', ['--test', 'packages/premier-cli/test/*.test.js']],
  ['npm', ['run', 'test:npm-distribution']],
  ['npx', ['playwright', 'test']]
];

for (const [command, args] of steps) {
  process.stdout.write(`\n› ${command} ${args.join(' ')}\n`);
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

process.stdout.write('\nAll Premier checks passed.\n');
