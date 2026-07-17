import { rmSync, mkdirSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';

const cwd = new URL('..', import.meta.url).pathname;
const port = process.env.PREMIER_E2E_PORT ?? '4318';
const traceRoot = '.tmp/e2e-traces';
rmSync(new URL(`../${traceRoot}`, import.meta.url), { recursive: true, force: true });
mkdirSync(new URL(`../${traceRoot}`, import.meta.url), { recursive: true });

function run(command, args) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit' });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

run('npm', ['run', 'build', '--workspace', '@premier/viewer']);
run('cargo', ['run', '--quiet', '-p', 'premier-cli', '--bin', 'premier', '--', 'record', '--output', `${traceRoot}/passing-smoke.atrace`, '--name', 'Passing smoke run', 'sh', '-c', 'printf "passing evidence\\n"']);
run('cargo', ['run', '--quiet', '-p', 'premier-cli', '--bin', 'premier', '--', 'demo', '--output', `${traceRoot}/multi-agent.atrace`]);

// Serve uses the embedded viewer by default (built into the binary after npm run build).
const server = spawn('cargo', ['run', '--quiet', '-p', 'premier-cli', '--bin', 'premier', '--', 'serve', '--trace-dir', traceRoot, '--bind', `127.0.0.1:${port}`, '--password', 'e2e-secret'], { cwd, stdio: 'inherit' });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.kill(signal));
server.on('exit', (code) => process.exit(code ?? 0));
