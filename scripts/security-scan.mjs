import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], { encoding: 'utf8' })
  .trim()
  .split('\n')
  .filter(Boolean);

const secretPatterns = [
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ['GitHub token', /gh[pousr]_[A-Za-z0-9_]{30,}/],
  ['Stripe secret key', /(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/],
  ['AWS access key', /AKIA[0-9A-Z]{16}/],
  ['npm token', /npm_[A-Za-z0-9]{30,}/],
  ['Slack token', /xox[baprs]-[A-Za-z0-9-]{20,}/],
  ['Slack webhook', /hooks\.slack\.com\/services\/[A-Z0-9]{8,}\/[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/],
];

const findings = [];

for (const file of files) {
  let contents;
  try {
    contents = readFileSync(file, 'utf8');
  } catch {
    continue;
  }

  if (contents.includes('\0')) continue;

  for (const [label, pattern] of secretPatterns) {
    if (pattern.test(contents)) findings.push(`${label}: ${file}`);
  }
}

if (findings.length > 0) {
  console.error('Potential committed secrets detected:');
  console.error(findings.join('\n'));
  process.exit(1);
}

console.log(`Secret scan passed (${files.length} tracked files).`);
