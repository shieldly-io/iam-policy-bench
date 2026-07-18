import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { lint } from '@shieldly/iam-lint';

// Runs @shieldly/iam-lint, Parliament, and Cloudsplaining against every
// policy in policies/ and reports whether each tool detected ANY finding —
// not raw finding counts, which aren't comparable across tools with very
// different output granularity (see README "Why detection, not counts").
const HERE = dirname(fileURLToPath(import.meta.url));
const POLICIES_DIR = join(HERE, 'policies');
const groundTruth = JSON.parse(readFileSync(join(HERE, 'ground-truth.json'), 'utf8'));

const files = readdirSync(POLICIES_DIR)
  .filter((f) => f.endsWith('.json'))
  .sort();

function mark(detected, classification) {
  const shouldDetect = classification === 'vulnerable';
  if (detected === shouldDetect) return '✓';
  return shouldDetect ? '✗ (missed)' : '✗ (false positive)';
}

const rows = [];
for (const file of files) {
  const filePath = join(POLICIES_DIR, file);
  const policy = JSON.parse(readFileSync(filePath, 'utf8'));
  const shieldlyDetected = lint(policy).length > 0;

  const pyOut = execFileSync('python3', [join(HERE, 'python_findings.py'), filePath], {
    encoding: 'utf8',
  });
  const { parliament, cloudsplaining } = JSON.parse(pyOut);

  const { classification, category } = groundTruth[file];
  rows.push({
    file,
    classification,
    category,
    shieldly: mark(shieldlyDetected, classification),
    parliament: mark(parliament > 0, classification),
    cloudsplaining: mark(cloudsplaining > 0, classification),
  });
}

console.log('| Policy | Ground truth | @shieldly/iam-lint | Parliament | Cloudsplaining |');
console.log('|---|---|---|---|---|');
for (const r of rows) {
  console.log(
    `| \`${r.file}\` (${r.category}) | ${r.classification} | ${r.shieldly} | ${r.parliament} | ${r.cloudsplaining} |`
  );
}
