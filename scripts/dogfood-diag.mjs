// One-off: dump every dogfood finding with file:line, severity, probe, title.
// Run with `node scripts/dogfood-diag.mjs`.
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { PROBES, attachStableIds, attachProbeMeta } from '../src/lib/probes.js';

const ROOT = process.cwd();
const TARGETS = [
  'dist',
  'public',
  'src',
  'index.html',
  '.preflight.yml',
  'package.json',
  '.npmrc',
];

function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  const s = statSync(dir);
  if (s.isFile()) {
    out.push(dir);
    return out;
  }
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git') continue;
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) walk(full, out);
    else if (stat.isFile() && stat.size < 500_000) out.push(full);
  }
  return out;
}

const paths = TARGETS.flatMap((t) => walk(join(ROOT, t)));
const files = paths.map((p) => ({
  path: relative(ROOT, p).replace(/\\/g, '/'),
  content: readFileSync(p, 'utf-8'),
}));

const all = [];
for (const probe of PROBES) {
  try {
    all.push(...probe.fn(files));
  } catch (e) {
    console.error('Probe crashed:', probe.name, e?.message);
  }
}
attachStableIds(all, files);
attachProbeMeta(all);

console.log(`Total: ${all.length}\n`);
const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
all.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity] || a.probe.localeCompare(b.probe));
for (const f of all) {
  console.log(
    `[${f.severity.toUpperCase().padEnd(8)}] ${f.probe.padEnd(20)} ${f.file || '-'}:${f.line || '-'}`
  );
  console.log(`    ${f.title}`);
  if (f.evidence) console.log(`    ev: ${String(f.evidence).slice(0, 140)}`);
}
