// scripts/scan-dir.mjs
//
// Run every registered probe over a directory on disk and print the findings,
// the way the browser does it, minus the browser. This is the canary replay
// used for every probe change: record a baseline before the edit, replay after
// it, and explain every row that moved.
//
//   node scripts/scan-dir.mjs <dir>                   counts by title
//   node scripts/scan-dir.mjs <dir> "SQL|Auth"        rows whose title or probe match
//   GIT=1 node scripts/scan-dir.mjs <dir>             tracked files only (git ls-files)
//   BASELINE=out.txt node scripts/scan-dir.mjs <dir>  also write sorted rows for diff
//
// Without GIT=1 the walk skips node_modules, .git and any file over 500KB,
// which drops a large package-lock.json; with GIT=1 nothing is skipped by size.
// Record which mode a baseline was made in, and replay in the same one.

import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execSync } from 'node:child_process';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { PROBES, attachStableIds, attachProbeMeta } = await import(
  pathToFileURL(join(REPO, 'src/lib/probes.js')).href
);
const { shouldScanFile } = await import(pathToFileURL(join(REPO, 'src/lib/file-filter.js')).href);

const ROOT = process.argv[2];
if (!ROOT) {
  console.error(
    'usage: [GIT=1] [BASELINE=file] node scripts/scan-dir.mjs <dir> [titleFilterRegex]'
  );
  process.exit(2);
}
const FILTER = process.argv[3] ? new RegExp(process.argv[3], 'i') : null;

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === 'node_modules' || entry === '.git') continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, out);
    else if (st.size < 500_000) out.push(full);
  }
  return out;
}

const list = process.env.GIT
  ? execSync('git ls-files', { cwd: ROOT }).toString().split(/\r?\n/).filter(Boolean)
  : walk(ROOT).map((p) => relative(ROOT, p).split(sep).join('/'));
const files = list
  .filter((p) => shouldScanFile(p))
  .map((path) => ({ path, content: readFileSync(join(ROOT, path), 'utf-8') }));
console.error(`files scanned: ${files.length}`);

const all = [];
for (const probe of PROBES) {
  try {
    all.push(...probe.fn(files));
  } catch (e) {
    console.error('CRASH', probe.name, e?.message);
  }
}
attachStableIds(all, files);
attachProbeMeta(all);

const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sel = all.filter((f) => !FILTER || FILTER.test(f.title) || FILTER.test(f.probe));
sel.sort((a, b) => sev[a.severity] - sev[b.severity] || a.probe.localeCompare(b.probe));
console.log(`Total: ${all.length}  selected: ${sel.length}`);

if (!FILTER) {
  const byTitle = {};
  for (const f of all) {
    const k = `${f.severity}|${f.probe}|${f.title.replace(/"[^"]*"/g, '"…"').slice(0, 80)}`;
    byTitle[k] = (byTitle[k] || 0) + 1;
  }
  console.log('\n--- counts by title ---');
  Object.entries(byTitle)
    .sort((a, b) => b[1] - a[1])
    .forEach(([k, v]) => console.log(String(v).padStart(4), k));
} else {
  for (const f of sel) {
    console.log(
      `[${f.severity}] ${f.probe} ${f.file}:${f.line}\n    ${f.title}\n    ev: ${String(f.evidence || '').slice(0, 160)}`
    );
  }
}

if (process.env.BASELINE) {
  const rows = all.map((f) => `${f.severity}|${f.probe}|${f.file}:${f.line}|${f.title}`).sort();
  writeFileSync(process.env.BASELINE, rows.join('\n') + '\n');
  console.error(`baseline written: ${rows.length} rows -> ${process.env.BASELINE}`);
}
