// Dogfood-scan: run the full PROBES set against our own repo, then report the totals by
// severity. Used to track the noise floor over time. This is not a strict assertion — it
// just prints the count so we can see whether the dogfood number trends down on each commit.
//
// Run with `npx vitest run src/test/dogfood-scan.test.js`. Not part of `npm test` (it's not
// a unit test and we don't want to fail CI on a finding-count drift).

import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { PROBES, attachStableIds, attachProbeMeta } from '../lib/probes.js';

const ROOT = process.cwd();
// Include `.preflight.yml` so the dogfood scan mirrors what the browser sees when it scans this
// repo (FILE_INCLUDE pulls .preflight.yml so probes can read self_domains).
const TARGET_ROOTS = [
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

describe('dogfood-scan', () => {
  it('reports finding counts by severity (no assertion — just reporting)', () => {
    const paths = TARGET_ROOTS.flatMap((r) => walk(join(ROOT, r)));
    const files = paths.map((p) => ({
      path: relative(ROOT, p).replace(/\\/g, '/'),
      content: readFileSync(p, 'utf-8'),
    }));

    const all = [];
    for (const probe of PROBES) {
      try {
        const found = probe.fn(files);
        all.push(...found);
      } catch (e) {
        console.error('Probe crashed:', probe.name, e?.message);
      }
    }
    attachStableIds(all, files);
    attachProbeMeta(all);

    const bySev = all.reduce((a, f) => {
      a[f.severity] = (a[f.severity] || 0) + 1;
      return a;
    }, {});
    const total = all.length;

    console.log('\n=== DOGFOOD SCAN ===');
    console.log(`Files: ${files.length}`);
    console.log(`Total findings: ${total}`);
    for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
      console.log(`  ${sev.padEnd(10)} ${bySev[sev] || 0}`);
    }
    // Breakdown by probe so we can see which is loudest.
    const byProbe = all.reduce((a, f) => {
      const k = `${f.probe} :: ${f.severity}`;
      a[k] = (a[k] || 0) + 1;
      return a;
    }, {});
    console.log('\nBy probe + severity:');
    for (const [k, v] of Object.entries(byProbe).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${v.toString().padStart(3)}  ${k}`);
    }
    console.log('====================\n');
    expect(total).toBeGreaterThanOrEqual(0); // never fail
  });
});
