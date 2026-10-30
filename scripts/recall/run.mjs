// Offline, measurement-only runner. Corpus code is read as text, never executed.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { PROBES, attachProbeMeta } from '../../src/lib/probes.js';
import { shouldScanFile, setSelfScanMode } from '../../src/lib/file-filter.js';
import { scoreBenchmark, validateManifest } from './score.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--output')) {
  throw new Error('usage: npm run test:recall -- [--output path.json]');
}
const output = resolve(ROOT, args[1] || '.scratch/recall-scorecard.json');
const manifestBytes = readFileSync(resolve(ROOT, 'bench/recall/manifest.json'));
const manifest = validateManifest(JSON.parse(manifestBytes));
const observations = {};
setSelfScanMode(false);
for (const c of manifest.cases) {
  const files = c.files.map((f) => {
    const bytes = readFileSync(resolve(ROOT, f.path));
    if (sha256(bytes) !== f.sha256) throw new Error(`Corpus integrity mismatch: ${f.path}`);
    const content = bytes.toString('utf8');
    for (const l of c.labels.filter((l) => l.file === f.scanPath)) {
      if (l.endLine > content.split('\n').length)
        throw new Error(`Label past EOF: ${c.id}/${l.id}`);
    }
    if (!shouldScanFile(f.scanPath)) throw new Error(`Unscannable scanPath: ${f.scanPath}`);
    return { path: f.scanPath, content };
  });
  observations[c.id] = [];
  for (const probe of PROBES) {
    try {
      observations[c.id].push(...probe.fn(files));
    } catch (error) {
      throw new Error(`Probe crash in ${c.id}: ${probe.name}`, { cause: error });
    }
  }
  attachProbeMeta(observations[c.id]);
}
const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' }).trim();
const engineFiles = git('ls-files', 'src/lib').split('\n').filter(Boolean).sort();
const engineHash = createHash('sha256');
for (const path of engineFiles)
  engineHash
    .update(path + '\0')
    .update(readFileSync(resolve(ROOT, path)))
    .update('\0');
const report = {
  ...scoreBenchmark(manifest, observations),
  measurement: {
    mode: 'measurement-only',
    node: process.version,
    scannerRevision: git('rev-parse', 'HEAD'),
    scannerSourceSha256: engineHash.digest('hex'),
    manifestSha256: sha256(manifestBytes),
    harnessSha256: sha256(
      Buffer.concat(
        ['scripts/recall/run.mjs', 'scripts/recall/score.js'].map((p) =>
          readFileSync(resolve(ROOT, p))
        )
      )
    ),
    probeCount: PROBES.length,
  },
};
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
console.log(`Recall report: ${relative(ROOT, output)} (measurement only; no recall floor)`);
for (const r of report.scorecards)
  console.log(
    `${r.corpus} | ${r.provenance} | ${r.language} | ${r.cwe}: detected=${r.detected} missed=${r.missed} FP=${r.falsePositives} excluded=${r.excluded}`
  );
console.log(
  `Unadjudicated findings: ${report.cases.reduce((n, c) => n + c.unadjudicated.length, 0)}`
);
