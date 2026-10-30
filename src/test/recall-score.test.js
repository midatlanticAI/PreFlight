// @vitest-environment node
import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { normalizeFinding, scoreBenchmark, validateManifest } from '../../scripts/recall/score.js';

const label = (id, startLine, kind = 'positive', extra = {}) => ({
  id,
  file: 'app/a.py',
  cwe: 'CWE-502',
  startLine,
  endLine: startLine,
  kind,
  ...extra,
});
const finding = (extra = {}) => ({
  file: 'app/a.py',
  line: 10,
  cwe: 'CWE-502',
  probe: 'probe',
  title: 'risk',
  ...extra,
});
function manifest(labels = [label('a', 10)]) {
  return {
    schemaVersion: 1,
    cases: [
      {
        id: 'one',
        corpus: 'external',
        provenance: 'independent',
        language: 'Python',
        source: 'pinned upstream',
        license: 'Apache-2.0',
        labelBasis: 'upstream labels',
        files: [{ path: 'bench/a.py', scanPath: 'app/a.py', sha256: 'a'.repeat(64) }],
        labels,
      },
    ],
  };
}
const score = (m, findings = []) => scoreBenchmark(m, { one: findings });

describe('bounded recall scorer', () => {
  it('requires exact file and CWE plus inclusive range; title alone cannot detect', () => {
    const m = manifest([label('a', 10, 'positive', { endLine: 12 })]);
    for (const f of [
      finding({ file: 'app/b.py' }),
      finding({ cwe: 'CWE-89' }),
      finding({ cwe: undefined }),
      finding({ line: 9 }),
      finding({ line: 13 }),
      finding({ line: undefined }),
    ]) {
      const r = score(m, [f]);
      expect(r.scorecards[0]).toMatchObject({ detected: 0, missed: 1, recall: 0 });
      expect(r.cases[0].unadjudicated).toHaveLength(1);
    }
    for (const line of [10, 11, 12])
      expect(score(m, [finding({ line })]).scorecards[0].detected).toBe(1);
  });
  it('counts missed positives, negative-region false positives, and clear negatives', () => {
    const r = score(
      manifest([
        label('a', 10),
        label('b', 20),
        label('c', 30, 'negative'),
        label('d', 40, 'negative'),
      ]),
      [finding(), finding({ line: 30 }), finding({ line: 99 })]
    );
    expect(r.scorecards[0]).toMatchObject({
      detected: 1,
      missed: 1,
      positives: 2,
      recall: 0.5,
      falsePositives: 1,
      clearNegatives: 1,
    });
    expect(r.cases[0].unadjudicated).toHaveLength(1);
  });
  it('duplicates and findings from overlapping probes cannot inflate recall or FP counts', () => {
    const r = score(manifest([label('a', 10), label('b', 30, 'negative')]), [
      finding(),
      finding(),
      finding({ probe: 'other' }),
      finding({ line: 30 }),
      finding({ line: 30 }),
    ]);
    expect(r.scorecards[0]).toMatchObject({
      detected: 1,
      falsePositives: 1,
      duplicateFindings: 3,
      recall: 1,
    });
  });
  it('exclusions require reasons and stay out of both denominators even when detected', () => {
    const m = manifest([label('a', 10, 'excluded', { reason: 'Documented unsupported dataflow' })]);
    for (const fs of [[], [finding(), finding()]]) {
      const r = score(m, fs);
      expect(r.scorecards[0]).toMatchObject({
        detected: 0,
        missed: 0,
        falsePositives: 0,
        positives: 0,
        recall: null,
        excluded: 1,
        duplicateFindings: 0,
      });
      expect(r.cases[0].results[0].status).toBe('excluded');
    }
    delete m.cases[0].labels[0].reason;
    expect(() => validateManifest(m)).toThrow('reason');
  });
  it('never pools corpora, provenance, language or CWE into an overall number', () => {
    const m = manifest();
    for (const [key, value] of [
      ['corpus', 'local'],
      ['provenance', 'preflight-fixture'],
      ['language', 'JavaScript'],
    ]) {
      m.cases.push({ ...structuredClone(m.cases[0]), id: key, [key]: value });
    }
    const differentCwe = structuredClone(m.cases[0]);
    differentCwe.id = 'cwe';
    differentCwe.labels[0].cwe = 'CWE-89';
    m.cases.push(differentCwe);
    const r = scoreBenchmark(m, Object.fromEntries(m.cases.map((c) => [c.id, []])));
    expect(r.scorecards).toHaveLength(5);
    expect(r).not.toHaveProperty('recall');
  });
  it('rejects malformed, ambiguous, missing and duplicate input instead of silently scoring', () => {
    for (const mutate of [
      (m) => {
        m.schemaVersion = 2;
      },
      (m) => {
        m.cases.push(m.cases[0]);
      },
      (m) => {
        m.cases[0].labels.push(label('b', 10));
      },
      (m) => {
        m.cases[0].labels[0].file = 'other.py';
      },
      (m) => {
        m.cases[0].labels[0].startLine = 0;
      },
      (m) => {
        m.cases[0].files[0].path = '../escape.py';
      },
      (m) => {
        m.cases[0].files[0].sha256 = 'missing';
      },
    ]) {
      const m = manifest();
      mutate(m);
      expect(() => validateManifest(m)).toThrow();
    }
    expect(() => scoreBenchmark(manifest(), {})).toThrow();
    expect(() => scoreBenchmark(manifest(), { wrong: [] })).toThrow();
    expect(() => scoreBenchmark(manifest(), { one: [], extra: [] })).toThrow();
  });
  it('normalizes Windows paths without guessing missing CWE/location metadata', () => {
    expect(normalizeFinding(finding({ file: '.\\app\\a.py' }))).toEqual(
      normalizeFinding(finding())
    );
    expect(normalizeFinding({})).toMatchObject({ file: null, line: null, cwe: null });
  });
  it('seeded property: finding order and repeated detections never change coverage', () => {
    fc.assert(
      fc.property(fc.array(fc.integer({ min: 1, max: 25 }), { maxLength: 50 }), (lines) => {
        const m = manifest([label('a', 10), label('b', 20)]);
        const findings = lines.map((line) => finding({ line }));
        const a = score(m, findings);
        expect(score(m, [...findings].reverse())).toEqual(a);
        const b = score(m, [...findings, ...findings]);
        expect(b.scorecards[0].detected).toBe(a.scorecards[0].detected);
        expect(b.scorecards[0].recall).toBe(a.scorecards[0].recall);
      }),
      { seed: 20261030, numRuns: 100 }
    );
  });
  it('offline full-registry runner emits byte-identical reports on repeated runs', () => {
    const dir = mkdtempSync(join(tmpdir(), 'preflight-recall-'));
    try {
      const out = join(dir, 'report.json');
      const run = () => {
        execFileSync(process.execPath, ['scripts/recall/run.mjs', '--output', out]);
        return readFileSync(out, 'utf8');
      };
      const first = run();
      expect(run()).toBe(first);
      const report = JSON.parse(first);
      expect(report.measurement.probeCount).toBeGreaterThan(100);
      expect(report.scorecards.some((r) => r.provenance === 'independent')).toBe(true);
      expect(report.scorecards.some((r) => r.provenance === 'preflight-fixture')).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
