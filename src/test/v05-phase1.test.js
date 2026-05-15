// Phase 1 tests. The four XL families (XL-001/002/004/006) with their Python
// adapters, end-to-end:
//   - every registered adapter detects its positive fixture (>=1 finding)
//     and stays silent on its negative fixture (0 findings)
//   - the build-time contracts hold: every adapter's fixture files exist on
//     disk, and every adapter resolves to a non-draft Learn page
//   - Phase 1 adapters are shadow-only: zero v0.4 user-visible behavior change
//
// Reference: docs/v05-research/v05-architecture.md ("Phase 1")

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import {
  PROBE_MANIFEST_V05,
  validateFixturePaths,
  validateLearnContent,
} from '../lib/probes/v05/manifest.js';
import { runShadow } from '../lib/probes/v05/shadow.js';
import { getBySlug } from '../lib/learn-content.js';
import { attachProbeMeta } from '../lib/stable-id.js';
import { PROBES } from '../App.jsx';

// Phase 1 = the four Python adapters. The manifest also carries Phase 2+
// adapters now, so scope every Phase 1 assertion to these ids rather than
// the whole manifest.
const PHASE1_IDS = ['PY-DESERIALIZE-001', 'PY-SECRETS-001', 'PY-SQL-RAW-001', 'PY-TLS-VERIFY-001'];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => PHASE1_IDS.includes(e.probe_id));

describe('Phase 1: manifest shape', () => {
  it('registers the four Phase 1 Python adapters and they are the only python ones', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of PHASE1_IDS) expect(ids).toContain(id);
    const pythonIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'python')
      .map((e) => e.probe_id)
      .sort();
    expect(pythonIds).toEqual([...PHASE1_IDS].sort());
  });

  it('every Phase 1 adapter is shadow + experimental (no user-visible change yet)', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(true);
      expect(e.maturity).toBe('experimental');
      expect(e.language).toBe('python');
    }
  });

  it('every adapter references a registered XL family and inherits its Learn slug', () => {
    for (const e of ENTRIES) {
      expect(e.xl_family).toMatch(/^XL-\d{3}$/);
      expect(typeof e.learn_more_slug).toBe('string');
      expect(e.learn_more_slug.length).toBeGreaterThan(0);
    }
  });

  it('Phase 1 adapter names are NOT in the v0.4 PROBES array (shadow-only)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(false);
    }
  });
});

// ---- Build-time contracts (hard failures, exercised here as tests) ----

describe('Phase 1: fixture contract', () => {
  it('every adapter declares fixture paths that exist on disk', () => {
    for (const e of ENTRIES) {
      expect(() => validateFixturePaths(e, existsSync)).not.toThrow();
    }
  });
});

describe('Phase 1: Learn-content contract', () => {
  const patternExists = (slug) => !!getBySlug(slug);
  const patternIsDraft = (slug) => {
    const entry = getBySlug(slug);
    return !entry || entry.draft === true;
  };

  it('every adapter resolves to a Learn page that exists and is not draft', () => {
    for (const e of ENTRIES) {
      expect(() => validateLearnContent(e, patternExists, patternIsDraft)).not.toThrow();
    }
  });

  it('the four XL family Learn pages are present and published', () => {
    for (const slug of [
      'xl-unsafe-deserialization',
      'xl-raw-query-interpolation',
      'xl-tls-verification-disabled',
      'xl-hardcoded-secrets',
    ]) {
      const entry = getBySlug(slug);
      expect(entry, `Learn page "${slug}" missing`).toBeDefined();
      expect(entry.draft).toBe(false);
      expect(entry.type).toBe('pattern');
    }
  });
});

// ---- Per-adapter behaviour against the real fixture files on disk ----

// Read the fixture from its real on-disk path (that path's existence is
// enforced separately by validateFixturePaths). Present the CONTENT to the
// adapter under a synthetic neutral .py path, because the adapter's
// production scope filter correctly refuses to scan the scanner's own
// repo tree (isScannerSelfSource covers src/lib/probes/). This models the
// real case: "an adapter detecting a user's Python file."
const fixtureFile = (realPath) => ({
  path: realPath.replace(/^.*\/fixtures\//, '__fixture_under_test__/'),
  content: readFileSync(realPath, 'utf8'),
});

describe('Phase 1: adapter detection (positive fires, negative silent)', () => {
  for (const e of ENTRIES) {
    describe(e.probe_id, () => {
      it('flags the positive fixture (>=1 finding)', () => {
        const f = runShadow(e, [fixtureFile(e.fixtures_v05.positive)]);
        expect(f.length).toBeGreaterThan(0);
        // Every finding carries the adapter's probe name + the family CWE.
        for (const finding of f) {
          expect(finding.probe).toBe(e.name);
          expect(finding.cwe).toBe(e.cwe);
          expect(['critical', 'high', 'medium', 'low', 'info']).toContain(finding.severity);
        }
      });

      it('stays silent on the negative fixture (0 findings)', () => {
        const f = runShadow(e, [fixtureFile(e.fixtures_v05.negative)]);
        expect(f).toEqual([]);
      });
    });
  }
});

// ---- attachProbeMeta copies v0.5 fields for a Phase 1 probe finding ----

describe('Phase 1: v0.5 field propagation', () => {
  it('attachProbeMeta copies probe_id/xl_family/maturity/why_ai onto a matching finding', () => {
    const f = [
      {
        probe: 'Python Unsafe Deserialization',
        file: 'app.py',
        line: 3,
        title: 'Unsafe deserialization: yaml.load without a safe loader',
        severity: 'critical',
      },
    ];
    attachProbeMeta(f);
    expect(f[0].probe_id).toBe('PY-DESERIALIZE-001');
    expect(f[0].xl_family).toBe('XL-001');
    expect(f[0].maturity).toBe('experimental');
    expect(typeof f[0].why_ai_v05).toBe('string');
    expect(typeof f[0].vibe_v05).toBe('string');
    expect(Array.isArray(f[0].fp_gates_v05)).toBe(true);
    expect(f[0].autofix_v05).toBe('review-needed');
  });

  it('a v0.4-only probe finding is untouched (no v0.5 fields)', () => {
    const f = [{ probe: 'Env File Hygiene', file: '.env', line: 1, title: 't' }];
    attachProbeMeta(f);
    expect(f[0].probe_id).toBeUndefined();
    expect(f[0].confidence).toBe('high'); // v0.4 PROBE_META still wins
  });
});
