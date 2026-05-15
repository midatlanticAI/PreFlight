// Phase 3 (Java). Java adapters for the existing XL families. New
// detection (no v0.4 probe covers Java), shadow only, family Learn pages
// inherited. Same contract shape as the Rust/Go Phase 3 suites.
//
// Reference: docs/v05-research/preflight_v05_probe_inventory.md "4. Java"

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import {
  PROBE_MANIFEST_V05,
  MANIFEST_OWASP_MAP,
  validateFixturePaths,
  validateLearnContent,
} from '../lib/probes/v05/manifest.js';
import { runShadow } from '../lib/probes/v05/shadow.js';
import { getBySlug } from '../lib/learn-content.js';
import { PROBES } from '../App.jsx';

const PHASE3_JV_IDS = [
  'JV-DESERIALIZE-001',
  'JV-SECRETS-001',
  'JV-SQL-RAW-001',
  'JV-TLS-VERIFY-001',
];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => PHASE3_JV_IDS.includes(e.probe_id));
const byId = (id) => PROBE_MANIFEST_V05[id];

describe('Phase 3 (Java): manifest shape', () => {
  it('registers the four Java adapters and they are the only java ones', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of PHASE3_JV_IDS) expect(ids).toContain(id);
    const javaIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'java')
      .map((e) => e.probe_id)
      .sort();
    expect(javaIds).toEqual([...PHASE3_JV_IDS].sort());
  });

  it('every Java adapter is shadow + experimental + java + no legacy seed', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(true);
      expect(e.maturity).toBe('experimental');
      expect(e.language).toBe('java');
      expect(e.legacy_finding_id_seed).toBe(null);
    }
  });

  it('each Java adapter inherits its XL family Learn slug', () => {
    expect(byId('JV-DESERIALIZE-001').xl_family).toBe('XL-001');
    expect(byId('JV-DESERIALIZE-001').learn_more_slug).toBe('xl-unsafe-deserialization');
    expect(byId('JV-SQL-RAW-001').xl_family).toBe('XL-002');
    expect(byId('JV-SQL-RAW-001').learn_more_slug).toBe('xl-raw-query-interpolation');
    expect(byId('JV-TLS-VERIFY-001').xl_family).toBe('XL-004');
    expect(byId('JV-TLS-VERIFY-001').learn_more_slug).toBe('xl-tls-verification-disabled');
    expect(byId('JV-SECRETS-001').xl_family).toBe('XL-006');
    expect(byId('JV-SECRETS-001').learn_more_slug).toBe('xl-hardcoded-secrets');
  });

  it('Java adapters are invisible to users (not in v0.4 PROBES, not in OWASP map)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    const owaspNames = new Set(Object.values(MANIFEST_OWASP_MAP).flat());
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(false);
      expect(owaspNames.has(e.name)).toBe(false);
    }
  });
});

describe('Phase 3 (Java): fixture + Learn contracts', () => {
  it('every adapter declares fixture paths that exist on disk', () => {
    for (const e of ENTRIES) {
      expect(() => validateFixturePaths(e, existsSync)).not.toThrow();
    }
  });

  const patternExists = (slug) => !!getBySlug(slug);
  const patternIsDraft = (slug) => {
    const entry = getBySlug(slug);
    return !entry || entry.draft === true;
  };

  it('every adapter resolves to a published Learn page (inherited from the family)', () => {
    for (const e of ENTRIES) {
      expect(() => validateLearnContent(e, patternExists, patternIsDraft)).not.toThrow();
    }
  });
});

const fixtureFile = (realPath) => ({
  path: realPath.replace(/^.*\/fixtures\//, '__fixture_under_test__/'),
  content: readFileSync(realPath, 'utf8'),
});

describe('Phase 3 (Java): adapter detection (positive fires, negative silent)', () => {
  for (const e of ENTRIES) {
    describe(e.probe_id, () => {
      it('flags the positive fixture (>=1 finding, carries adapter name)', () => {
        const f = runShadow(e, [fixtureFile(e.fixtures_v05.positive)]);
        expect(f.length).toBeGreaterThan(0);
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
