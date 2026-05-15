// Phase 3 tests. First non-Python/JS language: Rust adapters for the
// existing XL families (XL-001/002/004/006). New detection (Rust is not
// covered by any v0.4 probe), so legacy_finding_id_seed is null and there
// is no parity block — the contracts are: shadow-only, fixtures fire
// correctly, and each adapter inherits its family's Learn page.
//
// Reference: docs/v05-research/v05-architecture.md ("Phase 3"),
//            docs/v05-research/preflight_v05_probe_inventory.md "2. Rust"

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

const PHASE3_IDS = ['RS-DESERIALIZE-001', 'RS-SECRETS-001', 'RS-SQL-RAW-001', 'RS-TLS-VERIFY-001'];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => PHASE3_IDS.includes(e.probe_id));
const byId = (id) => PROBE_MANIFEST_V05[id];

describe('Phase 3: Rust manifest shape', () => {
  it('registers the four Rust adapters and they are the only rust ones', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of PHASE3_IDS) expect(ids).toContain(id);
    const rustIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'rust')
      .map((e) => e.probe_id)
      .sort();
    expect(rustIds).toEqual([...PHASE3_IDS].sort());
  });

  it('every Rust adapter is shadow + experimental + rust + no legacy seed', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(true);
      expect(e.maturity).toBe('experimental');
      expect(e.language).toBe('rust');
      expect(e.legacy_finding_id_seed).toBe(null);
    }
  });

  it('each Rust adapter inherits its XL family Learn slug', () => {
    expect(byId('RS-DESERIALIZE-001').xl_family).toBe('XL-001');
    expect(byId('RS-DESERIALIZE-001').learn_more_slug).toBe('xl-unsafe-deserialization');
    expect(byId('RS-SQL-RAW-001').xl_family).toBe('XL-002');
    expect(byId('RS-SQL-RAW-001').learn_more_slug).toBe('xl-raw-query-interpolation');
    expect(byId('RS-TLS-VERIFY-001').xl_family).toBe('XL-004');
    expect(byId('RS-TLS-VERIFY-001').learn_more_slug).toBe('xl-tls-verification-disabled');
    expect(byId('RS-SECRETS-001').xl_family).toBe('XL-006');
    expect(byId('RS-SECRETS-001').learn_more_slug).toBe('xl-hardcoded-secrets');
  });

  it('Rust adapters are invisible to users (not in v0.4 PROBES, not in OWASP map)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    const owaspNames = new Set(Object.values(MANIFEST_OWASP_MAP).flat());
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(false);
      expect(owaspNames.has(e.name)).toBe(false);
    }
  });
});

describe('Phase 3: fixture + Learn contracts', () => {
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

describe('Phase 3: Rust adapter detection (positive fires, negative silent)', () => {
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
