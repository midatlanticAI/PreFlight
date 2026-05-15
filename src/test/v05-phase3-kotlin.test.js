// Phase 3 (Kotlin). XL-002 (Room raw SQL), XL-004 (trust-all), XL-006
// (secrets), XL-013 (jjwt unsigned parse). XL-001 is intentionally NOT
// adapted — the corpus does not emphasise a Kotlin-specific unsafe-
// deserialization pattern (composition: adapt only families that apply).
// New detection, shadow only, family Learn pages inherited.
//
// Reference: docs/v05-research/preflight_v05_probe_inventory.md "5. Kotlin"

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

const IDS = ['KT-AUTH-001', 'KT-SECRETS-001', 'KT-SQL-RAW-001', 'KT-TLS-VERIFY-001'];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => IDS.includes(e.probe_id));
const byId = (id) => PROBE_MANIFEST_V05[id];

describe('Phase 3 (Kotlin): manifest shape', () => {
  it('registers the four Kotlin adapters and they are the only kotlin ones', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of IDS) expect(ids).toContain(id);
    const ktIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'kotlin')
      .map((e) => e.probe_id)
      .sort();
    expect(ktIds).toEqual([...IDS].sort());
  });

  it('every Kotlin adapter is shadow + experimental + kotlin + no legacy seed', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(true);
      expect(e.maturity).toBe('experimental');
      expect(e.language).toBe('kotlin');
      expect(e.legacy_finding_id_seed).toBe(null);
    }
  });

  it('each Kotlin adapter resolves the right XL family + inherited Learn slug', () => {
    expect(byId('KT-SQL-RAW-001').xl_family).toBe('XL-002');
    expect(byId('KT-SQL-RAW-001').learn_more_slug).toBe('xl-raw-query-interpolation');
    expect(byId('KT-TLS-VERIFY-001').xl_family).toBe('XL-004');
    expect(byId('KT-TLS-VERIFY-001').learn_more_slug).toBe('xl-tls-verification-disabled');
    expect(byId('KT-SECRETS-001').xl_family).toBe('XL-006');
    expect(byId('KT-SECRETS-001').learn_more_slug).toBe('xl-hardcoded-secrets');
    expect(byId('KT-AUTH-001').xl_family).toBe('XL-013');
    expect(byId('KT-AUTH-001').learn_more_slug).toBe('xl-auth-token-verification');
  });

  it('Kotlin adapters are invisible to users (not in v0.4 PROBES, not in OWASP map)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    const owaspNames = new Set(Object.values(MANIFEST_OWASP_MAP).flat());
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(false);
      expect(owaspNames.has(e.name)).toBe(false);
    }
  });
});

describe('Phase 3 (Kotlin): fixture + Learn contracts', () => {
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

describe('Phase 3 (Kotlin): adapter detection (positive fires, negative silent)', () => {
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
