// Phase 3 (C family). C and C++ adapters for XL-002/004/006. XL-001
// (unsafe deserialization) does not meaningfully apply to C/C++ — there is
// no pickle / ObjectInputStream gadget concept — so the C family adapts
// only the families that apply (composition: a language need not cover
// every XL family). New detection, shadow only, family Learn pages
// inherited.
//
// Reference: docs/v05-research/preflight_v05_probe_inventory.md
//            "8. C" / "9. C++"

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

const C_IDS = ['CC-SECRETS-001', 'CC-SQL-RAW-001', 'CC-TLS-VERIFY-001'];
const CPP_IDS = ['CPP-SECRETS-001', 'CPP-SQL-RAW-001', 'CPP-TLS-VERIFY-001'];
const ALL = [...C_IDS, ...CPP_IDS];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => ALL.includes(e.probe_id));
const byId = (id) => PROBE_MANIFEST_V05[id];

const SLUG = {
  'SQL-RAW': 'xl-raw-query-interpolation',
  'TLS-VERIFY': 'xl-tls-verification-disabled',
  SECRETS: 'xl-hardcoded-secrets',
};
const XL = { 'SQL-RAW': 'XL-002', 'TLS-VERIFY': 'XL-004', SECRETS: 'XL-006' };
const familyKey = (id) => id.replace(/^(?:CC|CPP)-/, '').replace(/-001$/, '');

describe('Phase 3 (C family): manifest shape', () => {
  it('registers the three C and three C++ adapters', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of ALL) expect(ids).toContain(id);
    const cIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'c')
      .map((e) => e.probe_id)
      .sort();
    const cppIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'cpp')
      .map((e) => e.probe_id)
      .sort();
    expect(cIds).toEqual([...C_IDS].sort());
    expect(cppIds).toEqual([...CPP_IDS].sort());
  });

  it('every C-family adapter is shadow + experimental + no legacy seed', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(true);
      expect(e.maturity).toBe('experimental');
      expect(e.legacy_finding_id_seed).toBe(null);
      expect(['c', 'cpp']).toContain(e.language);
    }
  });

  it('each adapter resolves the right XL family + inherited Learn slug', () => {
    for (const e of ENTRIES) {
      const k = familyKey(e.probe_id);
      expect(e.xl_family).toBe(XL[k]);
      expect(e.learn_more_slug).toBe(SLUG[k]);
    }
  });

  it('C-family adapters are invisible to users (not in v0.4 PROBES, not in OWASP map)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    const owaspNames = new Set(Object.values(MANIFEST_OWASP_MAP).flat());
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(false);
      expect(owaspNames.has(e.name)).toBe(false);
    }
  });
});

describe('Phase 3 (C family): fixture + Learn contracts', () => {
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

describe('Phase 3 (C family): adapter detection (positive fires, negative silent)', () => {
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
