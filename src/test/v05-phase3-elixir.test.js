// Phase 3 (Elixir). XL-001 (:erlang.binary_to_term), XL-002 (Ecto
// fragment interpolation), XL-004 (verify_none/insecure), XL-006
// (secret_key_base). New detection, shadow only, family Learn pages
// inherited.
//
// Reference: docs/v05-research/preflight_v05_probe_inventory.md "13. Elixir"

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

const IDS = ['EX-DESERIALIZE-001', 'EX-SECRETS-001', 'EX-SQL-RAW-001', 'EX-TLS-VERIFY-001'];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => IDS.includes(e.probe_id));
const byId = (id) => PROBE_MANIFEST_V05[id];

describe('Phase 3 (Elixir): manifest shape', () => {
  it('registers the four Elixir adapters and they are the only elixir ones', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of IDS) expect(ids).toContain(id);
    const exIds = Object.values(PROBE_MANIFEST_V05)
      .filter((e) => e.language === 'elixir')
      .map((e) => e.probe_id)
      .sort();
    expect(exIds).toEqual([...IDS].sort());
  });

  it('every Elixir adapter is shadow + experimental + elixir + no legacy seed', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(false);
      expect(e.maturity).toBe('experimental');
      expect(e.language).toBe('elixir');
      expect(e.legacy_finding_id_seed).toBe(null);
    }
  });

  it('each Elixir adapter resolves the right XL family + inherited Learn slug', () => {
    expect(byId('EX-DESERIALIZE-001').xl_family).toBe('XL-001');
    expect(byId('EX-DESERIALIZE-001').learn_more_slug).toBe('xl-unsafe-deserialization');
    expect(byId('EX-SQL-RAW-001').xl_family).toBe('XL-002');
    expect(byId('EX-SQL-RAW-001').learn_more_slug).toBe('xl-raw-query-interpolation');
    expect(byId('EX-TLS-VERIFY-001').xl_family).toBe('XL-004');
    expect(byId('EX-TLS-VERIFY-001').learn_more_slug).toBe('xl-tls-verification-disabled');
    expect(byId('EX-SECRETS-001').xl_family).toBe('XL-006');
    expect(byId('EX-SECRETS-001').learn_more_slug).toBe('xl-hardcoded-secrets');
  });

  it('Elixir adapters are LIVE and user-visible (in v0.4 PROBES + OWASP map)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    const owaspNames = new Set(Object.values(MANIFEST_OWASP_MAP).flat());
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(true);
      expect(owaspNames.has(e.name)).toBe(true);
    }
  });
});

describe('Phase 3 (Elixir): fixture + Learn contracts', () => {
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

describe('Phase 3 (Elixir): adapter detection (positive fires, negative silent)', () => {
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
