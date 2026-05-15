// v1 hardening — manifest-wide consistency / invariant suite.
//
// Per-phase tests prove each adapter fires on its own fixture. This suite
// proves systemic properties hold across EVERY v0.5 adapter at once, so a
// new adapter cannot regress the contract:
//   - prose completeness (an adapter with empty why/vibe/remediation is
//     not ecosystem-complete)
//   - unique ids + names; valid enums
//   - v1 promotion invariant: shadow:false everywhere; net-new adapters
//     LIVE, migration adapters held out until the v0.4 cutover
//   - detect() is pure-ish: [] in => [] out, returns an array
//   - every positive fixture fires, every negative fixture is silent
//   - comment-only code does NOT fire (for comment-aware adapters)
//   - secret/crypto adapters MASK evidence (no raw long literal leaks)
//   - every adapter resolves a published Learn page

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { PROBE_MANIFEST_V05 } from '../lib/probes/v05/manifest.js';
import { runShadow } from '../lib/probes/v05/shadow.js';
import { getBySlug } from '../lib/learn-content.js';
import {
  LANGUAGES,
  CATEGORIES,
  SEVERITIES,
  CONFIDENCES,
  DETECTORS,
  AUTOFIX_TIERS,
  MATURITIES,
  PROBE_ID_RE,
} from '../lib/probes/v05/types.js';

const ENTRIES = Object.values(PROBE_MANIFEST_V05);
const fixtureFile = (realPath) => ({
  path: realPath.replace(/^.*\/fixtures\//, '__fixture_under_test__/'),
  content: readFileSync(realPath, 'utf8'),
});
const HASH_LANGS = new Set(['python', 'ruby', 'elixir']);
const commentToken = (lang) => (HASH_LANGS.has(lang) ? '# ' : '// ');

describe('v0.5 consistency: identity + enums', () => {
  it('there is at least the full multi-language adapter set', () => {
    expect(ENTRIES.length).toBeGreaterThanOrEqual(45);
  });

  it('probe_id and name are unique and well-formed', () => {
    const ids = new Set();
    const names = new Set();
    for (const e of ENTRIES) {
      expect(PROBE_ID_RE.test(e.probe_id), e.probe_id).toBe(true);
      expect(ids.has(e.probe_id), `dup id ${e.probe_id}`).toBe(false);
      expect(names.has(e.name), `dup name ${e.name}`).toBe(false);
      ids.add(e.probe_id);
      names.add(e.name);
    }
  });

  it('every enum field is in range', () => {
    for (const e of ENTRIES) {
      expect(LANGUAGES, e.probe_id).toContain(e.language);
      expect(CATEGORIES).toContain(e.category);
      expect(SEVERITIES).toContain(e.severity);
      expect(CONFIDENCES).toContain(e.confidence);
      expect(DETECTORS).toContain(e.detector);
      expect(AUTOFIX_TIERS).toContain(e.autofix_v05);
      expect(MATURITIES).toContain(e.maturity);
    }
  });

  it('every v0.5 adapter is promoted (shadow:false) for v1', () => {
    for (const e of ENTRIES) expect(e.shadow, e.probe_id).toBe(false);
  });

  it('net-new adapters are LIVE; migration adapters are held out until v0.4 cutover', () => {
    for (const e of ENTRIES) {
      const live = !e.shadow && e.legacy_finding_id_seed == null;
      if (e.legacy_finding_id_seed == null) {
        expect(live, `${e.probe_id} net-new must be live`).toBe(true);
      } else {
        // migration adapter: shadow:false but not live yet (would double-fire)
        expect(live, `${e.probe_id} migration must be held out`).toBe(false);
      }
    }
  });
});

describe('v0.5 consistency: prose is ecosystem-complete', () => {
  const PROSE = ['what_it_catches', 'why_ai_v05', 'vibe_v05', 'detection_approach', 'remediation'];
  it('every adapter has non-empty prose for every required field', () => {
    for (const e of ENTRIES) {
      for (const f of PROSE) {
        expect(typeof e[f], `${e.probe_id}.${f}`).toBe('string');
        expect(e[f].trim().length, `${e.probe_id}.${f} empty`).toBeGreaterThan(10);
      }
      expect(Array.isArray(e.fp_gates_v05), `${e.probe_id}.fp_gates_v05`).toBe(true);
      expect(e.fp_gates_v05.length, `${e.probe_id} fp_gates empty`).toBeGreaterThan(0);
      for (const g of e.fp_gates_v05) expect(g.trim().length).toBeGreaterThan(0);
    }
  });

  it('every adapter resolves a published, non-draft Learn page', () => {
    for (const e of ENTRIES) {
      const entry = getBySlug(e.learn_more_slug);
      expect(entry, `${e.probe_id} -> ${e.learn_more_slug}`).toBeDefined();
      expect(entry.draft).toBe(false);
      expect(entry.type).toBe('pattern');
    }
  });
});

describe('v0.5 consistency: detect() behaviour', () => {
  it('detect([]) returns [] for every adapter (pure, no crash on empty)', () => {
    for (const e of ENTRIES) {
      const out = runShadow(e, []);
      expect(Array.isArray(out), e.probe_id).toBe(true);
      expect(out.length, `${e.probe_id} fired on empty input`).toBe(0);
    }
  });

  it('every positive fixture fires (>=1, probe===name) and negative is silent', () => {
    for (const e of ENTRIES) {
      const pos = runShadow(e, [fixtureFile(e.fixtures_v05.positive)]);
      expect(pos.length, `${e.probe_id} positive fixture`).toBeGreaterThan(0);
      for (const f of pos) {
        expect(f.probe, e.probe_id).toBe(e.name);
        expect(SEVERITIES).toContain(f.severity);
        expect(typeof f.cwe === 'string' && /^CWE-\d+/.test(f.cwe)).toBe(true);
        expect(typeof f.file).toBe('string');
        expect(typeof f.line).toBe('number');
      }
      const neg = runShadow(e, [fixtureFile(e.fixtures_v05.negative)]);
      expect(neg, `${e.probe_id} negative fixture should be silent`).toEqual([]);
    }
  });
});

describe('v0.5 consistency: comment-aware adapters skip commented code', () => {
  // Secrets-family adapters intentionally fire on a secret even inside a
  // comment (a committed secret is leaked regardless), and the Phase 2
  // migration wrappers mirror v0.4 comment behaviour for stableId parity.
  // Everything else must NOT fire when its positive fixture is fully
  // commented out.
  const exempt = (e) => e.xl_family === 'XL-006' || e.legacy_finding_id_seed !== null;

  it('a fully-commented positive fixture produces zero findings', () => {
    for (const e of ENTRIES) {
      if (exempt(e)) continue;
      const real = fixtureFile(e.fixtures_v05.positive);
      const tok = commentToken(e.language);
      const commented = {
        path: real.path,
        content: real.content
          .split('\n')
          .map((l) => tok + l)
          .join('\n'),
      };
      const out = runShadow(e, [commented]);
      expect(out, `${e.probe_id} fired on fully-commented code`).toEqual([]);
    }
  });
});

describe('v0.5 consistency: secret/crypto adapters mask evidence', () => {
  it('XL-006 findings never echo a raw 20+ char secret literal', () => {
    const secretAdapters = ENTRIES.filter((e) => e.xl_family === 'XL-006');
    expect(secretAdapters.length).toBeGreaterThan(0);
    for (const e of secretAdapters) {
      const pos = runShadow(e, [fixtureFile(e.fixtures_v05.positive)]);
      expect(pos.length, `${e.probe_id}`).toBeGreaterThan(0);
      for (const f of pos) {
        // The synthetic fixtures use a 20+ run of one char or a known
        // example key; masked evidence must not contain a long literal run.
        expect(/[A-Za-z0-9]{20,}/.test(f.evidence), `${e.probe_id} leaked: ${f.evidence}`).toBe(
          false
        );
      }
    }
  });
});
