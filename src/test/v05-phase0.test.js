// Phase 0 infrastructure tests. Assert the v0.5 schema scaffolding works on
// empty input AND produces the right failures on malformed input — without
// any real adapters registered. These tests gate Phase 1+ adapter authoring:
// if Phase 0 regresses, the whole v0.5 surface is suspect.
//
// Reference: docs/v05-research/v05-architecture.md ("Phase 0 — Infrastructure
// landing")

import { describe, it, expect } from 'vitest';
import {
  PROBE_MANIFEST_V05,
  MANIFEST_OWASP_MAP,
  buildManifest,
  validateAdapter,
  validateFamily,
  validateFixturePaths,
  buildOwaspMapFromManifest,
  mergeOwaspMaps,
} from '../lib/probes/v05/manifest.js';
import { runShadow, compareShadowToProduction } from '../lib/probes/v05/shadow.js';
import {
  LANGUAGES,
  CATEGORIES,
  SEVERITIES,
  AUTOFIX_TIERS,
  MATURITIES,
  PROBE_ID_RE,
  XL_FAMILY_RE,
} from '../lib/probes/v05/types.js';
import { PROBE_OWASP_MAP, OWASP_BY_PROBE, attachProbeMeta, stableId } from '../lib/stable-id.js';

// ---- Empty-input contract: Phase 0 ships with zero adapters ----

describe('Phase 0: empty manifest', () => {
  it('PROBE_MANIFEST_V05 is an empty frozen object', () => {
    expect(PROBE_MANIFEST_V05).toEqual({});
    expect(Object.isFrozen(PROBE_MANIFEST_V05)).toBe(true);
  });

  it('MANIFEST_OWASP_MAP is empty for Phase 0', () => {
    expect(MANIFEST_OWASP_MAP).toEqual({});
  });

  it('buildManifest with empty inputs returns a frozen empty object', () => {
    const m = buildManifest([], []);
    expect(m).toEqual({});
    expect(Object.isFrozen(m)).toBe(true);
  });
});

// ---- Type-constant exports for downstream tooling ----

describe('Phase 0: schema constants', () => {
  it('LANGUAGES covers all 14 v0.5 target languages plus JS/TS', () => {
    expect(LANGUAGES.length).toBeGreaterThanOrEqual(14);
    expect(LANGUAGES).toContain('python');
    expect(LANGUAGES).toContain('rust');
    expect(LANGUAGES).toContain('elixir');
    expect(LANGUAGES).toContain('dart');
  });

  it('MATURITIES is exactly the four documented values', () => {
    expect([...MATURITIES]).toEqual(['experimental', 'beta', 'stable', 'deprecated']);
  });

  it('AUTOFIX_TIERS matches the v0.5 schema', () => {
    expect([...AUTOFIX_TIERS]).toEqual(['mechanical', 'review-needed', 'manual']);
  });

  it('SEVERITIES matches v0.4 (unchanged in v0.5)', () => {
    expect([...SEVERITIES]).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });

  it('CATEGORIES covers the v0.5 category enum', () => {
    expect(CATEGORIES).toContain('security');
    expect(CATEGORIES).toContain('supply');
    expect(CATEGORIES).toContain('llm');
    expect(CATEGORIES).toContain('crypto');
    expect(CATEGORIES).toContain('transport');
  });

  it('PROBE_ID_RE accepts valid LANG-CATEGORY-NNN ids', () => {
    expect(PROBE_ID_RE.test('PY-DESERIALIZE-001')).toBe(true);
    expect(PROBE_ID_RE.test('JV-MASS-ASSIGN-001')).toBe(true);
    expect(PROBE_ID_RE.test('RB-SQL-RAW-042')).toBe(true);
    expect(PROBE_ID_RE.test('CS-WPF-XAML-001')).toBe(true);
  });

  it('PROBE_ID_RE rejects malformed ids', () => {
    expect(PROBE_ID_RE.test('py-deserialize-001')).toBe(false); // lowercase
    expect(PROBE_ID_RE.test('PY-DESERIALIZE-1')).toBe(false); // <3 digits
    expect(PROBE_ID_RE.test('XL-001')).toBe(false); // that's an xl_family, not a probe_id
  });

  it('XL_FAMILY_RE accepts XL-001..XL-999', () => {
    expect(XL_FAMILY_RE.test('XL-001')).toBe(true);
    expect(XL_FAMILY_RE.test('XL-012')).toBe(true);
    expect(XL_FAMILY_RE.test('XL-1')).toBe(false);
    expect(XL_FAMILY_RE.test('xl-001')).toBe(false);
  });
});

// ---- Validator contract: hard failure on malformed input ----

const validAdapter = () => ({
  probe_id: 'PY-DESERIALIZE-001',
  xl_family: 'XL-001',
  language: 'python',
  name: 'Python Unsafe Deserialization',
  category: 'security',
  severity: 'critical',
  confidence: 'high',
  cwe: 'CWE-502',
  owasp_web: 'A08',
  owasp_llm: null,
  detector: 'ast',
  scope: '**/*.py',
  what_it_catches: 'pickle.load / yaml.load on untrusted input',
  why_ai_v05: 'tool corpus predates secure alternatives',
  vibe_v05: 'save object, load object',
  detection_approach: 'AST call match + import resolution',
  fp_gates_v05: ['signed internal artifact', 'allowlist filter present'],
  remediation: 'use safe_load or schema validation',
  autofix_v05: 'review-needed',
  fixtures_v05: {
    positive: 'src/lib/probes/v05/fixtures/PY-DESERIALIZE-001/positive.py',
    negative: 'src/lib/probes/v05/fixtures/PY-DESERIALIZE-001/negative.py',
  },
  known_incidents: null,
  ioc_bundle_ref: null,
  maturity: 'beta',
  detect: () => [],
});

describe('Phase 0: validateAdapter', () => {
  it('accepts a well-formed adapter record', () => {
    expect(() => validateAdapter(validAdapter())).not.toThrow();
  });

  it('rejects missing probe_id', () => {
    const a = validAdapter();
    delete a.probe_id;
    expect(() => validateAdapter(a)).toThrow(/probe_id/);
  });

  it('rejects malformed probe_id', () => {
    const a = validAdapter();
    a.probe_id = 'not-a-real-id';
    expect(() => validateAdapter(a)).toThrow(/LANG-CATEGORY-NNN/);
  });

  it('rejects unknown language', () => {
    const a = validAdapter();
    a.language = 'klingon';
    expect(() => validateAdapter(a)).toThrow(/language/);
  });

  it('rejects unknown severity', () => {
    const a = validAdapter();
    a.severity = 'apocalyptic';
    expect(() => validateAdapter(a)).toThrow(/severity/);
  });

  it('rejects unknown maturity', () => {
    const a = validAdapter();
    a.maturity = 'wishful';
    expect(() => validateAdapter(a)).toThrow(/maturity/);
  });

  it('rejects missing fixture paths', () => {
    const a = validAdapter();
    delete a.fixtures_v05.positive;
    expect(() => validateAdapter(a)).toThrow(/fixtures_v05/);
  });

  it('rejects non-function detect', () => {
    const a = validAdapter();
    a.detect = 'not a function';
    expect(() => validateAdapter(a)).toThrow(/detect/);
  });

  it('accepts xl_family: null (language-specific probe with no shared family)', () => {
    const a = validAdapter();
    a.xl_family = null;
    expect(() => validateAdapter(a)).not.toThrow();
  });

  it('rejects malformed xl_family', () => {
    const a = validAdapter();
    a.xl_family = 'XL001';
    expect(() => validateAdapter(a)).toThrow(/xl_family/);
  });
});

// ---- Family validator ----

const validFamily = () => ({
  xl_id: 'XL-001',
  name: 'Unsafe Deserialization',
  category: 'security',
  severity_default: 'critical',
  cwe: 'CWE-502',
  owasp_web: 'A08',
  owasp_llm: ['LLM03', 'LLM04'],
  why_ai_v05: 'AI tools reach for native API without trust boundary',
  vibe_v05: 'save object, load object',
  fp_gates_v05_shared: ['test fixtures', 'signed internal artifacts'],
  autofix_v05: 'review-needed',
  fixtures_v05_pattern: {
    positive: 'network body to load',
    negative: 'local trusted file',
  },
});

describe('Phase 0: validateFamily', () => {
  it('accepts a well-formed family record', () => {
    expect(() => validateFamily(validFamily())).not.toThrow();
  });

  it('rejects malformed xl_id', () => {
    const f = validFamily();
    f.xl_id = 'XL001';
    expect(() => validateFamily(f)).toThrow(/xl_id/);
  });

  it('rejects missing fixtures_v05_pattern', () => {
    const f = validFamily();
    delete f.fixtures_v05_pattern;
    expect(() => validateFamily(f)).toThrow(/fixtures_v05_pattern/);
  });
});

// ---- Aggregator: duplicate detection and cross-reference checking ----

describe('Phase 0: buildManifest cross-references', () => {
  it('rejects duplicate probe_id', () => {
    const a = validAdapter();
    expect(() => buildManifest([validFamily()], [a, a])).toThrow(/duplicate/);
  });

  it('rejects adapter referencing unknown XL family', () => {
    const a = validAdapter();
    a.xl_family = 'XL-999'; // not registered
    expect(() => buildManifest([validFamily()], [a])).toThrow(/unknown XL family/);
  });

  it('accepts an adapter that references no XL family', () => {
    const a = validAdapter();
    a.xl_family = null;
    expect(() => buildManifest([], [a])).not.toThrow();
  });

  it('builds a single-adapter manifest correctly', () => {
    const a = validAdapter();
    const m = buildManifest([validFamily()], [a]);
    expect(m[a.probe_id]).toBeDefined();
    expect(m[a.probe_id].name).toBe(a.name);
    expect(Object.isFrozen(m[a.probe_id])).toBe(true);
  });
});

// ---- Fixture-existence enforcement (decoupled from runtime) ----

describe('Phase 0: validateFixturePaths', () => {
  it('passes when caller-supplied existsSync returns true', () => {
    const a = validAdapter();
    expect(() => validateFixturePaths(a, () => true)).not.toThrow();
  });

  it('throws when a positive fixture path does not exist', () => {
    const a = validAdapter();
    expect(() => validateFixturePaths(a, () => false)).toThrow(/does not exist/);
  });

  it('treats adversarial as optional', () => {
    const a = validAdapter();
    expect(() => validateFixturePaths(a, () => true)).not.toThrow();
    a.fixtures_v05.adversarial = 'src/lib/probes/v05/fixtures/PY-DESERIALIZE-001/adversarial.py';
    let called = 0;
    validateFixturePaths(a, () => {
      called++;
      return true;
    });
    expect(called).toBe(3); // positive + negative + adversarial
  });
});

// ---- OWASP merge: phase 0 produces v0.4 shape unchanged ----

describe('Phase 0: OWASP merge', () => {
  it('PROBE_OWASP_MAP still exposes the v0.4 shape (hand-coded entries intact)', () => {
    expect(PROBE_OWASP_MAP.A01).toContain('Admin Route Exposure');
    expect(PROBE_OWASP_MAP.A03).toContain('SQL Injection');
    expect(PROBE_OWASP_MAP.LLM01).toContain('LLM Security');
  });

  it('OWASP_BY_PROBE still maps probe names to OWASP codes', () => {
    expect(OWASP_BY_PROBE['SQL Injection']).toContain('A03');
    expect(OWASP_BY_PROBE['Auth Weakness']).toContain('A03');
    expect(OWASP_BY_PROBE['Auth Weakness']).toContain('A07');
  });

  it('mergeOwaspMaps preserves order of hand-coded entries when manifest is empty', () => {
    const handCoded = { A01: ['One', 'Two'], A02: ['Three'] };
    const merged = mergeOwaspMaps(handCoded, {});
    expect(merged.A01).toEqual(['One', 'Two']);
    expect(merged.A02).toEqual(['Three']);
  });

  it('mergeOwaspMaps deduplicates probe names appearing in both sources', () => {
    const handCoded = { A03: ['SQL Injection'] };
    const fromManifest = { A03: ['SQL Injection', 'Python SQL Raw'] };
    const merged = mergeOwaspMaps(handCoded, fromManifest);
    expect(merged.A03).toEqual(['SQL Injection', 'Python SQL Raw']);
  });

  it('mergeOwaspMaps unions categories across both sources', () => {
    const handCoded = { A01: ['Hand-One'] };
    const fromManifest = { LLM06: ['Manifest-One'] };
    const merged = mergeOwaspMaps(handCoded, fromManifest);
    expect(merged.A01).toEqual(['Hand-One']);
    expect(merged.LLM06).toEqual(['Manifest-One']);
  });

  it('buildOwaspMapFromManifest projects adapter owasp_web and owasp_llm into the v0.4 shape', () => {
    const a1 = { ...validAdapter(), probe_id: 'PY-DEMO-001', name: 'P-A', owasp_web: 'A08' };
    const a2 = {
      ...validAdapter(),
      probe_id: 'PY-DEMO-002',
      name: 'P-B',
      owasp_web: null,
      owasp_llm: 'LLM06',
    };
    const m = buildManifest([validFamily()], [a1, a2]);
    const map = buildOwaspMapFromManifest(m);
    expect(map.A08).toEqual(['P-A']);
    expect(map.LLM06).toEqual(['P-B']);
  });
});

// ---- attachProbeMeta: v0.4 behavior unchanged when manifest is empty ----

describe('Phase 0: attachProbeMeta backward compat', () => {
  it('still copies confidence + autofix from PROBE_META for v0.4 probes', () => {
    const f = [{ probe: 'Env File Hygiene', file: 'a.env', line: 1, title: 't' }];
    attachProbeMeta(f);
    expect(f[0].confidence).toBe('high');
    expect(f[0].autofix).toBe('mechanical');
  });

  it('still attaches owasp array from OWASP_BY_PROBE', () => {
    const f = [{ probe: 'SQL Injection', file: 'a.js', line: 1, title: 't' }];
    attachProbeMeta(f);
    expect(f[0].owasp).toContain('A03');
  });

  it('does NOT attach v0.5 fields to v0.4-only probes (empty manifest)', () => {
    const f = [{ probe: 'SQL Injection', file: 'a.js', line: 1, title: 't' }];
    attachProbeMeta(f);
    expect(f[0].probe_id).toBeUndefined();
    expect(f[0].why_ai_v05).toBeUndefined();
    expect(f[0].xl_family).toBeUndefined();
    expect(f[0].maturity).toBeUndefined();
  });
});

// ---- stableId: legacy_finding_id_seed continuity ----

describe('Phase 0: stableId migration continuity', () => {
  it('hashes by probe name when no manifest entry exists (v0.4 path unchanged)', () => {
    const id1 = stableId({ probe: 'Env File Hygiene', file: 'a.env', line: 1, title: 't' }, 'X=1');
    const id2 = stableId({ probe: 'Env File Hygiene', file: 'a.env', line: 1, title: 't' }, 'X=1');
    expect(id1).toBe(id2);
    expect(typeof id1).toBe('string');
    expect(id1.length).toBeGreaterThan(0);
  });

  it('byte-identical IDs across calls for the same finding shape', () => {
    const f = { probe: 'X', file: 'src/a.js', line: 10, title: 'Found something' };
    const content = 'line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11';
    expect(stableId(f, content)).toBe(stableId(f, content));
  });
});

// ---- Shadow channel: harness works on empty input ----

describe('Phase 0: shadow channel', () => {
  it('runShadow returns adapter findings without mutating the input', () => {
    const adapter = {
      ...validAdapter(),
      detect: () => [
        { probe: 'X', file: 'a.py', line: 1, title: 'shadow finding', severity: 'high' },
      ],
    };
    const files = [{ path: 'a.py', content: 'import pickle' }];
    const out = runShadow(adapter, files);
    expect(out).toHaveLength(1);
    expect(out[0].title).toBe('shadow finding');
  });

  it('runShadow throws when adapter is malformed', () => {
    expect(() => runShadow({ detect: () => [] }, [])).toThrow();
  });

  it('runShadow throws when adapter.detect returns a non-array', () => {
    const adapter = { ...validAdapter(), detect: () => 'not-an-array' };
    expect(() => runShadow(adapter, [])).toThrow(/must return an array/);
  });

  it('compareShadowToProduction counts stableId matches', () => {
    const shadow = [
      { stableId: 'aaa', probe: 'X', file: 'a.js', line: 1 },
      { stableId: 'bbb', probe: 'X', file: 'b.js', line: 2 },
    ];
    const prod = [
      { stableId: 'aaa', probe: 'X', file: 'a.js', line: 1 },
      { stableId: 'ccc', probe: 'X', file: 'c.js', line: 3 },
    ];
    const cmp = compareShadowToProduction(shadow, prod);
    expect(cmp.matched).toBe(1);
    expect(cmp.onlyInShadow).toHaveLength(1);
    expect(cmp.onlyInShadow[0].stableId).toBe('bbb');
    expect(cmp.onlyInProduction).toHaveLength(1);
    expect(cmp.onlyInProduction[0].stableId).toBe('ccc');
  });

  it('compareShadowToProduction falls back to composite key when stableId is absent', () => {
    const shadow = [{ probe: 'X', file: 'a.js', line: 1 }];
    const prod = [{ probe: 'X', file: 'a.js', line: 1 }];
    const cmp = compareShadowToProduction(shadow, prod);
    expect(cmp.matched).toBe(1);
  });
});
