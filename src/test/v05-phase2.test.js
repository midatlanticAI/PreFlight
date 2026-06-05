// Phase 2 tests. Migration of three overlapping v0.4 probes into v0.5
// adapters under XL families, in shadow mode, with legacy_finding_id_seed
// for stableId continuity:
//
//   Secret Scanner -> JS-SECRET-001 (XL-006)
//   SQL Injection  -> JS-SQL-RAW-001 (XL-002)
//   Auth Weakness  -> JS-AUTH-001   (XL-013, the new family)
//
// The load-bearing test is PARITY: each shadow adapter must produce
// stableId-identical findings to the v0.4 probe it replaces, so that the
// eventual shadow:false flip preserves every user's suppression entries.
// If a re-expression drifts from its v0.4 source, the parity block fails.
//
// Reference: docs/v05-research/v05-architecture.md ("Phase 2", "execution
// gap #2: shadow-mode for adapters during Phase 2")

import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import {
  PROBE_MANIFEST_V05,
  MANIFEST_OWASP_MAP,
  validateFixturePaths,
  validateLearnContent,
} from '../lib/probes/v05/manifest.js';
import { runShadow, compareShadowToProduction } from '../lib/probes/v05/shadow.js';
import { getBySlug } from '../lib/learn-content.js';
import { stableId } from '../lib/stable-id.js';
import { probeSecrets, probeAuthWeakness } from '../lib/probes.js';
import { probeSQLInjectionTemplateLiterals } from '../lib/probes/v05.js';
import { PROBES } from '../App.jsx';

const PHASE2_IDS = ['JS-AUTH-001', 'JS-SECRET-001', 'JS-SQL-RAW-001'];
const ENTRIES = Object.values(PROBE_MANIFEST_V05).filter((e) => PHASE2_IDS.includes(e.probe_id));
const byId = (id) => PROBE_MANIFEST_V05[id];

describe('Phase 2: manifest shape', () => {
  it('registers the three JS migration adapters', () => {
    const ids = Object.keys(PROBE_MANIFEST_V05);
    for (const id of PHASE2_IDS) expect(ids).toContain(id);
  });

  it('every Phase 2 adapter is shadow + experimental + javascript', () => {
    for (const e of ENTRIES) {
      expect(e.shadow).toBe(false);
      expect(e.maturity).toBe('experimental');
      expect(e.language).toBe('javascript');
    }
  });

  it('each adapter carries the legacy_finding_id_seed of the v0.4 probe it migrates', () => {
    expect(byId('JS-SECRET-001').legacy_finding_id_seed).toBe('Secret Scanner');
    expect(byId('JS-SQL-RAW-001').legacy_finding_id_seed).toBe('SQL Injection');
    expect(byId('JS-AUTH-001').legacy_finding_id_seed).toBe('Auth Weakness');
  });

  it('each adapter resolves its XL family and inherits the family Learn slug', () => {
    expect(byId('JS-SECRET-001').xl_family).toBe('XL-006');
    expect(byId('JS-SECRET-001').learn_more_slug).toBe('xl-hardcoded-secrets');
    expect(byId('JS-SQL-RAW-001').xl_family).toBe('XL-002');
    expect(byId('JS-SQL-RAW-001').learn_more_slug).toBe('xl-raw-query-interpolation');
    expect(byId('JS-AUTH-001').xl_family).toBe('XL-013');
    expect(byId('JS-AUTH-001').learn_more_slug).toBe('xl-auth-token-verification');
  });

  it('Phase 2 adapters are invisible to users (not in v0.4 PROBES, not in OWASP map)', () => {
    const probeNames = new Set(PROBES.map((p) => p.name));
    const owaspNames = new Set(Object.values(MANIFEST_OWASP_MAP).flat());
    for (const e of ENTRIES) {
      expect(probeNames.has(e.name)).toBe(false);
      expect(owaspNames.has(e.name)).toBe(false);
    }
  });
});

// ---- Build-time contracts ----

describe('Phase 2: fixture + Learn contracts', () => {
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

  it('every adapter resolves to a published Learn page', () => {
    for (const e of ENTRIES) {
      expect(() => validateLearnContent(e, patternExists, patternIsDraft)).not.toThrow();
    }
  });

  it('the new XL-013 Learn page exists and is published', () => {
    const entry = getBySlug('xl-auth-token-verification');
    expect(entry, 'xl-auth-token-verification missing').toBeDefined();
    expect(entry.draft).toBe(false);
    expect(entry.type).toBe('pattern');
  });
});

// ---- Per-adapter behaviour on the real fixtures ----

const fixtureFile = (realPath) => ({
  path: realPath.replace(/^.*\/fixtures\//, '__fixture_under_test__/'),
  content: readFileSync(realPath, 'utf8'),
});

describe('Phase 2: adapter detection (positive fires, negative silent)', () => {
  for (const e of ENTRIES) {
    describe(e.probe_id, () => {
      it('flags the positive fixture (>=1 finding, carries adapter name)', () => {
        const f = runShadow(e, [fixtureFile(e.fixtures_v05.positive)]);
        expect(f.length).toBeGreaterThan(0);
        for (const finding of f) {
          expect(finding.probe).toBe(e.name);
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

// ---- The load-bearing parity block ----
//
// A realistic JS/TS corpus exercising every migrated pattern, plus
// negatives and a commented-out call (to prove comment-stripping parity).
// The same corpus is fed to the shadow adapter and to the real v0.4
// probe; stableIds must match exactly.

const CORPUS = [
  {
    path: 'app/db/users.js',
    content: [
      "import db from './client';",
      'export async function find(req) {',
      '  const id = req.params.id;',
      '  // db.query(`SELECT * FROM users WHERE id = ${id}`)  <- teaching comment, must NOT fire',
      '  const a = await db.query(`SELECT * FROM users WHERE id = ${id}`);',
      '  const b = await db.query("SELECT * FROM users WHERE id = $1", [id]);',
      '  return [a, b];',
      '}',
    ].join('\n'),
  },
  {
    path: 'app/config.ts',
    content: [
      'export const cfg = {',
      "  region: 'us-east-1',",
      // Synthetic AKIA shape. probeSecrets now correctly suppresses the
      // AWS-published documentation value `AKIAIOSFODNN7EXAMPLE` via its
      // placeholder filter; use a plain alphanumeric AKIA so both the v0.4
      // probe and the v0.5 JS-SECRET-001 adapter still fire on this row.
      "  accessKeyId: 'AKIA1234567890ABCDEF',",
      '  fromEnv: process.env.AWS_ACCESS_KEY_ID,',
      '};',
    ].join('\n'),
  },
  {
    path: 'app/auth/jwt.ts',
    content: [
      "import jwt from 'jsonwebtoken';",
      "export const sign = (p) => jwt.sign(p, null, { algorithm: 'none' });",
      '// const stale = jwt.verify(token)   <- commented out, must NOT fire',
      'export const check = (token) => jwt.verify(token);',
      'export const ok = (token) => jwt.verify(token, signingKey);',
      // expiresIn keeps both probes from firing the new CWE-613 auth-noexpiry
      // finding on this otherwise well-formed jwt.sign call.
      "export const good = (p) => jwt.sign(p, key, { algorithm: 'HS256', expiresIn: '15m' });",
    ].join('\n'),
  },
];

const CONTENT = new Map(CORPUS.map((f) => [f.path, f.content]));
const isJs = (p) => /\.[jt]sx?$|\.mjs$|\.cjs$/i.test(p);
const withIds = (findings) =>
  findings.map((x) => ({ ...x, stableId: stableId(x, CONTENT.get(x.file)) }));

describe('Phase 2: stableId parity vs the v0.4 probe (flip-safety)', () => {
  it('JS-SECRET-001 == v0.4 Secret Scanner (JS/TS slice), stableIds identical', () => {
    const shadow = withIds(runShadow(byId('JS-SECRET-001'), CORPUS));
    const prod = withIds(probeSecrets(CORPUS).filter((x) => isJs(x.file)));
    expect(prod.length).toBeGreaterThan(0);
    const cmp = compareShadowToProduction(shadow, prod);
    expect(cmp.onlyInProduction).toEqual([]);
    expect(cmp.onlyInShadow).toEqual([]);
    expect(cmp.matched).toBe(prod.length);
  });

  it('JS-SQL-RAW-001 == v0.4 SQL Injection (JS/TS slice), stableIds identical', () => {
    const shadow = withIds(runShadow(byId('JS-SQL-RAW-001'), CORPUS));
    const prod = withIds(probeSQLInjectionTemplateLiterals(CORPUS).filter((x) => isJs(x.file)));
    expect(prod.length).toBeGreaterThan(0);
    const cmp = compareShadowToProduction(shadow, prod);
    expect(cmp.onlyInProduction).toEqual([]);
    expect(cmp.onlyInShadow).toEqual([]);
    expect(cmp.matched).toBe(prod.length);
  });

  it('JS-AUTH-001 == the Auth Weakness facet of v0.4 (stableIds identical, Code Injection left behind)', () => {
    const shadow = withIds(runShadow(byId('JS-AUTH-001'), CORPUS));
    const v04 = probeAuthWeakness(CORPUS);
    const prod = withIds(v04.filter((x) => x.probe === 'Auth Weakness' && isJs(x.file)));
    expect(prod.length).toBeGreaterThan(0);
    const cmp = compareShadowToProduction(shadow, prod);
    expect(cmp.onlyInProduction).toEqual([]);
    expect(cmp.onlyInShadow).toEqual([]);
    expect(cmp.matched).toBe(prod.length);
    // The Code Injection facet is intentionally NOT migrated by JS-AUTH-001.
    const shadowTitles = new Set(shadow.map((s) => s.title));
    for (const ci of v04.filter((x) => x.probe === 'Code Injection')) {
      expect(shadowTitles.has(ci.title)).toBe(false);
    }
  });

  it('the JS adapters ignore non-JS files (the v0.4 probe still covers them)', () => {
    const py = [{ path: 'app/leak.py', content: "KEY = 'AKIAIOSFODNN7EXAMPLE'" }];
    expect(runShadow(byId('JS-SECRET-001'), py)).toEqual([]);
  });
});
