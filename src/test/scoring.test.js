import { describe, it, expect } from 'vitest';
import {
  computeScore,
  riskTier,
  shouldScanFile,
  SEV_ORDER,
  SEV_WEIGHT,
  timestampSlug,
  timeAgo,
} from '../App.jsx';

describe('SEV_ORDER & SEV_WEIGHT', () => {
  it('SEV_ORDER lists severities highest-first', () => {
    expect(SEV_ORDER[0]).toBe('critical');
    expect(SEV_ORDER[SEV_ORDER.length - 1]).toBe('info');
  });

  it('weights monotonically decrease by severity', () => {
    for (let i = 0; i < SEV_ORDER.length - 1; i++) {
      expect(SEV_WEIGHT[SEV_ORDER[i]]).toBeGreaterThan(SEV_WEIGHT[SEV_ORDER[i + 1]]);
    }
  });
});

describe('computeScore', () => {
  it('returns 100 for empty findings', () => {
    expect(computeScore([])).toBe(100);
  });

  // Scoring model changed 2026-07 from hard band caps to per-class diminishing
  // returns. The caps protected against noise but created a plateau: a real
  // scan went from 24 false-positive findings to 7 and the number did not move
  // a single point, because both counts sat past the cap. Findings now group
  // into classes by probe and severity, and a class costs its weight times
  // count^0.6 (capped at 6x), so removing any instance always changes the total.
  it('charges full weight for the first instance of a class', () => {
    expect(computeScore([{ probe: 'A', severity: 'critical' }])).toBe(100 - SEV_WEIGHT.critical);
  });

  it('charges repeat instances of the same class at a discount', () => {
    const two = computeScore([
      { probe: 'A', severity: 'critical' },
      { probe: 'A', severity: 'critical' },
    ]);
    // More than one, less than two.
    expect(two).toBeLessThan(100 - SEV_WEIGHT.critical);
    expect(two).toBeGreaterThan(100 - 2 * SEV_WEIGHT.critical);
  });

  it('charges separate classes at full weight each', () => {
    expect(
      computeScore([
        { probe: 'A', severity: 'critical' },
        { probe: 'B', severity: 'critical' },
      ])
    ).toBe(100 - 2 * SEV_WEIGHT.critical);
  });

  it('always moves when an instance is removed, at any volume', () => {
    const at = (n) =>
      computeScore(Array.from({ length: n }, () => ({ probe: 'A', severity: 'medium' })));
    // The plateau this replaced: 24 and 7 scored identically.
    expect(at(24)).toBeLessThan(at(12));
    expect(at(12)).toBeLessThan(at(7));
    expect(at(7)).toBeLessThan(at(3));
    expect(at(3)).toBeLessThan(at(1));
    expect(at(1)).toBeLessThan(100);
  });

  it('clamps to 0', () => {
    // Twenty DISTINCT criticals. Twenty instances of one critical pattern is
    // one thing to fix and is charged as such.
    const findings = Array.from({ length: 20 }, (_, i) => ({
      probe: 'P' + i,
      severity: 'critical',
    }));
    expect(computeScore(findings)).toBe(0);
  });

  it('ignores unknown severities (treats as 0)', () => {
    expect(computeScore([{ severity: 'rumor' }])).toBe(100);
  });

  // REGRESSION: two early users reported a frontend repo scoring ~32
  // ("CRITICAL") off nothing but sparse SEO meta. Low-severity bands now
  // have a capped TOTAL contribution so volume cannot crater the score.
  it('keeps repeat volume of one pattern from tanking the score', () => {
    const many = Array.from({ length: 100 }, () => ({ probe: 'A', severity: 'medium' }));
    // 100 * 5 = 500 if charged linearly. One pattern in 100 places is one
    // thing to fix, so it stays well clear of zero.
    const score = computeScore(many);
    expect(score).toBeGreaterThan(60);
    expect(score).toBeLessThan(90);
  });

  it('bounds a single noisy class so volume alone cannot tank the score', () => {
    // The bound is asymptotic, never reached, so the score keeps responding.
    const at = (n, sev) =>
      computeScore(Array.from({ length: n }, () => ({ probe: 'A', severity: sev })));
    expect(at(100, 'low')).toBeGreaterThan(100 - SEV_WEIGHT.low * 6);
    expect(at(100, 'low')).toBeLessThan(at(50, 'low'));
    expect(at(100, 'info')).toBeGreaterThan(100 - SEV_WEIGHT.info * 6);
  });

  it('keeps a cosmetic-only repo well clear of the danger zone', () => {
    const cosmetic = [
      ...Array.from({ length: 40 }, () => ({ probe: 'A', severity: 'medium' })),
      ...Array.from({ length: 40 }, () => ({ probe: 'B', severity: 'low' })),
      ...Array.from({ length: 40 }, () => ({ probe: 'C', severity: 'info' })),
    ];
    const score = computeScore(cosmetic);
    expect(score).toBeGreaterThan(40);
    expect(score).toBeLessThan(100);
  });

  it('real issues still tank it', () => {
    const crits = Array.from({ length: 5 }, (_, i) => ({ probe: 'P' + i, severity: 'critical' }));
    expect(computeScore(crits)).toBe(0); // 5 distinct criticals = 125, clamped
  });
});

describe('riskTier', () => {
  it('100 → LOW RISK', () => {
    expect(riskTier(100).label).toBe('LOW RISK');
  });
  it('70 → MODERATE RISK', () => {
    expect(riskTier(70).label).toBe('MODERATE RISK');
  });
  it('50 → HIGH RISK', () => {
    expect(riskTier(50).label).toBe('HIGH RISK');
  });
  it('10 → CRITICAL RISK', () => {
    expect(riskTier(10).label).toBe('CRITICAL RISK');
  });

  // Severity-aware labelling (the headline + exports pass this). The label
  // must reflect the worst real finding, not the volume of cosmetic ones.
  it('no critical/high present is never CRITICAL or HIGH, even at a low score', () => {
    expect(riskTier(32, { hasCritical: false, hasHigh: false }).label).toBe('MODERATE RISK');
    expect(riskTier(10, { hasCritical: false, hasHigh: false }).label).toBe('MODERATE RISK');
    expect(riskTier(95, { hasCritical: false, hasHigh: false }).label).toBe('LOW RISK');
  });

  it('a critical present reads CRITICAL even with a high numeric score', () => {
    expect(riskTier(90, { hasCritical: true, hasHigh: false }).label).toBe('CRITICAL RISK');
  });

  it('a high (no critical) reads HIGH regardless of score', () => {
    expect(riskTier(88, { hasCritical: false, hasHigh: true }).label).toBe('HIGH RISK');
  });

  it('omitting severity context keeps the original numeric mapping', () => {
    expect(riskTier(32).label).toBe('CRITICAL RISK');
    expect(riskTier(70).label).toBe('MODERATE RISK');
  });
});

describe('shouldScanFile', () => {
  it.each([
    ['.env', true],
    ['package.json', true],
    ['src/app.tsx', true],
    ['src/api/route.js', true],
    ['firestore.rules', true],
    ['next.config.js', true],
    ['vercel.json', true],
    ['.github/workflows/ci.yml', true],
    ['.cursorrules', true],
    ['claude_desktop_config.json', true],
    ['supabase/migrations/001_init.sql', true],
  ])('includes %s', (path, expected) => {
    expect(shouldScanFile(path)).toBe(expected);
  });

  it.each([
    ['node_modules/foo/index.js', false],
    ['.git/HEAD', false],
    ['dist/bundle.js', false],
    ['build/static/x.js', false],
    ['random.png', false],
    ['README.md', false],
  ])('excludes %s', (path, expected) => {
    expect(shouldScanFile(path)).toBe(expected);
  });
});

describe('timestampSlug', () => {
  it('produces YYYYMMDD-HHmm', () => {
    const d = new Date(2026, 4, 10, 13, 7); // local time
    const slug = timestampSlug(d);
    expect(slug).toMatch(/^\d{8}-\d{4}$/);
    expect(slug.startsWith('20260510')).toBe(true);
    expect(slug.endsWith('-1307')).toBe(true);
  });
});

describe('timeAgo', () => {
  it('formats seconds', () => {
    const iso = new Date(Date.now() - 5_000).toISOString();
    expect(timeAgo(iso)).toMatch(/s ago$/);
  });
  it('formats minutes', () => {
    const iso = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(timeAgo(iso)).toMatch(/m ago$/);
  });
  it('formats hours', () => {
    const iso = new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString();
    expect(timeAgo(iso)).toMatch(/h ago$/);
  });
  it('formats days', () => {
    const iso = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();
    expect(timeAgo(iso)).toMatch(/d ago$/);
  });
});
