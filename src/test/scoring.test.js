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

  it('subtracts critical weight per critical finding', () => {
    expect(computeScore([{ severity: 'critical' }])).toBe(100 - SEV_WEIGHT.critical);
    expect(computeScore([{ severity: 'critical' }, { severity: 'critical' }])).toBe(
      100 - 2 * SEV_WEIGHT.critical
    );
  });

  it('clamps to 0', () => {
    const findings = Array.from({ length: 20 }, () => ({ severity: 'critical' }));
    expect(computeScore(findings)).toBe(0);
  });

  it('ignores unknown severities (treats as 0)', () => {
    expect(computeScore([{ severity: 'rumor' }])).toBe(100);
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
