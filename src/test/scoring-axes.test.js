// Multiple score axes.
//
// One number could not answer "is this safe to ship" and "is this pleasant to
// maintain" at once, and trying made both answers worse: a private cockpit
// with no exploitable defects read MODERATE RISK because complexity opinions
// and SEO hygiene were subtracting from its security score.
import { describe, it, expect } from 'vitest';
import {
  computeScore,
  computeScores,
  axisForFinding,
  isAdvisoryFinding,
  SCORE_AXES,
} from '../lib/scoring.js';
import { PROBES } from '../lib/probes.js';
import { riskTier } from '../lib/theme.js';

const f = (probe, severity = 'medium') => ({ probe, severity, category: 'Misconfiguration' });

describe('axis assignment', () => {
  it('routes each probe family to its axis', () => {
    expect(axisForFinding(f('AI Codegen Bloat'))).toBe('health');
    expect(axisForFinding(f('Code Quality'))).toBe('health');
    expect(axisForFinding(f('A11y Landmarks'))).toBe('accessibility');
    expect(axisForFinding(f('SEO Hygiene'))).toBe('discoverability');
    expect(axisForFinding(f('GEO Hygiene'))).toBe('discoverability');
  });

  it('defaults an unlisted probe to security', () => {
    expect(axisForFinding(f('Secret Scanner'))).toBe('security');
    expect(axisForFinding(f('Some Future Probe'))).toBe('security');
  });

  it('gives classifiers no axis at all', () => {
    expect(axisForFinding(f('Architecture', 'info'))).toBeNull();
    expect(axisForFinding(f('Host Detection', 'info'))).toBeNull();
  });

  it('treats everything except security as advisory', () => {
    expect(isAdvisoryFinding(f('Secret Scanner'))).toBe(false);
    expect(isAdvisoryFinding(f('SEO Hygiene'))).toBe(true);
    expect(isAdvisoryFinding(f('AI Codegen Bloat'))).toBe(true);
  });
});

describe('computeScores', () => {
  it('scores each axis independently', () => {
    const set = [
      f('Secret Scanner', 'high'),
      f('AI Codegen Bloat', 'medium'),
      f('SEO Hygiene', 'low'),
      f('A11y Landmarks', 'low'),
    ];
    const s = computeScores(set);
    expect(s.security.score).toBe(90);
    expect(s.health.score).toBe(95);
    expect(s.discoverability.score).toBe(98);
    expect(s.accessibility.score).toBe(98);
  });

  it('reports the count behind each axis', () => {
    const s = computeScores([f('SEO Hygiene'), f('SEO Hygiene'), f('Secret Scanner')]);
    expect(s.discoverability.findings).toBe(2);
    expect(s.security.findings).toBe(1);
    expect(s.health.findings).toBe(0);
  });

  it('returns every axis even when a project has no findings for it', () => {
    const s = computeScores([]);
    for (const axis of SCORE_AXES) {
      expect(s[axis].score).toBe(100);
      expect(s[axis].findings).toBe(0);
    }
  });

  it('keeps a noisy axis from touching the others', () => {
    const set = Array.from({ length: 60 }, () => f('AI Codegen Bloat'));
    const s = computeScores(set);
    expect(s.health.score).toBeLessThan(100);
    expect(s.security.score).toBe(100);
  });

  it('survives null input', () => {
    expect(computeScores(null).security.score).toBe(100);
  });
});

describe('the cockpit case that started this', () => {
  it('a repo with no critical or high reads LOW despite heavy opinion volume', () => {
    const set = [
      ...Array.from({ length: 47 }, () => f('AI Codegen Bloat')),
      ...Array.from({ length: 8 }, () => f('SEO Hygiene')),
      f('Cookie Security', 'medium'),
    ];
    const score = computeScore(set);
    expect(riskTier(score, { hasCritical: false, hasHigh: false }).label).toBe('LOW RISK');
    // The opinions did not vanish; they moved to the axis that owns them.
    const s = computeScores(set);
    expect(s.health.findings).toBe(47);
    expect(s.discoverability.findings).toBe(8);
  });

  it('real security volume still holds the security number down', () => {
    // Distinct probes on purpose. Under the class-based model six instances of
    // ONE pattern is one thing to fix and scores milder than six different
    // problems, which is the behaviour we want.
    const set = Array.from({ length: 6 }, (_, i) => f('Security Probe ' + i, 'medium'));
    expect(riskTier(computeScore(set), { hasCritical: false, hasHigh: false }).label).toBe(
      'MODERATE RISK'
    );
  });
});

describe('registry contract', () => {
  it('every registered probe resolves to an axis or is a declared classifier', () => {
    for (const p of PROBES) {
      const axis = axisForFinding({ probe: p.name, severity: 'medium' });
      const ok = axis === null || SCORE_AXES.includes(axis);
      expect(ok, `${p.name} resolved to ${axis}`).toBe(true);
    }
  });
});
