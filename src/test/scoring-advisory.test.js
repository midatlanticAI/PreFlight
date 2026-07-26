// Maintainability findings are advisory: reported, not scored.
//
// Real-scan finding 2026-07. A private cockpit with zero critical and zero
// high findings scored 53 and displayed as MODERATE RISK, because 47 of its
// 78 mediums were cyclomatic-complexity opinions. riskTier promises that a
// repo with no critical and no high reads LOW at 80 or above; the cosmetic
// caps allowed a 47-point deduction, so that promise was unreachable for any
// repo with enough opinions. The two pieces were written to different
// contracts and this pins the resolution.
import { describe, it, expect } from 'vitest';
import { computeScore, isAdvisoryFinding, countAdvisoryFindings } from '../lib/scoring.js';
import { riskTier } from '../lib/theme.js';

// The axis discriminator is the PROBE NAME, not the finding category:
// `Misconfiguration` covers SEO meta, accessibility landmarks and genuine
// security misconfig alike, so category cannot separate them.
const finding = (severity, probe = 'Secret Scanner') => ({
  severity,
  probe,
  category: 'Injection',
});
const bloat = (severity = 'low') => finding(severity, 'AI Codegen Bloat');

describe('advisory findings do not move the score', () => {
  it('ignores maintainability findings entirely', () => {
    expect(computeScore(Array.from({ length: 50 }, () => bloat('medium')))).toBe(100);
  });

  it('still counts security findings of the same severity', () => {
    expect(computeScore([finding('medium')])).toBe(95);
  });

  it('scores a mixed set on the security findings only', () => {
    const set = [finding('medium'), finding('low'), ...Array.from({ length: 40 }, () => bloat())];
    expect(computeScore(set)).toBe(100 - 5 - 2);
  });

  it('identifies advisory findings', () => {
    expect(isAdvisoryFinding(bloat())).toBe(true);
    expect(isAdvisoryFinding(finding('high'))).toBe(false);
    expect(isAdvisoryFinding(null)).toBe(false);
    expect(isAdvisoryFinding({})).toBe(false);
  });

  it('counts them so the UI can report what it did not score', () => {
    expect(countAdvisoryFindings([bloat(), bloat(), finding('high')])).toBe(2);
    expect(countAdvisoryFindings([])).toBe(0);
    expect(countAdvisoryFindings(null)).toBe(0);
  });
});

describe('a repo with no critical and no high can reach LOW RISK', () => {
  it('the cockpit shape now reads LOW instead of MODERATE', () => {
    // 47 complexity opinions plus a couple of real mediums: previously this
    // floored at 53 and displayed MODERATE. The opinions no longer score.
    const set = [
      ...Array.from({ length: 47 }, () => bloat()),
      finding('medium'),
      finding('low'),
      finding('info'),
    ];
    const score = computeScore(set);
    expect(score).toBeGreaterThanOrEqual(80);
    expect(riskTier(score, { hasCritical: false, hasHigh: false }).label).toBe('LOW RISK');
  });

  it('real medium volume still reads MODERATE', () => {
    // Six DISTINCT real security mediums is genuine exposure, not opinion, and
    // should still hold the label down. Six instances of one pattern is one
    // thing to fix and now scores milder, which is intended.
    const set = Array.from({ length: 6 }, (_, i) => finding('medium', 'Security Probe ' + i));
    const score = computeScore(set);
    expect(riskTier(score, { hasCritical: false, hasHigh: false }).label).toBe('MODERATE RISK');
  });

  it('a real critical still outranks any score', () => {
    expect(riskTier(100, { hasCritical: true, hasHigh: false }).label).toBe('CRITICAL RISK');
  });

  it('advisory findings never rescue a repo that has real problems', () => {
    const set = [finding('critical'), ...Array.from({ length: 30 }, () => bloat())];
    expect(computeScore(set)).toBe(75);
  });
});

// --- The promise the model exists to keep -------------------------------
//
// A hard band cap meant progress stopped showing once you passed it: a real
// scan went 24 findings -> 7 with zero score movement. Whatever the curve, the
// score must respond to every fix, or people learn to ignore it.
describe('progress is always visible', () => {
  const at = (n, sev = 'medium') =>
    computeScore(Array.from({ length: n }, () => finding(sev, 'Code Injection')));

  it('moves at every step down, including deep in the tail', () => {
    const steps = [40, 24, 16, 12, 8, 4, 2, 1, 0];
    for (let i = 0; i < steps.length - 1; i++) {
      expect(at(steps[i]), `${steps[i]} should score below ${steps[i + 1]}`).toBeLessThan(
        at(steps[i + 1])
      );
    }
  });

  it('reaches a clean 100 when the last instance goes', () => {
    expect(at(0)).toBe(100);
  });

  it('never returns a negative or above-100 score', () => {
    for (const n of [0, 1, 5, 50, 500]) {
      for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
        const s = at(n, sev);
        expect(s).toBeGreaterThanOrEqual(0);
        expect(s).toBeLessThanOrEqual(100);
      }
    }
  });

  it('does not let one noisy class alone reach the danger zone', () => {
    // 500 instances of a single medium pattern is still one thing to fix.
    expect(at(500)).toBeGreaterThan(60);
  });

  it('still lets one genuine critical dominate', () => {
    expect(computeScore([finding('critical', 'Secret Scanner')])).toBe(75);
  });
});
