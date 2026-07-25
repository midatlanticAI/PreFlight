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

const finding = (severity, category = 'Injection') => ({ severity, category });
const bloat = (severity = 'low') => finding(severity, 'Maintainability');

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
    // Six real security mediums is genuine exposure, not opinion, and should
    // still hold the label down.
    const set = Array.from({ length: 6 }, () => finding('medium'));
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
