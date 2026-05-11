import { describe, it, expect, beforeEach } from 'vitest';
import {
  SUPPRESSION_KEY,
  SUPPRESSION_DISPOSITIONS,
  loadSuppressions,
  saveSuppressions,
  suppressFinding,
  unsuppressFinding,
  partitionFindings,
} from '../lib/probes.js';

const finding = (stableId, severity = 'high') => ({
  stableId,
  probe: 'p',
  title: 't',
  severity,
  category: 'X',
  file: 'src/a.js',
  line: 1,
});

describe('suppression storage', () => {
  beforeEach(() => {
    if (typeof localStorage !== 'undefined') localStorage.clear();
  });

  it('loads {} when nothing is stored', () => {
    expect(loadSuppressions()).toEqual({});
  });

  it('round-trips a suppression', () => {
    const initial = loadSuppressions();
    const updated = suppressFinding(initial, 'abc123', 'false-positive', 'this is a test fixture');
    expect(updated.abc123.disposition).toBe('false-positive');
    expect(updated.abc123.note).toBe('this is a test fixture');
    expect(updated.abc123.at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    saveSuppressions(updated);
    expect(loadSuppressions().abc123).toBeDefined();
  });

  it('rejects an unknown disposition (returns map unchanged)', () => {
    const m = suppressFinding({}, 'x', 'bogus');
    expect(m).toEqual({});
  });

  it('rejects an empty stableId', () => {
    expect(suppressFinding({}, '', 'false-positive')).toEqual({});
  });

  it('unsuppressFinding removes the entry', () => {
    let m = suppressFinding({}, 'x', 'wont-fix');
    expect(m.x).toBeDefined();
    m = unsuppressFinding(m, 'x');
    expect(m.x).toBeUndefined();
  });

  it('SUPPRESSION_DISPOSITIONS lists all three valid values', () => {
    expect(SUPPRESSION_DISPOSITIONS).toEqual(['false-positive', 'wont-fix', 'accepted-risk']);
  });

  it('ignores malformed JSON in localStorage', () => {
    localStorage.setItem(SUPPRESSION_KEY, '{ not valid');
    expect(loadSuppressions()).toEqual({});
  });
});

describe('partitionFindings', () => {
  it('returns all findings as visible when no suppressions exist', () => {
    const findings = [finding('a'), finding('b'), finding('c')];
    const { visible, suppressed } = partitionFindings(findings, {});
    expect(visible).toHaveLength(3);
    expect(suppressed).toHaveLength(0);
  });

  it('moves suppressed findings into the suppressed bucket', () => {
    const findings = [finding('a'), finding('b'), finding('c')];
    const supps = suppressFinding({}, 'b', 'false-positive', 'test');
    const { visible, suppressed } = partitionFindings(findings, supps);
    expect(visible.map((f) => f.stableId)).toEqual(['a', 'c']);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].stableId).toBe('b');
    expect(suppressed[0].suppression.disposition).toBe('false-positive');
    expect(suppressed[0].suppression.note).toBe('test');
  });

  it('does not suppress findings without a stableId (defensive)', () => {
    const findings = [{ ...finding('a'), stableId: undefined }];
    const { visible, suppressed } = partitionFindings(findings, {
      undefined: { disposition: 'wont-fix' },
    });
    expect(visible).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });
});
