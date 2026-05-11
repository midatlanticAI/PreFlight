import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadHistory,
  persistHistory,
  makeHistoryEntry,
  historyEntryToResults,
  HISTORY_KEY,
  HISTORY_MAX,
} from '../App.jsx';

const baseResults = (overrides = {}) => ({
  findings: [
    {
      id: 'a',
      severity: 'high',
      category: 'Data Breach',
      cwe: 'CWE-1',
      title: 't',
      file: 'f.js',
      line: 1,
      evidence: 'e',
      remediation: 'r',
    },
  ],
  score: 90,
  scannedAt: new Date('2026-05-10T12:00:00Z'),
  filesScanned: 1,
  source: 'https://github.com/foo/bar',
  ...overrides,
});

describe('loadHistory / persistHistory', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns [] when no key set', () => {
    expect(loadHistory()).toEqual([]);
  });

  it('returns [] when key is malformed JSON', () => {
    localStorage.setItem(HISTORY_KEY, '{not valid');
    expect(loadHistory()).toEqual([]);
  });

  it('returns [] when key is JSON but not an array', () => {
    localStorage.setItem(HISTORY_KEY, '{"foo":"bar"}');
    expect(loadHistory()).toEqual([]);
  });

  it('round-trips an entry', () => {
    const e = makeHistoryEntry(baseResults(), 'github');
    persistHistory([e]);
    const back = loadHistory();
    expect(back).toHaveLength(1);
    expect(back[0].id).toBe(e.id);
    expect(back[0].source).toBe('https://github.com/foo/bar');
    expect(back[0].sourceType).toBe('github');
  });
});

describe('makeHistoryEntry', () => {
  it('computes bySeverity counts', () => {
    const r = baseResults({
      findings: [
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'high' },
        { severity: 'low' },
      ],
    });
    const e = makeHistoryEntry(r, 'upload');
    expect(e.bySeverity.critical).toBe(1);
    expect(e.bySeverity.high).toBe(2);
    expect(e.bySeverity.low).toBe(1);
  });

  it('serializes scannedAt to ISO', () => {
    const e = makeHistoryEntry(baseResults(), 'github');
    expect(typeof e.scannedAt).toBe('string');
    expect(e.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('records the source type so re-run knows whether to fetch', () => {
    const e = makeHistoryEntry(baseResults(), 'upload');
    expect(e.sourceType).toBe('upload');
  });
});

describe('historyEntryToResults', () => {
  it('parses scannedAt back into a Date', () => {
    const e = makeHistoryEntry(baseResults(), 'github');
    const r = historyEntryToResults(e);
    expect(r.scannedAt).toBeInstanceOf(Date);
    expect(r.scannedAt.toISOString()).toBe('2026-05-10T12:00:00.000Z');
  });

  it('preserves findings array', () => {
    const e = makeHistoryEntry(baseResults(), 'github');
    const r = historyEntryToResults(e);
    expect(r.findings).toEqual(e.findings);
  });
});

describe('HISTORY_MAX', () => {
  it('is a sane positive number', () => {
    expect(typeof HISTORY_MAX).toBe('number');
    expect(HISTORY_MAX).toBeGreaterThan(0);
    expect(HISTORY_MAX).toBeLessThanOrEqual(50);
  });
});
