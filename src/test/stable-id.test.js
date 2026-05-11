import { describe, it, expect } from 'vitest';
import { stableId, attachStableIds, attachProbeMeta, PROBE_META } from '../lib/probes.js';

const FILE_A = `import { a } from './a';
import { b } from './b';

export const cfg = {
  awsKey: "AKIA-fake-for-test",
  dbUrl: process.env.DB_URL,
};

export function init() {
  return cfg;
}
`;

const FILE_A_WITH_EXTRA_HEADER = `// new top-level comment
// another header line

import { a } from './a';
import { b } from './b';

export const cfg = {
  awsKey: "AKIA-fake-for-test",
  dbUrl: process.env.DB_URL,
};

export function init() {
  return cfg;
}
`;

const findingAt = (line, file = 'src/config.js') => ({
  probe: 'Secret Scanner',
  title: 'AWS Access Key ID found in source',
  file,
  line,
});

describe('stableId', () => {
  it('returns a non-empty base36 string', () => {
    const id = stableId(findingAt(5), FILE_A);
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
    expect(/^[a-z0-9]+$/.test(id)).toBe(true);
  });

  it('is deterministic — same input → same id', () => {
    expect(stableId(findingAt(5), FILE_A)).toBe(stableId(findingAt(5), FILE_A));
  });

  it('survives a line shift when the surrounding context is identical', () => {
    // The vulnerability moves from line 5 to line 8, but the surrounding 3 lines on each
    // side are still the same actual content. The stable ID must NOT change.
    const idBefore = stableId(findingAt(5), FILE_A);
    const idAfter = stableId(findingAt(8), FILE_A_WITH_EXTRA_HEADER);
    expect(idBefore).toBe(idAfter);
  });

  it('changes when the probe identifies a genuinely different vulnerability', () => {
    const id1 = stableId(
      {
        probe: 'Secret Scanner',
        title: 'AWS Access Key ID found in source',
        file: 'x.js',
        line: 1,
      },
      'const k = "a";'
    );
    const id2 = stableId(
      { probe: 'Secret Scanner', title: 'OpenAI API Key found in source', file: 'x.js', line: 1 },
      'const k = "a";'
    );
    expect(id1).not.toBe(id2);
  });

  it('treats file path slashes consistently across platforms', () => {
    const win = stableId(findingAt(5, 'src\\config.js'), FILE_A);
    const nix = stableId(findingAt(5, 'src/config.js'), FILE_A);
    expect(win).toBe(nix);
  });

  it('survives whitespace-only reformats in the surrounding context', () => {
    const reformatted = FILE_A.replace(/\n/g, '\n  '); // double-indent everything
    expect(stableId(findingAt(5), FILE_A)).toBe(stableId(findingAt(5), reformatted));
  });
});

describe('attachStableIds', () => {
  it('attaches stableId to every finding', () => {
    const findings = [findingAt(5), findingAt(9)];
    const files = [{ path: 'src/config.js', content: FILE_A }];
    attachStableIds(findings, files);
    expect(findings.every((f) => typeof f.stableId === 'string' && f.stableId.length > 0)).toBe(
      true
    );
    expect(findings[0].stableId).not.toBe(findings[1].stableId);
  });

  it('handles findings whose file is missing from the file map', () => {
    const findings = [{ probe: 'p', title: 't', file: 'missing.js', line: 1 }];
    expect(() => attachStableIds(findings, [])).not.toThrow();
    expect(findings[0].stableId).toBeTruthy();
  });
});

describe('attachProbeMeta', () => {
  it('attaches confidence + autofix from PROBE_META', () => {
    const findings = [{ probe: 'Secret Scanner' }, { probe: 'Architecture' }];
    attachProbeMeta(findings);
    expect(findings[0].confidence).toBe('high');
    expect(findings[0].autofix).toBe('review-needed');
    expect(findings[1].confidence).toBe('heuristic');
    expect(findings[1].autofix).toBe('manual');
  });

  it('defaults unclassified probes to medium / manual', () => {
    const findings = [{ probe: 'Brand New Probe That Does Not Exist' }];
    attachProbeMeta(findings);
    expect(findings[0].confidence).toBe('medium');
    expect(findings[0].autofix).toBe('manual');
  });

  it('every probe in PROBE_META declares both fields', () => {
    Object.entries(PROBE_META).forEach(([_name, meta]) => {
      expect(['high', 'medium', 'heuristic']).toContain(meta.confidence);
      expect(['mechanical', 'review-needed', 'manual']).toContain(meta.autofix);
    });
  });
});
