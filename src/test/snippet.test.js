import { describe, it, expect } from 'vitest';
import { buildSnippet, snippetToText } from '../App.jsx';

const SAMPLE = `line one
line two
line three
line four
line five
line six
line seven
line eight
line nine
line ten`;

describe('buildSnippet', () => {
  it('returns null for empty content', () => {
    expect(buildSnippet('', 1)).toBeNull();
    expect(buildSnippet(null, 1)).toBeNull();
  });

  it('returns null when lineNum is missing', () => {
    expect(buildSnippet(SAMPLE, 0)).toBeNull();
    expect(buildSnippet(SAMPLE, undefined)).toBeNull();
  });

  it('captures ±5 lines around the hit by default', () => {
    const s = buildSnippet(SAMPLE, 6);
    expect(s.startLine).toBe(1);
    expect(s.endLine).toBe(10);
    expect(s.lines).toHaveLength(10);
    expect(s.lines.find(l => l.isHit).n).toBe(6);
  });

  it('clamps to start of file', () => {
    const s = buildSnippet(SAMPLE, 1, 5);
    expect(s.startLine).toBe(1);
    expect(s.endLine).toBe(6);
    expect(s.lines[0].n).toBe(1);
    expect(s.lines[0].isHit).toBe(true);
  });

  it('clamps to end of file', () => {
    const s = buildSnippet(SAMPLE, 10, 5);
    expect(s.startLine).toBe(5);
    expect(s.endLine).toBe(10);
    expect(s.lines[s.lines.length - 1].isHit).toBe(true);
  });

  it('honors custom context size', () => {
    const s = buildSnippet(SAMPLE, 5, 1);
    expect(s.lines).toHaveLength(3);
    expect(s.lines.map(l => l.n)).toEqual([4, 5, 6]);
  });

  it('marks exactly one line as the hit', () => {
    const s = buildSnippet(SAMPLE, 7);
    expect(s.lines.filter(l => l.isHit)).toHaveLength(1);
  });
});

describe('snippetToText', () => {
  it('returns empty string for null/undefined snippet', () => {
    expect(snippetToText(null)).toBe('');
    expect(snippetToText(undefined)).toBe('');
  });

  it('marks the hit line with > and others with :', () => {
    const s = buildSnippet('a\nb\nc', 2, 1);
    const txt = snippetToText(s);
    expect(txt).toMatch(/^\s+1: a$/m);
    expect(txt).toMatch(/^\s+2> b$/m);
    expect(txt).toMatch(/^\s+3: c$/m);
  });

  it('right-aligns line numbers in 4 columns', () => {
    const big = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`).join('\n');
    const s = buildSnippet(big, 50, 1);
    expect(snippetToText(s)).toMatch(/^\s{2}49: /m);
    expect(snippetToText(s)).toMatch(/^\s{2}50> /m);
  });
});
