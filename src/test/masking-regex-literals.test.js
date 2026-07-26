// Regex-literal handling in the shared comment/string masker.
//
// The masker blanks comments and string bodies so structural scans do not trip
// over quotes and braces that are really data. It did not understand regex
// literals, so any regex containing a quote character opened a string that ran
// to the next unrelated quote, blanking real code in between.
//
// The canonical case is escapeHtml:
//
//   String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`)
//
// That function appears in a large share of generated apps. On one real project
// it blanked lines 442 through 1098, which hid six unhandled promise chains,
// four empty catch blocks, and every other masked-content check in that range.
// The failure was silent: fewer findings looks like cleaner code.
//
// Offset parity is asserted throughout. Callers map indices in the masked
// string back to line numbers in the original, so the two must stay the same
// length, character for character, newlines included.

import { describe, it, expect } from 'vitest';
import { maskCommentsAndStringsFromContent as mask } from '../lib/probes/_internal/masking.js';

const parity = (src) => expect(mask(src).length).toBe(src.length);

describe('masker: regex literals', () => {
  it('does not let a quote inside a character class open a string', () => {
    const src = `function e(s){return String(s).replace(/[&<>"']/g,c=>c);}\nconst KEEP = alpha;`;
    const out = mask(src);
    expect(out).toContain('const KEEP = alpha;');
    parity(src);
  });

  it('blanks the regex body but keeps the delimiters and flags', () => {
    const out = mask('const re = /secret[a-z]+/gi;');
    expect(out).toMatch(/^const re = \/ +\/gi;$/);
  });

  it('keeps a slash inside a character class from ending the regex', () => {
    const src = `const re = /[/"']/g;\nconst KEEP = alpha;`;
    expect(mask(src)).toContain('const KEEP = alpha;');
    parity(src);
  });

  it('treats a slash after an identifier as division, not a regex', () => {
    const src = 'const ratio = total / count; const other = a / b;';
    // Division must pass through untouched: blanking it would erase real code.
    expect(mask(src)).toBe(src);
  });

  it('treats a slash after ) as division', () => {
    const src = 'const avg = sum(xs) / xs.length; const KEEP = alpha;';
    expect(mask(src)).toBe(src);
  });

  it('recognises a regex after return', () => {
    const src = `function f(){ return /['"]/.test(x); }\nconst KEEP = alpha;`;
    expect(mask(src)).toContain('const KEEP = alpha;');
    parity(src);
  });

  it('recognises a regex in argument position', () => {
    const src = `split(/["']/).map(f);\nconst KEEP = alpha;`;
    expect(mask(src)).toContain('const KEEP = alpha;');
    parity(src);
  });

  it('does not mistake a URL in a string for a regex', () => {
    const src = 'const u = "http://example.com/a"; const KEEP = alpha;';
    const out = mask(src);
    expect(out).toContain('const KEEP = alpha;');
    expect(out).not.toContain('example.com');
    parity(src);
  });

  it('still masks strings and comments', () => {
    const src = `// don't cache this\nconst s = "secret-value";\nconst KEEP = alpha;`;
    const out = mask(src);
    expect(out).not.toContain('secret-value');
    expect(out).not.toContain('cache this');
    expect(out).toContain('const KEEP = alpha;');
    parity(src);
  });

  it('preserves offsets across a mixed file', () => {
    const src = [
      `// leading note with an apostrophe: don't`,
      `const clean = (s) => s.replace(/[<>"']/g, '');`,
      `/* block\n   comment */`,
      'const half = total / 2;',
      'const msg = `a ${x} b`;',
      'const KEEP = alpha;',
    ].join('\n');
    const out = mask(src);
    expect(out.length).toBe(src.length);
    expect(out.split('\n').length).toBe(src.split('\n').length);
    expect(out).toContain('const KEEP = alpha;');
    expect(out).toContain('const half = total / 2;');
  });

  it('leaves an unterminated slash alone rather than blanking the rest', () => {
    // A lone `/` that never closes is not a regex. Consuming to end of file
    // here is exactly the failure mode this change exists to remove.
    const src = 'const a = b;\nconst KEEP = alpha;';
    expect(mask(src)).toContain('const KEEP = alpha;');
  });
});
