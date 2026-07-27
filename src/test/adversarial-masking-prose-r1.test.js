/**
 * Adversarial round, 2026-07-27. Every case here was found by contextless
 * agents attacking the masking layer, the prose guard and the taint engine
 * with no knowledge of what had just been written — and every one of them
 * reproduced. They are regression tests now because all three defects were
 * invisible to the suites that shipped alongside the code.
 *
 * The direction that matters is SWALLOW / SUPPRESS: a scanner that stops
 * looking reports a clean result, and nothing in the output says otherwise.
 */

import { describe, it, expect } from 'vitest';
import {
  maskCommentsOnly,
  maskCommentsAndStringsFromContent,
  maskBlockCommentsAndTemplateLiterals,
} from '../lib/probes/_internal/masking.js';
import { lineIsProseString, looksLikeProse } from '../lib/probes/_internal/prose.js';
import { probeAuthWeakness } from '../lib/probes/auth.js';
import { probeTaintFlow } from '../lib/probes.js';

const f = (path, content) => ({ path, content });
const MASKS = [
  maskCommentsOnly,
  maskCommentsAndStringsFromContent,
  maskBlockCommentsAndTemplateLiterals,
];

describe('masking: an unterminated construct must not blank the rest of the file', () => {
  // `src/data/*` in JSX copy opened a block comment with no terminator, and
  // blanked 95 of the 187 lines of this repo's own TermsView.jsx.
  it('a /* in JSX text does not swallow the code after it', () => {
    const src = `export const App = () => (
  <div>
    <code>src/data/*</code>
    <button onClick={() => eval(payload)}>go</button>
  </div>
);
`;
    for (const mask of MASKS) expect(mask(src)).toMatch(/eval\(payload\)/);
  });

  it('a lone backtick in JSX text does not swallow the code after it', () => {
    const src = `const Help = () => <p>The \` character starts a template literal</p>;
const tools = [new ShellTool()];
`;
    for (const mask of MASKS) expect(mask(src)).toMatch(/ShellTool/);
  });

  it('masks preserve length and newline count', () => {
    const src = `const a = 1; // note\nconst b = "x"; /* unclosed\nconst c = \`t\`;\n`;
    for (const mask of MASKS) {
      const out = mask(src);
      expect(out.length).toBe(src.length);
      expect(out.split('\n').length).toBe(src.split('\n').length);
    }
  });
});

describe('prose guard: a sentence beside code must not disable the line', () => {
  // The guard asked whether a line CONTAINED prose; callers use it to skip the
  // whole line. One readable sibling property switched off every check there.
  const attacks = [
    `const t = jwt.sign({ sub: user.id, note: 'this token is only ever issued for the partner integration and it is not meant to be used by anyone else' }, null, { algorithm: 'none' });`,
    `export const reportingDb = { note: 'this is the account that the batch jobs use to talk to the reporting database at night', user: 'reports', password: 'Sup3rS3cret!' };`,
  ];
  for (const [i, line] of attacks.entries()) {
    it(`attack ${i + 1}: prose sibling does not suppress the finding`, () => {
      expect(lineIsProseString(line)).toBe(false);
      expect(probeAuthWeakness([f('src/server/auth-service.js', line)]).length).toBeGreaterThan(0);
    });
  }

  it('a documentation string alone on its line is still recognised as prose', () => {
    expect(
      lineIsProseString(
        `  remediation: 'Same identifier for both user AND password is the strongest signal that this was never changed from the install default.',`
      )
    ).toBe(true);
  });

  // Documented limit: SQL reads as English. Guards this stays known rather
  // than being discovered by wiring it into a SQL probe.
  it('SQL is misread as prose — the reason this guard is off-limits to SQL probes', () => {
    expect(looksLikeProse('SELECT the user name from the users table where the id is ')).toBe(true);
  });
});

describe('taint: destructuring a tainted object yields tainted values', () => {
  const sinks = [
    ['fetch', 'CWE-918', `const { url } = req.query;\n  return fetch(url);`],
    ['renamed', 'CWE-918', `const { url: target } = req.query;\n  return fetch(target);`],
    ['nested', 'CWE-918', `const { body: { url } } = req;\n  return fetch(url);`],
    ['redirect', 'CWE-601', `const { next } = req.query;\n  res.redirect(next);`],
    ['eval', 'CWE-95', `const { expr } = req.body;\n  return eval(expr);`],
  ];
  for (const [name, cwe, body] of sinks) {
    it(`${name}: const { x } = req.* still reaches the sink`, () => {
      const src = `export function handler(req, res) {\n  ${body}\n}\n`;
      const found = probeTaintFlow([f('server/routes/h.js', src)]) || [];
      expect(found.some((x) => x.cwe === cwe)).toBe(true);
    });
  }

  it('destructuring an author-written object is not tainted', () => {
    const src = `export function handler(req, res) {\n  const { url } = { url: '/dashboard' };\n  res.redirect(url);\n}\n`;
    expect(probeTaintFlow([f('server/routes/safe.js', src)])).toHaveLength(0);
  });
});
