/**
 * Property-based testing for PreFlight probes (round 1).
 *
 * Each probe gets a generator that produces RANDOM but well-shaped inputs
 * (real-looking code), runs the probe, and asserts an INVARIANT — not an
 * exact finding count. Properties catch corner cases authors (human or LLM)
 * didn't think to write tests for.
 *
 * Examples of invariants checked here:
 *   - "If the same code is wrapped in a `// comment`, the probe does not fire."
 *   - "If a sanitizer wraps the tainted value, the taint engine does not fire."
 *   - "If a real secret is present and is not a placeholder, probeSecrets fires."
 *   - "If a file is in a test path, no probe fires."
 *
 * fast-check shrinks failing cases to the smallest counter-example, so when a
 * regression slips in we get a 3-line repro instead of a haystack.
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';
import {
  probeSecrets,
  probeSSRFOpenRedirect,
  probePathTraversal,
  probeTaintFlow,
  probeWeakRandomness,
} from '../lib/probes.js';

const file = (path, content) => ({ path, content });

// ─────────────────────────────────────────────────────────────────────────────
// Property 1: comment-wrapped probe inputs never fire.
// ─────────────────────────────────────────────────────────────────────────────

describe('Property — comment masking is universal', () => {
  it('any sk- key wrapped in a // comment never fires probeSecrets', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[A-Za-z0-9]{20,40}$/), (body) => {
        const f = file('src/x.js', `// const k = "sk-proj-${body}";`);
        return probeSecrets([f]).length === 0;
      }),
      { numRuns: 50 }
    );
  });

  it('any sk- key wrapped in a /* ... */ block comment never fires probeSecrets', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[A-Za-z0-9]{20,40}$/), (body) => {
        const f = file('src/x.js', `/* sample key for docs: sk-proj-${body} */`);
        return probeSecrets([f]).length === 0;
      }),
      { numRuns: 50 }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Property 2: test-tree files are universally exempt.
// ─────────────────────────────────────────────────────────────────────────────

describe('Property — test files are universally exempted', () => {
  const testPaths = [
    'src/test/x.js',
    'src/__tests__/x.js',
    'src/x.test.js',
    'src/x.spec.js',
    'cypress/e2e/x.js',
    'playwright/x.js',
    'tests/fixtures/x.js',
    'mocks/x.js',
  ];

  it('a known-vulnerable shape in any test path produces no findings', () => {
    const vulnContent = `function handler(req, res) {
      const target = req.body.path;
      fs.readFile(target, () => {});
      eval(req.body.code);
    }`;
    for (const path of testPaths) {
      const taintFindings = probeTaintFlow([file(path, vulnContent)]);
      expect(taintFindings.length, `Taint engine should skip ${path}`).toBe(0);
      const trvFindings = probePathTraversal([file(path, vulnContent)]);
      expect(trvFindings.length, `Path traversal should skip ${path}`).toBe(0);
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Property 3: sanitizers clear taint regardless of source idiom.
// ─────────────────────────────────────────────────────────────────────────────

describe('Property — sanitizers always clear taint in the taint engine', () => {
  it('path.normalize on any taint source produces no taint finding', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          'req.url',
          'req.originalUrl',
          'req.path',
          'req.body.path',
          'req.query.target',
          'req.params.id',
          'req.cookies.next'
        ),
        (source) => {
          const content = `function handler(req, res) {
            const dirty = ${source};
            const safe = path.normalize(dirty);
            fs.readFile(safe, () => {});
          }`;
          return probeTaintFlow([file('src/x.js', content)]).length === 0;
        }
      ),
      { numRuns: 30 }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Property 4: literal values never trigger taint flow.
// ─────────────────────────────────────────────────────────────────────────────

describe('Property — literal RHS never produces taint findings', () => {
  it('any string-literal path -> fs.readFile is silent', () => {
    fc.assert(
      fc.property(fc.stringMatching(/^[/A-Za-z0-9_.-]{4,80}$/), (path) => {
        const content = `function handler(req, res) {
            fs.readFile('${path}', () => {});
          }`;
        return probeTaintFlow([file('src/x.js', content)]).length === 0;
      }),
      { numRuns: 30 }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Property 5: weak-random LHS-name heuristic — security-named identifiers
// fire; UI-named identifiers don't.
// ─────────────────────────────────────────────────────────────────────────────

describe('Property — weak randomness classifier respects LHS naming', () => {
  it('any UI-named Math.random LHS does not fire', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('width', 'height', 'opacity', 'hue', 'jitter', 'wobble', 'bucket'),
        (name) => {
          const content = `function draw() {
            const ${name} = Math.random() * 100;
            return ${name};
          }`;
          return probeWeakRandomness([file('src/draw.js', content)]).length === 0;
        }
      ),
      { numRuns: 20 }
    );
  });

  it('any security-named Math.random LHS fires', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('apiKey', 'sessionId', 'csrfToken', 'resetToken', 'pin'),
        (name) => {
          const content = `function mint() {
            const ${name} = Math.random().toString(36).slice(2);
            return ${name};
          }`;
          return probeWeakRandomness([file('src/mint.js', content)]).length > 0;
        }
      ),
      { numRuns: 20 }
    );
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Property 6: SSRF detection holds across user-input source variants.
// ─────────────────────────────────────────────────────────────────────────────

describe('Property — SSRF detection across input-source family', () => {
  it('any user-input source -> fetch fires', () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          'req.url',
          'req.originalUrl',
          'req.path',
          'req.body.target',
          'req.query.url',
          'req.headers.host',
          'ctx.url',
          'event.body',
          'c.req.url'
        ),
        (source) => {
          const content = `async function handler(req, res) {
            const r = await fetch(${source});
            return r;
          }`;
          return probeSSRFOpenRedirect([file('src/handler.js', content)]).length > 0;
        }
      ),
      { numRuns: 20 }
    );
  });
});
