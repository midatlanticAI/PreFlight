// src/test/v2-families-gate3-2026-09.test.js
//
// Gate-3 pins for the v2 family build: forty confirmed defects from three
// contextless attackers (crash safety, ReDoS and performance, logic), each
// re-reproduced by a second checker before it was recorded in
// docs/gate3-findings-2026-09-04.md, and fixed 2026-10-28. They collapse
// into four causes: Build & Config threw on null content and undefined
// paths, the span scanners read raw source so a brace or paren inside a
// string truncated them, several patterns could not match a mainstream
// spelling, and O(n) work was recomputed per match.

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';
import { lineIndex } from '../lib/probes/v2/line-index.js';

const PROBE_BY_NAME = Object.fromEntries(PROBES.map((p) => [p.name, p.fn]));
const file = (path, content) => ({ path, content });
const run = (name, ...files) => PROBE_BY_NAME[name](files);
const titles = (res) => res.map((x) => `${x.severity}:${x.title}`).join(' | ');
const none = (res, re) =>
  expect(
    res.filter((x) => re.test(x.title)),
    titles(res)
  ).toHaveLength(0);
const some = (res, re) =>
  expect(
    res.some((x) => re.test(x.title)),
    titles(res)
  ).toBe(true);

describe('line index', () => {
  it('answers the same line numbers as the prefix split, at every offset', () => {
    const text = 'a\nbb\n\nccc\n';
    const lineAt = lineIndex(text);
    for (let i = 0; i <= text.length; i++)
      expect(lineAt(i), `offset ${i}`).toBe(text.slice(0, i).split('\n').length);
    expect(lineIndex(undefined)(0)).toBe(1);
  });
});

describe('Build & Config never throws (G1, G12, G34, G35)', () => {
  it('tolerates null, undefined and missing package.json content', () => {
    for (const content of [null, undefined]) {
      expect(() =>
        run('Build & Config', { path: 'package.json', content }, file('src/a.js', 'fetch("/x")'))
      ).not.toThrow();
    }
    expect(() => run('Build & Config', { path: 'package.json' })).not.toThrow();
  });
  it('tolerates a record with no path', () => {
    expect(() => run('Build & Config', { path: undefined, content: 'x' })).not.toThrow();
    expect(() => run('Build & Config', { content: 'x' }, file('package.json', '{}'))).not.toThrow();
  });
});

describe('React Hygiene: string-blind spans and structural holes', () => {
  it('G3: a ")" inside a string does not truncate the effect span', () => {
    none(
      run(
        'React Hygiene',
        file(
          'src/h.jsx',
          `import { useEffect } from 'react';\nexport function useR(onR) {\n  useEffect(() => {\n    window.addEventListener('resize', onR);\n    console.log('listening :)');\n    return () => window.removeEventListener('resize', onR);\n  }, [onR]);\n}\n`
        )
      ),
      /never removes/
    );
  });
  it('G4: a "}" inside a string does not end the callback body', () => {
    none(
      run(
        'React Hygiene',
        file(
          'src/h.jsx',
          `import { useEffect } from 'react';\nexport function useS(source, handler) {\n  useEffect(() => {\n    const unsub = source.subscribe(handler);\n    console.log("depth }");\n    return unsub;\n  }, [source, handler]);\n}\n`
        )
      ),
      /never unsubscribes/
    );
  });
  it('G5: an object literal declaration in the body is not a deps array', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/c.jsx',
          `import { useEffect, useState } from 'react';\nexport function C() {\n  const [data, setData] = useState(null);\n  useEffect(() => {\n    const opts = { a: 1 }, extra = 2;\n    fetch('/api/data' + extra, opts).then((r) => r.json()).then((d) => setData(d));\n  });\n  return data;\n}\n`
        )
      ),
      /no dependency array/
    );
  });
  it('G13: a $-named timer id still reads as a leak', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/t.jsx',
          `import { useEffect } from 'react';\nexport function useT(tick) {\n  useEffect(() => {\n    const $t = setTimeout(tick, 100);\n    return $t;\n  }, [tick]);\n}\n`
        )
      ),
      /timer it never clears/
    );
  });
  it('G36: a nested helper returning a closure is not the cleanup', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/h.jsx',
          `import { useEffect } from 'react';\nexport function useR() {\n  useEffect(() => {\n    function makeHandler() {\n      return () => console.log('tick');\n    }\n    window.addEventListener('resize', makeHandler());\n  }, []);\n}\n`
        )
      ),
      /never removes/
    );
  });
  it('G6: index-as-key fires on the Prettier multi-line shape', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/list.jsx',
          `export function List({ items }) {\n  return (\n    <ul>\n      {items.map((item, i) => (\n        <li key={i}>{item.name}</li>\n      ))}\n    </ul>\n  );\n}\n`
        )
      ),
      /index used as the key/
    );
  });
  it('G2: the root app/page.tsx is a route entry', () => {
    const page = `import { useState } from 'react';\nexport default function Page() {\n  const [n, setN] = useState(0);\n  return <button onClick={() => setN(n + 1)}>{n}</button>;\n}\n`;
    const cfg = file('next.config.js', 'module.exports = {};');
    some(run('React Hygiene', file('app/page.tsx', page), cfg), /client-only APIs/);
    some(run('React Hygiene', file('app/dash/page.tsx', page), cfg), /client-only APIs/);
  });
  it('G37: a nested component is found in a file with no hook vocabulary', () => {
    some(
      run(
        'React Hygiene',
        file(
          'src/o.jsx',
          `export function Outer() {\n  function Inner() {\n    return <b>x</b>;\n  }\n  return <Inner />;\n}\n`
        )
      ),
      /defined inside/
    );
  });
  it('still honors a real cleanup and still flags a real leak', () => {
    none(
      run(
        'React Hygiene',
        file(
          'src/h.jsx',
          `import { useEffect } from 'react';\nexport function useR(onR) {\n  useEffect(() => {\n    window.addEventListener('resize', onR);\n    return () => window.removeEventListener('resize', onR);\n  }, [onR]);\n}\n`
        )
      ),
      /never removes/
    );
    some(
      run(
        'React Hygiene',
        file(
          'src/h.jsx',
          `import { useEffect } from 'react';\nexport function useR(setW) {\n  useEffect(() => {\n    window.addEventListener('resize', () => setW(window.innerWidth));\n  }, []);\n}\n`
        )
      ),
      /never removes/
    );
  });
});

describe('Error Handling: typed and destructured catches, string-blind bodies', () => {
  it('G8/G40: catch (e: unknown) and catch ({ message }) reach every catch check', () => {
    const res = run(
      'Error Handling',
      file(
        'src/x.ts',
        `async function a() {\n  try {\n    await doWork();\n  } catch (err: unknown) {}\n  try {\n    await other();\n  } catch ({ message }) {}\n}\n`
      )
    );
    expect(
      res.filter((x) => /Empty catch/.test(x.title)),
      titles(res)
    ).toHaveLength(2);
  });
  it('G9: a "}" inside a log string does not hide the rethrow', () => {
    none(
      run(
        'Error Handling',
        file(
          'src/x.js',
          `async function a() {\n  try {\n    await doWork();\n  } catch (e) {\n    console.error("failed }", e);\n    throw new AppError('work failed', { cause: e });\n  }\n}\n`
        )
      ),
      /swallows/
    );
  });
  it('G39: the parameter spelled inside a string is not a use', () => {
    some(
      run(
        'Error Handling',
        file(
          'src/x.js',
          `async function a() {\n  try {\n    await send();\n  } catch (e) {\n    showBanner('e-mail failed');\n  }\n}\n`
        )
      ),
      /swallows/
    );
  });
  it('a $-named catch parameter does not break the dynamic patterns', () => {
    some(
      run(
        'Error Handling',
        file('src/x.js', `try {\n  go();\n} catch ($err) {\n  throw $err;\n}\n`)
      ),
      /only rethrows/
    );
  });
});

describe('Async Correctness: loop headers with calls (G7, G38)', () => {
  it('sees a loop whose header contains a call', () => {
    for (const header of ['getIds(list)', 'Object.keys(map)', 'items.filter((x) => x.ok)']) {
      some(
        run(
          'Async Correctness',
          file(
            'src/a.js',
            `async function m(map, list, items) {\n  for (const id of ${header}) {\n    await fetch('/api/items/' + id);\n  }\n}\n`
          )
        ),
        /serially/
      );
    }
  });
});

describe('TypeScript Hygiene: gate and JSONC (G10, G11)', () => {
  it('G10: a trailing non-null on an optional chain is reachable', () => {
    some(
      run(
        'TypeScript Hygiene',
        file('src/a.ts', `export const n = (u?: { name?: string }) => u?.name!;\n`)
      ),
      /Non-null assertion/
    );
  });
  it('G11: a comment recalling the old setting is not the setting', () => {
    none(
      run(
        'TypeScript Hygiene',
        file(
          'tsconfig.json',
          `{\n  // "strict": false was the old setting; enabled 2024-05\n  "compilerOptions": { "strict": true }\n}\n`
        )
      ),
      /strict mode is off/
    );
    some(
      run(
        'TypeScript Hygiene',
        file('tsconfig.json', `{ "compilerOptions": { "strict": false } }\n`)
      ),
      /strict mode is off/
    );
  });
});

// Superlinear scans. Each fixture doubles from 200KB to 400KB; a quadratic
// scan quadruples its time and a linear one roughly doubles. The ratio is
// the pin, with an absolute ceiling that only a regression could reach.
function timed(name, content, path) {
  const fn = PROBE_BY_NAME[name];
  const t0 = performance.now();
  fn([file(path, content)]);
  return performance.now() - t0;
}
function scaling(name, unit, path, kb = 400) {
  const big = unit.repeat(Math.ceil((kb * 1024) / unit.length));
  const half = big.slice(0, big.length >> 1);
  // Best of three on each size: a single run at tens of milliseconds is
  // dominated by GC and JIT noise, and the ratio is the sensitive pin.
  const best = (c) => Math.min(timed(name, c, path), timed(name, c, path), timed(name, c, path));
  const tHalf = best(half);
  const tFull = best(big);
  return { tHalf, tFull, ratio: tFull / Math.max(tHalf, 5) };
}

describe('performance: 400KB fixtures stay linear (G14 to G33)', () => {
  const cases = [
    [
      'Data & State',
      'function C(){\nconst [s]=useState();\n' + 'fetch("/api/x");\n'.repeat(40),
      'c.jsx',
    ],
    ['Data & State', 'setInterval((x)=>g(),1);'.repeat(40), 'p.js'],
    [
      'Data & State',
      'function C(props){\n' +
        'const [v,setV]=useState(props.value);\n'.repeat(40) +
        'return null}\n',
      'd.jsx',
    ],
    ['Error Handling', 'try{f()}catch(e){console.log(e)}\n'.repeat(40), 'e.js'],
    [
      'React Hygiene',
      'const [x,setX]=useState(0);\n' +
        "useEffect(()=>{fetch('/api/x').then(r=>r.json());setX(1);},[]);\n".repeat(40),
      'app.jsx',
    ],
    ['React Hygiene', 'x.map((a,b)=>a+b);'.repeat(40), 'm.jsx'],
    [
      'React Hygiene',
      'const A = () => <Route component={(' + ' '.repeat(2000) + 'x} />;\n',
      'r.jsx',
    ],
    [
      'Async Correctness',
      'async function m(){\n' + 'for(const u of us){await fetch(u)}\n'.repeat(40) + '}\n',
      'a.js',
    ],
    ['Async Correctness', 'await a[0] '.repeat(40), 'w.js'],
    ['AI Hallucinations', "import {a from 'x' ".repeat(40) + " from 'react' ", 'h.js'],
    [
      'Database Patterns',
      'async function w(){await prisma.a.create({});await prisma.b.create({});}\n'.repeat(40),
      'db.js',
    ],
    ['Database Patterns', 'x.update(knexq);\n'.repeat(40), 'k.js'],
    ['Performance Hazards', "import x from 'y';".repeat(40), 'i.js'],
    ['A11y Semantics', '.a { outline: none; }\n'.repeat(40), 's.css'],
    ['API Patterns', "app.post('/login',(req,res)=>{res.json(req.body)});\n".repeat(40), 'srv.js'],
  ];
  for (const [name, unit, path] of cases) {
    it(`${name} on ${path}`, () => {
      const { tHalf, tFull, ratio } = scaling(name, unit, path);
      expect(tFull, `${name} ${path}: ${tHalf.toFixed(0)}ms -> ${tFull.toFixed(0)}ms`).toBeLessThan(
        2500
      );
      expect(ratio, `${name} ${path}: ${tHalf.toFixed(0)}ms -> ${tFull.toFixed(0)}ms`).toBeLessThan(
        3.5
      );
    });
  }
});

describe('canary replay after Gate 3: what the string-blind views changed', () => {
  it("a cleanup returned from the effect's own if-block still counts", () => {
    none(
      run(
        'React Hygiene',
        file(
          'src/reach.jsx',
          `import { useEffect, useState } from 'react';\nexport function Reach({ data, reload }) {\n  const [dim, setDim] = useState('channel');\n  useEffect(() => { if (data && data.history_pending) { const t = setTimeout(reload, 400); return () => clearTimeout(t); } }, [data]);\n  return dim;\n}\n`
        )
      ),
      /timer it never clears/
    );
  });
  it('a nested template literal does not end the outer one for the masked views', () => {
    const res = run(
      'Error Handling',
      file(
        'admin/public/app.js',
        "function App({ items }) {\n  return html`<ul>${items.map((v) => html`<li class=${v.on ? 'on' : ''}>${v.name}</li>`)}</ul>`;\n}\nfunction report(message) {\n  try { api.post('/api/client-errors', { message }).catch(() => {}); } catch {}\n}\n"
      )
    );
    some(res, /Empty catch block/);
  });
  it('a catch inside a string of JavaScript source is not a catch', () => {
    none(
      run(
        'Error Handling',
        file(
          'src/overlay.ts',
          'export function buildScript(): string {\n  return `(() => {\n    try { el.animate([], {}); } catch (e) {\n      // ignore\n    }\n  })`;\n}\n'
        )
      ),
      /swallows|Empty catch/
    );
  });
  it("an interpolation inside a folded storage key is not the key's name", () => {
    none(
      run(
        'Client Auth Storage',
        file(
          'views/dev.js',
          'function Procedures({ me }) {\n  const key = `dev-proc-${me.session.userId}`;\n  useEffect(() => { try { localStorage.setItem(key, JSON.stringify(done)); } catch {} }, [done]);\n}\n'
        )
      ),
      /localStorage/
    );
    some(
      run(
        'Client Auth Storage',
        file('views/auth.js', "const KEY = 'auth' + '_token';\nlocalStorage.setItem(KEY, token);\n")
      ),
      /localStorage/
    );
  });
});
