// src/test/v2-react.test.js — F1 React Hygiene family suite.
// Positive and negative per check, plus the family contract block.
import { describe, it, expect } from 'vitest';
import { probeReactHygiene } from '../lib/probes/v2/react.js';

const file = (path, content) => ({ path, content });
const run = (...files) => probeReactHygiene(files);
const has = (res, re) => res.some((x) => re.test(x.title));
const titles = (res) => res.map((x) => `${x.severity}:${x.title}`).join(' | ');

describe('effect cleanup family', () => {
  it('flags addEventListener without cleanup', () => {
    const res = run(
      file(
        'src/Resize.jsx',
        `import { useEffect } from 'react';\nexport function useResize(setW) {\n  useEffect(() => {\n    window.addEventListener('resize', () => setW(window.innerWidth));\n  }, []);\n}\n`
      )
    );
    expect(has(res, /listener it never removes/), titles(res)).toBe(true);
  });
  it('does NOT flag a listener with matching cleanup', () => {
    const res = run(
      file(
        'src/Resize.jsx',
        `import { useEffect } from 'react';\nexport function useResize(setW) {\n  useEffect(() => {\n    const onR = () => setW(window.innerWidth);\n    window.addEventListener('resize', onR);\n    return () => window.removeEventListener('resize', onR);\n  }, []);\n}\n`
      )
    );
    expect(
      res.filter((x) => /listener/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('does NOT flag the AbortSignal listener form', () => {
    const res = run(
      file(
        'src/Resize.tsx',
        `import { useEffect } from 'react';\nexport function useResize(setW: (n: number) => void) {\n  useEffect(() => {\n    const ac = new AbortController();\n    window.addEventListener('resize', () => setW(window.innerWidth), { signal: ac.signal });\n    return () => ac.abort();\n  }, []);\n}\n`
      )
    );
    expect(
      res.filter((x) => /listener/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('flags setInterval without clearInterval, in .tsx too', () => {
    const res = run(
      file(
        'src/Clock.tsx',
        `import { useEffect, useState } from 'react';\nexport function Clock() {\n  const [now, setNow] = useState(Date.now());\n  useEffect(() => {\n    setInterval(() => setNow(Date.now()), 1000);\n  }, []);\n  return <span>{now}</span>;\n}\n`
      )
    );
    expect(has(res, /timer it never clears/), titles(res)).toBe(true);
  });
  it('flags subscribe/WebSocket/observer without release', () => {
    const res = run(
      file(
        'src/Live.jsx',
        `import { useEffect } from 'react';\nexport function useLive(feed, el, setV) {\n  useEffect(() => {\n    const sub = feed.subscribe(setV);\n    const ws = new WebSocket('wss://x.example/live');\n    const ob = new ResizeObserver(() => setV(el.width));\n    ob.observe(el);\n  }, [feed, el]);\n}\n`
      )
    );
    expect(has(res, /never unsubscribes/), titles(res)).toBe(true);
    expect(has(res, /WebSocket it never closes/), titles(res)).toBe(true);
    expect(has(res, /observer it never disconnects/), titles(res)).toBe(true);
  });
  it('flags fetch-in-effect with no cancellation', () => {
    const res = run(
      file(
        'src/Profile.jsx',
        `import { useEffect, useState } from 'react';\nexport function Profile({ id }) {\n  const [user, setUser] = useState(null);\n  useEffect(() => {\n    (async () => {\n      const res = await fetch('/api/user/' + id);\n      setUser(await res.json());\n    })();\n  }, [id]);\n  return <div>{user?.name}</div>;\n}\n`
      )
    );
    expect(has(res, /fetches without cancellation/), titles(res)).toBe(true);
  });
  it('does NOT flag fetch with an AbortController', () => {
    const res = run(
      file(
        'src/Profile.jsx',
        `import { useEffect, useState } from 'react';\nexport function Profile({ id }) {\n  const [user, setUser] = useState(null);\n  useEffect(() => {\n    const ac = new AbortController();\n    fetch('/api/user/' + id, { signal: ac.signal }).then((r) => r.json()).then(setUser);\n    return () => ac.abort();\n  }, [id]);\n  return <div>{user?.name}</div>;\n}\n`
      )
    );
    expect(
      res.filter((x) => /cancellation/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
});

describe('dependency arrays', () => {
  it('flags a state-setting effect with no deps array', () => {
    const res = run(
      file(
        'src/Sync.jsx',
        `import { useEffect, useState } from 'react';\nexport function Sync({ value }) {\n  const [v, setV] = useState(value);\n  useEffect(() => {\n    setV(value);\n  });\n  return <b>{v}</b>;\n}\n`
      )
    );
    expect(has(res, /no dependency array/), titles(res)).toBe(true);
  });
  it('flags a literal in the deps array', () => {
    const res = run(
      file(
        'src/Chart.jsx',
        `import { useEffect } from 'react';\nexport function Chart({ data, draw }) {\n  useEffect(() => {\n    draw(data);\n  }, [{ smooth: true }]);\n  return null;\n}\n`
      )
    );
    expect(has(res, /fresh literal every render/), titles(res)).toBe(true);
  });
  it('flags a stale closure over state in an interval', () => {
    const res = run(
      file(
        'src/Counter.jsx',
        `import { useEffect, useState } from 'react';\nexport function Counter() {\n  const [count, setCount] = useState(0);\n  useEffect(() => {\n    setInterval(() => setCount(count + 1), 1000);\n  }, []);\n  return <b>{count}</b>;\n}\n`
      )
    );
    expect(has(res, /stale state/), titles(res)).toBe(true);
  });
});

describe('structure and rendering', () => {
  it('flags a hook called inside a condition (AST)', () => {
    const res = run(
      file(
        'src/Cond.jsx',
        `import { useState } from 'react';\nexport function Cond({ on }) {\n  if (on) {\n    const [v] = useState(0);\n    return <b>{v}</b>;\n  }\n  return null;\n}\n`
      )
    );
    expect(has(res, /called conditionally/), titles(res)).toBe(true);
  });
  it('flags a setter called during render (AST)', () => {
    const res = run(
      file(
        'src/Loop.jsx',
        `import { useState } from 'react';\nexport function Loop({ items }) {\n  const [total, setTotal] = useState(0);\n  setTotal(items.length);\n  return <b>{total}</b>;\n}\n`
      )
    );
    expect(has(res, /called during render/), titles(res)).toBe(true);
  });
  it('does NOT flag a setter inside a handler', () => {
    const res = run(
      file(
        'src/Btn.jsx',
        `import { useState } from 'react';\nexport function Btn() {\n  const [n, setN] = useState(0);\n  return <button onClick={() => setN(n + 1)}>{n}</button>;\n}\n`
      )
    );
    expect(
      res.filter((x) => /during render/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
  it('flags a component defined inside a component (AST)', () => {
    const res = run(
      file(
        'src/Outer.jsx',
        `export function Outer({ items }) {\n  function Row({ item }) {\n    return <li>{item.name}</li>;\n  }\n  return <ul>{items.map((x) => <Row key={x.id} item={x} />)}</ul>;\n}\n`
      )
    );
    expect(has(res, /defined inside/), titles(res)).toBe(true);
  });
  it('flags index keys, inline component props, and inline Provider values', () => {
    const res = run(
      file(
        'src/List.jsx',
        `export const List = ({ items, C }) => (\n  <ul>{items.map((item, i) => <li key={i}>{item.name}</li>)}</ul>\n);\n`
      ),
      file('src/Route.jsx', `export const R = () => <Route component={() => <Home />} />;\n`),
      file(
        'src/Ctx.jsx',
        `export const App = ({ children }) => <Theme.Provider value={{ dark: true }}>{children}</Theme.Provider>;\n`
      )
    );
    expect(has(res, /index used as the key/), titles(res)).toBe(true);
    expect(has(res, /inline in a prop/), titles(res)).toBe(true);
    expect(has(res, /Context value/), titles(res)).toBe(true);
  });
  it('flags lazy-without-Suspense and forwardRef-without-displayName', () => {
    const res = run(
      file(
        'src/App.jsx',
        `import { lazy, forwardRef } from 'react';\nconst Page = lazy(() => import('./Page.jsx'));\nexport const Input = forwardRef((props, ref) => <input ref={ref} {...props} />);\nexport const App = () => <Page />;\n`
      )
    );
    expect(has(res, /without a Suspense/), titles(res)).toBe(true);
    expect(has(res, /no displayName/), titles(res)).toBe(true);
  });
  it('flags client APIs in an App Router server component', () => {
    const res = run(
      file('next.config.js', `module.exports = {};\n`),
      file(
        'app/dashboard/page.tsx',
        `export default function Page() {\n  const width = window.innerWidth;\n  return <div>{width}</div>;\n}\n`
      )
    );
    expect(has(res, /client-only APIs/), titles(res)).toBe(true);
  });
  it('does NOT flag the same file with "use client"', () => {
    const res = run(
      file('next.config.js', `module.exports = {};\n`),
      file(
        'app/dashboard/page.tsx',
        `'use client';\nimport { useState } from 'react';\nexport default function Page() {\n  const [w] = useState(0);\n  return <div>{w}</div>;\n}\n`
      )
    );
    expect(
      res.filter((x) => /client-only/.test(x.title)),
      titles(res)
    ).toHaveLength(0);
  });
});

describe('family contract', () => {
  it('never exceeds high severity', () => {
    const heavy = run(
      file(
        'src/Bad.jsx',
        `import { useEffect, useState } from 'react';\nexport function Bad({ items }) {\n  const [n, setN] = useState(0);\n  setN(items.length);\n  useEffect(() => {\n    window.addEventListener('resize', () => setN(1));\n    setInterval(() => setN(2), 50);\n  });\n  return <ul>{items.map((x, i) => <li key={i}>{x}</li>)}</ul>;\n}\n`
      )
    );
    expect(heavy.length).toBeGreaterThan(0);
    expect(heavy.every((x) => ['medium', 'low', 'info'].includes(x.severity))).toBe(true);
    expect(heavy.every((x) => x.probe === 'React Hygiene')).toBe(true);
  });
  it('skips test files, returns [] on empty input, never crashes on garbage', () => {
    expect(
      run(file('src/__tests__/x.test.jsx', `useEffect(() => { setInterval(() => {}, 1); });`))
    ).toEqual([]);
    expect(run()).toEqual([]);
    expect(run(file('src/x.jsx', `const = ) => {{{ useEffect(`))).toBeInstanceOf(Array);
  });
  it('stays silent on a clean component', () => {
    const res = run(
      file(
        'src/Clean.jsx',
        `import { useEffect, useState } from 'react';\nexport function Clean({ id }) {\n  const [user, setUser] = useState(null);\n  useEffect(() => {\n    const ac = new AbortController();\n    fetch('/api/u/' + id, { signal: ac.signal }).then((r) => r.json()).then(setUser);\n    return () => ac.abort();\n  }, [id]);\n  return <div onClick={() => setUser(null)}>{user?.name}</div>;\n}\n`
      )
    );
    expect(res, titles(res)).toHaveLength(0);
  });
});
