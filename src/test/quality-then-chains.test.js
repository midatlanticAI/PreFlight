// Promise .then() without .catch(): one finding per chain, and only when the
// promise is actually dropped.
//
// Two defects found on a real project scan (2026-07), which together turned 12
// unhandled chains into 40 findings:
//
//   1. `fetch(u).then(r => r.json()).then(render)` matched the .then pattern
//      twice and reported twice, same line, same text. One chain is one missing
//      .catch.
//
//   2. A returned, awaited, assigned, or argument-position promise has a caller
//      who owns its rejection. `window.fetch = (u, o) => rawFetch(u, o).then(…)`
//      and `e.waitUntil(caches.open(v).then(…))` both delegate correctly and
//      were both reported as unhandled.

import { describe, it, expect } from 'vitest';
import { probeCodeQuality } from '../lib/probes/quality.js';

const run = (content, path = 'src/a.js') =>
  probeCodeQuality([{ path, content }]).filter((f) =>
    /\.then\(\) with no \.catch\(\)/.test(f.title)
  );

describe('promise chains: one finding per chain', () => {
  it('reports a two-link chain once, not once per link', () => {
    const src = `function go() {\n  fetch('/api/x').then((r) => r.json()).then((j) => { render(j); });\n}`;
    expect(run(src)).toHaveLength(1);
  });

  it('reports a four-link chain once', () => {
    const src = `function go() {\n  load().then(a).then(b).then(c).then(d);\n}`;
    expect(run(src)).toHaveLength(1);
  });

  it('reports two separate chains separately', () => {
    const src = [
      'function go() {',
      "  fetch('/api/x').then((r) => r.json()).then(renderX);",
      "  fetch('/api/y').then((r) => r.json()).then(renderY);",
      '}',
    ].join('\n');
    expect(run(src)).toHaveLength(2);
  });
});

describe('promise chains: who owns the rejection', () => {
  it('declines a returned chain', () => {
    expect(run(`function go() {\n  return fetch('/x').then((r) => r.json());\n}`)).toHaveLength(0);
  });

  it('declines an awaited chain', () => {
    expect(
      run(`async function go() {\n  await fetch('/x').then((r) => r.json());\n}`)
    ).toHaveLength(0);
  });

  it('declines a concise arrow body', () => {
    expect(run('const f = (u) => rawFetch(u).then((r) => r.json());')).toHaveLength(0);
  });

  it('declines a chain passed as an argument', () => {
    expect(
      run(`function go(e) {\n  e.waitUntil(caches.open('v1').then((c) => c.add('/')));\n}`)
    ).toHaveLength(0);
  });

  it('declines a chain assigned to a variable', () => {
    expect(run(`function go() {\n  const p = fetch('/x').then((r) => r.json());\n}`)).toHaveLength(
      0
    );
  });

  it('declines a chain inside an array', () => {
    expect(run(`function go() {\n  Promise.all([a().then(f), b().then(g)]);\n}`)).toHaveLength(0);
  });

  it('still reports a bare fire-and-forget chain', () => {
    expect(run(`function go() {\n  loadThing().then((v) => { use(v); });\n}`)).toHaveLength(1);
  });

  it('still declines when the chain has its own .catch', () => {
    expect(run(`function go() {\n  fetch('/x').then((r) => r.json()).catch(log);\n}`)).toHaveLength(
      0
    );
  });
});

describe('promise chains: survives a regex literal earlier in the file', () => {
  it('does not go blind after an escapeHtml-style character class', () => {
    // The masker used to read the `"` in this character class as the start of a
    // string and blank everything after it, so the unhandled chain below was
    // never even matched. Anchoring case: this is what a real scan looked like.
    const src = [
      'function escapeHtml(s) {',
      '  return String(s).replace(/[&<>"\']/g, (c) => "&#" + c.charCodeAt(0) + ";");',
      '}',
      'function load() {',
      "  fetch('/api/tree').then((r) => r.json()).then((t) => { render(t); });",
      '}',
    ].join('\n');
    expect(run(src)).toHaveLength(1);
  });
});
