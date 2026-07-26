// Precision fixes driven by a real scan of a private cockpit app (2026-07).
//
// Every XSS finding in that report was a false positive, and all for the same
// root cause: the sink classifier could tell a literal from an expression, but
// not that an expression resolves to a constant. Same report also surfaced
// missing browser globals and a suspicious-TLD hit on a mainstream AI provider.
import { describe, it, expect } from 'vitest';
import { probeAuthWeakness, probeCodeCorrectness, probeExternalURLs } from '../lib/probes.js';
import { collectSafeBindings, resolvesToConstant } from '../lib/probes/_internal/const-eval.js';

const f = (path, content) => [{ path, content }];
const xss = (content) =>
  probeAuthWeakness(f('src/ui/preview.js', content)).filter((x) =>
    /XSS|dangerouslySetInnerHTML/i.test(x.title)
  );

describe('HTML sinks: values that resolve to constants are not sinks', () => {
  it('does not flag a const bound to a string literal, including escaped quotes', () => {
    const src = ['const TPL = "<div class=\\"row\\"></div>";', 'el.innerHTML = TPL;'].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('does not flag a template whose substitutions are all numeric', () => {
    const src = [
      'const errCount = errors.length;',
      'const snapCount = snaps.length;',
      'const bits = `<b>${errCount}</b> / <b>${snapCount}</b>`;',
      'el.innerHTML = bits;',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('does not flag a function that only ever returns string literals', () => {
    const src = [
      'function label(mode) {',
      '  switch (mode) {',
      "    case 1: return '-> vision';",
      "    default: return '-> read';",
      '  }',
      '}',
      'el.innerHTML = label(mode);',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it("does not flag the author's own escaper", () => {
    const src = [
      'function escapeHtml(s) {',
      '  return String(s).replace(/[&<>"]/g, (c) => MAP[c]);',
      '}',
      'el.innerHTML = escapeHtml(userText);',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('still flags a genuinely tainted value', () => {
    expect(xss('el.innerHTML = req.query.q;').length).toBeGreaterThan(0);
  });

  it('still flags a function whose returns are not all literals', () => {
    const src = [
      'function render(input) {',
      "  if (input) return '<b>' + input + '</b>';",
      "  return '';",
      '}',
      'el.innerHTML = render(userText);',
    ].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });

  it('still flags a template with a non-numeric substitution', () => {
    const src = ['const name = req.query.name;', 'el.innerHTML = `<p>${name}</p>`;'].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });
});

describe('collectSafeBindings / resolvesToConstant', () => {
  const b = (src) => collectSafeBindings(src);

  it('collects string constants', () => {
    expect(b("const A = 'x';").constants.has('A')).toBe(true);
  });

  it('collects numeric bindings from .length and arithmetic', () => {
    const r = b('const n = items.length;\nconst m = 4;\nconst k = a * 2;');
    expect(r.numerics.has('n')).toBe(true);
    expect(r.constants.has('m')).toBe(true);
    expect(r.numerics.has('k')).toBe(true);
  });

  it('recognises a locally defined escaper', () => {
    const r = b('function esc(s){ return s.replace(/[&<>]/g, m => M[m]); }');
    expect(r.sanitizers.has('esc')).toBe(true);
  });

  it('does not treat an arbitrary function as a sanitizer', () => {
    const r = b('function slugify(s){ return s.toLowerCase(); }');
    expect(r.sanitizers.has('slugify')).toBe(false);
  });

  it('declines what it cannot prove', () => {
    const r = b('const x = fetchSomething();');
    expect(resolvesToConstant('x', r)).toBe(false);
    expect(resolvesToConstant('someUnknown', r)).toBe(false);
  });

  it('survives empty and non-string input', () => {
    for (const v of ['', null, undefined, 42]) {
      const r = collectSafeBindings(v);
      expect(r.constants.size).toBe(0);
    }
  });
});

describe('Code Correctness: speech and audio browser globals', () => {
  it.each([
    'speechSynthesis',
    'SpeechSynthesisUtterance',
    'webkitSpeechRecognition',
    'AudioContext',
    'reportError',
  ])('does not report %s as undeclared', (g) => {
    expect(
      probeCodeCorrectness(f('src/ui/voice.js', `export function go(){ return ${g}; }`))
    ).toEqual([]);
  });

  it('still reports a genuinely wrong casing of a real global', () => {
    // The global is `indexedDB`. `IndexedDB` is a real mistake.
    const found = probeCodeCorrectness(
      f('src/ui/db.js', 'export function go(){ return IndexedDB; }')
    );
    expect(found.length).toBeGreaterThan(0);
  });
});

describe('URL Reputation: known-good hosts on flagged TLDs', () => {
  it('does not flag a mainstream inference API on .xyz', () => {
    const found = probeExternalURLs(
      f('src/lib/ai.js', 'fetch("https://api.together.xyz/v1/chat/completions")')
    );
    expect(found.filter((x) => /Suspicious TLD/i.test(x.title))).toEqual([]);
  });

  it('still flags an unknown host on a flagged TLD', () => {
    const found = probeExternalURLs(f('src/lib/x.js', 'fetch("https://freestuff.tk/x")'));
    expect(found.filter((x) => /Suspicious TLD/i.test(x.title)).length).toBeGreaterThan(0);
  });
});

// --- Second pass, from re-scanning the same cockpit after the first fix ---
//
// The first const-eval pass cleared the synthetic shapes but only 0 of 24 real
// findings, because value extraction was line-anchored. Real code does not put
// the whole expression on one line.
describe('HTML sinks: real-world expression shapes', () => {
  it('does not flag a multi-line template of static markup', () => {
    const src = [
      'el.innerHTML = `<div class="card">',
      '  <span class="title"></span>',
      '  <span class="body"></span>',
      '</div>`;',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('does not flag when another statement follows on the same line', () => {
    const src = "const box = $('x'); box.innerHTML = ''; box.style.display = '';";
    expect(xss(src)).toEqual([]);
  });

  it('does not flag a literal followed by a closing brace', () => {
    const src = 'function f() { list.innerHTML = \'<div class="hint">none</div>\'; }';
    expect(xss(src)).toEqual([]);
  });

  it('does not flag a ternary between two static strings', () => {
    const src = "box.innerHTML = items.length ? '' : '<div class=\"hint\">none yet</div>';";
    expect(xss(src)).toEqual([]);
  });

  it('does not flag concatenation of static strings', () => {
    const src = "row.innerHTML = '<span></span>' + '<button class=\"del\">x</button>';";
    expect(xss(src)).toEqual([]);
  });

  it('does not flag a template whose hole is sanitizer-wrapped', () => {
    const src = 'div.innerHTML = `<div class="p">Permission — ${escapeHtml(tool)}</div>`;';
    expect(xss(src)).toEqual([]);
  });

  it('still flags a multi-line template with a tainted hole', () => {
    const src = ['el.innerHTML = `<div>', '  ${req.query.q}', '</div>`;'].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });

  it('still flags a ternary with a tainted branch', () => {
    const src = "box.innerHTML = ok ? '<b>fine</b>' : userInput;";
    expect(xss(src).length).toBeGreaterThan(0);
  });
});

describe('vendored third-party code is out of scope', () => {
  it('excludes vendor directories from the scan set', async () => {
    const { shouldScanFile } = await import('../lib/file-filter.js');
    expect(shouldScanFile('web/public/vendor/cm/mode/php/php.js')).toBe(false);
    expect(shouldScanFile('src/third_party/lib.js')).toBe(false);
    expect(shouldScanFile('bower_components/x/y.js')).toBe(false);
    expect(shouldScanFile('src/vendors.js')).toBe(true);
    expect(shouldScanFile('src/app.js')).toBe(true);
  });
});

// --- Third pass: array-join assembly and inferred numerics ----------------
describe('array-of-fragments assembly', () => {
  it('does not flag joining an array whose pushes are all safe', () => {
    const src = [
      'function render(count) {',
      '  const bits = [];',
      "  if (count) bits.push(`${count} item${count > 1 ? 's' : ''} queued`);",
      "  el.innerHTML = bits.join(' · ');",
      '}',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('still flags joining an array that receives an unsafe value', () => {
    const src = [
      'function render(input) {',
      '  const bits = [];',
      '  bits.push(`<b>${input.name}</b>`);',
      "  el.innerHTML = bits.join('');",
      '}',
    ].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });

  it('treats a pluraliser ternary as safe', () => {
    const src = "el.innerHTML = `${n} file${n > 1 ? 's' : ''}`;\nlet n = 0;";
    expect(xss(src)).toEqual([]);
  });

  it('infers a function parameter is numeric from a comparison', () => {
    const src = [
      'function show(snapCount) {',
      '  el.innerHTML = `<b>${snapCount} snapshot${snapCount > 1 ? "s" : ""}</b>`;',
      '}',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('does not treat an unconstrained parameter as numeric', () => {
    const src = 'function show(name) {\n  el.innerHTML = `<b>${name}</b>`;\n}';
    expect(xss(src).length).toBeGreaterThan(0);
  });
});

// --- Fourth pass: cross-boundary safety ------------------------------------
//
// After a real read-through escaped every inconsistent interpolation, the only
// XSS findings left on that project were these two shapes. Both are safe and
// neither was provable while the resolver stopped at the function boundary.
describe('cross-boundary safety, same file', () => {
  it('clears a function whose returns are all safe', () => {
    const src = [
      'function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => MAP[c]); }',
      'const LINK_ROW = () => {',
      '  return `<div class="linkedit"><span>${escapeHtml(name)}</span></div>`;',
      '};',
      'wrap.innerHTML = LINK_ROW();',
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('clears a parameter that every call site feeds a safe value', () => {
    const src = [
      'function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => MAP[c]); }',
      'function addRow(boxId, html) {',
      '  row.innerHTML = html + \'<button class="rowdel">x</button>\';',
      '}',
      "addRow('a', `<span>${escapeHtml(one)}</span>`);",
      "addRow('b', `<span>${escapeHtml(two)}</span>`);",
    ].join('\n');
    expect(xss(src)).toEqual([]);
  });

  it('still flags when ONE call site passes an unsafe value', () => {
    const src = [
      'function escapeHtml(s) { return String(s).replace(/[&<>"]/g, (c) => MAP[c]); }',
      'function addRow(boxId, html) {',
      "  row.innerHTML = html + '<button/>';",
      '}',
      "addRow('a', `<span>${escapeHtml(one)}</span>`);",
      "addRow('b', userSuppliedMarkup);",
    ].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });

  it('still flags a function whose returns are not all safe', () => {
    const src = [
      'const ROW = () => {',
      '  return `<div>${untrusted}</div>`;',
      '};',
      'wrap.innerHTML = ROW();',
    ].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });

  it('declines a parameter name shared by two functions', () => {
    // Ambiguous claim: decline rather than approximate.
    const src = [
      'function a(html) { row.innerHTML = html; }',
      'function b(html) { other.innerHTML = html; }',
      "a('<b>safe</b>');",
      'b(userInput);',
    ].join('\n');
    expect(xss(src).length).toBeGreaterThan(0);
  });
});

describe('an embedded copy of this engine is not the host app', () => {
  it('excludes a vendored PreFlight engine from a host scan', async () => {
    const { shouldScanFile } = await import('../lib/file-filter.js');
    expect(shouldScanFile('server/src/preflight/engine/lib/probes.js')).toBe(false);
    expect(shouldScanFile('server/src/preflight/engine/lib/threat-intel.js')).toBe(false);
    expect(shouldScanFile('apps/api/preflight/engine/lib/probes/auth.js')).toBe(false);
    expect(shouldScanFile('server/src/preflight/preflight.lock')).toBe(false);
  });

  it("still scans the host's own code around it", async () => {
    const { shouldScanFile } = await import('../lib/file-filter.js');
    expect(shouldScanFile('server/src/preflight/scanProject.mjs')).toBe(true);
    expect(shouldScanFile('server/src/index.js')).toBe(true);
    // A user's own probes directory is theirs and stays in scope.
    expect(shouldScanFile('src/lib/probes/myRules.js')).toBe(true);
  });
});
