// App-shape awareness and cookie-helper resolution.
//
// Both come from the same real scan (2026-07) and the same root cause: the
// scanner judging code without understanding its context. Cookie flags set in
// a helper were reported missing; stack traces returned to the one person
// running a loopback tool were reported as disclosure.
import { describe, it, expect } from 'vitest';
import { probeCookieFlags } from '../lib/probes.js';
import { detectAppShape, applyAppShape } from '../lib/probes/v2/app-shape.js';

const f = (path, content) => [{ path, content }];

describe('cookie flags set in a same-file helper', () => {
  it('does not flag when the helper sets every flag', () => {
    const src = [
      'function cookieHeader(name, value) {',
      '  return `${name}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/`;',
      '}',
      'export function login(res, token) {',
      "  res.setHeader('Set-Cookie', cookieHeader('session', token));",
      '}',
    ].join('\n');
    expect(probeCookieFlags(f('src/server/auth.js', src))).toEqual([]);
  });

  it('does not flag an arrow helper', () => {
    const src = [
      'const buildSessionCookie = (v) => {',
      '  return `session=${v}; HttpOnly; Secure; SameSite=Strict`;',
      '};',
      'export function login(res, token) {',
      "  res.setHeader('Set-Cookie', buildSessionCookie(token));",
      '}',
    ].join('\n');
    expect(probeCookieFlags(f('src/server/auth.js', src))).toEqual([]);
  });

  it('still flags when the helper omits the flags', () => {
    const src = [
      'function cookieHeader(name, value) {',
      '  return `${name}=${value}; Path=/`;',
      '}',
      'export function login(res, token) {',
      "  res.setHeader('Set-Cookie', cookieHeader('session', token));",
      '}',
    ].join('\n');
    expect(probeCookieFlags(f('src/server/auth.js', src)).length).toBeGreaterThan(0);
  });

  it('still flags an inline cookie set with no flags', () => {
    const src = "res.cookie('session', token, { path: '/' });";
    expect(probeCookieFlags(f('src/server/auth.js', src)).length).toBeGreaterThan(0);
  });
});

describe('detectAppShape', () => {
  it('recognises a loopback-only server', () => {
    const s = detectAppShape(f('server.js', "app.listen(4589, '127.0.0.1');"));
    expect(s.isSingleUserLocal).toBe(true);
    expect(s.reasons).toContain('binds to loopback only');
  });

  it('recognises a desktop shell', () => {
    const s = detectAppShape(f('main.js', "const { BrowserWindow } = require('electron');"));
    expect(s.isSingleUserLocal).toBe(true);
  });

  it('declines when the app also binds a public interface', () => {
    const s = detectAppShape(
      f('server.js', ["app.listen(4589, '127.0.0.1');", "server.listen(80, '0.0.0.0');"].join('\n'))
    );
    expect(s.isSingleUserLocal).toBe(false);
    expect(s.reasons).toContain('also binds a public interface');
  });

  it('declines when there is a multi-user surface', () => {
    const s = detectAppShape(
      f(
        'server.js',
        ["app.listen(3000, 'localhost');", 'async function registerUser(x){}'].join('\n')
      )
    );
    expect(s.isSingleUserLocal).toBe(false);
  });

  it('declines when the project ships a deploy config', () => {
    const s = detectAppShape([
      { path: 'server.js', content: "app.listen(3000, '127.0.0.1');" },
      { path: 'vercel.json', content: '{}' },
    ]);
    expect(s.isSingleUserLocal).toBe(false);
  });

  it('declines for an ordinary web app with no local signal', () => {
    expect(detectAppShape(f('server.js', 'app.listen(process.env.PORT);')).isSingleUserLocal).toBe(
      false
    );
  });

  it('survives empty input', () => {
    expect(detectAppShape([]).isSingleUserLocal).toBe(false);
    expect(detectAppShape(null).isSingleUserLocal).toBe(false);
  });
});

describe('applyAppShape re-weights rather than hides', () => {
  const shape = { isSingleUserLocal: true };
  const finding = (probe, severity) => ({ probe, severity, title: 't' });

  it('keeps the finding in the report', () => {
    const out = applyAppShape([finding('Stack Trace Leaks', 'medium')], shape);
    expect(out).toHaveLength(1);
  });

  it('lowers the severity and records what it was', () => {
    const out = applyAppShape([finding('Stack Trace Leaks', 'medium')], shape);
    expect(out[0].severity).toBe('low');
    expect(out[0].originalSeverity).toBe('medium');
  });

  it('explains why, so the reader learns the deployed case still counts', () => {
    const out = applyAppShape([finding('Stack Trace Leaks', 'high')], shape);
    expect(out[0].shapeNote).toMatch(/single-user/i);
    expect(out[0].shapeNote).toMatch(/public interface|second user/i);
  });

  it('leaves exposure-independent findings alone', () => {
    const out = applyAppShape([finding('Secret Scanner', 'critical')], shape);
    expect(out[0].severity).toBe('critical');
    expect(out[0].shapeNote).toBeUndefined();
  });

  it('changes nothing when the app is not single-user local', () => {
    const out = applyAppShape([finding('Stack Trace Leaks', 'medium')], {
      isSingleUserLocal: false,
    });
    expect(out[0].severity).toBe('medium');
  });

  it('survives empty input', () => {
    expect(applyAppShape([], { isSingleUserLocal: true })).toEqual([]);
    expect(applyAppShape(null, { isSingleUserLocal: true })).toEqual([]);
  });
});

describe('discoverability follows the same shape logic', () => {
  const shape = { isSingleUserLocal: true };
  const finding = (probe, severity) => ({ probe, severity, title: 't' });

  it('downgrades SEO and GEO findings for a loopback tool', () => {
    const out = applyAppShape(
      [finding('SEO Hygiene', 'medium'), finding('GEO Hygiene', 'low')],
      shape
    );
    expect(out[0].severity).toBe('low');
    expect(out[1].severity).toBe('info');
  });

  it('explains the reason in audience terms, not exposure terms', () => {
    const out = applyAppShape([finding('SEO Hygiene', 'medium')], shape);
    expect(out[0].shapeNote).toMatch(/search engine|social card/i);
  });

  it('leaves them at full weight for a normal web app', () => {
    const out = applyAppShape([finding('SEO Hygiene', 'medium')], { isSingleUserLocal: false });
    expect(out[0].severity).toBe('medium');
  });
});

describe('vendored single files are out of scope', () => {
  it('excludes vendored library files, not just vendor directories', async () => {
    const { shouldScanFile } = await import('../lib/file-filter.js');
    expect(shouldScanFile('server/src/vendor-html2canvas.js')).toBe(false);
    expect(shouldScanFile('src/lib/app.vendor.js')).toBe(false);
    expect(shouldScanFile('src/jquery-3.6.0.js')).toBe(false);
    expect(shouldScanFile('src/xterm.js')).toBe(false);
    // First-party code that merely mentions a library name stays in scope.
    expect(shouldScanFile('src/vendors-page.jsx')).toBe(true);
    expect(shouldScanFile('src/lib/vendorBilling.js')).toBe(true);
  });
});
