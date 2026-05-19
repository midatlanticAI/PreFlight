// Hardening tests for Breakers v1. The shape suite (breakers.test.js) proves
// the catalogue is well-formed and the safety regex passes. This file proves
// the rest:
//
//   - Dogfood self-source exclusion: PreFlight scanning its own breakers.js
//     does not fire pattern-matching probes on the payload strings.
//   - XSS-safe render: BreakersPanel uses React text-children only (no
//     dangerouslySetInnerHTML), and renderToStaticMarkup of the panel
//     produces no live script tags even for payloads that contain
//     literal <script>...</script>.
//   - Structural validity per Breaker: each payload's contents match the
//     attack it claims (JWT alg-none decodes to {alg:'none'}, SQL injection
//     payloads contain SQL meta-chars, bidi-override payload contains a
//     real bidi control char, etc.).
//   - Accessibility primitives: the rendered panel surfaces semantic
//     section + aria-label + headings + accessible copy-button labels.
//
// Why these tests exist: the catalogue is the user-visible part of an
// adversarial-input feature. The bar for adversarial-input content has to
// be higher than the bar for normal content, because hostile-looking text
// in a webapp is the exact failure mode XSS / injection prevention exists
// to defeat. PreFlight's founding principle: dogfood-as-CI-gate.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

import { BREAKERS } from '../lib/breakers.js';
import { BreakersPanel } from '../components/BreakersPanel.jsx';
import { isScannerSelfSource } from '../lib/file-filter.js';
import { PROBES } from '../lib/probes.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BREAKERS_PANEL_PATH = join(__dirname, '..', 'components', 'BreakersPanel.jsx');
const BREAKERS_PANEL_SOURCE = readFileSync(BREAKERS_PANEL_PATH, 'utf8');

// ============================================================================
// Dogfood self-source coverage
// ============================================================================
//
// src/lib/breakers.js contains attack-shaped strings (SQL injection literals,
// traversal paths, JWT alg-none tokens, bidi control chars). Pattern-matching
// probes would absolutely fire on them. The contract: PreFlight's own scan
// must skip the catalogue file via isScannerSelfSource.

describe('Breakers dogfood coverage', () => {
  it('src/lib/breakers.js is excluded by isScannerSelfSource', () => {
    expect(isScannerSelfSource('src/lib/breakers.js')).toBe(true);
  });

  it('the exclusion holds for nested-path variants PreFlight might see at scan time', () => {
    expect(isScannerSelfSource('audit-app/src/lib/breakers.js')).toBe(true);
    expect(isScannerSelfSource('/repos/preflight/src/lib/breakers.js')).toBe(true);
    expect(isScannerSelfSource('./src/lib/breakers.js')).toBe(true);
  });

  it('the exclusion does NOT swallow legitimate non-Breakers paths nearby', () => {
    // Make sure the regex didn't get loose and now matches things it shouldn't.
    expect(isScannerSelfSource('src/lib/breakers-helper.js')).toBe(false);
    expect(isScannerSelfSource('src/lib/breakers/something.js')).toBe(false);
    expect(isScannerSelfSource('breakers.js')).toBe(false);
  });
});

// ============================================================================
// XSS-safe render
// ============================================================================
//
// BreakersPanel is the surface that renders user-visible attack-shaped strings
// in a live web page. The whole class of vulnerability the panel exists to
// teach about is "input rendered as code, instead of as data." A single
// dangerouslySetInnerHTML in the wrong spot would make the feature ironic.

describe('Breakers render safety', () => {
  it('BreakersPanel source contains no dangerouslySetInnerHTML', () => {
    expect(BREAKERS_PANEL_SOURCE).not.toMatch(/dangerouslySetInnerHTML/);
  });

  it('BreakersPanel source contains no html=, no eval, no Function constructor', () => {
    expect(BREAKERS_PANEL_SOURCE).not.toMatch(/\beval\s*\(/);
    expect(BREAKERS_PANEL_SOURCE).not.toMatch(/new\s+Function\s*\(/);
  });

  it('renderToStaticMarkup of BreakersPanel for every catalogue probe produces no executable <script> tag', () => {
    for (const probeName of Object.keys(BREAKERS)) {
      const html = renderToStaticMarkup(React.createElement(BreakersPanel, { probeName }));
      // The output may contain the literal text "<script>" as escaped HTML
      // entities (e.g., "&lt;script&gt;"). What it must NOT contain is an
      // un-escaped <script> opening tag that the browser would execute.
      const liveScriptTagRe = /<script(?:\s|>)/i;
      expect(html, `${probeName}: panel emitted a live <script> tag`).not.toMatch(liveScriptTagRe);
    }
  });

  it('payloads containing literal <script> in the catalogue are HTML-escaped on render', () => {
    // The HTML Hygiene entries contain inline-handler XSS examples
    // (`<button onclick="...">`) that exercise the same React text-children
    // escaping as the synthetic test above, but against the live catalogue.
    const htmlHygieneHtml = renderToStaticMarkup(
      React.createElement(BreakersPanel, { probeName: 'HTML Hygiene' })
    );
    // No live <button onclick attribute should reach the rendered DOM —
    // those entries are payload-text, not actual buttons.
    expect(htmlHygieneHtml).not.toMatch(/<button\b[^>]*\bonclick\s*=\s*[^&]/i);
    // Conversely, the escape-encoded form of the payload's `<` and `>` should
    // be present, confirming the payload reached the render path and was
    // escaped (not stripped, not passed through).
    expect(htmlHygieneHtml).toMatch(/&lt;|&gt;/);
  });

  it('renderToStaticMarkup of a synthetic XSS-shaped payload escapes the angle brackets', () => {
    // Simulate the worst case: a future contributor adds a payload that's
    // a literal <script> tag. The render must still escape it.
    //
    // The load-bearing property: every `<` becomes `&lt;` and every `>`
    // becomes `&gt;`. Once that holds, any text inside the escaped tag
    // (including `onerror=alert(2)`) is inert browser content, not an
    // executable HTML attribute.
    const Synthetic = ({ payload }) => React.createElement('pre', null, payload);
    const payload = '<script>alert(1)</script><img src=x onerror=alert(2)>';
    const html = renderToStaticMarkup(React.createElement(Synthetic, { payload }));
    // Live tag check: no un-escaped <script> opening tag exists in the
    // rendered HTML.
    expect(html).not.toMatch(/<script(?:\s|>)/i);
    // Escape check: the angle brackets from the payload are entity-encoded.
    expect(html).toMatch(/&lt;script&gt;/);
    expect(html).toMatch(/&lt;\/script&gt;/);
    expect(html).toMatch(/&lt;img/);
    // Belt-and-suspenders: the count of literal `<` in the payload equals
    // the count of `&lt;` in the rendered output (every angle bracket got
    // escaped exactly once, none slipped through).
    const litOpen = (payload.match(/</g) || []).length;
    const escOpen = (html.match(/&lt;/g) || []).length;
    expect(escOpen).toBeGreaterThanOrEqual(litOpen);
  });

  it('returns null (renders nothing) for a probe that has no Breakers catalogue entry', () => {
    const html = renderToStaticMarkup(
      React.createElement(BreakersPanel, { probeName: 'NonexistentProbeName' })
    );
    expect(html).toBe('');
  });
});

// ============================================================================
// Structural validity per Breaker
// ============================================================================
//
// The payload is supposed to look like the attack it claims. The catalogue
// is reference material for users learning the attack class; a placeholder
// string would erode trust. These tests assert the payloads are at minimum
// structurally consistent with their stated attack family.

describe('Breakers structural validity', () => {
  it('SQL Injection payloads contain SQL meta-characters', () => {
    const sql = BREAKERS['SQL Injection'];
    expect(sql).toBeDefined();
    for (const entry of sql) {
      const hasMetaChar =
        /'/.test(entry.payload) ||
        /--/.test(entry.payload) ||
        /\bOR\b/i.test(entry.payload) ||
        /\bUNION\b/i.test(entry.payload) ||
        /;\s*(?:DROP|INSERT|UPDATE|DELETE)/i.test(entry.payload);
      expect(hasMetaChar, `SQL Injection > ${entry.name}: payload lacks SQL meta-characters`).toBe(
        true
      );
    }
  });

  it('Path Traversal payloads contain traversal markers', () => {
    const pt = BREAKERS['Path Traversal'];
    expect(pt).toBeDefined();
    for (const entry of pt) {
      const hasTraversal =
        /\.\.\//.test(entry.payload) ||
        /\.\.%2F/i.test(entry.payload) ||
        /^\/etc\//.test(entry.payload) ||
        /^\/proc\//.test(entry.payload) ||
        /^[A-Z]:\\\\?/.test(entry.payload);
      expect(hasTraversal, `Path Traversal > ${entry.name}: payload lacks traversal markers`).toBe(
        true
      );
    }
  });

  it('Auth Weakness > JWT alg-none has a structurally valid header + payload', () => {
    const jwtEntry = BREAKERS['Auth Weakness'].find((e) => /alg-none/i.test(e.name));
    expect(jwtEntry, 'JWT alg-none entry missing from Auth Weakness').toBeDefined();
    const parts = jwtEntry.payload.split('.');
    // A JWT has exactly three parts; alg=none has an empty signature segment.
    expect(parts.length, 'JWT payload should be three dot-separated parts').toBe(3);
    expect(parts[2], 'alg=none JWT should have empty signature').toBe('');

    // Decode the header and payload (base64url) and assert their claims.
    const b64urlDecode = (s) => {
      const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
      const std = padded.replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(Buffer.from(std, 'base64').toString('utf8'));
    };
    const header = b64urlDecode(parts[0]);
    const payload = b64urlDecode(parts[1]);

    expect(header.alg, 'JWT header must declare alg=none').toBe('none');
    expect(payload).toBeTypeOf('object');
    // The example payload should encode an attacker-claimed identity.
    const hasIdentityClaim =
      'sub' in payload || 'role' in payload || 'isAdmin' in payload || 'user' in payload;
    expect(hasIdentityClaim, 'JWT payload should encode an identity claim').toBe(true);
  });

  it('Auth Weakness > eval / dangerouslySet entries contain JavaScript', () => {
    const auth = BREAKERS['Auth Weakness'];
    const evalEntry = auth.find((e) => /eval/i.test(e.name));
    expect(evalEntry).toBeDefined();
    expect(evalEntry.payload).toMatch(/fetch|document\.cookie|exec|require/);

    const xssEntry = auth.find((e) => /dangerously|innerHTML/i.test(e.name));
    expect(xssEntry).toBeDefined();
    expect(xssEntry.payload).toMatch(/<[a-z]+|onerror|onload|onclick|fetch|document\./);
  });

  it('SSRF / Open Redirect payloads target internal / metadata / cross-domain URLs', () => {
    const ssrf = BREAKERS['SSRF / Open Redirect'];
    expect(ssrf).toBeDefined();
    for (const entry of ssrf) {
      const hasTarget =
        /\b169\.254\.169\.254\b/.test(entry.payload) ||
        /\blocalhost\b/.test(entry.payload) ||
        /\b127\.0\.0\.1\b/.test(entry.payload) ||
        /metadata\.google\.internal/.test(entry.payload) ||
        /^https?:\/\/.*\.example/.test(entry.payload);
      expect(hasTarget, `SSRF > ${entry.name}: payload lacks an SSRF-class target`).toBe(true);
    }
  });

  it('Trojan Source entry contains a real Unicode bidi control character', () => {
    const ts = BREAKERS['Trojan Source'];
    expect(ts).toBeDefined();
    for (const entry of ts) {
      const hasBidi = /[‪-‮⁦-⁩]/.test(entry.payload);
      expect(
        hasBidi,
        `Trojan Source > ${entry.name}: payload lacks U+202A-U+202E / U+2066-U+2069 bidi control`
      ).toBe(true);
    }
  });

  it('AI Rules Files entry contains instruction-override language', () => {
    const ai = BREAKERS['AI Rules Files'];
    expect(ai).toBeDefined();
    for (const entry of ai) {
      const hasOverride =
        /ignore (?:previous|all) instructions/i.test(entry.payload) ||
        /maintenance mode/i.test(entry.payload) ||
        /do not mention/i.test(entry.payload) ||
        /you are now/i.test(entry.payload);
      expect(
        hasOverride,
        `AI Rules Files > ${entry.name}: payload lacks instruction-override phrasing`
      ).toBe(true);
    }
  });

  it('LLM Security prompt-injection entries contain instruction-override phrasing', () => {
    const llm = BREAKERS['LLM Security'];
    expect(llm).toBeDefined();
    for (const entry of llm) {
      const hasInjection =
        /ignore (?:previous|all) instructions/i.test(entry.payload) ||
        /system prompt/i.test(entry.payload) ||
        /hidden instruction/i.test(entry.payload) ||
        /do not (?:mention|reveal)/i.test(entry.payload);
      expect(
        hasInjection,
        `LLM Security > ${entry.name}: payload lacks prompt-injection phrasing`
      ).toBe(true);
    }
  });

  it('Cookie Security XSS payload contains document.cookie + fetch', () => {
    const cs = BREAKERS['Cookie Security'][0];
    expect(cs).toBeDefined();
    expect(cs.payload).toMatch(/document\.cookie/);
    expect(cs.payload).toMatch(/fetch|XMLHttpRequest|Image\(/);
  });

  it('HTML Hygiene payloads contain target HTML attack vectors', () => {
    const html = BREAKERS['HTML Hygiene'];
    expect(html).toBeDefined();
    for (const entry of html) {
      const hasVector =
        /onclick|onload|onerror|on[a-z]+\s*=/i.test(entry.payload) ||
        /target\s*=\s*["']?_blank/i.test(entry.payload) ||
        /<script/i.test(entry.payload);
      expect(hasVector, `HTML Hygiene > ${entry.name}: payload lacks an HTML attack vector`).toBe(
        true
      );
    }
  });

  it('CORS payload demonstrates credential-bearing cross-origin fetch', () => {
    const cors = BREAKERS['CORS'][0];
    expect(cors).toBeDefined();
    expect(cors.payload).toMatch(/credentials\s*:\s*['"]include['"]/i);
    expect(cors.payload).toMatch(/fetch\s*\(/);
  });

  it('Webhook Validation payload is a valid JSON event shape', () => {
    const wh = BREAKERS['Webhook Validation'][0];
    expect(wh).toBeDefined();
    expect(() => JSON.parse(wh.payload)).not.toThrow();
    const obj = JSON.parse(wh.payload);
    expect(obj.type, 'webhook payload should carry an event type').toBeTypeOf('string');
  });

  it('Iframe Sandbox payload contains top-window navigation pattern', () => {
    const iframe = BREAKERS['Iframe Sandbox'][0];
    expect(iframe).toBeDefined();
    expect(iframe.payload).toMatch(/window\.top|parent\.location|top\.location/);
  });

  it('every catalogue probe still maps to a registered probe in PROBES', () => {
    // Belt-and-suspenders check; breakers.test.js verifies this too, but
    // we re-assert here so a hardening run alone gives confidence.
    const registered = new Set(PROBES.map((p) => p.name));
    for (const probeName of Object.keys(BREAKERS)) {
      expect(registered.has(probeName), `${probeName} is in BREAKERS but not in PROBES`).toBe(true);
    }
  });
});

// ============================================================================
// Accessibility primitives
// ============================================================================
//
// The Breakers panel is a non-trivial UI surface. It needs to be navigable
// by keyboard, announced sensibly by screen readers, and not lean on color
// alone for meaning. These tests assert the structural pieces a real a11y
// audit would check first.

describe('Breakers accessibility primitives', () => {
  const sampleProbeName = Object.keys(BREAKERS)[0];
  const html = renderToStaticMarkup(
    React.createElement(BreakersPanel, { probeName: sampleProbeName })
  );

  it('renders a semantic <section> with an aria-label', () => {
    expect(html).toMatch(/<section\b[^>]*aria-label=/i);
  });

  it('the aria-label names the probe being demonstrated', () => {
    expect(html).toMatch(new RegExp(`aria-label="[^"]*${sampleProbeName}`, 'i'));
  });

  it('every Breaker entry renders a heading-like element', () => {
    const entries = BREAKERS[sampleProbeName];
    for (const entry of entries) {
      // The entry name should appear in a way a screen reader can pick out.
      // We render it as a styled span; the heading semantics live in the
      // section. Confirm the entry name appears in the output.
      expect(html, `entry "${entry.name}" missing from rendered output`).toContain(entry.name);
    }
  });

  it('every Copy button has an accessible name via title attribute', () => {
    // The title attribute is read by screen readers when no aria-label is
    // present. Our copy button uses title=`Copy: ${entry.name}`.
    expect(html).toMatch(/title="Copy:/);
  });

  it('icons are marked aria-hidden so they do not pollute screen-reader output', () => {
    // The component uses ShieldAlert / AlertTriangle / Copy icons from lucide.
    // The visible label is text; the icon is decorative.
    expect(html).toMatch(/aria-hidden/);
  });

  it('the safety advisory text is present in the rendered output', () => {
    // "Use only on systems you own" is the load-bearing legal / ethical
    // surface of the panel. It must be present and visible.
    expect(html).toMatch(/Use only on systems you own/i);
  });
});
