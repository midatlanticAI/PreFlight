// Equivalent-control recognition.
//
// Real-scan finding 2026-07 (Atlan cockpit): three probes kept firing after
// the author had actually implemented the control, because each matched one
// exact spelling rather than the property it cared about. One of them rejected
// a control that is stronger than the one it suggested.
//
// A scanner that pushes an author toward a weaker implementation to satisfy it
// is worse than not having the check.
import { describe, it, expect } from 'vitest';
import { probeIframeSandbox, probeA11yLandmarks, probeNpmrcHygiene } from '../lib/probes.js';

const f = (path, content) => [{ path, content }];
const originFindings = (src) =>
  probeIframeSandbox(f('src/ui/preview.js', src)).filter((x) => /postMessage/i.test(x.title));
const skipFindings = (src) =>
  probeA11yLandmarks(f('index.html', src)).filter((x) => /skip-to-content/i.test(x.title));

describe('postMessage: a sender check is a sender check', () => {
  it('accepts the conventional origin comparison', () => {
    const src = [
      "window.addEventListener('message', (e) => {",
      "  if (e.origin !== 'https://trusted.example') return;",
      '  handle(e.data);',
      '});',
    ].join('\n');
    expect(originFindings(src)).toEqual([]);
  });

  it('accepts an event.source reference check, which is not forgeable', () => {
    const src = [
      "window.addEventListener('message', (e) => {",
      '  if (e.source !== window.parent) return;',
      '  handle(e.data);',
      '});',
    ].join('\n');
    expect(originFindings(src)).toEqual([]);
  });

  it('accepts a source check against a specific iframe window', () => {
    const src = [
      "window.addEventListener('message', (event) => {",
      '  if (event.source !== frame.contentWindow) return;',
      '  handle(event.data);',
      '});',
    ].join('\n');
    expect(originFindings(src)).toEqual([]);
  });

  it('still flags a handler with no sender check at all', () => {
    const src = ["window.addEventListener('message', (e) => {", '  handle(e.data);', '});'].join(
      '\n'
    );
    expect(originFindings(src).length).toBeGreaterThan(0);
  });
});

describe('skip link: recognised by what it does', () => {
  const page = (body) => `<html lang="en"><body>${body}<main id="main">x</main></body></html>`;

  it.each([
    ['exact conventional form', '<a href="#main">Skip to main content</a>'],
    ['hyphenated target', '<a href="#main-content">Skip to content</a>'],
    ['different target id', '<a href="#app">Skip navigation</a>'],
    ['text on the next line', '<a href="#main">\n  Skip to content\n</a>'],
    ['wrapped in a span', '<a href="#main"><span>Skip to content</span></a>'],
    ['identified by class', '<a href="#top" class="skip-link">Go to content</a>'],
    ['identified by aria-label', '<a href="#x" aria-label="Skip to main content"></a>'],
    ['jump wording', '<a href="#main">Jump to content</a>'],
  ])('accepts %s', (_label, link) => {
    expect(skipFindings(page(link))).toEqual([]);
  });

  it('still flags a page with no skip link', () => {
    expect(skipFindings(page('<nav>menu</nav>')).length).toBeGreaterThan(0);
  });

  it('does not accept an unrelated in-page anchor', () => {
    expect(skipFindings(page('<a href="#pricing">See pricing</a>')).length).toBeGreaterThan(0);
  });
});

describe('.npmrc release cooldown: any spelling of the control', () => {
  const withNpmrc = (content) => [
    { path: 'package.json', content: '{}' },
    { path: '.npmrc', content },
  ];
  const cooldown = (content) =>
    probeNpmrcHygiene(withNpmrc(content)).filter((x) => /release-age|cooldown/i.test(x.title));

  it.each([
    ['npm min-release-age', 'min-release-age=10080'],
    ['pnpm minimumReleaseAge', 'minimumReleaseAge=10080'],
    ['hyphenated variant', 'minimum-release-age=10080'],
    ['npm before= date pin', 'before=2026-07-01'],
  ])('accepts %s', (_label, content) => {
    expect(cooldown(content)).toEqual([]);
  });

  it('still flags an .npmrc with no cooldown control', () => {
    expect(cooldown('audit-level=high').length).toBeGreaterThan(0);
  });
});
