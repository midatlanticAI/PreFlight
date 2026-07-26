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

describe('.npmrc install-time control: the spelling has to be one the tool implements', () => {
  // This block used to assert that `min-release-age=10080` in .npmrc counted as
  // hardened. Verified 2026-07-26 against npm 10.9.8: npm does not recognise
  // that key. It survives in `npm config ls -l` only because npm echoes unknown
  // .npmrc keys back, which is exactly why it looked like it worked. The probe
  // was recommending an inert line and then certifying the project for adding
  // it, and this test was holding that loop closed.
  //
  // pnpm does implement the rolling cooldown, as `minimumReleaseAge`, but reads
  // it from pnpm-workspace.yaml. Setting it in .npmrc reads back undefined
  // (pnpm 10.34.1, same day). So the answer depends on the package manager, and
  // the tests now say which one they are talking about.
  const npmProject = (content) => [
    { path: 'package.json', content: '{}' },
    { path: 'package-lock.json', content: '{}' },
    { path: '.npmrc', content },
  ];
  const pnpmProject = (npmrc, workspace) =>
    [
      { path: 'package.json', content: '{}' },
      { path: 'pnpm-lock.yaml', content: 'lockfileVersion: 9.0' },
      { path: '.npmrc', content: npmrc },
      workspace ? { path: 'pnpm-workspace.yaml', content: workspace } : null,
    ].filter(Boolean);
  const control = (files) =>
    probeNpmrcHygiene(files).filter((x) => /release cooldown|supply-chain control/i.test(x.title));

  describe('npm projects', () => {
    it.each([
      ['ignore-scripts, the control that stops lifecycle-script worms', 'ignore-scripts=true'],
      ['before=, which npm actually implements', 'before=2026-07-01'],
    ])('accepts %s', (_label, content) => {
      expect(control(npmProject(content))).toEqual([]);
    });

    it('does NOT accept min-release-age, which npm ignores', () => {
      expect(control(npmProject('min-release-age=10080')).length).toBeGreaterThan(0);
    });

    it('does not accept pnpm spelling in an npm project either', () => {
      expect(control(npmProject('minimumReleaseAge=10080')).length).toBeGreaterThan(0);
    });

    it('flags an .npmrc carrying only audit-level', () => {
      expect(control(npmProject('audit-level=high')).length).toBeGreaterThan(0);
    });

    it('names the real npm controls in the remediation, and warns off the inert one', () => {
      const [f] = control(npmProject('audit-level=high'));
      expect(f.remediation).toMatch(/ignore-scripts=true/);
      expect(f.remediation).toMatch(/before=/);
      expect(f.remediation).toMatch(/npm does not recognise the key/);
    });
  });

  describe('pnpm projects', () => {
    it('accepts minimumReleaseAge in pnpm-workspace.yaml, where pnpm reads it', () => {
      expect(control(pnpmProject('', 'minimumReleaseAge: 10080'))).toEqual([]);
    });

    it('flags a pnpm project with no cooldown anywhere', () => {
      expect(control(pnpmProject('audit-level=high')).length).toBeGreaterThan(0);
    });

    it('points at pnpm-workspace.yaml rather than .npmrc', () => {
      const [f] = control(pnpmProject('audit-level=high'));
      expect(f.remediation).toMatch(/pnpm-workspace\.yaml, not \.npmrc/);
    });
  });
});
