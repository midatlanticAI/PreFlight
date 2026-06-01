// src/test/sandbox.test.js
//
// Smoke tests for the v2 sandbox surface. Asserts:
//   - All three sandbox modules expose the functions the rest of the app
//     imports by name (so a rename or accidental default-export breaks the
//     gate, not the user).
//   - The /sandbox route is registered in App.jsx via lazyNamed, so the
//     route does not silently drop off the router.
//   - The Sandbox NavLink is present in Nav.jsx, so the surface stays
//     reachable from primary navigation.
//   - CodeMirror's umbrella package + the JavaScript language pack are in
//     package.json dependencies (not devDependencies), so a production build
//     keeps them.

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const read = (rel) => readFileSync(join(ROOT, ...rel.split('/')), 'utf-8');

describe('sandbox module exports', () => {
  it('SandboxView is exported by name from src/components/sandbox/SandboxView.jsx', async () => {
    const mod = await import('../components/sandbox/SandboxView.jsx');
    expect(typeof mod.SandboxView).toBe('function');
  });

  it('Editor is exported by name from src/components/sandbox/Editor.jsx', async () => {
    const mod = await import('../components/sandbox/Editor.jsx');
    expect(typeof mod.Editor).toBe('function');
  });

  it('FindingsPanel is exported by name from src/components/sandbox/FindingsPanel.jsx', async () => {
    const mod = await import('../components/sandbox/FindingsPanel.jsx');
    expect(typeof mod.FindingsPanel).toBe('function');
  });
});

describe('sandbox route wiring', () => {
  const app = read('src/App.jsx');

  it('App.jsx declares the SandboxView lazyNamed import', () => {
    expect(app).toMatch(
      /lazyNamed\(\s*\(\)\s*=>\s*import\(['"][^'"]*sandbox\/SandboxView\.jsx['"]\)/
    );
  });

  it('App.jsx registers a route for /sandbox', () => {
    expect(app).toMatch(/<Route\s+path=["']\/sandbox["']\s+element=\{<SandboxView\s*\/>\}\s*\/>/);
  });
});

describe('sandbox primary-nav reachability', () => {
  const nav = read('src/components/Nav.jsx');

  it('Nav.jsx includes the /sandbox NavItem', () => {
    expect(nav).toMatch(/to:\s*['"]\/sandbox['"]/);
  });

  it('Nav.jsx labels it "Sandbox"', () => {
    expect(nav).toMatch(/label:\s*['"]Sandbox['"]/);
  });
});

describe('sandbox dependencies are committed', () => {
  const pkg = JSON.parse(read('package.json'));

  it('codemirror is a runtime dependency', () => {
    expect(pkg.dependencies?.codemirror).toBeTruthy();
  });

  it('@codemirror/lang-javascript is a runtime dependency', () => {
    expect(pkg.dependencies?.['@codemirror/lang-javascript']).toBeTruthy();
  });
});
