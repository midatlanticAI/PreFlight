// The engine declares its runtime dependencies, and this keeps the declaration
// true.
//
// Consumers vendor src/lib and src/data and need to know what to install.
// Parsing imports out of the vendored tree is the obvious approach and it is a
// trap: src/lib/probes/v05/fixtures/ holds deliberately-vulnerable sample code
// that probes parse as INPUT, and those samples carry real import statements.
// A downstream cockpit did exactly that and installed `jsonwebtoken` into its
// own dependency tree, where nothing ever ran it (outside review, 2026-07-26).
//
// Benign that time. It would not stay benign: a fixture is precisely where an
// attacker-shaped package name belongs, and this repo ships more than a hundred
// of them deliberately.
//
// A declared list only helps if it is right, so the first test derives the
// answer from the source and compares. If someone adds a real dependency to the
// engine and forgets the declaration, this fails.

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { ENGINE_RUNTIME_DEPS, engineInfo } from '../lib/cockpit-scan.js';

// Resolved from the repo root rather than import.meta.url: these run under
// jsdom, where import.meta.url is not a file: URL.
const ROOT = process.cwd();
const SRC = join(ROOT, 'src');
const ROOTS = ['lib', 'data'].filter((d) => existsSync(join(SRC, d)));
// Fixtures are scan input, not engine code. Their imports are bait.
const FIXTURE_RE = /(^|[\\/])fixtures[\\/]/;

function importedPackages({ includeFixtures = false } = {}) {
  const found = new Map();
  const IMPORT_RE = /^\s*(?:import|export)[^'"]*?from\s*['"]([^'"]+)['"]/gm;
  const SIDE_RE = /^\s*import\s*['"]([^'"]+)['"]/gm;
  const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1');
  const walk = (rel) => {
    for (const entry of readdirSync(join(SRC, rel), { withFileTypes: true })) {
      const child = join(rel, entry.name);
      if (entry.isDirectory()) {
        walk(child);
        continue;
      }
      if (!/\.(js|mjs)$/.test(entry.name)) continue;
      if (!includeFixtures && FIXTURE_RE.test(child)) continue;
      const s = strip(readFileSync(join(SRC, child), 'utf8'));
      for (const re of [IMPORT_RE, SIDE_RE]) {
        let m;
        re.lastIndex = 0;
        while ((m = re.exec(s))) {
          const spec = m[1];
          if (spec.startsWith('.') || spec.startsWith('node:')) continue;
          const pkg = spec.startsWith('@')
            ? spec.split('/').slice(0, 2).join('/')
            : spec.split('/')[0];
          if (!found.has(pkg)) found.set(pkg, child);
        }
      }
    }
  };
  for (const r of ROOTS) walk(r);
  return found;
}

describe('declared runtime deps match the source', () => {
  it('every package the engine really imports is declared', () => {
    const actual = importedPackages();
    const undeclared = [...actual.keys()].filter((p) => !ENGINE_RUNTIME_DEPS.includes(p));
    expect(
      undeclared.map((p) => `${p} (imported by ${actual.get(p)})`),
      'a new engine dependency was added without declaring it in ENGINE_RUNTIME_DEPS'
    ).toEqual([]);
  });

  it('every declared package is really imported', () => {
    const actual = importedPackages();
    const stale = ENGINE_RUNTIME_DEPS.filter((p) => !actual.has(p));
    expect(stale, 'ENGINE_RUNTIME_DEPS lists something the engine no longer imports').toEqual([]);
  });

  it('engineInfo() exposes the list to embedders', () => {
    expect(engineInfo().runtimeDeps).toEqual([...ENGINE_RUNTIME_DEPS]);
  });

  it('the list is frozen, so a consumer cannot mutate it', () => {
    expect(Object.isFrozen(ENGINE_RUNTIME_DEPS)).toBe(true);
  });
});

describe('why the list exists at all', () => {
  it('fixtures do import packages the engine does not depend on', () => {
    // If this ever comes back empty the hazard is gone and the guard could be
    // reconsidered. While it holds, source-parsing gives a consumer the wrong
    // answer, which is the whole reason for declaring.
    const withFixtures = importedPackages({ includeFixtures: true });
    const baitOnly = [...withFixtures.keys()].filter((p) => !ENGINE_RUNTIME_DEPS.includes(p));
    expect(baitOnly.length).toBeGreaterThan(0);
  });

  it('the known bait package is not a real dependency of this repo', () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
    const declared = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    expect(declared.jsonwebtoken).toBeUndefined();
  });

  it('fixture files are classified as fixtures by our own filter', () => {
    // The consumer-side fix and this list agree with file-filter.js. If that
    // ever stops being true, a vendoring script following isTestFile would
    // start tracing bait again.
    const dir = join(SRC, 'lib/probes/v05/fixtures');
    if (!existsSync(dir) || !statSync(dir).isDirectory()) return;
    expect(FIXTURE_RE.test('lib/probes/v05/fixtures/JS-AUTH-001/negative.js')).toBe(true);
  });
});
