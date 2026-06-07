/**
 * Regression suite for the May 2026 emailassist scan-coverage gap.
 *
 * The OTHER half of the emailassist miss (beyond the req.url taint blind spot):
 * PreFlight ingested only 5 frontend files because the user uploaded the PWA
 * frontend folder. server.js was the backend entry point per package.json
 * `scripts.start`, but never made it into the scan set. PreFlight finished
 * scanning with a clean 85/100 and gave the user no signal that the most
 * security-sensitive file was unscanned.
 *
 * This suite pins the proactive surfacing: when package.json references a
 * file via `main`, `scripts.start`, `scripts.dev`, `scripts.serve`, or
 * `scripts.server` and that file is NOT in the scan set, fire HIGH.
 */

import { describe, it, expect } from 'vitest';
import { probePackageJson } from '../lib/probes.js';

const f = (path, content) => ({ path, content });

describe('emailassist gap — package.json entry not in scan set', () => {
  it('canonical emailassist shape: scripts.start = node server.js, server.js absent -> fires', () => {
    const findings = probePackageJson([
      f(
        'package.json',
        JSON.stringify({ name: 'emailassist', scripts: { start: 'node server.js' } })
      ),
      f('index.html', '<!doctype html><html></html>'),
      f('app.js', 'console.log("client")'),
      f('sw.js', 'self.addEventListener("install", () => {});'),
      f('manifest.json', JSON.stringify({ name: 'X', display: 'standalone' })),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    const coverageFinding = findings.find((x) =>
      /Entry point referenced in package\.json/.test(x.title)
    );
    expect(coverageFinding).toBeTruthy();
    expect(coverageFinding.severity).toBe('high');
    expect(coverageFinding.evidence).toContain('server.js');
  });

  it('server.js IS in scan set -> does not fire', () => {
    const findings = probePackageJson([
      f('package.json', JSON.stringify({ name: 'app', scripts: { start: 'node server.js' } })),
      f('server.js', 'require("http").createServer().listen(3000);'),
    ]);
    const coverageFinding = findings.find((x) =>
      /Entry point referenced in package\.json/.test(x.title)
    );
    expect(coverageFinding).toBeFalsy();
  });

  it('main field referenced + file absent -> fires', () => {
    const findings = probePackageJson([
      f('package.json', JSON.stringify({ name: 'lib', main: 'dist/index.js' })),
    ]);
    const coverageFinding = findings.find((x) =>
      /Entry point referenced in package\.json/.test(x.title)
    );
    expect(coverageFinding).toBeTruthy();
  });

  it('TypeScript entry via ts-node -> fires', () => {
    const findings = probePackageJson([
      f('package.json', JSON.stringify({ scripts: { dev: 'ts-node src/server.ts' } })),
    ]);
    const coverageFinding = findings.find((x) =>
      /Entry point referenced in package\.json/.test(x.title)
    );
    expect(coverageFinding).toBeTruthy();
  });

  it('nodemon entry -> fires', () => {
    const findings = probePackageJson([
      f('package.json', JSON.stringify({ scripts: { dev: 'nodemon --watch src api/index.js' } })),
    ]);
    const coverageFinding = findings.find((x) =>
      /Entry point referenced in package\.json/.test(x.title)
    );
    expect(coverageFinding).toBeTruthy();
  });

  it('framework command (vite, next) with no file ref -> does not fire', () => {
    // `vite` / `next dev` / `astro dev` are framework commands, not file paths.
    // The regex extracts a literal .js / .ts / .mjs / .cjs token; a bare
    // framework command has none, so no finding.
    const findings1 = probePackageJson([
      f('package.json', JSON.stringify({ scripts: { dev: 'vite' } })),
    ]);
    expect(findings1.find((x) => /Entry point referenced/.test(x.title))).toBeFalsy();

    const findings2 = probePackageJson([
      f('package.json', JSON.stringify({ scripts: { dev: 'next dev' } })),
    ]);
    expect(findings2.find((x) => /Entry point referenced/.test(x.title))).toBeFalsy();
  });

  it('relative path resolution: ./server.js -> server.js -> does not fire', () => {
    const findings = probePackageJson([
      f('package.json', JSON.stringify({ scripts: { start: 'node ./server.js' } })),
      f('server.js', '// server'),
    ]);
    expect(findings.find((x) => /Entry point referenced/.test(x.title))).toBeFalsy();
  });

  it('monorepo: package.json under apps/api/, server.js under apps/api/server.js', () => {
    const findings = probePackageJson([
      f('apps/api/package.json', JSON.stringify({ scripts: { start: 'node server.js' } })),
      f('apps/api/server.js', '// api server'),
    ]);
    // Should resolve relative to package.json's directory.
    expect(findings.find((x) => /Entry point referenced/.test(x.title))).toBeFalsy();
  });

  it('monorepo: server.js absent under apps/api/ -> fires', () => {
    const findings = probePackageJson([
      f('apps/api/package.json', JSON.stringify({ scripts: { start: 'node server.js' } })),
    ]);
    expect(findings.find((x) => /Entry point referenced/.test(x.title))).toBeTruthy();
  });
});
