// Taint engine: module-alias resolution and the outbound-request sink.
// Verified round 2026-07.
//
// The engine already propagated taint one hop through a variable. What it
// lacked was (a) any outbound-request sink, so `fetch(u)` was not a sink at
// all, and (b) alias resolution, so its shell sink only matched a literal
// `child_process.exec(...)` spelling that real code almost never uses.
import { describe, it, expect } from 'vitest';
import { probeTaintFlow } from '../lib/probes.js';

const run = (content, path = 'src/api/route.js') => probeTaintFlow([{ path, content }]);
const ssrf = (c, p) => run(c, p).filter((f) => /Outbound request/i.test(f.title));
const shell = (c, p) => run(c, p).filter((f) => /Shell command/i.test(f.title));

describe('one-hop taint into an outbound request', () => {
  it('flags a request value passed through a variable into fetch', () => {
    const src = [
      'export function handler(req) {',
      '  const u = req.query.url;',
      '  return fetch(u);',
      '}',
    ].join('\n');
    expect(ssrf(src).length).toBeGreaterThan(0);
  });

  it('flags the direct form too', () => {
    expect(ssrf('export function h(req) { return fetch(req.query.url); }').length).toBeGreaterThan(
      0
    );
  });

  it('names both ends of the flow in the evidence', () => {
    const src = [
      'export function h(req) {',
      '  const u = req.body.target;',
      '  return fetch(u);',
      '}',
    ].join('\n');
    const f = ssrf(src)[0];
    expect(f.evidence).toMatch(/req\.body\.target/);
    expect(f.cwe).toBe('CWE-918');
  });

  it.each([
    ['axios.get', 'const u = req.query.url; axios.get(u);'],
    ['got.post', 'const u = req.query.url; got.post(u);'],
    ['http.request', 'const u = req.query.url; http.request(u);'],
  ])('flags %s', (_label, body) => {
    expect(ssrf(`export function h(req) { ${body} }`).length).toBeGreaterThan(0);
  });

  it('does not flag a fetch of a hardcoded URL', () => {
    expect(ssrf('export function h(req) { return fetch("https://api.example.com/v1"); }')).toEqual(
      []
    );
  });

  it('does not flag a local variable that never touched the request', () => {
    const src = [
      'export function h(req) {',
      '  const u = "https://api.example.com";',
      '  return fetch(u);',
      '}',
    ].join('\n');
    expect(ssrf(src)).toEqual([]);
  });
});

describe('module alias resolution into the shell sink', () => {
  it('flags the canonical dotted spelling', () => {
    const src = [
      "const child_process = require('child_process');",
      'export function h(req) { child_process.exec(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags a namespaced require alias', () => {
    const src = [
      "const cp = require('child_process');",
      'export function h(req) { cp.exec(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags a destructured require', () => {
    const src = [
      "const { exec } = require('child_process');",
      'export function h(req) { exec(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags a destructured require with renaming', () => {
    const src = [
      "const { exec: runIt } = require('child_process');",
      'export function h(req) { runIt(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags an ESM named import', () => {
    const src = [
      "import { exec } from 'child_process';",
      'export function h(req) { exec(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags the node: prefixed module specifier', () => {
    const src = [
      "import { execSync } from 'node:child_process';",
      'export function h(req) { execSync(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags an ESM namespace import', () => {
    const src = [
      "import * as cp from 'child_process';",
      'export function h(req) { cp.spawn(req.query.cmd); }',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('flags through one hop as well as directly', () => {
    const src = [
      "const { exec } = require('child_process');",
      'export function h(req) {',
      '  const cmd = req.body.cmd;',
      '  exec(cmd);',
      '}',
    ].join('\n');
    expect(shell(src).length).toBeGreaterThan(0);
  });

  it('does not flag an unrelated local function that shares the name', () => {
    const src = [
      'function exec(safeValue) { return safeValue; }',
      'export function h(req) { exec(req.query.cmd); }',
    ].join('\n');
    expect(shell(src)).toEqual([]);
  });

  it('does not flag a shell call with a hardcoded command', () => {
    const src = [
      "const { exec } = require('child_process');",
      'export function h() { exec("ls -la"); }',
    ].join('\n');
    expect(shell(src)).toEqual([]);
  });

  it('does not resolve an alias from a different module', () => {
    const src = [
      "const { exec } = require('./my-local-helpers');",
      'export function h(req) { exec(req.query.cmd); }',
    ].join('\n');
    expect(shell(src)).toEqual([]);
  });
});
