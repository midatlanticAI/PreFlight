/**
 * Depth regression suite for probeSSRFOpenRedirect.
 *
 * Same shape as the May 2026 emailassist gap for probePathTraversal: the
 * probe's category was right, the input-source enumeration was incomplete.
 * Originally tracked: req.body / req.query / req.params and three HTTP
 * clients (fetch / axios / node:http). Real production Node code uses far
 * more for both the source side AND the client side. This file pins each
 * idiom so the depth list cannot silently shrink.
 */

import { describe, it, expect } from 'vitest';
import { probeSSRFOpenRedirect } from '../lib/probes.js';

const file = (path, content) => ({ path, content });

describe('probeSSRFOpenRedirect — input-source idioms', () => {
  it('req.url -> fetch fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await fetch(req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.originalUrl -> axios.get fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/handler.js', 'const r = await axios.get(req.originalUrl);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.path -> got fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/handler.js', 'const r = await got(req.path);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.headers.host -> fetch fires (Host-header SSRF)', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await fetch(req.headers.host);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.headers.referer -> https.get fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'https.get(req.headers.referer, (res) => {});'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('Koa ctx.url -> fetch fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/koa.js', 'const r = await fetch(ctx.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('CF Worker c.req.url -> fetch fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/worker.ts', 'const r = await fetch(c.req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('Lambda event.body -> fetch fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/lambda.js', 'const r = await fetch(event.body);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('Lambda event.queryStringParameters.url -> fetch fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/lambda.js', 'const r = await fetch(event.queryStringParameters.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('probeSSRFOpenRedirect — HTTP client family', () => {
  it('node-fetch -> fires on req.url', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await fetch(req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('undici.fetch -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await undici.fetch(req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('undici.request -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await undici.request(req.body.target);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('superagent.get -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await superagent.get(req.body.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('phin -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await phin(req.query.target);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('ky.get -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await ky.get(req.params.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('https.request -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'https.request(req.body.target, (res) => {});'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('https.get -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'https.get(req.url, (res) => {});'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('request(...) -> fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'request(req.body.target, callback);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('probeSSRFOpenRedirect — open redirect, framework redirects', () => {
  it('res.redirect(req.url) fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'res.redirect(req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('NextResponse.redirect(req.url) fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('app/api/r/route.ts', 'return NextResponse.redirect(req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('Response.redirect(req.url) fires (Web Fetch API)', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/edge.ts', 'return Response.redirect(req.url);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('Location-header write via res.setHeader fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'res.setHeader("Location", req.query.next);'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('searchParams.get("next") -> res.redirect fires', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'res.redirect(searchParams.get("next"));'),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});

describe('probeSSRFOpenRedirect — negatives, must NOT fire', () => {
  it('fetch with a literal URL does not fire', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await fetch("https://api.example.com/v1");'),
    ]);
    expect(findings.filter((f) => f.probe === 'SSRF').length).toBe(0);
  });

  it('axios.get with an env-loaded URL does not fire', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'const r = await axios.get(process.env.UPSTREAM_URL);'),
    ]);
    expect(findings.filter((f) => f.probe === 'SSRF').length).toBe(0);
  });

  it('res.redirect with a literal path does not fire', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/server.js', 'res.redirect("/login");'),
    ]);
    expect(findings.filter((f) => f.probe === 'Open Redirect').length).toBe(0);
  });

  it('test file path does not fire (probe is scope-filtered)', () => {
    const findings = probeSSRFOpenRedirect([
      file('src/test/handler.test.js', 'const r = await fetch(req.url);'),
    ]);
    expect(findings.length).toBe(0);
  });
});
