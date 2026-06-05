/**
 * Regression suite for the May 2026 emailassist field-tech PWA gap report.
 *
 * The miss: PreFlight scored 85/100 while server.js had a public unauthenticated
 * arbitrary file read. The probe DID run — `path.join` was matched — but the
 * `USER_INPUT_TOKEN_RE` alternation was missing `req.url`, the single most
 * fundamental request-derived value on a raw Node http.createServer handler.
 *
 * This file pins the fix shape so the gap cannot silently reopen. Every test
 * here asserts probePathTraversal fires on a req.url-shaped taint, AND a
 * paired test asserts a sanitizer in the ±3-line window correctly suppresses.
 */

import { describe, it, expect } from 'vitest';
import { probePathTraversal } from '../lib/probes.js';
import { probeRAGIngestion } from '../lib/probes.js';

const file = (path, content) => ({ path, content });

describe('emailassist gap — probePathTraversal must detect req.url -> path.join -> fs.readFile', () => {
  it('canonical emailassist server.js shape -> fires', () => {
    const findings = probePathTraversal([
      file(
        'server.js',
        `
const http = require('http');
const path = require('path');
const fs = require('fs');
http.createServer((req, res) => {
  let filePath = req.url === '/' ? '/index.html' : req.url;
  filePath = path.join(__dirname, filePath);
  fs.readFile(filePath, (err, data) => { res.end(data); });
}).listen(3000);
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.cwe === 'CWE-22' || /traversal/i.test(f.title || ''))).toBe(true);
  });

  it('Express req.url variant -> fires', () => {
    const findings = probePathTraversal([
      file(
        'src/routes/files.js',
        `
app.get('/files/*', (req, res) => {
  const full = path.join(STATIC_ROOT, req.url);
  fs.createReadStream(full).pipe(res);
});
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.originalUrl variant -> fires', () => {
    const findings = probePathTraversal([
      file(
        'src/handler.js',
        `
function serve(req, res) {
  const target = path.resolve(ROOT, req.originalUrl);
  fs.readFileSync(target);
}
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('req.path variant -> fires', () => {
    const findings = probePathTraversal([
      file(
        'src/handler.js',
        `
app.get('/static', (req, res) => {
  fs.readFile(path.join(BASE, req.path), cb);
});
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('Koa ctx.url variant -> fires', () => {
    const findings = probePathTraversal([
      file(
        'src/koa.js',
        `
router.get('/serve', async (ctx) => {
  const f = path.join(__dirname, ctx.url);
  ctx.body = await fsp.readFile(f);
});
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('SAFE: req.url with path.normalize + root-confine check -> SUPPRESSED', () => {
    // The actual emailassist fix shape: decode + normalize + resolve + confine
    // before fs.readFile. SAFE_NORMALIZE_RE catches `path.normalize`.
    const findings = probePathTraversal([
      file(
        'server.js',
        `
http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost').pathname;
  const safePath = path.normalize(url);
  const full = path.resolve(ROOT, '.' + safePath);
  if (!full.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(full, (err, data) => res.end(data));
}).listen(3000);
`
      ),
    ]);
    expect(findings.length).toBe(0);
  });

  it('SAFE: req.url + sanitize() helper in window -> SUPPRESSED', () => {
    const findings = probePathTraversal([
      file(
        'server.js',
        `
http.createServer((req, res) => {
  const safe = sanitizePath(req.url);
  fs.readFile(path.join(ROOT, safe), (e, d) => res.end(d));
});
`
      ),
    ]);
    expect(findings.length).toBe(0);
  });
});

describe('emailassist gap — same widening for probeRAGIngestion USER_INPUT_NEAR_RE', () => {
  it('req.url in RAG ingestion taint -> fires', () => {
    const findings = probeRAGIngestion([
      file(
        'src/rag/ingest.ts',
        `
app.post('/ingest', async (req, res) => {
  const doc = await fetch(req.url).then((r) => r.text());
  const embedding = await openai.embeddings.create({ input: doc, model: 'text-embedding-3-small' });
  await pinecone.upsert({ id: '1', values: embedding });
});
`
      ),
    ]);
    expect(findings.length).toBeGreaterThan(0);
  });
});
