// Functional tests for the v0.5 wave-2 OWASP-framed probes in v05b.js.

import { describe, it, expect } from 'vitest';
import {
  probeSourceMapExposure,
  probeIframeSandbox,
  probeSecurityLogging,
  probeRAGIngestion,
  probeVectorEmbeddingWeaknesses,
} from '../lib/probes/v05b.js';

const file = (path, content) => ({ path, content });

describe('probeSourceMapExposure', () => {
  it('flags Vite config with build.sourcemap: true', () => {
    const f = probeSourceMapExposure([
      file('vite.config.js', 'export default { build: { sourcemap: true } };'),
    ]);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].cwe).toBe('CWE-540');
  });

  it('flags Next.js config with productionBrowserSourceMaps: true', () => {
    const f = probeSourceMapExposure([
      file('next.config.js', 'module.exports = { productionBrowserSourceMaps: true };'),
    ]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('flags JS file with sourceMappingURL comment', () => {
    // Use a non-dist path so the scanner-self-source exclusion doesn't skip it.
    const f = probeSourceMapExposure([
      file('static/bundle.js', 'console.log("hello");\n//# sourceMappingURL=bundle.js.map'),
    ]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('does NOT flag Vite config with sourcemap: false', () => {
    const f = probeSourceMapExposure([
      file('vite.config.js', 'export default { build: { sourcemap: false } };'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeSourceMapExposure([file('src/test/foo.test.js', 'build: { sourcemap: true }')]);
    expect(f).toEqual([]);
  });
});

describe('probeIframeSandbox', () => {
  it('flags cross-origin iframe without sandbox', () => {
    const f = probeIframeSandbox([
      file('index.html', '<iframe src="https://embed.example.com/widget"></iframe>'),
    ]);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('high');
    expect(f[0].cwe).toBe('CWE-1021');
  });

  it('flags same-origin iframe without sandbox at lower severity', () => {
    const f = probeIframeSandbox([file('index.html', '<iframe src="/preview"></iframe>')]);
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe('medium');
  });

  it('does NOT flag iframe WITH sandbox attribute', () => {
    const f = probeIframeSandbox([
      file(
        'index.html',
        '<iframe src="https://embed.example.com" sandbox="allow-scripts"></iframe>'
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag iframe with empty sandbox=""', () => {
    const f = probeIframeSandbox([
      file('index.html', '<iframe src="https://example.com" sandbox=""></iframe>'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeIframeSandbox([
      file('src/test/foo.test.js', '<iframe src="https://example.com"></iframe>'),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeSecurityLogging', () => {
  it('flags an auth/login handler with no logging anywhere in the file', () => {
    const f = probeSecurityLogging([
      file(
        'src/api/auth/login.js',
        `
        export async function POST(req) {
          const { email, password } = await req.json();
          const user = await db.users.findOne({ email });
          if (!user) return new Response('invalid', { status: 401 });
          const token = await signJwt({ sub: user.id });
          return new Response(JSON.stringify({ token }));
        }
      `
      ),
    ]);
    expect(f.length).toBe(1);
    expect(f[0].cwe).toBe('CWE-778');
  });

  it('does NOT flag an auth handler that uses log.info', () => {
    const f = probeSecurityLogging([
      file(
        'src/api/auth/login.js',
        `
        import { log } from '@/lib/logger';
        export async function POST(req) {
          const { email } = await req.json();
          log.info({ event: 'login.attempt', email });
          return new Response('ok');
        }
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  // FP triage 2026-07: audit logging is a server-side control. A CLI's auth
  // config matching the path heuristic is not a missing-audit-log finding.
  it('does NOT flag an auth-named file with no server handler in it', () => {
    const f = probeSecurityLogging([
      file(
        'packages/cli/src/config/auth.ts',
        `
        export const AUTH_MODES = ['oauth', 'api-key'];
        export function resolveAuthMode(settings) {
          if (settings.apiKey) return 'api-key';
          return 'oauth';
        }
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('flags a DELETE handler with no logging even outside auth paths', () => {
    const f = probeSecurityLogging([
      file(
        'src/api/users/[id]/route.js',
        `
        export async function DELETE(req, { params }) {
          await db.users.delete({ where: { id: params.id } });
          return new Response(null, { status: 204 });
        }
      `
      ),
    ]);
    expect(f.length).toBe(1);
  });

  it('does NOT flag a non-security file with no logging', () => {
    const f = probeSecurityLogging([
      file('src/components/Button.jsx', 'export function Button() { return <button/>; }'),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeSecurityLogging([
      file(
        'src/test/auth.test.js',
        'export async function POST(req) { return new Response("ok"); }'
      ),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeRAGIngestion', () => {
  it('flags openai.embeddings.create with user-supplied input', () => {
    const f = probeRAGIngestion([
      file(
        'src/api/ingest.js',
        `
        const userDoc = await req.formData().then(f => f.get('file').text());
        const result = await openai.embeddings.create({ input: userDoc, model: 'text-embedding-3-large' });
      `
      ),
    ]);
    expect(f.length).toBe(1);
    expect(f[0].cwe).toBe('CWE-1395');
  });

  it('flags pinecone.upsert with user-supplied content', () => {
    const f = probeRAGIngestion([
      file(
        'src/api/ingest.js',
        `
        const content = req.body.text;
        await pinecone.upsert({ vectors: [{ id: 'x', values: emb, metadata: { text: content } }] });
      `
      ),
    ]);
    expect(f.length).toBe(1);
  });

  it('does NOT flag embeddings.create when sanitize is visible nearby', () => {
    const f = probeRAGIngestion([
      file(
        'src/api/ingest.js',
        `
        const userDoc = await req.formData().then(f => f.get('file').text());
        const clean = sanitizeDocument(userDoc);
        const result = await openai.embeddings.create({ input: clean });
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeRAGIngestion([
      file(
        'src/test/ingest.test.js',
        'const r = await openai.embeddings.create({ input: req.body.x });'
      ),
    ]);
    expect(f).toEqual([]);
  });
});

describe('probeVectorEmbeddingWeaknesses', () => {
  it('flags pinecone.query with no namespace or tenant scope', () => {
    const f = probeVectorEmbeddingWeaknesses([
      file(
        'src/api/search.js',
        `
        const queryEmbedding = await embed(query);
        const results = await pinecone.query({ vector: queryEmbedding, topK: 5 });
        return Response.json({ results });
      `
      ),
    ]);
    expect(f.length).toBe(1);
    expect(f[0].cwe).toBe('CWE-200');
  });

  it('does NOT flag pinecone.query with namespace scope', () => {
    const f = probeVectorEmbeddingWeaknesses([
      file(
        'src/api/search.js',
        `
        const tenantId = req.user.tenantId;
        const results = await pinecone.query({ namespace: tenantId, vector: emb, topK: 5 });
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag vector query with filter on tenantId', () => {
    const f = probeVectorEmbeddingWeaknesses([
      file(
        'src/api/search.js',
        `
        const results = await qdrant.search('docs', {
          vector: emb,
          filter: { must: [{ key: 'tenantId', match: { value: tenantId } }] },
        });
      `
      ),
    ]);
    expect(f).toEqual([]);
  });

  it('does NOT flag in test files', () => {
    const f = probeVectorEmbeddingWeaknesses([
      file('src/test/search.test.js', 'await pinecone.query({ vector: e, topK: 5 });'),
    ]);
    expect(f).toEqual([]);
  });
});
