// Tests for src/lib/github.js — specifically that fetchGitHubRepo() attaches the
// Authorization header when a PAT is saved, and behaves unauthenticated otherwise.
// The PAT storage helpers themselves are covered in settings.test.js; here we verify
// the load-time read + header injection inside the fetch call.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { fetchGitHubRepo, saveGitHubPAT, clearGitHubPAT } from '../lib/github.js';

describe('fetchGitHubRepo Authorization header', () => {
  let originalFetch;
  let capturedRequests;

  beforeEach(() => {
    capturedRequests = [];
    originalFetch = globalThis.fetch;
    clearGitHubPAT();
    // Mock fetch to capture every call's URL + headers, and return canned responses.
    globalThis.fetch = vi.fn(async (url, opts) => {
      capturedRequests.push({ url, headers: opts?.headers || {} });
      // /repos/:owner/:repo — repo metadata. Default fixture is PUBLIC so blob fetches
      // route through raw.githubusercontent.com (the CDN-fast path). Match the exact
      // shape so /contents/ and /git/trees/ URLs fall through to their own handlers.
      if (/\/repos\/[^/]+\/[^/]+$/.test(url)) {
        return {
          ok: true,
          status: 200,
          headers: new Map(),
          json: async () => ({ default_branch: 'main', private: false }),
        };
      }
      // /git/trees/main?recursive=1 — repo tree
      if (url.includes('/git/trees/')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            tree: [
              {
                path: 'package.json',
                type: 'blob',
                size: 100,
              },
            ],
            truncated: false,
          }),
        };
      }
      // raw.githubusercontent.com — blob content
      if (url.includes('raw.githubusercontent.com')) {
        return {
          ok: true,
          status: 200,
          text: async () => '{"name":"test"}',
        };
      }
      return { ok: false, status: 404, statusText: 'Not Found' };
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    clearGitHubPAT();
  });

  it('sends NO Authorization header when no PAT is stored (public repo path)', async () => {
    await fetchGitHubRepo('https://github.com/octocat/Hello-World');
    expect(capturedRequests.length).toBeGreaterThan(0);
    for (const req of capturedRequests) {
      // Either no Authorization key at all, or an empty headers object.
      expect(req.headers.Authorization).toBeUndefined();
    }
  });

  it('attaches Authorization: token <pat> on every request when PAT is stored', async () => {
    const pat = 'ghp_test_token_aaaaaaaaaaaaaaaaaaaaaaa';
    saveGitHubPAT(pat);

    await fetchGitHubRepo('https://github.com/octocat/private-repo');

    expect(capturedRequests.length).toBeGreaterThan(0);
    for (const req of capturedRequests) {
      expect(req.headers.Authorization).toBe(`token ${pat}`);
    }
  });

  it('attaches the header on api.github.com AND raw.githubusercontent.com', async () => {
    const pat = 'github_pat_' + 'a'.repeat(60);
    saveGitHubPAT(pat);

    await fetchGitHubRepo('https://github.com/octocat/something');

    const apiCalls = capturedRequests.filter((r) => r.url.includes('api.github.com'));
    const rawCalls = capturedRequests.filter((r) => r.url.includes('raw.githubusercontent.com'));

    expect(apiCalls.length).toBeGreaterThan(0);
    expect(rawCalls.length).toBeGreaterThan(0);

    apiCalls.forEach((req) => expect(req.headers.Authorization).toBe(`token ${pat}`));
    rawCalls.forEach((req) => expect(req.headers.Authorization).toBe(`token ${pat}`));
  });

  it('uses the freshly-saved PAT, not a stale one cached at module load', async () => {
    // Saving a PAT mid-test should change the subsequent fetch call's header.
    const firstPat = 'ghp_first' + 'a'.repeat(28);
    saveGitHubPAT(firstPat);
    await fetchGitHubRepo('https://github.com/octocat/one');
    const firstCall = capturedRequests[0];
    expect(firstCall.headers.Authorization).toBe(`token ${firstPat}`);

    capturedRequests = [];
    const secondPat = 'ghp_second' + 'a'.repeat(28);
    saveGitHubPAT(secondPat);
    await fetchGitHubRepo('https://github.com/octocat/two');
    const secondCall = capturedRequests[0];
    expect(secondCall.headers.Authorization).toBe(`token ${secondPat}`);
  });
});

describe('fetchGitHubRepo private-repo blob path', () => {
  // Regression test for the v0.6 fix: raw.githubusercontent.com ignores Authorization
  // headers for private-repo blobs, so private repos must route through the api.github.com
  // contents endpoint with `Accept: application/vnd.github.raw`.
  let originalFetch;
  let capturedRequests;

  beforeEach(() => {
    capturedRequests = [];
    originalFetch = globalThis.fetch;
    saveGitHubPAT('ghp_private_' + 'a'.repeat(30));
    globalThis.fetch = vi.fn(async (url, opts) => {
      capturedRequests.push({ url, headers: opts?.headers || {} });
      if (/\/repos\/[^/]+\/[^/]+$/.test(url)) {
        return {
          ok: true,
          status: 200,
          headers: new Map(),
          json: async () => ({ default_branch: 'main', private: true }),
        };
      }
      if (url.includes('/git/trees/')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            tree: [{ path: 'package.json', type: 'blob', size: 100 }],
            truncated: false,
          }),
        };
      }
      if (url.includes('/contents/')) {
        return { ok: true, status: 200, text: async () => '{"name":"secret"}' };
      }
      return { ok: false, status: 404, statusText: 'Not Found' };
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    clearGitHubPAT();
  });

  it('routes private-repo blob fetches through api.github.com/contents, not raw.githubusercontent.com', async () => {
    const files = await fetchGitHubRepo('https://github.com/acme/secret-repo');

    expect(files).toHaveLength(1);
    expect(files[0].path).toBe('package.json');
    expect(files[0].content).toBe('{"name":"secret"}');

    const rawCalls = capturedRequests.filter((r) => r.url.includes('raw.githubusercontent.com'));
    const contentsCalls = capturedRequests.filter((r) => r.url.includes('/contents/'));
    expect(rawCalls).toHaveLength(0);
    expect(contentsCalls).toHaveLength(1);
  });

  it('sends Accept: application/vnd.github.raw on the contents call', async () => {
    await fetchGitHubRepo('https://github.com/acme/secret-repo');
    const contentsCall = capturedRequests.find((r) => r.url.includes('/contents/'));
    expect(contentsCall).toBeDefined();
    expect(contentsCall.headers.Accept).toBe('application/vnd.github.raw');
    expect(contentsCall.headers.Authorization).toMatch(/^token ghp_private_/);
  });
});

describe('fetchGitHubRepo error messages mention BYOT in v0.4', () => {
  let originalFetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
    clearGitHubPAT();
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('404 unauthenticated → error suggests pasting a PAT', async () => {
    globalThis.fetch = vi.fn(async () => ({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: new Map(),
    }));
    let err;
    try {
      await fetchGitHubRepo('https://github.com/octocat/private');
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toMatch(/private|PAT|token|Personal Access Token/i);
  });

  it('404 authenticated → error suggests scope check', async () => {
    saveGitHubPAT('ghp_' + 'a'.repeat(36));
    globalThis.fetch = vi.fn(async () => ({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      headers: new Map(),
    }));
    let err;
    try {
      await fetchGitHubRepo('https://github.com/octocat/private');
    } catch (e) {
      err = e;
    }
    expect(err).toBeDefined();
    expect(err.message).toMatch(/scope|token|access/i);
  });
});
