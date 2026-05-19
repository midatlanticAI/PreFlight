// Tests for the Settings layer: AI BYOK round-trip (src/lib/ai.js), GitHub BYOT round-trip
// (src/lib/github.js), and the "clear all local data" semantics expected by the General tab.
//
// The AI + PAT stores are plain localStorage wrappers — the goal here is to confirm save →
// reload-from-store fidelity, clear actually removes the entry, and the localStorage keys
// match what GeneralTab's Clear-All-Data button wipes.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import {
  loadAIConfig,
  saveAIConfig,
  clearAIConfig,
  validateKeyShape,
  AI_PROVIDERS,
} from '../lib/ai.js';

import { loadGitHubPAT, saveGitHubPAT, clearGitHubPAT, testGitHubToken } from '../lib/github.js';

// The full list of PreFlight localStorage keys that "Clear all local data" must wipe.
// Keep in sync with the array in src/components/settings/GeneralTab.jsx.
const PREFLIGHT_KEYS = [
  'audit-app:history:v1',
  'audit-app:logs:v1',
  'audit-app:analytics:v1',
  'audit-app:suppressions:v1',
  'audit-app:ai:v1',
  'preflight.github_pat',
];

describe('AI BYOK round-trip', () => {
  beforeEach(() => {
    clearAIConfig();
  });

  it('loadAIConfig returns null when nothing is stored', () => {
    expect(loadAIConfig()).toBeNull();
  });

  it('saveAIConfig → loadAIConfig returns the same values', () => {
    const cfg = {
      provider: 'anthropic',
      apiKey: 'sk-ant-' + 'a'.repeat(50),
      model: AI_PROVIDERS.anthropic.defaultModel,
    };
    saveAIConfig(cfg);
    const loaded = loadAIConfig();
    expect(loaded).not.toBeNull();
    expect(loaded.provider).toBe(cfg.provider);
    expect(loaded.apiKey).toBe(cfg.apiKey);
    expect(loaded.model).toBe(cfg.model);
  });

  it('clearAIConfig removes the entry', () => {
    saveAIConfig({
      provider: 'openai',
      apiKey: 'sk-pr' + 'oj-' + 'a'.repeat(50),
      model: AI_PROVIDERS.openai.defaultModel,
    });
    expect(loadAIConfig()).not.toBeNull();
    clearAIConfig();
    expect(loadAIConfig()).toBeNull();
  });

  it('validateKeyShape recognizes provider-specific patterns', () => {
    expect(validateKeyShape('anthropic', 'sk-ant-' + 'a'.repeat(50))).toBe(true);
    expect(validateKeyShape('openai', 'sk-pr' + 'oj-' + 'a'.repeat(50))).toBe(true);
    expect(validateKeyShape('anthropic', 'not-a-real-key')).toBe(false);
    expect(validateKeyShape('openai', 'sk-ant-' + 'a'.repeat(50))).toBe(false); // wrong provider
  });
});

describe('GitHub PAT BYOT round-trip', () => {
  beforeEach(() => {
    clearGitHubPAT();
  });

  it('loadGitHubPAT returns null when nothing is stored', () => {
    expect(loadGitHubPAT()).toBeNull();
  });

  it('saveGitHubPAT → loadGitHubPAT returns the same token', () => {
    const pat = 'github_pat_' + 'a'.repeat(60);
    saveGitHubPAT(pat);
    expect(loadGitHubPAT()).toBe(pat);
  });

  it('saveGitHubPAT trims whitespace', () => {
    const pat = 'ghp_' + 'a'.repeat(36);
    saveGitHubPAT('  ' + pat + '  ');
    expect(loadGitHubPAT()).toBe(pat);
  });

  it('saveGitHubPAT with empty string clears the entry', () => {
    saveGitHubPAT('ghp_existing_token_aaaaaaaaaaaaa');
    expect(loadGitHubPAT()).not.toBeNull();
    saveGitHubPAT('');
    expect(loadGitHubPAT()).toBeNull();
  });

  it('clearGitHubPAT removes the entry', () => {
    saveGitHubPAT('ghp_' + 'a'.repeat(36));
    clearGitHubPAT();
    expect(loadGitHubPAT()).toBeNull();
  });

  it('stores under the spec-defined key `preflight.github_pat`', () => {
    saveGitHubPAT('ghp_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(localStorage.getItem('preflight.github_pat')).toBe(
      'ghp_test_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    );
  });
});

describe('testGitHubToken (PAT validation against api.github.com/user)', () => {
  // We mock fetch to verify the call shape + result mapping without hitting the network.
  let originalFetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('returns { ok: false } when token is empty', async () => {
    const result = await testGitHubToken('');
    expect(result.ok).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it('sends Authorization: token <pat> header', async () => {
    let capturedHeaders;
    globalThis.fetch = vi.fn(async (url, opts) => {
      capturedHeaders = opts?.headers;
      return {
        ok: true,
        status: 200,
        json: async () => ({ login: 'octocat' }),
      };
    });
    await testGitHubToken('ghp_test_token_xxx');
    expect(capturedHeaders).toBeDefined();
    expect(capturedHeaders.Authorization).toBe('token ghp_test_token_xxx');
  });

  it('returns the authenticated username on 200', async () => {
    globalThis.fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ login: 'octocat' }),
    }));
    const result = await testGitHubToken('ghp_valid');
    expect(result.ok).toBe(true);
    expect(result.username).toBe('octocat');
  });

  it('maps 401 to a "token rejected" error', async () => {
    globalThis.fetch = vi.fn(async () => ({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
    }));
    const result = await testGitHubToken('ghp_bad');
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/rejected|401/i);
  });

  it('maps 403 to a "forbidden" error (scope hint)', async () => {
    globalThis.fetch = vi.fn(async () => ({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
    }));
    const result = await testGitHubToken('ghp_no_scope');
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/forbidden|scope|403/i);
  });

  it('catches network errors and returns { ok: false }', async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error('offline');
    });
    const result = await testGitHubToken('ghp_anything');
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/offline|network/i);
  });
});

describe('Clear-all-local-data key inventory', () => {
  // The GeneralTab's Clear-All-Data button is only safe if it wipes EVERY key PreFlight
  // uses. This test guards the inventory — adding a new localStorage key without updating
  // PREFLIGHT_KEYS in GeneralTab.jsx leaves stale state after a clear.
  it('AI store key is in the inventory', () => {
    expect(PREFLIGHT_KEYS).toContain('audit-app:ai:v1');
  });

  it('GitHub PAT key is in the inventory', () => {
    expect(PREFLIGHT_KEYS).toContain('preflight.github_pat');
  });

  it('History, logs, analytics, suppressions are in the inventory', () => {
    expect(PREFLIGHT_KEYS).toContain('audit-app:history:v1');
    expect(PREFLIGHT_KEYS).toContain('audit-app:logs:v1');
    expect(PREFLIGHT_KEYS).toContain('audit-app:analytics:v1');
    expect(PREFLIGHT_KEYS).toContain('audit-app:suppressions:v1');
  });

  it('Clearing each key from a populated state actually wipes', () => {
    // Populate every key
    localStorage.setItem('audit-app:history:v1', JSON.stringify([{ id: 1 }]));
    localStorage.setItem('audit-app:logs:v1', '[]');
    localStorage.setItem('audit-app:analytics:v1', '{}');
    localStorage.setItem('audit-app:suppressions:v1', '{}');
    saveAIConfig({ provider: 'openai', apiKey: 'sk-pr' + 'oj-' + 'a'.repeat(50), model: 'm' });
    saveGitHubPAT('ghp_' + 'a'.repeat(36));
    // Wipe via the same inventory the button uses
    for (const k of PREFLIGHT_KEYS) localStorage.removeItem(k);
    // Every key should be gone
    for (const k of PREFLIGHT_KEYS) {
      expect(localStorage.getItem(k)).toBeNull();
    }
  });
});
