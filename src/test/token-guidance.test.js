// Token shape advisor. The guidance UI renders whatever this returns, so the
// classification is pinned here rather than in a component test.
import { describe, it, expect } from 'vitest';
import { classifyGitHubToken } from '../lib/github.js';

describe('classifyGitHubToken', () => {
  it('recognises a fine-grained token', () => {
    const r = classifyGitHubToken('github_pat_11ABCDEFG0abcdefghijkl_ZZZ');
    expect(r.kind).toBe('fine-grained');
    expect(r.tone).toBe('ok');
    expect(r.advice).toMatch(/read-only/i);
  });

  it.each(['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_'])(
    'recognises the classic family prefix %s',
    (prefix) => {
      const r = classifyGitHubToken(`${prefix}0123456789abcdefghijklmnopqrstuvwxyz`);
      expect(r.kind).toBe('classic');
      expect(r.tone).toBe('warn');
    }
  );

  it('warns that a classic token reaches every repo the account can see', () => {
    const r = classifyGitHubToken('ghp_0123456789abcdefghijklmnopqrstuvwxyz');
    expect(r.advice).toMatch(/every repository/i);
    expect(r.advice).toMatch(/fine-grained/i);
  });

  it('treats an unrecognised prefix as unknown rather than guessing', () => {
    const r = classifyGitHubToken('not-a-github-token');
    expect(r.kind).toBe('unknown');
    expect(r.advice).toMatch(/does not look like/i);
  });

  it('returns empty with no advice for blank input', () => {
    for (const v of ['', '   ', null, undefined, 42, {}]) {
      const r = classifyGitHubToken(v);
      expect(r.kind).toBe('empty');
      expect(r.advice).toBe('');
    }
  });

  it('ignores surrounding whitespace from a paste', () => {
    expect(classifyGitHubToken('  github_pat_abc  ').kind).toBe('fine-grained');
  });

  it('is pure: never reads or writes storage', () => {
    // Calling it must not throw even where localStorage does not exist, which
    // is also what makes it safe to call on every keystroke.
    expect(() => classifyGitHubToken('ghp_x')).not.toThrow();
  });
});
