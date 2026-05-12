// src/components/settings/PrivateReposTab.jsx
// BYOT — Bring Your Own Token. GitHub Personal Access Token stored in localStorage under
// `preflight.github_pat`. When present, src/lib/github.js attaches it as an
// `Authorization: token <pat>` header on every GitHub call, unlocking private repos and
// the 5000/hr authenticated rate limit.
//
// "Test token" calls api.github.com/user with the candidate token and reports the
// authenticated username on success, or the actual API error on failure. Pure check —
// the token isn't saved until the user clicks Save.

import { useState, useEffect } from 'react';
import { Check, Eye, EyeOff, Trash2, ExternalLink, Wifi } from 'lucide-react';
import { T, fontMono } from '../../lib/theme.js';
import { track } from '../../lib/analytics.js';
import { loadGitHubPAT, saveGitHubPAT, clearGitHubPAT, testGitHubToken } from '../../lib/github.js';

const COPY = `Pre-Flight scans public GitHub repos using unauthenticated API access (60 requests per hour, plenty for most scans). To scan a private repo, paste a GitHub Personal Access Token below. Same rules as the AI key: stored only in your browser, never sent to our server, deletable at any time.

The token only needs \`repo\` scope (read access to your repositories). Use a fine-grained PAT scoped to specific repos for tighter control. Pre-Flight will use this token automatically when you paste a GitHub URL for a private repo.`;

const PAT_DOCS_URL =
  'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens';

export function PrivateReposTab() {
  const [pat, setPat] = useState('');
  const [reveal, setReveal] = useState(false);
  const [status, setStatus] = useState(null);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    queueMicrotask(() => {
      const stored = loadGitHubPAT();
      if (stored) setPat(stored);
    });
  }, []);

  const handleSave = () => {
    if (!pat.trim()) {
      clearGitHubPAT();
      setStatus({ kind: 'ok', text: 'Token removed.' });
      track('github.pat.clear');
      return;
    }
    saveGitHubPAT(pat);
    track('github.pat.save');
    setStatus({
      kind: 'ok',
      text: 'Token saved. Private repo URLs will now use this token automatically.',
    });
  };

  const handleClear = () => {
    clearGitHubPAT();
    setPat('');
    setStatus({ kind: 'ok', text: 'Token removed.' });
    track('github.pat.clear');
  };

  const handleTest = async () => {
    if (!pat.trim()) {
      setStatus({ kind: 'err', text: 'Paste a token first.' });
      return;
    }
    setTesting(true);
    setStatus({ kind: 'info', text: 'Testing token…' });
    try {
      const result = await testGitHubToken(pat);
      if (result.ok) {
        setStatus({
          kind: 'ok',
          text: `Token valid. Authenticated as @${result.username}.`,
        });
      } else {
        setStatus({ kind: 'err', text: result.error });
      }
    } catch (e) {
      setStatus({ kind: 'err', text: e?.message || 'Test failed.' });
    } finally {
      setTesting(false);
    }
  };

  return (
    <section>
      <h2 className="ap-display" style={{ margin: '0 0 14px', fontSize: 22, color: T.text }}>
        Private Repos
      </h2>

      <div
        className="ap-card"
        style={{
          padding: 18,
          marginBottom: 18,
          background: T.bg,
          borderLeft: `3px solid ${T.accentAlt}`,
        }}
      >
        <div className="ap-eyebrow" style={{ marginBottom: 6, color: T.accentAlt }}>
          BYOT — BRING YOUR OWN TOKEN
        </div>
        <p
          style={{
            margin: 0,
            fontSize: 13,
            color: T.textDim,
            lineHeight: 1.7,
            whiteSpace: 'pre-line',
          }}
        >
          {COPY}
        </p>
      </div>

      <div className="ap-card" style={{ padding: 18 }}>
        <label
          htmlFor="github-pat"
          className="ap-eyebrow"
          style={{ display: 'block', marginBottom: 8, fontSize: 11, color: T.textMuted }}
        >
          GITHUB PERSONAL ACCESS TOKEN
        </label>
        <div style={{ position: 'relative', marginBottom: 12 }}>
          <input
            id="github-pat"
            type={reveal ? 'text' : 'password'}
            className="ap-input"
            placeholder="github_pat_… or ghp_…"
            value={pat}
            onChange={(e) => {
              setPat(e.target.value);
              setStatus(null);
            }}
            autoComplete="off"
            spellCheck={false}
            style={{ paddingRight: 70, fontFamily: fontMono, fontSize: 12 }}
          />
          <button
            type="button"
            onClick={() => setReveal((v) => !v)}
            aria-label={reveal ? 'Hide token' : 'Show token'}
            className="ap-mono"
            style={{
              position: 'absolute',
              right: 6,
              top: '50%',
              transform: 'translateY(-50%)',
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              cursor: 'pointer',
              fontSize: 10,
              padding: '4px 8px',
              minHeight: 24,
            }}
          >
            {reveal ? (
              <EyeOff size={11} aria-hidden="true" />
            ) : (
              <Eye size={11} aria-hidden="true" />
            )}
            <span style={{ marginLeft: 4 }}>{reveal ? 'hide' : 'show'}</span>
          </button>
        </div>

        <a
          href={PAT_DOCS_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="ap-mono"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            color: T.accent,
            fontSize: 12,
            marginBottom: 14,
          }}
        >
          How to create a GitHub Personal Access Token
          <ExternalLink size={10} aria-hidden="true" />
        </a>

        {status && (
          <div
            role="status"
            aria-live="polite"
            style={{
              padding: 10,
              marginBottom: 12,
              fontSize: 12,
              background:
                status.kind === 'ok'
                  ? T.sev.info.bg
                  : status.kind === 'err'
                    ? T.sev.critical.bg
                    : T.panelAlt,
              border: `1px solid ${
                status.kind === 'ok'
                  ? T.sev.info.border
                  : status.kind === 'err'
                    ? T.sev.critical.border
                    : T.border
              }`,
              color:
                status.kind === 'ok'
                  ? T.good
                  : status.kind === 'err'
                    ? T.sev.critical.fg
                    : T.textDim,
            }}
          >
            {status.text}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            onClick={handleSave}
            className="ap-btn"
            type="button"
            style={{ fontSize: 12 }}
            disabled={testing}
          >
            <Check
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            Save token
          </button>
          <button
            onClick={handleTest}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 12 }}
            disabled={testing}
          >
            <Wifi
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            {testing ? 'Testing…' : 'Test token'}
          </button>
          <button
            onClick={handleClear}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 12 }}
            disabled={testing}
          >
            <Trash2
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            Clear token
          </button>
        </div>
      </div>
    </section>
  );
}
