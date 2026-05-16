// src/components/settings/GeneralTab.jsx
// Default Settings sub-route. Privacy posture explainer, "Clear all local data" with
// confirmation, version info, changelog link.
//
// "Clear all local data" wipes every Pre-Flight localStorage key + suppression store +
// in-memory log buffer, then hard-reloads the page so React state resets cleanly. This
// is the only path to a true factory-default; clearing one panel at a time leaves
// orphan state.

import { useState } from 'react';
import { Trash2, AlertTriangle, ExternalLink } from 'lucide-react';
import { T, fontMono } from '../../lib/theme.js';

// Every Pre-Flight localStorage key in one place. Keep this in sync as new stores
// land; the Clear-All button reads only this list.
const PREFLIGHT_KEYS = [
  'audit-app:history:v1',
  'audit-app:logs:v1',
  'audit-app:analytics:v1',
  'audit-app:suppressions:v1',
  'audit-app:ai:v1',
  'preflight.github_pat',
];

const VERSION = '0.4.0';
const BUILD_DATE = '2026-05-16';
const CHANGELOG_URL = 'https://github.com/midatlanticAI/PreFlight/blob/main/CHANGELOG.md';

function ExplainerBlock() {
  return (
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
        PRIVACY POSTURE
      </div>
      <p style={{ margin: 0, fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>
        Pre-Flight stores everything in your browser. Nothing leaves this tab unless you scan a
        public GitHub URL (which fetches from GitHub directly, not through us) or opt into Explain
        &amp; Verify (which sends to your chosen AI provider with your own key).
      </p>
    </div>
  );
}

export function GeneralTab() {
  const [showConfirm, setShowConfirm] = useState(false);

  const handleClearAll = () => {
    try {
      if (typeof localStorage !== 'undefined') {
        PREFLIGHT_KEYS.forEach((k) => localStorage.removeItem(k));
      }
    } catch {
      // localStorage may be disabled in private mode — the reload below is still helpful.
    }
    // Hard reload to reset React state, log buffer, analytics state, etc.
    if (typeof window !== 'undefined' && window.location) window.location.reload();
  };

  return (
    <section>
      <h2 className="ap-display" style={{ margin: '0 0 14px', fontSize: 24, color: T.text }}>
        General
      </h2>

      <ExplainerBlock />

      <div className="ap-card" style={{ padding: 18, marginBottom: 14 }}>
        <h3 className="ap-eyebrow" style={{ margin: '0 0 8px', fontSize: 12, color: T.textMuted }}>
          LOCAL DATA
        </h3>
        <p style={{ margin: '0 0 12px', fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>
          Wipe scan history, the diagnostics log buffer, your AI settings, your GitHub token, the
          suppression store, and the analytics counter — everything Pre-Flight remembers locally.
          The page reloads to a fresh state when you confirm.
        </p>
        {!showConfirm ? (
          <button
            onClick={() => setShowConfirm(true)}
            className="ap-btn ap-btn-ghost"
            type="button"
            style={{ fontSize: 13 }}
          >
            <Trash2
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            Clear all local data
          </button>
        ) : (
          <div
            role="alertdialog"
            aria-label="Confirm clearing all local data"
            style={{
              padding: 14,
              background: T.bg,
              border: `1px solid ${T.sev.medium.border}`,
              borderLeft: `3px solid ${T.sev.medium.fg}`,
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                marginBottom: 8,
                color: T.sev.medium.fg,
              }}
            >
              <AlertTriangle size={14} aria-hidden="true" />
              <strong style={{ fontSize: 14 }}>This cannot be undone.</strong>
            </div>
            <ul
              style={{
                margin: '0 0 12px 18px',
                padding: 0,
                fontSize: 13,
                color: T.textDim,
                lineHeight: 1.7,
              }}
            >
              <li>Scan history</li>
              <li>AI settings (Explain &amp; Verify)</li>
              <li>GitHub token (Private Repos)</li>
              <li>Diagnostics logs</li>
              <li>Suppressions (false-positive / won&apos;t-fix / accepted-risk)</li>
              <li>Analytics counter</li>
            </ul>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => setShowConfirm(false)}
                className="ap-btn ap-btn-ghost"
                type="button"
                style={{ fontSize: 12 }}
              >
                Cancel
              </button>
              <button
                onClick={handleClearAll}
                className="ap-btn"
                type="button"
                style={{
                  fontSize: 12,
                  background: T.sev.critical.fg,
                  borderColor: T.sev.critical.fg,
                }}
              >
                Yes, clear everything
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="ap-card" style={{ padding: 18 }}>
        <h3 className="ap-eyebrow" style={{ margin: '0 0 8px', fontSize: 12, color: T.textMuted }}>
          VERSION
        </h3>
        <div style={{ fontSize: 14, color: T.text, fontFamily: fontMono }}>
          Pre-Flight v{VERSION} · built {BUILD_DATE}
        </div>
        <a
          href={CHANGELOG_URL}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 4,
            color: T.accent,
            fontSize: 13,
            marginTop: 8,
            fontFamily: fontMono,
          }}
        >
          Changelog
          <ExternalLink size={10} aria-hidden="true" />
        </a>
      </div>
    </section>
  );
}
