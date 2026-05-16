// src/components/BreakersPanel.jsx
//
// Renders the per-finding Breakers panel: a small set of concrete
// adversarial inputs for the finding's probe class, each with a copy
// button, a description of where to use it, and a description of what
// happens when vulnerable code processes it.
//
// Safety contract enforced by this component:
//   - Every entry is a string. We render it inside a <pre>.
//   - We never execute, fetch, or otherwise act on the payload.
//   - Copying is opt-in (the user clicks the button).
//   - The panel surface itself is collapsed by default; the user expands.
//
// Lives inside the FindingCard. Visible only when getBreakers(probe) is
// non-empty and the parent passes showBreakers=true.

import { useState } from 'react';
import { AlertTriangle, Copy, ShieldAlert } from 'lucide-react';
import { getBreakers } from '../lib/breakers.js';
import { T, fontMono, fontUI } from '../lib/theme.js';
import { copyToClipboard } from '../lib/clipboard.js';
import { log } from '../lib/logger.js';

function CopyButton({ value, label }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={async () => {
        const ok = await copyToClipboard(value);
        if (ok) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } else {
          log.warn('breakers: copy failed', { label });
        }
      }}
      className="ap-mono"
      style={{
        background: 'transparent',
        border: `1px solid ${T.border}`,
        color: T.textDim,
        fontSize: 11,
        padding: '3px 8px',
        cursor: 'pointer',
        letterSpacing: '0.06em',
        textTransform: 'uppercase',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        minHeight: 24,
      }}
      title={`Copy: ${label}`}
    >
      <Copy size={11} aria-hidden="true" />
      {copied ? 'copied' : 'copy'}
    </button>
  );
}

function BreakerEntry({ entry }) {
  return (
    <li
      style={{
        listStyle: 'none',
        marginBottom: 12,
        padding: 14,
        background: T.bg,
        border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${T.sev.high.fg}`,
      }}
    >
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          gap: 8,
          marginBottom: 6,
        }}
      >
        <span className="ap-display" style={{ fontSize: 14, fontWeight: 700, color: T.text }}>
          {entry.name}
        </span>
        <CopyButton value={entry.payload} label={entry.name} />
      </div>
      <pre
        className="ap-mono"
        style={{
          margin: '0 0 8px',
          padding: 10,
          background: T.panel,
          border: `1px solid ${T.border}`,
          fontSize: 12,
          color: T.text,
          fontFamily: fontMono,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          maxHeight: 160,
          overflowY: 'auto',
        }}
      >
        {entry.payload}
      </pre>
      <div style={{ fontSize: 12, color: T.textDim, lineHeight: 1.6, marginBottom: 4 }}>
        <strong style={{ color: T.text }}>Where:</strong> {entry.where}
      </div>
      <div style={{ fontSize: 12, color: T.textDim, lineHeight: 1.6 }}>
        <strong style={{ color: T.text }}>Effect:</strong> {entry.effect}
      </div>
      {entry.note && (
        <div
          style={{
            fontSize: 11,
            color: T.textMuted,
            lineHeight: 1.5,
            marginTop: 6,
            fontStyle: 'italic',
          }}
        >
          {entry.note}
        </div>
      )}
    </li>
  );
}

export function BreakersPanel({ probeName, xlFamily }) {
  const breakers = getBreakers(probeName, xlFamily);
  if (breakers.length === 0) return null;

  return (
    <section
      aria-label={`Adversarial inputs for ${probeName}`}
      style={{
        marginTop: 14,
        padding: 14,
        background: T.panel,
        border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${T.accent}`,
      }}
    >
      <header
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 10,
          color: T.accent,
        }}
      >
        <ShieldAlert size={14} aria-hidden="true" />
        <span
          className="ap-eyebrow"
          style={{
            fontSize: 11,
            letterSpacing: '0.16em',
            textTransform: 'uppercase',
            color: T.accent,
          }}
        >
          Breakers — adversarial inputs
        </span>
      </header>

      <p
        style={{
          margin: '0 0 12px',
          fontSize: 12,
          color: T.textDim,
          lineHeight: 1.6,
          fontFamily: fontUI,
        }}
      >
        Concrete examples of what an attacker would type to exploit this finding. Static only.
        Pre-Flight does not send, run, or otherwise act on these payloads. They are here so you can
        reproduce the failure in your own dev environment and confirm the fix.
      </p>

      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 8,
          marginBottom: 14,
          padding: '8px 12px',
          background: T.bg,
          border: `1px dashed ${T.borderAlt}`,
          fontSize: 11,
          color: T.textMuted,
          lineHeight: 1.5,
        }}
      >
        <AlertTriangle size={11} aria-hidden="true" style={{ flexShrink: 0, marginTop: 2 }} />
        <span>
          Use only on systems you own or have explicit authorization to test. Replaying these
          against systems you do not own is unauthorized access in most jurisdictions.
        </span>
      </div>

      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {breakers.map((entry, i) => (
          <BreakerEntry key={i} entry={entry} />
        ))}
      </ul>
    </section>
  );
}
