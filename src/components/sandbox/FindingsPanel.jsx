// src/components/sandbox/FindingsPanel.jsx
//
// Right-side findings surface for the sandbox. Empty in this first cut; the
// worker-driven probe pipeline lands in the next sandbox chunk and feeds real
// findings in. The contract this commit establishes: editor on the left,
// findings on the right, both backed by the existing theme so the eventual
// swap to live findings is a drop-in.

import { T, fontUI, fontMono } from '../../lib/theme.js';

export function FindingsPanel({ findings = [] }) {
  return (
    <aside
      aria-label="Findings"
      style={{
        background: T.panel,
        border: `1px solid ${T.border}`,
        padding: 20,
        minHeight: 360,
        fontFamily: fontUI,
        color: findings.length === 0 ? T.textDim : T.text,
      }}
    >
      <div
        style={{
          fontFamily: fontMono,
          fontSize: 11,
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
          color: T.textMuted,
          marginBottom: 12,
        }}
      >
        Findings
      </div>
      {findings.length === 0 ? (
        <p style={{ fontSize: 14, lineHeight: 1.6, margin: 0 }}>
          No findings yet. Live scanning lands in the next sandbox chunk.
        </p>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {findings.map((f) => (
            <li key={f.id} style={{ marginBottom: 12 }}>
              <strong style={{ fontSize: 14 }}>{f.title}</strong>
              {f.evidence && (
                <p style={{ fontSize: 13, color: T.textDim, margin: '4px 0 0' }}>{f.evidence}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}
