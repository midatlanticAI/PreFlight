// src/components/sandbox/FindingsPanel.jsx
//
// Right-side findings surface for the sandbox. Renders the array the runner
// emits, sorted critical-first, with a severity-coloured left border and a
// compact metadata line. Layout intentionally matches the spec's split-pane
// shape (preflight-v2-spec.md §1.11 / §3 of Track 2) so the eventual move to
// Worker-emitted findings is a drop-in.

import { T, fontUI, fontMono } from '../../lib/theme.js';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Fall back to neutral text-muted when a probe emits an unexpected severity
// string. The theme's T.sev set already has entries for every documented
// severity; this guard is just defensive.
function sevColor(severity) {
  return T.sev?.[severity]?.fg || T.textMuted;
}

export function FindingsPanel({ findings = [] }) {
  const sorted = [...findings].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
  );

  return (
    <aside
      aria-label="Findings"
      style={{
        background: T.panel,
        border: `1px solid ${T.border}`,
        padding: 20,
        minHeight: 360,
        fontFamily: fontUI,
        color: T.text,
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
        Findings ({sorted.length})
      </div>
      {sorted.length === 0 ? (
        <p style={{ fontSize: 14, lineHeight: 1.6, margin: 0, color: T.textDim }}>
          No findings on this code. Edit to try patterns the scanner catches.
        </p>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {sorted.map((f) => (
            <li
              key={f.id}
              style={{
                marginBottom: 14,
                paddingLeft: 12,
                borderLeft: `3px solid ${sevColor(f.severity)}`,
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontFamily: fontMono,
                  color: sevColor(f.severity),
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                }}
              >
                {f.severity}
                {f.probe ? ` · ${f.probe}` : ''}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, color: T.text, marginTop: 2 }}>
                {f.title}
              </div>
              {f.evidence && (
                <p style={{ fontSize: 12, color: T.textDim, margin: '4px 0 0', lineHeight: 1.5 }}>
                  {f.evidence}
                </p>
              )}
              {f.line ? (
                <div
                  style={{
                    fontSize: 11,
                    fontFamily: fontMono,
                    color: T.textMuted,
                    marginTop: 4,
                  }}
                >
                  Line {f.line}
                </div>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </aside>
  );
}
