// src/components/learn/IndexView.jsx
// Generic list view for one Learn content type. Used by the patterns / incidents / shapes
// sub-routes. Pulls entries from learn-content.js, displays them as a card list with
// title, summary, last_updated, and a draft badge when applicable.

import { Link } from 'react-router-dom';
import { Clock } from 'lucide-react';
import { getByType } from '../../lib/learn-content.js';
import { T, fontMono } from '../../lib/theme.js';

// Map content type to the URL segment + nice page heading.
const TYPE_META = {
  pattern: { segment: 'patterns', heading: 'Patterns we look for', kind: 'pattern' },
  incident: { segment: 'incidents', heading: 'Field reports', kind: 'incident' },
  shape: { segment: 'shapes', heading: 'Architecture shapes', kind: 'shape' },
};

export function IndexView({ type }) {
  const meta = TYPE_META[type];
  const entries = getByType(type);

  if (!meta) return null;

  return (
    <section aria-labelledby={`learn-${type}-heading`}>
      <h2
        id={`learn-${type}-heading`}
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        {meta.heading}
      </h2>
      <p style={{ color: T.textMuted, fontSize: 14, margin: '0 0 18px' }}>
        {entries.length} {meta.kind}
        {entries.length === 1 ? '' : 's'} · {entries.filter((e) => !e.draft).length} published ·{' '}
        {entries.filter((e) => e.draft).length} draft
      </p>

      {entries.length === 0 ? (
        <div
          className="ap-card"
          style={{
            padding: 24,
            color: T.textMuted,
            fontSize: 14,
            textAlign: 'center',
          }}
        >
          No entries yet.
        </div>
      ) : (
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {entries.map((e) => (
            <li key={e.slug} style={{ marginBottom: 10 }}>
              <Link
                to={`/learn/${meta.segment}/${e.slug}`}
                style={{
                  display: 'block',
                  padding: 18,
                  background: T.panel,
                  border: `1px solid ${T.border}`,
                  borderLeft: `3px solid ${e.draft ? T.borderAlt : T.accent}`,
                  textDecoration: 'none',
                  transition: 'background 0.15s ease, border-color 0.15s ease',
                }}
                onMouseOver={(ev) => {
                  ev.currentTarget.style.background = T.panelHover;
                }}
                onMouseOut={(ev) => {
                  ev.currentTarget.style.background = T.panel;
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'baseline',
                    justifyContent: 'space-between',
                    gap: 12,
                    marginBottom: 6,
                  }}
                >
                  <h3
                    className="ap-display"
                    style={{
                      margin: 0,
                      fontSize: 17,
                      fontWeight: 700,
                      color: T.text,
                    }}
                  >
                    {e.title}
                  </h3>
                  {e.draft && (
                    <span
                      className="ap-mono"
                      style={{
                        fontSize: 11,
                        padding: '2px 7px',
                        color: T.textDim,
                        background: T.bg,
                        border: `1px solid ${T.borderAlt}`,
                        letterSpacing: '0.1em',
                        textTransform: 'uppercase',
                      }}
                    >
                      Draft
                    </span>
                  )}
                </div>
                {e.summary && (
                  <p
                    style={{
                      margin: '0 0 10px',
                      fontSize: 14,
                      color: T.textDim,
                      lineHeight: 1.6,
                    }}
                  >
                    {e.summary}
                  </p>
                )}
                {e.last_updated && (
                  <span
                    className="ap-mono"
                    style={{ fontSize: 11, color: T.textMuted, fontFamily: fontMono }}
                  >
                    <Clock
                      size={9}
                      aria-hidden="true"
                      style={{
                        display: 'inline-block',
                        marginRight: 4,
                        verticalAlign: '-1px',
                      }}
                    />
                    Updated {e.last_updated}
                  </span>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
