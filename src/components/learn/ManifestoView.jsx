// src/components/learn/ManifestoView.jsx
// Default Learn sub-route (/learn). Renders the manifesto markdown if it exists and
// isn't draft, otherwise shows a friendly placeholder pointing at the index pages.

import { getManifesto } from '../../lib/learn-content.js';
import { EntryBody } from './EntryView.jsx';
import { T } from '../../lib/theme.js';

export function ManifestoView() {
  const entry = getManifesto();
  if (entry && !entry.draft) return <EntryBody entry={entry} />;
  return (
    <div
      className="ap-card"
      style={{ padding: 32, color: T.textDim, fontSize: 15, lineHeight: 1.7 }}
    >
      <div className="ap-eyebrow" style={{ marginBottom: 12 }}>
        VIBE-AWARE
      </div>
      <h2
        className="ap-display"
        style={{ margin: '0 0 14px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        Manifesto — coming soon.
      </h2>
      <p>
        The PreFlight manifesto explains what "Vibe-Aware" means in practice: why AI-built apps need
        a different kind of security tooling, how teaching the pattern beats flagging the line, and
        how the same audit can fit in a browser tab instead of a procurement review.
      </p>
      <p style={{ marginTop: 14 }}>
        While that's being written, head over to <strong>Patterns</strong> for the bug shapes
        PreFlight catches, <strong>Field Reports</strong> for the named supply-chain incidents we
        ship threat-intel against, or <strong>Shapes</strong> for the architecture types and the
        hardening checklists that come with each.
      </p>
    </div>
  );
}
