// src/components/learn/EntryView.jsx
// Per-slug detail view. Reads the entry from learn-content.js, renders the markdown body
// via react-markdown (with GFM tables / strikethrough / autolinks), then a Related section
// (probes + cross-referenced incidents) and a Sources section with outbound links.
//
// 404-friendly: if the slug doesn't resolve, returns a "not found" card with a back link.

import { Link, useParams } from 'react-router-dom';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { ChevronLeft, ExternalLink } from 'lucide-react';
import { getBySlug } from '../../lib/learn-content.js';
import { shapesForPattern } from '../../lib/sandbox/shapes.js';
import { T, fontMono } from '../../lib/theme.js';

// Map a content type to its index URL segment so the back-link points home.
const SEGMENT_FOR = {
  pattern: 'patterns',
  incident: 'incidents',
  shape: 'shapes',
  manifesto: '', // manifesto lives at /learn (root)
};

export function EntryView() {
  const { slug } = useParams();
  const entry = getBySlug(slug);
  if (!entry) {
    return (
      <div className="ap-card" style={{ padding: 24, color: T.textDim, fontSize: 15 }}>
        <h2
          className="ap-display"
          style={{ margin: '0 0 8px', fontSize: 22, fontWeight: 700, color: T.text }}
        >
          Not found.
        </h2>
        <p style={{ margin: '0 0 14px' }}>
          No Learn entry matches the slug <code>{slug}</code>.
        </p>
        <Link to="/learn" style={{ color: T.accent, fontFamily: fontMono, fontSize: 13 }}>
          <ChevronLeft
            size={12}
            aria-hidden="true"
            style={{ display: 'inline-block', verticalAlign: '-1px', marginRight: 4 }}
          />
          Back to Learn
        </Link>
      </div>
    );
  }
  return <EntryBody entry={entry} />;
}

// Does this entry have any incident-specific structured metadata worth surfacing?
// We only show the metadata header when at least one of the five optional fields is
// populated, so a stub field report without these doesn't render an empty card.
function hasIncidentMeta(entry) {
  return !!(entry.cve || entry.cvss || entry.campaign || entry.threat_actor || entry.attack_date);
}

// Map a CVSS score to a severity tier color. Mirrors the CVSS 3.1 / 4.0 bands:
//   9.0 - 10.0  critical
//   7.0 - 8.9   high
//   4.0 - 6.9   medium
//   0.1 - 3.9   low
// The label text is derived too so we stay readable even when the score is borderline.
function cvssTier(score) {
  if (typeof score !== 'number') return null;
  if (score >= 9.0)
    return {
      label: 'CRITICAL',
      color: T.sev.critical.fg,
      bg: T.sev.critical.bg,
      border: T.sev.critical.border,
    };
  if (score >= 7.0)
    return { label: 'HIGH', color: T.sev.high.fg, bg: T.sev.high.bg, border: T.sev.high.border };
  if (score >= 4.0)
    return {
      label: 'MEDIUM',
      color: T.sev.medium.fg,
      bg: T.sev.medium.bg,
      border: T.sev.medium.border,
    };
  return { label: 'LOW', color: T.sev.low.fg, bg: T.sev.low.bg, border: T.sev.low.border };
}

function IncidentMetaHeader({ entry }) {
  const tier = cvssTier(entry.cvss);
  const items = [];
  if (entry.cve) items.push({ label: 'CVE', value: entry.cve, mono: true });
  if (entry.attack_date) items.push({ label: 'ATTACK DATE', value: entry.attack_date, mono: true });
  if (entry.threat_actor)
    items.push({ label: 'THREAT ACTOR', value: entry.threat_actor, mono: false });
  if (entry.campaign) items.push({ label: 'CAMPAIGN', value: entry.campaign, mono: false });

  return (
    <div
      className="ap-card"
      style={{
        padding: 16,
        marginBottom: 16,
        background: T.bg,
        borderLeft: `3px solid ${tier ? tier.color : T.borderAlt}`,
        display: 'flex',
        alignItems: 'flex-start',
        flexWrap: 'wrap',
        gap: 18,
      }}
    >
      {tier && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ap-eyebrow" style={{ fontSize: 11, color: T.textMuted }}>
            CVSS
          </span>
          <span
            style={{
              fontFamily: fontMono,
              fontSize: 24,
              fontWeight: 700,
              color: tier.color,
              lineHeight: 1,
            }}
          >
            {entry.cvss.toFixed(1)}
          </span>
          <span
            style={{
              fontFamily: fontMono,
              fontSize: 11,
              color: tier.color,
              background: tier.bg,
              border: `1px solid ${tier.border}`,
              padding: '2px 6px',
              letterSpacing: '0.1em',
              alignSelf: 'flex-start',
              marginTop: 2,
            }}
          >
            {tier.label}
          </span>
        </div>
      )}
      {items.map((it) => (
        <div key={it.label} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ap-eyebrow" style={{ fontSize: 11, color: T.textMuted }}>
            {it.label}
          </span>
          <span
            style={{
              fontFamily: it.mono ? fontMono : 'inherit',
              fontSize: 14,
              fontWeight: 600,
              color: T.text,
            }}
          >
            {it.value}
          </span>
        </div>
      ))}
    </div>
  );
}

// Extracted so ManifestoView can render the manifesto entry without going through useParams.
export function EntryBody({ entry }) {
  const segment = SEGMENT_FOR[entry.type] ?? '';
  const backTo = segment ? `/learn/${segment}` : '/learn';

  return (
    <article className="ap-fade-in">
      <Link
        to={backTo}
        className="ap-mono"
        style={{
          color: T.textDim,
          fontSize: 12,
          textDecoration: 'none',
          marginBottom: 12,
          display: 'inline-flex',
          alignItems: 'center',
        }}
      >
        <ChevronLeft
          size={12}
          aria-hidden="true"
          style={{ verticalAlign: '-1px', marginRight: 4 }}
        />
        Back
      </Link>

      <header style={{ marginBottom: 16 }}>
        <h1
          className="ap-display"
          style={{
            margin: '0 0 6px',
            fontSize: 35,
            fontWeight: 700,
            color: T.text,
            letterSpacing: '-0.01em',
          }}
        >
          {entry.title}
        </h1>
        {entry.last_updated && (
          <span
            className="ap-mono"
            style={{ fontSize: 12, color: T.textMuted, fontFamily: fontMono }}
          >
            Updated {entry.last_updated}
            {entry.draft && ' · Draft'}
          </span>
        )}
      </header>

      {entry.type === 'incident' && hasIncidentMeta(entry) && <IncidentMetaHeader entry={entry} />}

      <div
        className="ap-card"
        style={{
          padding: 28,
          color: T.textDim,
          fontSize: 15,
          lineHeight: 1.75,
        }}
      >
        <div className="ap-markdown">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{entry.body}</ReactMarkdown>
        </div>

        {entry.related_probe_ids?.length > 0 && (
          <section style={{ marginTop: 28, paddingTop: 20, borderTop: `1px solid ${T.border}` }}>
            <h3
              className="ap-eyebrow"
              style={{ margin: '0 0 8px', fontSize: 12, color: T.textMuted }}
            >
              RELATED PROBES
            </h3>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {entry.related_probe_ids.map((p) => (
                <li
                  key={p}
                  className="ap-mono"
                  style={{ fontSize: 13, color: T.text, marginBottom: 4 }}
                >
                  · {p}
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* The pattern explains the shape; the sandbox is where you change it
            and watch the finding go. Only rendered for patterns that have a
            shape, which today is a small number of them. */}
        {shapesForPattern(entry.slug).length > 0 && (
          <section style={{ marginTop: 28 }}>
            <h3
              className="ap-eyebrow"
              style={{ margin: '0 0 10px', fontSize: 11, color: T.textMuted }}
            >
              TRY IT IN THE SANDBOX
            </h3>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {shapesForPattern(entry.slug).map((shape) => (
                <li key={shape.slug} style={{ marginBottom: 8 }}>
                  <Link
                    to={`/sandbox?shape=${shape.slug}`}
                    style={{ color: T.accent, textDecoration: 'none', fontSize: 14 }}
                  >
                    {shape.title}
                  </Link>
                  <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>
                    Open it, edit it, and watch the finding clear.
                  </div>
                </li>
              ))}
            </ul>
          </section>
        )}

        {entry.sources?.length > 0 && (
          <section style={{ marginTop: 20, paddingTop: 20, borderTop: `1px solid ${T.border}` }}>
            <h3
              className="ap-eyebrow"
              style={{ margin: '0 0 8px', fontSize: 12, color: T.textMuted }}
            >
              SOURCES
            </h3>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {entry.sources.map((s, i) => (
                <li key={i} style={{ marginBottom: 6 }}>
                  <a
                    href={s.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: T.accent, fontSize: 14 }}
                  >
                    {s.title}
                    <ExternalLink
                      size={10}
                      aria-hidden="true"
                      style={{ display: 'inline', verticalAlign: '-1px', marginLeft: 4 }}
                    />
                  </a>
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </article>
  );
}
