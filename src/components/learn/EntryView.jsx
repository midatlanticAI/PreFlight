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
      <div className="ap-card" style={{ padding: 24, color: T.textDim, fontSize: 14 }}>
        <h2
          className="ap-display"
          style={{ margin: '0 0 8px', fontSize: 20, fontWeight: 700, color: T.text }}
        >
          Not found.
        </h2>
        <p style={{ margin: '0 0 14px' }}>
          No Learn entry matches the slug <code>{slug}</code>.
        </p>
        <Link to="/learn" style={{ color: T.accent, fontFamily: fontMono, fontSize: 12 }}>
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
          fontSize: 11,
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
            fontSize: 32,
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
            style={{ fontSize: 11, color: T.textMuted, fontFamily: fontMono }}
          >
            Updated {entry.last_updated}
            {entry.draft && ' · Draft'}
          </span>
        )}
      </header>

      <div
        className="ap-card"
        style={{
          padding: 28,
          color: T.textDim,
          fontSize: 14,
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
              style={{ margin: '0 0 8px', fontSize: 11, color: T.textMuted }}
            >
              RELATED PROBES
            </h3>
            <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
              {entry.related_probe_ids.map((p) => (
                <li
                  key={p}
                  className="ap-mono"
                  style={{ fontSize: 12, color: T.text, marginBottom: 4 }}
                >
                  · {p}
                </li>
              ))}
            </ul>
          </section>
        )}

        {entry.sources?.length > 0 && (
          <section style={{ marginTop: 20, paddingTop: 20, borderTop: `1px solid ${T.border}` }}>
            <h3
              className="ap-eyebrow"
              style={{ margin: '0 0 8px', fontSize: 11, color: T.textMuted }}
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
                    style={{ color: T.accent, fontSize: 13 }}
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
