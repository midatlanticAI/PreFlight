// src/components/learn/GlossaryView.jsx
//
// The "Glossary" sub-tab under /learn. Every concept Pre-Flight names anywhere
// has a one-line definition + a link to an authoritative free reference
// (Wikipedia, MDN, OWASP, CWE, RFC, vendor spec). Where Pre-Flight has its
// own pattern / field-report page on the topic, the entry's internal link
// goes there.
//
// Voice: Demi register. The page is a reference surface. Brief intros per
// group, terms list with definition + external + internal links.
//
// Token economy: definitions are short on purpose. Outbound links carry the
// depth. Pre-Flight curates which terms matter; we don't try to be the
// encyclopedia.

import { useMemo, useState } from 'react';
import { ExternalLink, Search } from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  GLOSSARY_GROUPS,
  searchGlossary,
  getGlossaryCount,
  getGlossaryGroupCount,
} from '../../lib/glossary.js';
import { T, fontMono, fontUI } from '../../lib/theme.js';

function EntryRow({ entry }) {
  return (
    <li
      style={{
        listStyle: 'none',
        padding: 12,
        marginBottom: 6,
        background: T.panel,
        border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${T.borderAlt}`,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'baseline',
          justifyContent: 'space-between',
          gap: 12,
          marginBottom: 4,
          flexWrap: 'wrap',
        }}
      >
        <span
          className="ap-display"
          style={{
            fontSize: 14,
            fontWeight: 700,
            color: T.text,
          }}
        >
          {entry.term}
        </span>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {entry.internal && (
            <Link
              to={entry.internal}
              className="ap-mono"
              style={{
                fontSize: 11,
                color: T.accent,
                textDecoration: 'none',
                letterSpacing: '0.04em',
                whiteSpace: 'nowrap',
              }}
              title={`Open Pre-Flight page: ${entry.internal}`}
            >
              Pre-Flight pattern →
            </Link>
          )}
          <a
            href={entry.link}
            target="_blank"
            rel="noopener noreferrer"
            className="ap-mono"
            style={{
              fontSize: 11,
              color: T.textDim,
              textDecoration: 'none',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              whiteSpace: 'nowrap',
            }}
            title={`Open external reference: ${entry.link}`}
          >
            reference
            <ExternalLink size={10} aria-hidden="true" />
          </a>
        </div>
      </div>
      <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>{entry.definition}</div>
    </li>
  );
}

function GroupSection({ group, entries }) {
  if (!entries.length) return null;
  return (
    <section
      id={group.id}
      aria-labelledby={`gloss-${group.id}-heading`}
      style={{ marginBottom: 28 }}
    >
      <h2
        id={`gloss-${group.id}-heading`}
        className="ap-display"
        style={{ margin: '0 0 4px', fontSize: 18, fontWeight: 700, color: T.text }}
      >
        {group.title}
      </h2>
      {group.intro && (
        <p style={{ margin: '0 0 12px', fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>
          {group.intro}
        </p>
      )}
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {entries.map((entry) => (
          <EntryRow key={entry.term} entry={entry} />
        ))}
      </ul>
    </section>
  );
}

export function GlossaryView() {
  const [query, setQuery] = useState('');
  const totalEntries = getGlossaryCount();
  const totalGroups = getGlossaryGroupCount();

  // When a query is active, render a flat filtered list grouped by original group.
  // When the query is empty, render every group in its natural order.
  const filtered = useMemo(() => searchGlossary(query), [query]);
  const matchedByGroup = useMemo(() => {
    const map = new Map();
    for (const e of filtered) {
      if (!map.has(e.group)) map.set(e.group, []);
      map.get(e.group).push(e);
    }
    return map;
  }, [filtered]);

  return (
    <section aria-labelledby="glossary-heading">
      <h1
        id="glossary-heading"
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        Glossary
      </h1>
      <p
        style={{
          color: T.textMuted,
          fontSize: 14,
          margin: '0 0 8px',
          maxWidth: 720,
          lineHeight: 1.6,
        }}
      >
        {totalEntries} terms across {totalGroups} groups. Every definition is one sentence; every
        entry links to an authoritative free reference (Wikipedia, MDN, OWASP, MITRE CWE, RFCs,
        vendor spec docs). When Pre-Flight has its own page on the topic, the entry also links
        there.
      </p>
      <p
        style={{
          color: T.textMuted,
          fontSize: 13,
          margin: '0 0 18px',
          maxWidth: 720,
          lineHeight: 1.6,
          fontStyle: 'italic',
        }}
      >
        Curated, not authored. We pick the terms that matter and link out for the depth.
      </p>

      <div
        style={{
          position: 'relative',
          marginBottom: 18,
        }}
      >
        <Search
          size={14}
          aria-hidden="true"
          style={{
            position: 'absolute',
            left: 12,
            top: 14,
            color: T.textMuted,
            pointerEvents: 'none',
          }}
        />
        <input
          type="search"
          aria-label="Filter glossary terms"
          placeholder="Filter by term, definition, or alias…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="ap-input"
          style={{
            paddingLeft: 36,
            fontFamily: fontUI,
            fontSize: 14,
          }}
        />
      </div>

      {/* Anchor index. Hidden during search (anchors don't match a filtered view). */}
      {!query && (
        <nav
          aria-label="Glossary group index"
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 6,
            marginBottom: 22,
            padding: 12,
            background: T.bg,
            border: `1px solid ${T.border}`,
          }}
        >
          {GLOSSARY_GROUPS.map((g) => (
            <a
              key={g.id}
              href={`#${g.id}`}
              className="ap-mono"
              style={{
                fontSize: 11,
                padding: '4px 10px',
                border: `1px solid ${T.border}`,
                color: T.textDim,
                textDecoration: 'none',
                letterSpacing: '0.06em',
              }}
            >
              {g.title}
            </a>
          ))}
        </nav>
      )}

      {/* When filtering, show empty-state if nothing matches. */}
      {query && filtered.length === 0 && (
        <div
          className="ap-card"
          style={{ padding: 24, color: T.textMuted, fontSize: 13, textAlign: 'center' }}
        >
          No glossary entries match &quot;{query}&quot;. Try a shorter prefix or check the full list
          below.
        </div>
      )}

      {/* Group sections. When a query is active, each group only renders its matched entries. */}
      {GLOSSARY_GROUPS.map((group) => (
        <GroupSection
          key={group.id}
          group={group}
          entries={query ? matchedByGroup.get(group.id) || [] : group.entries}
        />
      ))}

      <p
        style={{
          margin: '32px 0 0',
          padding: 16,
          fontSize: 13,
          color: T.textMuted,
          lineHeight: 1.6,
          background: T.bg,
          border: `1px dashed ${T.border}`,
          fontFamily: fontMono,
        }}
      >
        Source-of-truth: <code>src/lib/glossary.js</code>. Spotted a term that should be here, or a
        definition that’s off? Open a PR at{' '}
        <a
          href="https://github.com/midatlanticAI/PreFlight"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: T.accent }}
        >
          github.com/midatlanticAI/PreFlight
        </a>
        .
      </p>
    </section>
  );
}
