// src/components/sandbox/SandboxView.jsx
//
// Top-level sandbox surface. Lives at /sandbox; one of the load-bearing
// surfaces in the v2 overhaul (see docs/preflight-v2-spec.md). The route
// becomes the application's new entry point once the worker-driven probe
// pipeline and the persona cards land; this first cut establishes the editor
// surface, the right-side findings panel, and the route wire so subsequent
// commits can layer functionality without churning the shell.
//
// SSR caveat: CodeMirror touches DOM during construction. SandboxView is
// client-only (the prerender skips /sandbox the same way it skips / and
// /settings); App.jsx wraps the route in React.Suspense so the first paint
// is the loading state and the editor mounts after.

import { useState } from 'react';
import { Editor } from './Editor.jsx';
import { FindingsPanel } from './FindingsPanel.jsx';
import { T, fontUI, fontMono } from '../../lib/theme.js';

// Starter buffer. Intentionally vibe-coded so the surface demonstrates the
// patterns the sandbox will eventually catch: a fetch in useEffect with no
// AbortController and no r.ok check, an addEventListener with no cleanup,
// a console.log left behind, an index-as-key in a dynamic list. None of
// these fire today (probes plug in next); the file is here so the editor
// has real-shaped code from the first paint.
const STARTER_BUFFER = `import { useState, useEffect } from 'react';

function UserSearch({ onSelect }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);

  useEffect(() => {
    fetch('/api/search?q=' + query)
      .then((r) => r.json())
      .then(setResults);
  }, [query]);

  useEffect(() => {
    window.addEventListener('resize', () => {
      console.log('resized');
    });
  }, []);

  return (
    <div>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      {results.map((r, i) => (
        <div key={i} onClick={() => onSelect(r)}>
          {r.name}
        </div>
      ))}
    </div>
  );
}
`;

export function SandboxView() {
  const [code, setCode] = useState(STARTER_BUFFER);

  return (
    <section aria-labelledby="sandbox-heading" className="ap-fade-in">
      <header style={{ marginBottom: 20 }}>
        <div className="ap-eyebrow" style={{ marginBottom: 8, fontFamily: fontMono }}>
          PREFLIGHT SANDBOX
        </div>
        <h1
          id="sandbox-heading"
          className="ap-display"
          style={{
            margin: '0 0 8px',
            fontSize: 'clamp(24px, 6vw, 39px)',
            fontWeight: 700,
            color: T.text,
            letterSpacing: '-0.01em',
          }}
        >
          Edit code. See what PreFlight catches.
        </h1>
        <p
          style={{
            fontSize: 15,
            color: T.textDim,
            lineHeight: 1.7,
            margin: 0,
            maxWidth: 720,
            fontFamily: fontUI,
          }}
        >
          A live workspace for trying patterns and watching the findings change as you type. Nothing
          leaves your browser. The starter file is intentionally rough; that is the point.
        </p>
      </header>

      <div
        className="ap-sandbox-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 360px',
          gap: 16,
          alignItems: 'flex-start',
        }}
      >
        <Editor initialValue={STARTER_BUFFER} onChange={setCode} />
        <FindingsPanel findings={[]} />
      </div>

      <style>{`
        @media (max-width: 880px) {
          .ap-sandbox-grid {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>

      <p
        aria-live="polite"
        style={{
          fontSize: 12,
          color: T.textMuted,
          marginTop: 16,
          fontFamily: fontMono,
        }}
      >
        Editor characters: {code.length}
      </p>
    </section>
  );
}
