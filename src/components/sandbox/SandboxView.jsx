// src/components/sandbox/SandboxView.jsx
//
// Top-level sandbox surface. Lives at /sandbox; one of the load-bearing
// surfaces in the v2 overhaul (see docs/preflight-v2-spec.md). Designed to
// become the application's new entry point once the worker-driven probe
// pipeline and the persona cards land; this first iteration establishes the
// editor surface, the right-side findings panel, the route wire, and a
// debounced live scan against an opening set of v0.4 probes so subsequent
// commits extend rather than rebuild the contract.
//
// SSR caveat: CodeMirror touches DOM during construction. SandboxView is
// client-only (the prerender skips /sandbox the same way it skips / and
// /settings); App.jsx wraps the route in React.Suspense so the first paint
// is the loading state and the editor mounts after.

import { useEffect, useState } from 'react';
import { Editor } from './Editor.jsx';
import { FindingsPanel } from './FindingsPanel.jsx';
import { runSandboxScan } from '../../lib/sandbox/runner.js';
import { T, fontUI, fontMono } from '../../lib/theme.js';

// Starter buffer. Intentionally vibe-coded so the surface demonstrates the
// patterns the sandbox catches: a fetch in useEffect with no AbortController
// and no r.ok check, an addEventListener with no cleanup, a console.log left
// behind, an index-as-key in a dynamic list. The console.log alone is enough
// for the runner's current probe set to fire on first paint, so a user
// landing on /sandbox immediately sees the panel populated.
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

// Debounce window in ms before re-running the scan after the user stops
// typing. 300ms is the budget from preflight-v2-spec.md §1.12.
const SCAN_DEBOUNCE_MS = 300;

export function SandboxView() {
  const [code, setCode] = useState(STARTER_BUFFER);
  // Initial findings computed synchronously so the first paint already shows
  // what fires on the starter buffer rather than an empty panel.
  const [findings, setFindings] = useState(() => runSandboxScan(STARTER_BUFFER));

  useEffect(() => {
    const id = setTimeout(() => {
      setFindings(runSandboxScan(code));
    }, SCAN_DEBOUNCE_MS);
    return () => clearTimeout(id);
  }, [code]);

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
        <FindingsPanel findings={findings} />
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
        Editor characters: {code.length} · Findings: {findings.length}
      </p>
    </section>
  );
}
