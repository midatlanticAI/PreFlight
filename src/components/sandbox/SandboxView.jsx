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
// /sandbox?shape=<slug> seeds the editor from src/lib/sandbox/shapes.js, which
// is how a Learn page and a finding card both point INTO this surface instead
// of it sitting off to one side. getShape() falls back to the default entry for
// a missing or unknown slug, so there is no error state to render and no reason
// to add /sandbox to scripts/lib/routes.mjs (it stays out of the prerender and
// the sitemap).
//
// SSR caveat: CodeMirror touches DOM during construction. SandboxView is
// client-only (the prerender skips /sandbox the same way it skips / and
// /settings); App.jsx wraps the route in React.Suspense so the first paint
// is the loading state and the editor mounts after.

import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Editor } from './Editor.jsx';
import { FindingsPanel } from './FindingsPanel.jsx';
import { runSandboxScan } from '../../lib/sandbox/runner.js';
import { getShape } from '../../lib/sandbox/shapes.js';
import { T, fontUI, fontMono } from '../../lib/theme.js';

// Debounce window in ms before re-running the scan after the user stops
// typing. 300ms is the budget from preflight-v2-spec.md §1.12.
const SCAN_DEBOUNCE_MS = 300;

export function SandboxView() {
  const [params] = useSearchParams();
  const shape = getShape(params.get('shape'));

  // `seed` is what the editor was last mounted with. Editor keys its mount
  // effect on initialValue, so reloading the SAME text (Reset after edits)
  // would not change that dependency; the nonce forces a real remount.
  const [seed, setSeed] = useState(() => ({ text: shape.buffer, n: 0 }));
  const [code, setCode] = useState(shape.buffer);
  // Initial findings computed synchronously so the first paint already shows
  // what fires on this shape rather than an empty panel.
  const [findings, setFindings] = useState(() => runSandboxScan(shape.buffer, shape.filename));

  const load = (text) => {
    setSeed((prev) => ({ text, n: prev.n + 1 }));
    setCode(text);
  };

  // A different ?shape= is a different exercise, not an edit to this one, so
  // the buffer resets. Adjusted during render rather than in an effect: an
  // effect would paint the previous shape's code once and then replace it.
  const [prevSlug, setPrevSlug] = useState(shape.slug);
  if (prevSlug !== shape.slug) {
    setPrevSlug(shape.slug);
    setSeed({ text: shape.buffer, n: 0 });
    setCode(shape.buffer);
  }

  useEffect(() => {
    const id = setTimeout(() => {
      setFindings(runSandboxScan(code, shape.filename));
    }, SCAN_DEBOUNCE_MS);
    return () => clearTimeout(id);
  }, [code, shape.filename]);

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
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          alignItems: 'baseline',
          gap: 12,
          marginBottom: 12,
        }}
      >
        <span style={{ fontSize: 13, color: T.textDim, lineHeight: 1.6, flex: '1 1 320px' }}>
          <strong style={{ color: T.text, fontWeight: 600 }}>{shape.title}.</strong> {shape.note}
        </span>
        <span style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            className="ap-btn ap-btn-ghost"
            style={{ fontSize: 12, padding: '6px 14px' }}
            onClick={() => load(shape.fixedBuffer)}
          >
            Show the fix
          </button>
          <button
            type="button"
            className="ap-btn ap-btn-ghost"
            style={{ fontSize: 12, padding: '6px 14px' }}
            onClick={() => load(shape.buffer)}
          >
            Reset
          </button>
        </span>
      </div>

      <div
        className="ap-sandbox-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 360px',
          gap: 16,
          alignItems: 'flex-start',
        }}
      >
        <Editor key={seed.n} initialValue={seed.text} onChange={setCode} />
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
