// src/components/GlobalStyle.jsx
// Single <style> block emitted once at the top of the App tree. Holds every CSS rule
// used in the app: brand-coloured chrome, the WCAG 2.2 SC 2.5.8 target-size floor,
// :focus-visible outline, prefers-reduced-motion / prefers-contrast / forced-colors
// overrides, skip-link reveal, the .ap-btn / .ap-input / .ap-card tokens, and the
// font-family tokens (fontDisplay / fontUI / fontCondensed / fontEyebrow / fontMono).
// Brand fonts themselves are preloaded by index.html — this file only carries rules.

import { T, fontDisplay, fontUI, fontCondensed, fontEyebrow, fontMono } from '../lib/theme.js';

export function GlobalStyle() {
  return (
    <style>{`
      /* Brand fonts loaded non-render-blocking via index.html's <link rel="preload" as="style"> +
         onload swap. Keeping @import here would re-fetch and re-block paint. */
      * { box-sizing: border-box; }
      body { margin: 0; }
      /* WCAG 2.4.7 — visible focus indicator for keyboard users */
      .ap-app *:focus-visible {
        outline: 2px solid ${T.accent};
        outline-offset: 2px;
      }
      /* WCAG 2.2 SC 2.5.8 Target Size (Minimum) — every interactive target ≥ 24×24 CSS px.
         Inline-styled buttons that need to be visually smaller use box-shadow / outline padding
         to retain the hit area while keeping the visible chrome compact. */
      .ap-app button, .ap-app [role="button"], .ap-app a {
        min-height: 24px;
        min-width: 24px;
      }
      /* Compact inline buttons (e.g. filter chips) still get a 24px hit-area via padding floor. */
      .ap-compact-btn {
        min-height: 24px !important;
        padding: 4px 10px !important;
        display: inline-flex; align-items: center; justify-content: center;
      }
      /* Honor reduced-motion preference (WCAG 2.3.3) */
      @media (prefers-reduced-motion: reduce) {
        .ap-app *, .ap-app *::before, .ap-app *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }
      }
      /* Screen-reader-only utility */
      .ap-sr-only {
        position: absolute;
        width: 1px; height: 1px;
        padding: 0; margin: -1px;
        overflow: hidden; clip: rect(0,0,0,0);
        white-space: nowrap; border: 0;
      }
      /* Skip-to-content link — hidden until keyboard-focused (WCAG 2.4.1) */
      .ap-skip-link {
        position: absolute;
        top: -100px; left: 8px;
        background: ${T.accent};
        color: ${T.bg};
        padding: 10px 16px;
        font-family: ${fontUI};
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        z-index: 1000;
        transition: top 0.15s ease-out;
      }
      .ap-skip-link:focus {
        top: 8px;
        outline: 2px solid ${T.text};
        outline-offset: 2px;
      }
      /* High-contrast preference — flatten gradients and bump borders */
      @media (prefers-contrast: more) {
        .ap-app {
          background-image: none !important;
        }
        .ap-card, .ap-finding {
          border-color: ${T.text} !important;
        }
        .ap-eyebrow {
          color: ${T.text} !important;
        }
      }
      /* Forced-colors (Windows high contrast) — let the OS recolor */
      @media (forced-colors: active) {
        .ap-app {
          background: Canvas;
          color: CanvasText;
        }
        .ap-btn {
          border: 1px solid ButtonBorder;
          background: ButtonFace;
          color: ButtonText;
        }
      }
      .ap-app {
        background: ${T.bg};
        background-image:
          linear-gradient(${T.bgGrid} 1px, transparent 1px),
          linear-gradient(90deg, ${T.bgGrid} 1px, transparent 1px);
        background-size: 48px 48px;
        color: ${T.text};
        font-family: ${fontUI};
        font-size: 13px;
        line-height: 1.55;
        min-height: 100vh;
        letter-spacing: 0.01em;
      }
      .ap-app *::-webkit-scrollbar { width: 10px; height: 10px; }
      .ap-app *::-webkit-scrollbar-track { background: ${T.bg}; }
      .ap-app *::-webkit-scrollbar-thumb { background: ${T.border}; border-radius: 0; }
      .ap-app *::-webkit-scrollbar-thumb:hover { background: ${T.borderAlt}; }
      .ap-btn {
        font-family: ${fontMono};
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        background: ${T.accent};
        color: ${T.bg};
        border: 1px solid ${T.accent};
        padding: 12px 20px;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      .ap-btn:hover:not(:disabled) { background: ${T.accentDim}; border-color: ${T.accentDim}; }
      /* Disabled: clearly distinct from enabled, still WCAG 3:1 UI contrast.
         textDim (#a8b1c5) on panel (#11192e) ≈ 7.5:1 so text is readable;
         strikethrough + dashed border + not-allowed cursor make "disabled" obvious. */
      .ap-btn:disabled, .ap-btn-ghost:disabled {
        background: ${T.panel};
        color: ${T.textDim};
        border: 1px dashed ${T.borderAlt};
        cursor: not-allowed;
        text-decoration: line-through;
        text-decoration-color: ${T.textMuted};
      }
      .ap-btn-ghost {
        background: transparent;
        color: ${T.textDim};
        border: 1px solid ${T.border};
      }
      .ap-btn-ghost:hover:not(:disabled) {
        background: ${T.panel};
        color: ${T.text};
        border-color: ${T.borderAlt};
      }
      .ap-input {
        font-family: ${fontMono};
        font-size: 13px;
        background: ${T.bg};
        color: ${T.text};
        border: 1px solid ${T.border};
        padding: 12px 14px;
        width: 100%;
        outline: none;
        transition: border-color 0.15s ease;
      }
      .ap-input:focus { border-color: ${T.accent}; }
      .ap-tab {
        font-family: ${fontMono};
        font-size: 11px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        padding: 14px 24px;
        background: transparent;
        color: ${T.textMuted};
        border: none;
        border-bottom: 2px solid transparent;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      .ap-tab:hover { color: ${T.textDim}; }
      .ap-tab-active {
        color: ${T.accent};
        border-bottom-color: ${T.accent};
      }
      .ap-card {
        background: ${T.panel};
        border: 1px solid ${T.border};
      }
      .ap-finding {
        background: ${T.panel};
        border: 1px solid ${T.border};
        border-left-width: 3px;
        transition: background 0.15s ease;
      }
      .ap-finding:hover { background: ${T.panelHover}; }
      .ap-spin { animation: ap-spin 0.8s linear infinite; }
      @keyframes ap-spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
      .ap-pulse { animation: ap-pulse 2s ease-in-out infinite; }
      @keyframes ap-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
      .ap-fade-in { animation: ap-fade 0.4s ease-out; }
      @keyframes ap-fade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
      .ap-eyebrow {
        font-family: ${fontEyebrow};
        font-size: 11px;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: ${T.textMuted};
        font-weight: 400;
      }
      .ap-display { font-family: ${fontDisplay}; font-weight: 700; font-style: normal; }
      .ap-condensed { font-family: ${fontCondensed}; }
      .ap-mono { font-family: ${fontMono}; }
    `}</style>
  );
}
