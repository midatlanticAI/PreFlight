// src/components/HomeOverview.jsx
//
// Prerender-ONLY static overview for "/". Rendered solely by
// src/entry-server.jsx so crawlers, LLMs, and no-JavaScript visitors get a
// real, machine-readable description of the tool at the entry point instead
// of an empty #root. The client never imports this: App.jsx boots the live
// AuditView and React mounts fresh over this markup (the same
// prerender-for-bots / CSR-for-users contract used for every Learn route),
// so there is zero client bundle cost and no behavior change for users.
//
// Hard constraints honored here:
//   - SSR-safe: pure presentational JSX, no hooks, no browser globals.
//   - No new dependencies. Only the existing theme tokens.
//   - Copy is reused verbatim from shipped surfaces (README intro + "What it
//     does" result-schema line, HowToView, the AuditView hero). No new prose
//     is authored here, and manifesto.md is intentionally untouched.

import { T, fontUI, fontMono } from '../lib/theme.js';

const P = ({ children }) => (
  <p
    style={{ color: T.textDim, fontSize: 16, lineHeight: 1.75, margin: '0 0 12px', maxWidth: 720 }}
  >
    {children}
  </p>
);
const H2 = ({ children }) => (
  <h2 style={{ fontSize: 18, fontWeight: 700, color: T.text, margin: '28px 0 10px' }}>
    {children}
  </h2>
);
const LI = ({ children }) => (
  <li style={{ color: T.textDim, fontSize: 15, lineHeight: 1.7, marginBottom: 6 }}>{children}</li>
);
const A = ({ href, children }) => (
  <a href={href} style={{ color: T.accent, textDecoration: 'none' }}>
    {children}
  </a>
);

export function HomeOverview() {
  return (
    <main
      id="main"
      style={{
        fontFamily: fontUI,
        maxWidth: 880,
        margin: '0 auto',
        padding: '40px 24px',
        color: T.text,
        background: T.bg,
      }}
    >
      <div
        style={{
          fontFamily: fontMono,
          fontSize: 12,
          letterSpacing: '0.12em',
          marginBottom: 10,
        }}
      >
        <span style={{ color: T.accent }}>MID-ATLANTIC AI</span>
        <span style={{ color: T.textMuted }}> · PREFLIGHT AUDIT TOOL</span>
      </div>

      <h1
        className="ap-display"
        style={{ margin: 0, fontSize: 'clamp(30px, 6vw, 48px)', fontWeight: 700, lineHeight: 1.1 }}
      >
        <span style={{ fontStyle: 'italic', color: T.accent }}>PreFlight</span>
        <br />
        An educational audit tool for vibers building vibeware.
      </h1>

      <p style={{ maxWidth: 640, marginTop: 20, fontSize: 19, fontWeight: 700, lineHeight: 1.5 }}>
        Flying blind is bad. PreFlight handles the safety checks, so we can all fly with confidence.
      </p>

      <P>
        Free, in-browser static security audit for apps built with AI coding tools (Lovable, Cursor,
        Bolt, Replit, Claude Code, v0, GitHub Copilot) and any other web application.
      </P>
      <P>
        No signup. No backend. No analytics beacons. All scanning runs in your browser tab and stays
        there. Nothing leaves your machine.
      </P>

      <H2>What it does</H2>
      <P>
        PreFlight catches what your AI probably missed: exposed secrets, misconfigured RLS,
        supply-chain compromises, unprotected admin routes. Then we explain each finding so you can
        learn why it matters and how to avoid it in the future. All scanning runs locally in your
        browser. Nothing leaves your machine. Ever.
      </P>

      <H2>How it works</H2>
      <P>
        PreFlight is a free in-browser security audit for AI-built apps. Open the page, point it at
        your code, read what it found, fix what matters. Nothing leaves your machine. The three ways
        to scan:
      </P>
      <ul style={{ paddingLeft: 18, margin: 0 }}>
        <LI>
          <b>GitHub URL.</b> The browser fetches the public source directly from
          raw.githubusercontent.com. Private repos use a token you provide in Settings; it goes to
          GitHub, never to us.
        </LI>
        <LI>
          <b>Local folder.</b> Pick a directory. The File API reads it in the tab. The bytes never
          upload anywhere.
        </LI>
        <LI>
          <b>Paste.</b> Drop a single file or snippet in for a quick look.
        </LI>
      </ul>

      <H2>What every finding carries (result schema)</H2>
      <P>
        Every finding carries severity (critical / high / medium / low / info), CWE, file:line,
        evidence, remediation, confidence tag (high / medium / heuristic), and autofix tag
        (mechanical / review-needed / manual). Every finding also carries the OWASP category code(s)
        it maps to.
      </P>

      <H2>What it is not</H2>
      <ul style={{ paddingLeft: 18, margin: 0 }}>
        <LI>Static analysis only. It does not run your code or probe your endpoints.</LI>
        <LI>Not a certification, an SBOM, or a license tool. Those exist elsewhere.</LI>
        <LI>
          Not a replacement for professional review. It catches the class of failure someone assumed
          was already being watched.
        </LI>
      </ul>

      <H2>Read more</H2>
      <ul style={{ paddingLeft: 18, margin: 0 }}>
        <LI>
          <A href="/learn/how-it-works">How it works</A> — the full tour: scanning, reading a
          finding, scoped coverage, the compliance lens.
        </LI>
        <LI>
          <A href="/learn">Learn</A> — the patterns, field reports on named incidents, OWASP
          coverage map, glossary.
        </LI>
        <LI>
          <A href="/learn/owasp">OWASP coverage</A> · <A href="/privacy">Privacy</A> ·{' '}
          <A href="/terms">Terms</A>
        </LI>
      </ul>

      <p style={{ marginTop: 24, fontSize: 13, color: T.textMuted, fontFamily: fontMono }}>
        OWASP Top 10 2025 + OWASP LLM Top 10 2026 · Free, no signup · Code MIT, threat-intel data
        CC-BY-4.0 · <A href="mailto:John@midatlantic.ai">John@midatlantic.ai</A>
      </p>
    </main>
  );
}
