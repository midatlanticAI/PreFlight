// src/components/learn/HowToView.jsx
//
// The "How it works" sub-tab under /learn. End-to-end reference: the
// three ways to scan, how to read a finding, what every panel does, how
// coverage is scoped, and what the tool is not. Reference material in
// the manifesto's plain register. No marketing prose, no em-dashes.

import { T } from '../../lib/theme.js';

const H2 = ({ children }) => (
  <h2
    style={{
      fontSize: 16,
      fontWeight: 700,
      color: T.text,
      margin: '26px 0 8px',
    }}
  >
    {children}
  </h2>
);
const P = ({ children }) => (
  <p
    style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.6, margin: '0 0 10px', maxWidth: 760 }}
  >
    {children}
  </p>
);
const LI = ({ children }) => (
  <li style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.6, marginBottom: 6 }}>{children}</li>
);

export function HowToView() {
  return (
    <section aria-labelledby="howto-heading">
      <h1
        id="howto-heading"
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        How it works
      </h1>
      <P>
        Pre-Flight is a free in-browser security audit for AI-built apps. Open the page, point it at
        your code, read what it found, fix what matters. Nothing leaves your machine. This page is
        the full tour.
      </P>

      <H2>The three ways to scan</H2>
      <ul style={{ paddingLeft: 18, margin: 0 }}>
        <LI>
          <b>GitHub URL.</b> Paste github.com/&lt;you&gt;/&lt;repo&gt;.git. The browser fetches the
          public source directly from raw.githubusercontent.com. Private repos use a token you
          provide in Settings; it goes to GitHub, never to us.
        </LI>
        <LI>
          <b>Local folder.</b> Pick a directory. The File API reads it in the tab. The bytes never
          upload anywhere.
        </LI>
        <LI>
          <b>Paste.</b> Drop a single file or snippet in for a quick look.
        </LI>
      </ul>

      <H2>Reading a finding</H2>
      <P>
        Each finding is one row: a severity chip, the category, the CWE id, and the title. Expand it
        for the evidence line, a short code snapshot, and the specific fix. The chips on the row
        tell you more at a glance:
      </P>
      <ul style={{ paddingLeft: 18, margin: 0 }}>
        <LI>
          <b>OWASP.</b> The OWASP Top 10 / LLM category the pattern maps to.
        </LI>
        <LI>
          <b>Confidence and fixability.</b> Whether the match is deterministic or wants a glance,
          and whether the fix is a drop-in, a review, or architectural.
        </LI>
        <LI>
          <b>MAPS TO.</b> When the pattern touches a code-detectable regulatory clause (HIPAA,
          PCI-DSS, GDPR, SOC2), the framework shows here. It says "indicative" or "direct" and is an
          interpretation, never a certification.
        </LI>
        <LI>
          <b>Breakers.</b> Inside the expanded finding, the concrete adversarial input an attacker
          would type. Static strings with a copy button. Pre-Flight never runs them.
        </LI>
        <LI>
          <b>Explain &amp; Verify.</b> An optional pass that uses your own AI key (BYOK) to talk
          through the finding. The key goes straight from the tab to your provider.
        </LI>
        <LI>
          <b>Suppress.</b> Mark a finding handled or not-applicable. The decision is keyed to a
          stable id so it survives reformatting and re-scans.
        </LI>
      </ul>

      <H2>Coverage is scoped: not everything fires every time</H2>
      <P>
        Pre-Flight covers 14 languages. Every probe is scoped to the files and constructs it applies
        to. A Rust deserialization probe only looks at Rust; a Django setting probe only looks at
        Python config. On a single-language project the probes for other languages stay silent by
        design. You see signal for the code you actually wrote, not a wall of irrelevant checks.
      </P>

      <H2>The compliance lens</H2>
      <P>
        When a scan produces findings that map to a regulatory clause, a collapsible Regulatory
        mapping panel appears above the list. It rolls every mapping up by framework and clause so a
        non-coder can read the picture without opening 40 cards, and it exports a plain-text auditor
        handoff. It also states plainly what Pre-Flight does not scan. FERPA, SOX, FDA 21 CFR 11,
        FTC, and the EU AI Act are taught in the Learn pages, not detected, because they are not
        decidable from source code.
      </P>

      <H2>Learn</H2>
      <P>
        Every finding links to a write-up: what the pattern is, why AI emits it, what has gone wrong
        in the field, and how to fix it. The Learn tab also holds field reports on named incidents,
        the OWASP coverage map, a glossary, the Breakers catalogue, vetted external resources, and
        the compliance pages.
      </P>

      <H2>Re-scan, baseline, export</H2>
      <P>
        Scan the same source again and Pre-Flight shows the delta since last time: what is new, what
        is fixed, what is still open. Export the full result as JSON or Markdown, a PR comment, or
        an agent prompt. History and suppressions live in your browser only.
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
    </section>
  );
}
