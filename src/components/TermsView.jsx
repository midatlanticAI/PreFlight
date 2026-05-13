// src/components/TermsView.jsx
// The /terms route. Trust signal page paired with /privacy. Written in John's
// voice, not legalese. The terms are short because there is very little to
// agree to: it's free, it's open source, it doesn't run on a server you have
// to trust, and there is no warranty.

import { Link } from 'react-router-dom';
import { T, fontMono, fontUI } from '../lib/theme.js';

export function TermsView() {
  return (
    <article
      style={{
        maxWidth: 760,
        margin: '0 auto',
        fontFamily: fontUI,
        color: T.text,
        lineHeight: 1.7,
      }}
    >
      <div className="ap-eyebrow" style={{ marginBottom: 8 }}>
        PRE-FLIGHT
      </div>
      <h1
        className="ap-display"
        style={{ margin: '0 0 8px', fontSize: 34, fontWeight: 700, letterSpacing: '-0.01em' }}
      >
        Terms
      </h1>
      <p className="ap-mono" style={{ margin: '0 0 28px', fontSize: 12, color: T.textMuted }}>
        Effective 2026-05-13 · Mid-Atlantic AI ·{' '}
        <a href="mailto:john@midatlantic.ai" style={{ color: T.accent }}>
          john@midatlantic.ai
        </a>
      </p>

      <p style={{ fontSize: 16, color: T.text, marginBottom: 24 }}>
        Pre-Flight is a free, open-source, in-browser static security audit. There is no signup, no
        payment, no account, and no warranty. The short version of what follows is: use it, learn
        from it, ship safer code; we don’t guarantee it will catch every issue and we don’t promise
        it’s suitable for any particular purpose.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        What you can do with Pre-Flight
      </h2>
      <ul style={{ paddingLeft: 22, marginBottom: 22, color: T.textDim }}>
        <li>Use it to audit any code you have permission to audit, including your own.</li>
        <li>Run it on production and pre-production code.</li>
        <li>Export findings as JSON, Markdown, GitHub PR comment, or agent prompt.</li>
        <li>Fork the code under MIT license and run your own copy.</li>
        <li>Use the threat-intel data manifest under CC-BY-4.0 (credit Pre-Flight when you do).</li>
        <li>Build commercial products that include Pre-Flight code, subject to the MIT terms.</li>
      </ul>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        What you shouldn’t do with Pre-Flight
      </h2>
      <ul style={{ paddingLeft: 22, marginBottom: 22, color: T.textDim }}>
        <li>
          Don’t use it to audit code you don’t have permission to audit. The fact that public source
          code is publicly readable doesn’t automatically grant you permission to publish security
          findings about it.
        </li>
        <li>
          Don’t treat findings as a complete security review. Pre-Flight catches common static
          patterns. It does not perform dynamic testing, business-logic review, or live exploitation
          testing.
        </li>
        <li>
          Don’t treat a clean Pre-Flight report as a guarantee of security. The absence of findings
          means the absence of findings, not the absence of vulnerabilities.
        </li>
      </ul>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Licenses
      </h2>
      <p style={{ color: T.textDim, marginBottom: 12 }}>
        The codebase is split into two license tiers:
      </p>
      <ul style={{ paddingLeft: 22, marginBottom: 22, color: T.textDim }}>
        <li>
          <strong style={{ color: T.text }}>Code (MIT License):</strong> everything under{' '}
          <code className="ap-mono">src/</code>, <code className="ap-mono">public/</code>,{' '}
          <code className="ap-mono">.github/</code>, plus the config files and{' '}
          <code className="ap-mono">package.json</code>. Use it, fork it, integrate it, ship it. No
          attribution required for the source code itself.
        </li>
        <li>
          <strong style={{ color: T.text }}>Threat-intel data (CC-BY-4.0):</strong>{' '}
          <code className="ap-mono">src/data/compromised-packages.js</code> and any future{' '}
          <code className="ap-mono">src/data/*-data.{'{js,json}'}</code> manifests. Use the data,
          integrate it into your own scanner, but credit the source as “Mid-Atlantic AI / Pre-Flight
          Audit Tool.”
        </li>
      </ul>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Optional AI features (BYOK)
      </h2>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        The Explain &amp; Verify and Copy Agent Prompt features are optional. If you use Explain
        &amp; Verify, the AI request goes from your browser directly to the AI provider you
        configured. The provider’s terms govern that interaction. We charge nothing for the use of
        these features; your AI provider charges you whatever they charge. Pre-Flight has no billing
        relationship with your AI provider and no visibility into your usage.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        No warranty
      </h2>
      <p style={{ color: T.textDim, marginBottom: 12 }}>
        Pre-Flight is provided as-is. We make no warranty that it is fit for any particular purpose,
        that it will catch every vulnerability in the code you scan, that the threat-intel data is
        complete or current, or that the application will operate without interruption.
      </p>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        You use Pre-Flight at your own risk. If a Pre-Flight scan says your code is clean and you
        ship it and it turns out to have a serious vulnerability, that is on you, not on us. The
        same applies in the other direction: if Pre-Flight flags a finding you don’t think is real,
        the decision to ignore or suppress it is yours.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Limitation of liability
      </h2>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        To the maximum extent permitted by law, Mid-Atlantic AI and the contributors to Pre-Flight
        will not be liable for any direct, indirect, incidental, consequential, special, or
        exemplary damages arising out of your use of Pre-Flight, even where we have been advised of
        the possibility of such damages. The MIT license terms in the repository’s LICENSE file are
        the governing terms for the code; this clause is a plain-English summary of them.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Changes
      </h2>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        We may update Pre-Flight and these terms at any time. Material changes are tracked in the
        public git history at{' '}
        <a
          href="https://github.com/midatlanticAI/PreFlight"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: T.accent }}
        >
          github.com/midatlanticAI/PreFlight
        </a>
        . If you forked the project and don’t want our changes, your fork is the version that
        applies to you.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Contact
      </h2>
      <p style={{ color: T.textDim, marginBottom: 28 }}>
        Questions about these terms or how Pre-Flight is licensed: email{' '}
        <a href="mailto:john@midatlantic.ai" style={{ color: T.accent }}>
          john@midatlantic.ai
        </a>
        .
      </p>

      <p
        className="ap-mono"
        style={{
          fontSize: 12,
          color: T.textMuted,
          borderTop: `1px solid ${T.border}`,
          paddingTop: 16,
          fontFamily: fontMono,
        }}
      >
        See also:{' '}
        <Link to="/privacy" style={{ color: T.accent }}>
          Privacy
        </Link>{' '}
        ·{' '}
        <Link to="/learn" style={{ color: T.accent }}>
          Manifesto
        </Link>
      </p>
    </article>
  );
}
