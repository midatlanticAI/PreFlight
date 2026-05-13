// src/components/PrivacyView.jsx
// The /privacy route. Trust signal page for "where are your privacy terms?"
// Written in John's voice, not legalese. The architecture enforces the claims;
// this page just names them in the order someone evaluating Pre-Flight expects
// to see them.

import { Link } from 'react-router-dom';
import { T, fontMono, fontUI } from '../lib/theme.js';

export function PrivacyView() {
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
        Privacy
      </h1>
      <p className="ap-mono" style={{ margin: '0 0 28px', fontSize: 12, color: T.textMuted }}>
        Effective 2026-05-13 · Mid-Atlantic AI · <a href="mailto:john@midatlantic.ai" style={{ color: T.accent }}>john@midatlantic.ai</a>
      </p>

      <p style={{ fontSize: 16, color: T.text, marginBottom: 24 }}>
        Pre-Flight is a static security audit that runs entirely in your browser tab. The privacy
        story below isn’t a promise. It’s a description of how the app is built. There is no
        backend that could leak your data because there is no backend.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        What we don’t do
      </h2>
      <ul style={{ paddingLeft: 22, marginBottom: 22, color: T.textDim }}>
        <li>No account, no signup, no login.</li>
        <li>No analytics SDK. No tracking pixels. No fingerprinting.</li>
        <li>No remote telemetry. No “anonymous usage” beacons.</li>
        <li>No advertising. No third-party trackers.</li>
        <li>No cookies set by Pre-Flight.</li>
        <li>No upload of your source code to Mid-Atlantic AI infrastructure. Ever.</li>
      </ul>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        What stays in your browser
      </h2>
      <p style={{ color: T.textDim, marginBottom: 12 }}>
        Pre-Flight uses your browser’s localStorage to remember the following between visits. It
        never leaves your machine.
      </p>
      <ul style={{ paddingLeft: 22, marginBottom: 22, color: T.textDim }}>
        <li>Your last few scan results (up to 10, so you can view or re-run).</li>
        <li>Your suppression decisions (false-positive / wont-fix / accepted-risk tags).</li>
        <li>Your AI provider configuration if you set one up (provider name, model, API key).</li>
        <li>Your GitHub personal access token if you set one up for private repo scanning.</li>
        <li>A counter of local actions (scans started, exports clicked) used only to populate the
          Diagnostics panel you can view yourself in Settings.</li>
      </ul>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        You can clear all of it at any time by clearing site data for preflight.midatlantic.ai in
        your browser. The Settings → Diagnostics tab also has a Reset Counters control for the
        local action counter.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        When AI features run
      </h2>
      <p style={{ color: T.textDim, marginBottom: 12 }}>
        Pre-Flight ships two optional AI surfaces. Both use your own credentials and run entirely
        in your browser.
      </p>
      <ul style={{ paddingLeft: 22, marginBottom: 22, color: T.textDim }}>
        <li>
          <strong style={{ color: T.text }}>Copy Agent Prompt:</strong> formats a prompt and writes
          it to your clipboard. You paste it into whatever AI tool you already use. Pre-Flight does
          not execute the prompt and does not know whether you used it.
        </li>
        <li>
          <strong style={{ color: T.text }}>Explain &amp; Verify:</strong> if you’ve configured an
          AI provider in Settings, clicking this button sends a single finding to your chosen
          provider using your API key. The request goes from your browser directly to your provider
          (api.openai.com, api.anthropic.com, etc.). Pre-Flight’s origin never sees the request,
          the response, or your API key. Whatever the AI provider does with the request is governed
          by their terms.
        </li>
      </ul>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        When you scan a GitHub URL
      </h2>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        Your browser fetches the repository contents from raw.githubusercontent.com directly.
        Pre-Flight’s origin never sees the URL or the source code. GitHub’s servers see the
        request the same way they would for any browser visiting a public repo.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        What our infrastructure does see
      </h2>
      <p style={{ color: T.textDim, marginBottom: 12 }}>
        Pre-Flight is hosted on Cloudflare Pages. At the edge, Cloudflare records standard
        server-access data for every static asset request (your IP address, the file path you
        requested, the user agent, a timestamp). This logging happens for every site hosted on
        Cloudflare and exists for reliability, abuse prevention, and DDoS mitigation. We do not
        operate or have direct access to the raw logs; they live with Cloudflare under their own
        operational controls.
      </p>
      <p style={{ color: T.textDim, marginBottom: 12 }}>
        Cloudflare aggregates that data into a site-metrics dashboard the Pre-Flight maintainers
        can view. The dashboard shows aggregate counts: page views per path (e.g., how many people
        opened <code className="ap-mono">/learn/glossary</code> last week), bandwidth used, country-
        level geographic distribution, top referring domains, HTTP status codes. We use it to
        answer questions like "is the site being used" and "which Learn pages do people actually
        open." We do not use it, and cannot use it, to identify individual users, follow
        sessions, build behavior funnels, or correlate visits across time.
      </p>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        Pre-Flight has not added any analytics JavaScript to the page. There is no Google
        Analytics, no Plausible, no Fathom, no third-party tracking SDK, no fingerprinting library.
        The aggregation in the paragraph above happens at Cloudflare’s edge from the access logs
        they already generate. Your browser does not run any tracking code that Pre-Flight
        installed.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Changes and audit trail
      </h2>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        Pre-Flight is open source. Every change to the application, including changes to this
        policy, is publicly tracked in the git history at{' '}
        <a
          href="https://github.com/midatlanticAI/PreFlight"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: T.accent }}
        >
          github.com/midatlanticAI/PreFlight
        </a>
        . If you want to verify any claim on this page, check the source.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Children
      </h2>
      <p style={{ color: T.textDim, marginBottom: 22 }}>
        Pre-Flight does not collect any data about anyone, including children. We don’t target the
        service to children specifically. If you are under 13, the privacy controls above apply to
        you the same way they apply to every other visitor.
      </p>

      <h2 className="ap-display" style={{ fontSize: 20, marginTop: 28, marginBottom: 10 }}>
        Contact
      </h2>
      <p style={{ color: T.textDim, marginBottom: 28 }}>
        Questions, corrections, or a request to remove access-log data: email{' '}
        <a href="mailto:john@midatlantic.ai" style={{ color: T.accent }}>
          john@midatlantic.ai
        </a>
        . We typically respond within a week.
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
        See also: <Link to="/terms" style={{ color: T.accent }}>Terms</Link> ·{' '}
        <Link to="/learn" style={{ color: T.accent }}>Manifesto</Link>
      </p>
    </article>
  );
}
