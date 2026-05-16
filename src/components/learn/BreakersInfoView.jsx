// src/components/learn/BreakersInfoView.jsx
//
// The "Breakers" sub-tab under /learn. Explains what the Breakers feature
// is, the static-only safety contract, and lists which probes currently
// have a Breakers catalogue.
//
// Voice: Demi register. The page is reference + framing material. No
// marketing prose. The safety section is load-bearing.

import { ShieldAlert, AlertTriangle, ExternalLink } from 'lucide-react';
import { BREAKERS, getBreakersCount, getBreakersProbeCount } from '../../lib/breakers.js';
import { PROBE_META } from '../../lib/stable-id.js';
import { resolvePatternForProbe } from '../../lib/learn-content.js';
import { T, fontMono } from '../../lib/theme.js';

export function BreakersInfoView() {
  const totalEntries = getBreakersCount();
  const totalProbes = getBreakersProbeCount();
  const orderedProbes = Object.keys(BREAKERS).sort();

  return (
    <section aria-labelledby="breakers-heading">
      <h1
        id="breakers-heading"
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        Breakers
      </h1>
      <p
        style={{
          color: T.textMuted,
          fontSize: 14,
          margin: '0 0 18px',
          maxWidth: 720,
          lineHeight: 1.6,
        }}
      >
        Breakers are the concrete adversarial inputs paired with each finding. When you
        expand a finding, you see what an attacker would type or upload to exploit it. {totalEntries}{' '}
        entries across {totalProbes} probe classes, growing as new probes ship.
      </p>

      <section
        aria-labelledby="breakers-safety-heading"
        style={{
          marginBottom: 24,
          padding: 16,
          background: T.panel,
          border: `1px solid ${T.border}`,
          borderLeft: `3px solid ${T.accent}`,
        }}
      >
        <h2
          id="breakers-safety-heading"
          className="ap-display"
          style={{
            margin: '0 0 10px',
            fontSize: 16,
            fontWeight: 700,
            color: T.text,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <ShieldAlert size={14} color={T.accent} aria-hidden="true" />
          Static-only safety contract
        </h2>
        <ul style={{ margin: 0, paddingLeft: 18, color: T.textDim, fontSize: 14, lineHeight: 1.7 }}>
          <li>Every Breaker entry is a <strong style={{ color: T.text }}>string</strong>. We render it; we never execute it.</li>
          <li>Pre-Flight does not send the payload anywhere. The Copy button writes to your clipboard only when you click it.</li>
          <li>No payload references a real production hostname; placeholders only (example.com, attacker.example).</li>
          <li>No payload includes a real credential, token, or working exploit against a named third party.</li>
          <li>The contract is enforced by tests under <code className="ap-mono">src/test/breakers.test.js</code>: payload-only, anonymized hosts, no credential-shaped values.</li>
        </ul>
      </section>

      <section
        style={{
          marginBottom: 24,
          padding: 14,
          background: T.bg,
          border: `1px dashed ${T.borderAlt}`,
          fontSize: 13,
          color: T.textMuted,
          lineHeight: 1.6,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
          <AlertTriangle size={12} color={T.textMuted} aria-hidden="true" style={{ flexShrink: 0, marginTop: 3 }} />
          <span>
            Use these on systems you own or have explicit authorization to test. Replaying these
            against systems you do not own is unauthorized access in most jurisdictions. Breakers
            exist to help you reproduce a finding in a dev environment so you can confirm the fix,
            not as a how-to for hitting somebody else.
          </span>
        </div>
      </section>

      <h2
        className="ap-display"
        style={{ margin: '0 0 8px', fontSize: 18, fontWeight: 700, color: T.text }}
      >
        Coverage by probe
      </h2>
      <p style={{ margin: '0 0 14px', fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>
        Each probe listed below has one or more Breaker entries shown alongside its findings on
        the scan page. Click a probe name to open the matching pattern explainer.
      </p>

      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {orderedProbes.map((probeName) => {
          const entries = BREAKERS[probeName];
          const slug = PROBE_META[probeName]?.learn_more_slug;
          const pattern = slug ? resolvePatternForProbe(slug) : null;
          const linkBody = (
            <span
              className="ap-display"
              style={{ fontSize: 14, fontWeight: 700, color: T.text }}
            >
              {probeName}
            </span>
          );
          return (
            <li
              key={probeName}
              style={{
                padding: 12,
                marginBottom: 8,
                background: T.panel,
                border: `1px solid ${T.border}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                gap: 12,
              }}
            >
              <div style={{ minWidth: 0 }}>
                {pattern ? (
                  <a
                    href={`/learn/patterns/${slug}`}
                    style={{
                      textDecoration: 'none',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 6,
                    }}
                  >
                    {linkBody}
                    <ExternalLink size={10} aria-hidden="true" color={T.textMuted} />
                  </a>
                ) : (
                  linkBody
                )}
                <div
                  className="ap-mono"
                  style={{ fontSize: 11, color: T.textMuted, marginTop: 3 }}
                >
                  {entries.map((e) => e.name).join(' · ')}
                </div>
              </div>
              <span
                className="ap-mono"
                style={{
                  fontSize: 11,
                  padding: '2px 8px',
                  background: T.bg,
                  border: `1px solid ${T.border}`,
                  color: T.textDim,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  whiteSpace: 'nowrap',
                }}
              >
                {entries.length}× breaker{entries.length === 1 ? '' : 's'}
              </span>
            </li>
          );
        })}
      </ul>

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
        Data lives in <code>src/lib/breakers.js</code>; the contract is enforced by{' '}
        <code>src/test/breakers.test.js</code>. Breakers v1 ships on the
        <code> feature/breakers-v1</code> branch; v1 is static-only by design. A DAST-style
        execution surface is explicitly out of scope.
      </p>
    </section>
  );
}
