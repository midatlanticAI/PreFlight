// src/components/settings/AboutTab.jsx
// About + Resources page. Licensing split, contributing info, contact, and a small
// links section pointing at the broader Mid-Atlantic AI footprint + the canonical
// reference sources the threat-intel manifest is built against.

import { Github, Mail, ExternalLink } from 'lucide-react';
import { T, fontMono } from '../../lib/theme.js';

const RESOURCES = [
  { label: 'Privacy', url: '/privacy' },
  { label: 'Terms', url: '/terms' },
  { label: 'Mid-Atlantic AI', url: 'https://midatlantic.ai' },
  { label: 'Vibe-Aware (in-app Learn corpus)', url: '/learn' },
  { label: 'OWASP coverage mapping', url: '/learn/owasp' },
  { label: 'Glossary', url: '/learn/glossary' },
  { label: 'Resources & best practices', url: '/learn/resources' },
  { label: 'OWASP Top 10 2025', url: 'https://owasp.org/Top10/' },
  { label: 'OWASP LLM Top 10 2025', url: 'https://genai.owasp.org/llm-top-10/' },
  { label: 'GitHub repo (MIT)', url: 'https://github.com/midatlanticAI/PreFlight' },
];

export function AboutTab() {
  return (
    <section>
      <h2 className="ap-display" style={{ margin: '0 0 14px', fontSize: 24, color: T.text }}>
        About
      </h2>

      <div className="ap-card" style={{ padding: 18, marginBottom: 14 }}>
        <p style={{ margin: '0 0 12px', fontSize: 15, color: T.textDim, lineHeight: 1.75 }}>
          I built and maintain PreFlight at Mid-Atlantic AI. No tracking, no analytics beacons, no
          account required. Everything runs in your browser tab. Nothing leaves your machine.
        </p>
        <ul
          style={{
            listStyle: 'none',
            padding: 0,
            margin: '0 0 12px',
            fontSize: 14,
            color: T.text,
            lineHeight: 1.9,
          }}
        >
          <li>
            <strong style={{ color: T.textDim }}>Code:</strong> MIT licensed.
          </li>
          <li>
            <strong style={{ color: T.textDim }}>Threat-intel data:</strong> CC-BY-4.0 (use freely
            with attribution).
          </li>
        </ul>
        <p style={{ margin: '0 0 8px', fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>
          Star the repo, file issues, or contribute probes:
        </p>
        <a
          href="https://github.com/midatlanticAI/PreFlight"
          target="_blank"
          rel="noopener noreferrer"
          className="ap-mono"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
            color: T.accent,
            fontSize: 14,
            marginBottom: 12,
          }}
        >
          <Github size={12} aria-hidden="true" />
          github.com/midatlanticAI/PreFlight
        </a>
        <p style={{ margin: 0, fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>
          Questions or feedback:{' '}
          <a
            href="mailto:john@midatlantic.ai"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 4,
              color: T.accent,
              fontFamily: fontMono,
              fontSize: 14,
            }}
          >
            <Mail size={11} aria-hidden="true" />
            john@midatlantic.ai
          </a>
        </p>
      </div>

      <div className="ap-card" style={{ padding: 18 }}>
        <h3 className="ap-eyebrow" style={{ margin: '0 0 12px', fontSize: 12, color: T.textMuted }}>
          RESOURCES
        </h3>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {RESOURCES.map(({ label, url }) => (
            <li key={label} style={{ marginBottom: 8 }}>
              {/* Internal /learn routes get a same-tab Link-style anchor (no target=_blank, no
                  external-link icon). External URLs open in a new tab. The distinction matters
                  for accessibility: internal navigation should not surprise the user with a new
                  tab. */}
              {url.startsWith('/') ? (
                <a
                  href={url}
                  className="ap-mono"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    color: T.accent,
                    fontSize: 14,
                  }}
                >
                  {label}
                </a>
              ) : (
                <a
                  href={url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ap-mono"
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    color: T.accent,
                    fontSize: 14,
                  }}
                >
                  {label}
                  <ExternalLink size={10} aria-hidden="true" />
                </a>
              )}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
