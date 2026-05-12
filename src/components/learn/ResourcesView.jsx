// src/components/learn/ResourcesView.jsx
// The "Resources" sub-tab under /learn. Curated external links grouped by
// discipline, plus a short framing paragraph per group so the link list is
// not just decoration.
//
// Voice: Demi register. Mechanics-instructor, concrete-first, no marketing
// prose, no fear framing. Each section opens with what the discipline is and
// where the reader should start, then enumerates the authoritative sources.
//
// No competitor names. Sources cite OWASP, MITRE/CWE, CISA, vendor docs,
// W3C / WAI, MDN, and similar reference authorities.

import { ExternalLink } from 'lucide-react';
import { T, fontUI, fontMono } from '../../lib/theme.js';

const SECTIONS = [
  {
    id: 'engineering',
    title: 'Engineering discipline',
    intro:
      'How code is structured, named, organized, and reviewed. Vibe-coded apps reach the same bar as hand-written code only when these are deliberately practiced, not assumed.',
    links: [
      {
        title: '12-Factor App',
        url: 'https://12factor.net/',
        note: 'The reference model for SaaS apps that are configurable, deployable, and operable. Twelve principles, each worth internalizing.',
      },
      {
        title: 'Google Engineering Practices Documentation',
        url: 'https://google.github.io/eng-practices/',
        note: 'Open-sourced internal docs on code review (both as reviewer and as author). Short, practical, free.',
      },
      {
        title: 'OpenAPI Specification',
        url: 'https://www.openapis.org/',
        note: 'The standard way to describe an HTTP API. Type-safe clients, generated docs, contract tests.',
      },
      {
        title: 'Conventional Commits',
        url: 'https://www.conventionalcommits.org/',
        note: 'A small spec for commit messages that pays for itself in auto-generated changelogs and PR review speed.',
      },
      {
        title: 'TypeScript Handbook',
        url: 'https://www.typescriptlang.org/docs/handbook/intro.html',
        note: 'The closer-to-canon reference for TypeScript itself. Better than most blog posts that claim to summarize it.',
      },
    ],
  },
  {
    id: 'security',
    title: 'Application security',
    intro:
      'The authoritative references behind most of Pre-Flight\'s probes. Read OWASP first; everything else makes more sense after it.',
    links: [
      {
        title: 'OWASP Top 10 (2025)',
        url: 'https://owasp.org/Top10/',
        note: 'The ten highest-prevalence application-security risks. Each entry has a "what to do about it" section.',
      },
      {
        title: 'OWASP LLM Top 10 (2025)',
        url: 'https://genai.owasp.org/llm-top-10/',
        note: 'The LLM-specific equivalent. Covers prompt injection, sensitive information disclosure, agent autonomy, and seven more.',
      },
      {
        title: 'OWASP API Security Top 10',
        url: 'https://owasp.org/API-Security/',
        note: 'For HTTP-only systems (no UI rendering), this is the more relevant list.',
      },
      {
        title: 'OWASP Cheat Sheet Series',
        url: 'https://cheatsheetseries.owasp.org/',
        note: 'Concrete how-to guidance per topic. Auth, sessions, JWT, CORS, XSS, CSP, every concrete control.',
      },
      {
        title: 'MITRE CWE',
        url: 'https://cwe.mitre.org/',
        note: 'Common Weakness Enumeration. The taxonomy every CVE traces back to. Pre-Flight findings carry CWE IDs that link here.',
      },
      {
        title: 'CISA Cybersecurity Advisories',
        url: 'https://www.cisa.gov/news-events/cybersecurity-advisories',
        note: 'US-government threat intel. The named actor groups, the active campaigns, the patch advisories.',
      },
    ],
  },
  {
    id: 'design',
    title: 'Design and UX',
    intro:
      'A vibe-built app can be functionally correct and still unusable. Design references that produce usable, accessible interfaces by default.',
    links: [
      {
        title: 'Refactoring UI',
        url: 'https://www.refactoringui.com/',
        note: 'The most practical "design for developers" reference in print. Concrete rules with worked examples.',
      },
      {
        title: 'Nielsen Norman Group articles',
        url: 'https://www.nngroup.com/articles/',
        note: 'Forty years of UX research, summarized in readable articles. The reference for how users actually behave.',
      },
      {
        title: 'Refactoring.Guru — Design Patterns',
        url: 'https://refactoring.guru/design-patterns',
        note: 'Software design patterns explained with diagrams and worked code. Maps to Drew\'s rules surface in v1.1.',
      },
      {
        title: 'Material Design',
        url: 'https://m3.material.io/',
        note: 'A complete design system with research-backed defaults. Even if you don\'t adopt it wholesale, the rationale per component is valuable.',
      },
    ],
  },
  {
    id: 'accessibility',
    title: 'Accessibility',
    intro:
      '15-20% of users need accessibility considerations. The guidelines below are what regulators look at and what assistive tech expects. Pre-Flight\'s A11y Landmarks probe surfaces a subset.',
    links: [
      {
        title: 'WCAG 2.2',
        url: 'https://www.w3.org/TR/WCAG22/',
        note: 'The authoritative web accessibility guidelines. Read the success criteria (numbered like 2.4.7) not the principles overview.',
      },
      {
        title: 'WebAIM',
        url: 'https://webaim.org/',
        note: 'Practical accessibility guidance and the WebAIM Million annual report on real-world site accessibility.',
      },
      {
        title: 'MDN — Accessibility',
        url: 'https://developer.mozilla.org/en-US/docs/Web/Accessibility',
        note: 'Reference docs for ARIA roles, accessible patterns, and browser-level accessibility APIs.',
      },
      {
        title: 'Inclusive Components',
        url: 'https://inclusive-components.design/',
        note: 'A book\'s worth of "how to build common UI components accessibly," free online.',
      },
    ],
  },
  {
    id: 'audit',
    title: 'Audit and review',
    intro:
      'Pre-Flight is one audit surface. The broader practice of code and security review is its own discipline.',
    links: [
      {
        title: 'OWASP Code Review Guide',
        url: 'https://owasp.org/www-project-code-review-guide/',
        note: 'A long PDF covering how to do an application security code review end to end.',
      },
      {
        title: 'Stripe API Review (engineering blog)',
        url: 'https://stripe.com/blog/api-versioning',
        note: 'Worked example of how Stripe versions its API for a decade-plus without breaking integrations. The audit discipline at scale.',
      },
      {
        title: 'GitHub Security Lab',
        url: 'https://securitylab.github.com/',
        note: 'Open-source advisories, CodeQL queries, and write-ups of real bugs. Excellent for learning how vulnerabilities actually present.',
      },
    ],
  },
  {
    id: 'supply-chain',
    title: 'Supply chain',
    intro:
      'The 2025-2026 wave of npm worms ([Shai-Hulud](/learn/incidents/mini-shai-hulud-tanstack-2026-05), [Sapphire Sleet](/learn/incidents/sapphire-sleet-axios-2026-03), [Bitwarden CLI](/learn/incidents/intercom-client-bitwarden-cli-2026-04)) was a wake-up call. The references below carry the discipline forward.',
    links: [
      {
        title: 'SLSA (Supply-chain Levels for Software Artifacts)',
        url: 'https://slsa.dev/',
        note: 'A framework for build-pipeline integrity. Note SLSA verifies the pipeline; it does not verify the code being built.',
      },
      {
        title: 'CNCF Supply Chain Security Whitepaper',
        url: 'https://github.com/cncf/tag-security/tree/main/community/working-groups/supply-chain-security',
        note: 'The cloud-native ecosystem\'s framing of supply-chain risk. Vendor-neutral.',
      },
      {
        title: 'OpenSSF Best Practices Badge',
        url: 'https://www.bestpractices.dev/',
        note: 'A self-assessment for open-source projects. Useful as a checklist for any project you depend on.',
      },
      {
        title: 'npm Docs — Audit and signed packages',
        url: 'https://docs.npmjs.com/cli/v10/commands/npm-audit',
        note: 'The official reference for `npm audit`, `npm sign`, and registry-side controls.',
      },
    ],
  },
  {
    id: 'observability',
    title: 'Observability and operations',
    intro:
      'What happens after the audit. Logs, metrics, traces, alerting, and the discipline of running production.',
    links: [
      {
        title: 'OpenTelemetry',
        url: 'https://opentelemetry.io/',
        note: 'The cross-vendor standard for tracing, metrics, and logs. Stops you from being locked into one observability vendor.',
      },
      {
        title: 'Google SRE Books',
        url: 'https://sre.google/books/',
        note: 'Two free books on running production at Google scale. Even if you operate at much smaller scale, the discipline is portable.',
      },
      {
        title: 'CNCF Observability Whitepaper',
        url: 'https://github.com/cncf/tag-observability/blob/main/whitepaper.md',
        note: 'Vendor-neutral framing of what observability means and what it costs.',
      },
    ],
  },
  {
    id: 'ai-coding',
    title: 'AI-assisted coding',
    intro:
      'The audience Pre-Flight is built for. References for using AI coding tools deliberately rather than incidentally.',
    links: [
      {
        title: 'Anthropic — Engineering with Claude',
        url: 'https://www.anthropic.com/engineering',
        note: 'Anthropic\'s own writing on how Claude is built and how to use it well.',
      },
      {
        title: 'OpenAI — Best Practices for Production',
        url: 'https://platform.openai.com/docs/guides/production-best-practices',
        note: 'OpenAI\'s production guidance for API consumers. Rate limits, retries, prompt design.',
      },
      {
        title: 'simonwillison.net — LLM tag',
        url: 'https://simonwillison.net/tags/llms/',
        note: 'Simon Willison\'s ongoing notes on LLM tooling. Detailed, pragmatic, well-cited.',
      },
      {
        title: 'Model Context Protocol Specification',
        url: 'https://modelcontextprotocol.io/',
        note: 'The MCP spec, the same one Pre-Flight\'s MCP Security probe references.',
      },
    ],
  },
];

function Section({ section }) {
  return (
    <section
      id={section.id}
      aria-labelledby={`${section.id}-heading`}
      style={{ marginBottom: 32 }}
    >
      <h2
        id={`${section.id}-heading`}
        className="ap-display"
        style={{
          margin: '0 0 8px',
          fontSize: 21,
          fontWeight: 700,
          color: T.text,
        }}
      >
        {section.title}
      </h2>
      <p style={{ margin: '0 0 14px', fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>
        {section.intro}
      </p>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {section.links.map((link) => (
          <li
            key={link.url}
            style={{
              padding: '13px 16px',
              marginBottom: 8,
              background: T.panel,
              border: `1px solid ${T.border}`,
              borderLeft: `3px solid ${T.borderAlt}`,
            }}
          >
            <a
              href={link.url}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                color: T.accent,
                fontFamily: fontUI,
                fontSize: 15,
                fontWeight: 600,
                textDecoration: 'none',
                marginBottom: 4,
              }}
            >
              {link.title}
              <ExternalLink size={12} aria-hidden="true" />
            </a>
            <div
              className="ap-mono"
              style={{
                fontSize: 11,
                color: T.textMuted,
                fontFamily: fontMono,
                marginBottom: 5,
                wordBreak: 'break-all',
              }}
            >
              {link.url}
            </div>
            <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>{link.note}</div>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function ResourcesView() {
  return (
    <section aria-labelledby="resources-heading">
      <h1
        id="resources-heading"
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        Resources
      </h1>
      <p style={{ color: T.textMuted, fontSize: 14, margin: '0 0 24px', maxWidth: 720, lineHeight: 1.6 }}>
        Curated external references. The first place to go for each discipline, picked for being
        authoritative and freely readable rather than for being recent. Every link opens in a new tab.
      </p>

      {/* Anchor nav: quick links to sections without scrolling. */}
      <nav
        aria-label="Resource section index"
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 6,
          marginBottom: 24,
          padding: 12,
          background: T.bg,
          border: `1px solid ${T.border}`,
        }}
      >
        {SECTIONS.map((s) => (
          <a
            key={s.id}
            href={`#${s.id}`}
            className="ap-mono"
            style={{
              fontSize: 11,
              padding: '5px 10px',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              textDecoration: 'none',
              letterSpacing: '0.06em',
              textTransform: 'uppercase',
            }}
          >
            {s.title}
          </a>
        ))}
      </nav>

      {SECTIONS.map((s) => (
        <Section key={s.id} section={s} />
      ))}

      <p
        style={{
          margin: '32px 0 0',
          padding: 16,
          fontSize: 13,
          color: T.textMuted,
          lineHeight: 1.6,
          background: T.bg,
          border: `1px dashed ${T.border}`,
        }}
      >
        Spot a broken link or a reference that should be here? File an issue or open a PR at{' '}
        <a
          href="https://github.com/midatlanticAI/PreFlight"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: T.accent }}
        >
          github.com/midatlanticAI/PreFlight
        </a>
        . The list lives in <code className="ap-mono">src/components/learn/ResourcesView.jsx</code>{' '}
        and is reviewed against Demi&apos;s voice rules before merge.
      </p>
    </section>
  );
}
