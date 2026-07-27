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
      "The authoritative references behind most of PreFlight's probes. Read OWASP first; everything else makes more sense after it.",
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
        note: 'Common Weakness Enumeration. The taxonomy every CVE traces back to. PreFlight findings carry CWE IDs that link here.',
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
      'A vibe-built app can be functionally correct and still unusable. Free design references that produce usable, accessible interfaces by default.',
    links: [
      {
        title: 'Practical Typography (Matthew Butterick)',
        url: 'https://practicaltypography.com/',
        note: 'A free book on typography written for working developers. The opinionated defaults section alone is worth reading.',
      },
      {
        title: 'Nielsen Norman Group articles',
        url: 'https://www.nngroup.com/articles/',
        note: 'Forty years of UX research, summarized in readable articles. The reference for how users actually behave.',
      },
      {
        title: 'Refactoring.Guru — Design Patterns',
        url: 'https://refactoring.guru/design-patterns',
        note: 'Software design patterns explained with diagrams and worked code.',
      },
      {
        title: 'Material Design 3',
        url: 'https://m3.material.io/',
        note: "A complete design system with research-backed defaults. Even if you don't adopt it wholesale, the rationale per component is valuable.",
      },
      {
        title: 'Apple Human Interface Guidelines',
        url: 'https://developer.apple.com/design/human-interface-guidelines',
        note: "Apple's reference for what good UI feels like across their platforms. Free.",
      },
      {
        title: 'IBM Carbon Design System',
        url: 'https://carbondesignsystem.com/',
        note: "IBM's open-source design system. Tokens, components, patterns, all documented.",
      },
      {
        title: 'Atlassian Design System',
        url: 'https://atlassian.design/',
        note: "Atlassian's design system. Strong on collaboration / workflow patterns.",
      },
    ],
  },
  {
    id: 'cs-fundamentals',
    title: 'CS fundamentals',
    intro:
      'If you came up without a CS degree and want to fill in the gaps, this is where to start. Free curricula and textbooks. Stop pretending you have to pay $10k to learn what a hash table is.',
    links: [
      {
        title: 'Harvard CS50',
        url: 'https://cs50.harvard.edu/',
        note: 'Harvard\'s intro CS course. Free to audit on edX, full lecture videos on YouTube. The default "where do I start" answer.',
      },
      {
        title: 'Teach Yourself Computer Science',
        url: 'https://teachyourselfcs.com/',
        note: 'A curated curriculum of nine free university-grade CS courses + textbooks, in recommended order.',
      },
      {
        title: 'Open Source Society University (CS)',
        url: 'https://github.com/ossu/computer-science',
        note: 'A community-curated CS degree using only free online materials. Path through algorithms, systems, theory, AI.',
      },
      {
        title: 'MIT Missing Semester',
        url: 'https://missing.csail.mit.edu/',
        note: 'The class that teaches the tooling no CS program does: shell, vim, git, debugging, profiling, security tools.',
      },
      {
        title: 'MIT OpenCourseWare',
        url: 'https://ocw.mit.edu/',
        note: 'Free lecture notes, problem sets, and (often) video from most MIT undergrad classes including the entire 6.xxx CS sequence.',
      },
      {
        title: 'Crafting Interpreters',
        url: 'https://craftinginterpreters.com/',
        note: 'A free book that builds a working programming language from scratch. The clearest single text on how compilers work.',
      },
      {
        title: 'Open Data Structures',
        url: 'https://opendatastructures.org/',
        note: 'A free textbook covering every data structure a working developer encounters.',
      },
      {
        title: 'The Algorithms (GitHub)',
        url: 'https://github.com/TheAlgorithms',
        note: "Reference implementations of every standard algorithm in every common language. Read, don't paste.",
      },
      {
        title: 'freeCodeCamp',
        url: 'https://www.freecodecamp.org/',
        note: 'Free, hands-on, browser-based curriculum across CS, web dev, data, ML, security. Verified certifications, no paywall.',
      },
      {
        title: 'roadmap.sh',
        url: 'https://roadmap.sh/',
        note: 'Visual roadmaps for major paths (frontend, backend, devops, AI engineer, etc.) linking to free resources.',
      },
    ],
  },
  {
    id: 'architecture-knowledge',
    title: 'Software architecture',
    intro:
      'Once you have more than one moving part, you need a vocabulary for how the pieces fit. Free references; the field has more good free writing than good paid books.',
    links: [
      {
        title: "Martin Fowler's bliki",
        url: 'https://martinfowler.com/bliki/',
        note: "Martin Fowler's long-running architecture blog. Microservices, CQRS, event sourcing, the original sources for many terms.",
      },
      {
        title: 'Software Engineering at Google (free PDF)',
        url: 'https://abseil.io/resources/swe-book',
        note: "O'Reilly published it as a book; Google posts the full PDF free. How engineering works at scale.",
      },
      {
        title: 'Google SRE books (free online)',
        url: 'https://sre.google/books/',
        note: 'Two free books on running production. SRE Book + Workbook. The reference for the SLO/SLI/error-budget vocabulary.',
      },
      {
        title: 'AWS Well-Architected Framework',
        url: 'https://aws.amazon.com/architecture/well-architected/',
        note: "AWS's framework for designing reliable, secure, efficient, sustainable workloads. Vendor-flavored but transferable.",
      },
      {
        title: 'Microsoft Azure Architecture Center',
        url: 'https://learn.microsoft.com/en-us/azure/architecture/',
        note: "Microsoft's catalog of architecture patterns with worked examples per pattern. Free.",
      },
      {
        title: 'High Scalability',
        url: 'https://highscalability.com/',
        note: 'A long-running blog featuring detailed writeups of how real systems at scale are built. Mostly free.',
      },
      {
        title: 'Papers We Love',
        url: 'https://paperswelove.org/',
        note: 'A community curating classic and current CS papers. Distributed systems, databases, programming languages, security.',
      },
      {
        title: "Pat Helland's papers",
        url: 'https://www.microsoft.com/en-us/research/people/phelland/',
        note: 'One of the clearest writers in distributed systems. "Life Beyond Distributed Transactions" is mandatory.',
      },
      {
        title: 'CNCF Cloud Native Glossary',
        url: 'https://glossary.cncf.io/',
        note: 'The cross-vendor reference for cloud-native terminology. Pairs well with our internal glossary.',
      },
    ],
  },
  {
    id: 'deep-learning',
    title: 'Deep learning and AI engineering',
    intro:
      "If you're shipping AI features, this is the ground floor. All free, all from the people actually building the field.",
    links: [
      {
        title: 'fast.ai',
        url: 'https://www.fast.ai/',
        note: 'The two free deep-learning courses everyone recommends. Practical Deep Learning for Coders is the entry point.',
      },
      {
        title: 'Hugging Face Course',
        url: 'https://huggingface.co/learn',
        note: 'Free courses on NLP, audio, computer vision, RL, agents. Hands-on with the ecosystem most people actually use.',
      },
      {
        title: 'Andrej Karpathy — Neural Networks: Zero to Hero',
        url: 'https://karpathy.ai/zero-to-hero.html',
        note: "A free YouTube series that builds up to GPT-style models from scratch. The closest to first-principles you'll find.",
      },
      {
        title: 'Deep Learning (Goodfellow, Bengio, Courville)',
        url: 'https://www.deeplearningbook.org/',
        note: 'The reference textbook. The complete book is free online. Heavy on theory; pair with hands-on courses.',
      },
      {
        title: 'Dive into Deep Learning',
        url: 'https://d2l.ai/',
        note: 'A free interactive textbook with code in PyTorch, TensorFlow, JAX, MXNet. Used in 500+ universities.',
      },
      {
        title: '3Blue1Brown — Neural Networks',
        url: 'https://www.3blue1brown.com/topics/neural-networks',
        note: 'The visualization series that finally makes backpropagation make sense. Free.',
      },
      {
        title: 'Distill.pub',
        url: 'https://distill.pub/',
        note: 'Long-form interactive explainers of deep learning research. Inactive since 2021 but the archive is gold.',
      },
      {
        title: 'Stanford CS231n / CS229 / CS224N',
        url: 'https://cs231n.stanford.edu/',
        note: "Stanford's computer-vision, ML, and NLP courses. Lecture videos and assignments posted free.",
      },
      {
        title: 'MIT 6.S191 — Introduction to Deep Learning',
        url: 'https://introtodeeplearning.com/',
        note: "MIT's intro DL course. New videos each year, all free, with labs.",
      },
      {
        title: 'Anthropic Cookbook',
        url: 'https://github.com/anthropics/anthropic-cookbook',
        note: 'Hands-on examples for building with Claude. Tool use, agents, RAG, evaluations.',
      },
      {
        title: 'OpenAI Cookbook',
        url: 'https://cookbook.openai.com/',
        note: "OpenAI's recipes for embeddings, RAG, function calling, fine-tuning, evaluation. Free.",
      },
      {
        title: 'LangChain documentation',
        url: 'https://python.langchain.com/docs/get_started/introduction',
        note: 'The most-cited agent / chain framework. Docs are free; the framework decisions are opinionated.',
      },
    ],
  },
  {
    id: 'accessibility',
    title: 'Accessibility',
    intro:
      "15-20% of users need accessibility considerations. The guidelines below are what regulators look at and what assistive tech expects. PreFlight's A11y Landmarks probe surfaces a subset.",
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
      'PreFlight is one audit surface. The broader practice of code and security review is its own discipline.',
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
        note: "The cloud-native ecosystem's framing of supply-chain risk. Vendor-neutral.",
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
      'The audience PreFlight is built for. References for using AI coding tools deliberately rather than incidentally.',
    links: [
      {
        title: 'Anthropic — Engineering with Claude',
        url: 'https://www.anthropic.com/engineering',
        note: "Anthropic's own writing on how Claude is built and how to use it well.",
      },
      {
        title: 'OpenAI — Best Practices for Production',
        url: 'https://platform.openai.com/docs/guides/production-best-practices',
        note: "OpenAI's production guidance for API consumers. Rate limits, retries, prompt design.",
      },
      {
        title: 'simonwillison.net — LLM tag',
        url: 'https://simonwillison.net/tags/llms/',
        note: "Simon Willison's ongoing notes on LLM tooling. Detailed, pragmatic, well-cited.",
      },
      {
        title: 'Model Context Protocol Specification',
        url: 'https://modelcontextprotocol.io/',
        note: "The MCP spec, the same one PreFlight's MCP Security probe references.",
      },
    ],
  },
];

function Section({ section }) {
  return (
    <section id={section.id} aria-labelledby={`${section.id}-heading`} style={{ marginBottom: 32 }}>
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
      <p
        style={{
          color: T.textMuted,
          fontSize: 14,
          margin: '0 0 8px',
          maxWidth: 720,
          lineHeight: 1.6,
        }}
      >
        Curated external references. The first place to go for each discipline, picked for being
        authoritative and freely readable. Every link opens in a new tab.
      </p>
      <p
        style={{
          color: T.textMuted,
          fontSize: 13,
          margin: '0 0 24px',
          maxWidth: 720,
          lineHeight: 1.6,
          fontStyle: 'italic',
        }}
      >
        Inclusion criterion: free or zero-friction free tier. No paywalled books, no "free trial
        that converts to paid", no marketing-gated PDFs. If a course costs money for the certificate
        but is free to audit, it's listed. If a book has its full text online for free, it's listed;
        if it doesn't, it isn't. The bar is "a viber on hopes and dreams and empty wallets can use
        this today."
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
