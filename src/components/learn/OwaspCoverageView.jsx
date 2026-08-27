// src/components/learn/OwaspCoverageView.jsx
//
// The "OWASP" sub-tab under /learn. Maps every PreFlight probe to the OWASP
// Top 10 2025 and OWASP LLM Top 10 2026 categories it covers. The mapping
// data lives in src/lib/stable-id.js (PROBE_OWASP_MAP + OWASP_LABELS); this
// component just renders it.
//
// Voice: Demi register. The page is reference material, so each section is
// brief: the category code, the human-readable label, the probes that cover
// it, and a one-sentence framing. No marketing prose, no fear framing.

import { ExternalLink } from 'lucide-react';
import { PROBE_OWASP_MAP, OWASP_LABELS, PROBE_META } from '../../lib/stable-id.js';
import { PROBES } from '../../lib/probes.js';
import { resolvePatternForProbe } from '../../lib/learn-content.js';
import { T, fontMono, fontUI } from '../../lib/theme.js';

// One-sentence framing per category. Brief on purpose; the full picture is in
// the per-probe pattern pages.
const CATEGORY_FRAMING = {
  A01: 'Authorization gone wrong: missing checks, broken hierarchies, paths a user reaches that they should not.',
  A02: 'Secrets in the wrong place, weak crypto choices, credentials stored or transmitted insecurely.',
  A03: 'User input executed as code or query, instead of being parsed as data.',
  A04: 'Architectural choices that produce vulnerable shapes regardless of how carefully the lines are written.',
  A05: 'Defaults left in production, security headers absent, dev surfaces exposed.',
  A06: 'Dependencies with known vulnerabilities, compromised versions, or supply-chain compromises in the install chain.',
  A07: 'Authentication primitives misconfigured: weak signatures, missing verification, session handling errors.',
  A08: 'Trust placed in components, packages, or supply-chain artifacts that have not been verified.',
  A09: 'Security-relevant events that happen without leaving a log entry. The blind spot in every incident response.',
  A10: 'Server fetches a URL the client supplies. Used to talk to internal services that should not be reachable from outside.',
  LLM01:
    'User input flows into a prompt without isolation. The LLM follows the user instead of the system.',
  LLM02:
    'LLM completions surface data the calling user should not see (cross-tenant leakage, system-prompt disclosure).',
  LLM04:
    'User-uploaded documents become future system-prompt content. Indirect prompt injection at the data layer.',
  LLM06:
    'Agent tools (PythonREPL, ShellTool, MCP servers) that let the LLM take actions beyond the intended scope.',
  LLM07: 'System prompts embedded in client bundles or surfaced through error responses.',
  LLM08:
    "Vector similarity search without scope filtering. Tenant A asks a question, the answer is built from tenant B's notes.",
};

const ORDERED_CATEGORIES = [
  'A01',
  'A02',
  'A03',
  'A04',
  'A05',
  'A06',
  'A07',
  'A08',
  'A09',
  'A10',
  'LLM01',
  'LLM02',
  'LLM04',
  'LLM06',
  'LLM07',
  'LLM08',
];

const OWASP_TOP10_URL = 'https://owasp.org/Top10/';
const OWASP_LLM_TOP10_URL = 'https://genai.owasp.org/llm-top-10/';

function urlForCode(code) {
  if (code.startsWith('LLM')) {
    const num = code.slice(3).padStart(2, '0');
    return `https://genai.owasp.org/llmrisk/llm${num}-${categorySlug(code)}/`;
  }
  // Top 10 2025 URLs follow https://owasp.org/Top10/A01_2021-... pattern.
  // The OWASP site has the 2025 update at the same per-category URLs.
  const num = code.slice(1).padStart(2, '0');
  return `https://owasp.org/Top10/A${num}_2021-${categorySlug(code)}/`;
}

function categorySlug(code) {
  // Map to the URL-slug form OWASP uses in its per-category pages.
  const slugs = {
    A01: 'Broken_Access_Control',
    A02: 'Cryptographic_Failures',
    A03: 'Injection',
    A04: 'Insecure_Design',
    A05: 'Security_Misconfiguration',
    A06: 'Vulnerable_and_Outdated_Components',
    A07: 'Identification_and_Authentication_Failures',
    A08: 'Software_and_Data_Integrity_Failures',
    A09: 'Security_Logging_and_Monitoring_Failures',
    A10: 'Server-Side_Request_Forgery_(SSRF)',
    LLM01: 'prompt-injection',
    LLM02: 'sensitive-information-disclosure',
    LLM04: 'data-and-model-poisoning',
    LLM06: 'excessive-agency',
    LLM07: 'system-prompt-leakage',
    LLM08: 'vector-and-embedding-weaknesses',
  };
  return slugs[code] || '';
}

function ProbePill({ probeName }) {
  const meta = PROBE_META[probeName];
  const slug = meta?.learn_more_slug;
  const pattern = slug ? resolvePatternForProbe(slug) : null;
  const inner = (
    <span
      className="ap-mono"
      style={{
        fontSize: 11,
        padding: '3px 8px',
        background: T.panel,
        border: `1px solid ${T.border}`,
        color: T.text,
        letterSpacing: '0.02em',
        textDecoration: 'none',
        whiteSpace: 'nowrap',
      }}
    >
      {probeName}
    </span>
  );
  if (pattern) {
    return (
      <a
        href={`/learn/patterns/${slug}`}
        title={`Open pattern: ${pattern.title}`}
        style={{ textDecoration: 'none' }}
      >
        {inner}
      </a>
    );
  }
  return inner;
}

function CategoryBlock({ code }) {
  const label = OWASP_LABELS[code];
  const probes = PROBE_OWASP_MAP[code] || [];
  const framing = CATEGORY_FRAMING[code] || '';
  return (
    <section
      aria-labelledby={`owasp-${code}-heading`}
      style={{
        marginBottom: 20,
        padding: 16,
        background: T.panel,
        border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${T.accent}`,
      }}
    >
      <h3
        id={`owasp-${code}-heading`}
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 16, fontWeight: 700, color: T.text }}
      >
        <a
          href={urlForCode(code)}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            color: T.text,
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {label}
          <ExternalLink size={12} aria-hidden="true" style={{ color: T.textMuted }} />
        </a>
      </h3>
      <p style={{ margin: '0 0 12px', fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>
        {framing}
      </p>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {probes.map((p) => (
          <ProbePill key={p} probeName={p} />
        ))}
      </div>
    </section>
  );
}

export function OwaspCoverageView() {
  const totalProbes = new Set(Object.values(PROBE_OWASP_MAP).flat()).size;
  const totalCategories = ORDERED_CATEGORIES.length;

  return (
    <section aria-labelledby="owasp-heading">
      <h1
        id="owasp-heading"
        className="ap-display"
        style={{ margin: '0 0 6px', fontSize: 26, fontWeight: 700, color: T.text }}
      >
        OWASP coverage
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
        PreFlight's {PROBES.length} probes map to {totalCategories} OWASP categories. {totalProbes}{' '}
        probes carry at least one OWASP code; the rest cover discoverability, accessibility, or
        supply-chain hygiene outside the OWASP scope.
      </p>
      <p
        style={{
          color: T.textMuted,
          fontSize: 13,
          margin: '0 0 18px',
          maxWidth: 720,
          lineHeight: 1.6,
        }}
      >
        Each finding emitted by a probe carries its OWASP code(s) on the finding card. Click any
        probe pill below to open its pattern page.
      </p>

      <nav
        aria-label="OWASP category index"
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
        {ORDERED_CATEGORIES.map((code) => (
          <a
            key={code}
            href={`#owasp-${code}-heading`}
            className="ap-mono"
            style={{
              fontSize: 11,
              padding: '5px 10px',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              textDecoration: 'none',
              letterSpacing: '0.06em',
            }}
          >
            {code}
          </a>
        ))}
      </nav>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          padding: '10px 14px',
          background: T.bg,
          border: `1px solid ${T.border}`,
          marginBottom: 18,
          fontSize: 13,
          color: T.textDim,
          lineHeight: 1.5,
          fontFamily: fontUI,
        }}
      >
        <span>
          <strong style={{ color: T.text }}>Sources:</strong>{' '}
          <a
            href={OWASP_TOP10_URL}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: T.accent }}
          >
            OWASP Top 10 2025
          </a>
          {' · '}
          <a
            href={OWASP_LLM_TOP10_URL}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: T.accent }}
          >
            OWASP LLM Top 10 2026
          </a>
        </span>
      </div>

      {ORDERED_CATEGORIES.map((code) => (
        <CategoryBlock key={code} code={code} />
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
          fontFamily: fontMono,
        }}
      >
        Mapping source-of-truth lives in <code>src/lib/stable-id.js</code> (PROBE_OWASP_MAP +
        OWASP_LABELS). A coverage test in <code>src/test/probe-coverage.test.js</code> asserts every
        PROBE_OWASP_MAP entry references a real probe.
      </p>
    </section>
  );
}
