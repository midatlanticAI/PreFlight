// src/components/learn/ToolsView.jsx
//
// The "Tools" sub-tab under /learn. A neutral catalog of the AI coding and
// build tools the audience actually uses. The neutrality IS the product:
// no affiliate, no sponsored placement, no rankings sold, strengths AND
// weaknesses, sourced, dated.
//
// Metaphor (locked): PreFlight is the safety check, FlightSchool is the
// training, this is the hangar. Every plane is welcome because PreFlight
// is not an airline; it does not fly anyone anywhere or compete for
// passengers, it teaches and secures. So: name AI/dev tools freely and
// honestly. NEVER name a rival security scanner here or anywhere.
//
// Voice: reference register, no em-dashes, no marketing prose, no fear
// framing. This list rots fast: REVIEWED is the visible expiry. Update
// the entries and bump REVIEWED when you revisit.

import { T, fontMono } from '../../lib/theme.js';

const REVIEWED = 'May 2026';

const P = ({ children }) => (
  <p
    style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.7, margin: '0 0 12px', maxWidth: 760 }}
  >
    {children}
  </p>
);

const TOOLS = [
  {
    name: 'Claude Code',
    what: 'Anthropic’s agentic coding tool. Large context, strong on autonomous multi-file work and async or CLI-driven workflows.',
    strengths:
      'The most capable autonomous agent in this set for complex, multi-file changes and architecture-level work. Scales from L2 assistance up to L5 orchestration.',
    weaknesses:
      'Context is large but still bounded, so very long-running projects force periodic fresh starts. CLI and agent-centric rather than a full IDE.',
    fit: 'L2 to L5',
  },
  {
    name: 'Cursor',
    what: 'An AI-native IDE built around inline editing, autocomplete, and an in-editor agent.',
    strengths:
      'The deepest day-to-day developer experience: the best AI-native IDE for someone writing and steering code all day.',
    weaknesses:
      'Performance degrades as a session grows (context rot: the model gets overloaded with stale context and makes worse calls). Premium pricing at the power tiers.',
    fit: 'L2 to L4',
  },
  {
    name: 'GitHub Copilot',
    what: 'The most broadly compatible assistant: VS Code, JetBrains, Visual Studio, and the GitHub web UI. Now includes agent mode and PR review.',
    strengths:
      'The most accessible and widely integrated option. Lowest-friction starting point, good PR-review and code-review automation.',
    weaknesses:
      'Less deep than Cursor or Claude Code for complex multi-file changes and architecture decisions.',
    fit: 'L1 to L3',
  },
  {
    name: 'Windsurf',
    what: 'An AI-native IDE in the same class as Cursor, with agentic flows.',
    strengths:
      'Strong agentic editing experience; a credible alternative if Cursor’s model or pricing does not fit.',
    weaknesses:
      'Smaller ecosystem and community than Cursor. Same session context-rot failure mode as every IDE agent.',
    fit: 'L2 to L4',
  },
  {
    name: 'Bolt.new',
    what: 'In-browser full-app generation: describe an app, get a running full-stack scaffold.',
    strengths: 'Fast zero-setup path from idea to a running prototype.',
    weaknesses:
      'High cost and quality issues at scale. A generator, not a maintainer: it scaffolds, it does not keep a codebase healthy.',
    fit: 'L1',
  },
  {
    name: 'Lovable',
    what: 'Prompt-to-app builder with an emphasis on visual quality.',
    strengths: 'Strong visual output and speed for UI-forward prototypes.',
    weaknesses:
      'Weaker code structure and production readiness. Not its sweet spot for complex algorithmic logic, data pipelines, or anything you must maintain.',
    fit: 'L1',
  },
  {
    name: 'v0',
    what: 'Vercel’s UI generation tool. Produces front-end components and pages from prompts.',
    strengths: 'Excellent at generating UI quickly and cleanly.',
    weaknesses:
      'No backend layer: no auth, no database, no workflows. It breaks immediately when you need a real application behind the interface.',
    fit: 'L1',
  },
  {
    name: 'Replit',
    what: 'Browser IDE plus hosting, database, and an agent. Closer to real infrastructure than the pure generators.',
    strengths:
      'The most end-to-end of the app builders: edit, run, store, and deploy in one place.',
    weaknesses:
      'Still lacks production guarantees like real scaling, monitoring, and structured deployment. Closer to infrastructure than the others, not equal to it.',
    fit: 'L1 to L2',
  },
];

function ToolCard({ t }) {
  return (
    <section
      aria-label={t.name}
      style={{
        marginTop: 14,
        padding: '16px 18px',
        background: T.panel,
        border: `1px solid ${T.border}`,
      }}
    >
      <h2
        className="ap-display"
        style={{ margin: '0 0 4px', fontSize: 20, fontWeight: 700, color: T.text }}
      >
        {t.name}{' '}
        <span style={{ fontFamily: fontMono, fontSize: 12, color: T.textDim, fontWeight: 400 }}>
          best fit: {t.fit}
        </span>
      </h2>
      <p
        style={{
          color: T.textMuted,
          fontSize: 14,
          lineHeight: 1.65,
          margin: '0 0 8px',
          maxWidth: 760,
        }}
      >
        {t.what}
      </p>
      <p
        style={{
          color: T.textMuted,
          fontSize: 13.5,
          lineHeight: 1.65,
          margin: '0 0 4px',
          maxWidth: 760,
        }}
      >
        <strong style={{ color: T.text }}>Strengths.</strong> {t.strengths}
      </p>
      <p
        style={{
          color: T.textMuted,
          fontSize: 13.5,
          lineHeight: 1.65,
          margin: '0 0 4px',
          maxWidth: 760,
        }}
      >
        <strong style={{ color: T.text }}>Weaknesses.</strong> {t.weaknesses}
      </p>
    </section>
  );
}

export function ToolsView() {
  return (
    <section aria-labelledby="tools-heading">
      <h1
        id="tools-heading"
        className="ap-display"
        style={{
          margin: '0 0 6px',
          fontSize: 'clamp(22px, 5.5vw, 30px)',
          fontWeight: 700,
          color: T.text,
          overflowWrap: 'break-word',
        }}
      >
        Tools
      </h1>
      <P>
        This is the hangar. Every plane sits here, and that is the point. PreFlight is not an
        airline. It does not fly anyone anywhere and it does not compete with these tools for your
        work. It teaches and it secures. So this page names them plainly, with what each is good at
        and what each is bad at, and nothing is sold a spot.
      </P>
      <p
        style={{
          color: T.textDim,
          fontSize: 13,
          lineHeight: 1.7,
          margin: '0 0 12px',
          maxWidth: 760,
          padding: '12px 16px',
          background: T.bg,
          border: `1px dashed ${T.border}`,
        }}
      >
        No affiliate links. No sponsored placement. No rankings sold. Strengths and weaknesses both,
        every time. This space moves fast, so treat the review date as an expiry, not a stamp.
        Reviewed: {REVIEWED}.
      </p>
      <P>
        One pattern holds across all of them. They are generators, not maintainers. None alone is a
        production-ready system, and the most productive builders combine a few rather than betting
        on one. And every one of them writes code that ships with vulnerabilities at a rate no
        honest reading of the 2025 to 2026 data lets you ignore. These tools build. They do not
        secure. That gap is the entire reason PreFlight exists: scan what any of them generated,
        before it ships.
      </P>

      {TOOLS.map((t) => (
        <ToolCard key={t.name} t={t} />
      ))}

      <p
        style={{
          color: T.textDim,
          fontSize: 13,
          lineHeight: 1.7,
          margin: '22px 0 0',
          maxWidth: 760,
        }}
      >
        Best fit maps to the tiers in The Climb. Whatever you fly, run it through PreFlight before
        anyone else does. Everything here is free guidance. PreFlight asks for nothing.
      </p>
    </section>
  );
}
