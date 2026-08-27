// src/components/learn/OwaspLlm2026View.jsx
//
// Standalone landing page: how the OWASP LLM Top 10 reordered from 2025 to
// 2026, told as a slopegraph. Branded in the PreFlight palette (navy / orange
// / mint) and funnels to the scanner. Linked from social posts; the whole job
// of the page is to deliver real value for free and land the reader on the
// free tool. Verified against OWASP's own 2025 and 2026 published documents.

import React from 'react';
import { Link } from 'react-router-dom';
import { T, fontDisplay, fontUI, fontMono } from '../../lib/theme.js';

// delta = r25 - r26; positive means the risk climbed.
const ENTRIES = [
  {
    name: 'Prompt Injection',
    r25: 1,
    r26: 1,
    desc: 'Hidden instructions in text your model reads, and obeys. Every LLM app has this door.',
  },
  {
    name: 'Sensitive Information Disclosure',
    r25: 2,
    r26: 2,
    desc: "The model hands back secrets, PII, or another user's data it should never have surfaced.",
  },
  {
    name: 'Excessive Agency',
    r25: 6,
    r26: 3,
    desc: 'You gave the AI more power to act than it needed. Its tools, permissions, and reach are the blast radius.',
  },
  {
    name: 'Supply Chain',
    r25: 3,
    r26: 4,
    desc: 'A poisoned model, dataset, or dependency you pulled in without checking what was inside.',
  },
  {
    name: 'Data and Model Poisoning',
    r25: 4,
    r26: 5,
    desc: 'Training or fine-tuning data tampered with to plant behavior you never intended.',
  },
  {
    name: 'Unbounded Consumption',
    r25: 10,
    r26: 6,
    desc: 'The model that loops on itself, or that one user can spam into a runaway bill overnight.',
  },
  {
    name: 'Misinformation',
    r25: 9,
    r26: 7,
    desc: 'Confident, wrong output that a user or another system acts on as if it were true.',
  },
  {
    name: 'Hidden Context Exposure',
    r25: 7,
    r26: 8,
    renamedFrom: 'System Prompt Leakage',
    desc: 'Renamed and broadened. Your memory, RAG data, and hidden context leaking out, not just the system prompt.',
  },
  {
    name: 'Vector and Embedding Weaknesses',
    r25: 8,
    r26: 9,
    desc: 'Attacks on the embeddings and vector store behind your retrieval, poisoning what the model recalls.',
  },
  {
    name: 'Improper Output Handling',
    r25: 5,
    r26: 10,
    desc: 'Passing raw model output into a shell, a query, or the DOM without treating it as untrusted.',
  },
];

const UP = T.accent; // orange: climbed
const DOWN = T.textMuted; // muted: fell
const HELD = T.accentAlt; // mint: held
const RENAMED = T.sev.low.fg; // blue: renamed

function Slopegraph() {
  const W = 620,
    H = 440,
    padT = 12,
    padB = 12;
  const rowH = (H - padT - padB) / 9;
  const xL = 250,
    xR = 370;
  const y = (rank) => padT + (rank - 1) * rowH;
  const byR25 = [...ENTRIES].sort((a, b) => a.r25 - b.r25);
  const byR26 = [...ENTRIES].sort((a, b) => a.r26 - b.r26);
  const strokeFor = (d) => {
    if (d.renamedFrom) return RENAMED;
    const delta = d.r25 - d.r26;
    return delta > 0 ? UP : delta < 0 ? DOWN : HELD;
  };
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      role="img"
      aria-label="Slopegraph of OWASP LLM Top 10 rankings moving from 2025 to 2026"
      style={{ display: 'block', width: '100%', height: 'auto' }}
    >
      {ENTRIES.map((d) => {
        const delta = d.r25 - d.r26;
        const stroke = strokeFor(d);
        const w = d.renamedFrom ? 1.8 : Math.abs(delta) >= 3 ? 3 : delta === 0 ? 2 : 1.6;
        return (
          <g key={d.name}>
            <line
              x1={xL}
              y1={y(d.r25)}
              x2={xR}
              y2={y(d.r26)}
              stroke={stroke}
              strokeWidth={w}
              strokeDasharray={d.renamedFrom ? '3 3' : ''}
              strokeLinecap="round"
              opacity={delta < 0 && !d.renamedFrom ? 0.7 : 1}
            />
            <circle cx={xL} cy={y(d.r25)} r={2.6} fill={stroke} />
            <circle cx={xR} cy={y(d.r26)} r={2.6} fill={stroke} />
          </g>
        );
      })}
      {byR25.map((d) => (
        <text
          key={'l' + d.name}
          x={xL - 12}
          y={y(d.r25) + 4}
          textAnchor="end"
          style={{ fontFamily: fontUI, fontSize: 12.5, fill: T.text }}
        >
          <tspan style={{ fontFamily: fontMono, fill: T.textMuted, fontWeight: 600 }}>
            {d.r25}{' '}
          </tspan>
          {d.name}
        </text>
      ))}
      {byR26.map((d) => {
        const delta = d.r25 - d.r26;
        const fill = d.renamedFrom ? RENAMED : delta > 0 ? UP : T.text;
        return (
          <text
            key={'r' + d.name}
            x={xR + 12}
            y={y(d.r26) + 4}
            textAnchor="start"
            style={{ fontFamily: fontUI, fontSize: 12.5, fill }}
          >
            {d.name + '  '}
            <tspan
              style={{ fontFamily: fontMono, fill: delta > 0 ? UP : T.textMuted, fontWeight: 600 }}
            >
              {d.r26}
            </tspan>
          </text>
        );
      })}
    </svg>
  );
}

export function OwaspLlm2026View() {
  const byR26 = [...ENTRIES].sort((a, b) => a.r26 - b.r26);
  const card = { background: T.panel, border: `1px solid ${T.border}`, borderRadius: 6 };
  return (
    <div
      style={{
        maxWidth: 880,
        margin: '0 auto',
        padding: 'clamp(28px,5vw,56px) clamp(18px,4vw,32px) 56px',
        color: T.text,
      }}
    >
      <p
        style={{
          fontFamily: fontMono,
          fontSize: 12,
          letterSpacing: '0.16em',
          textTransform: 'uppercase',
          color: T.textMuted,
          margin: '0 0 14px',
        }}
      >
        OWASP · Top 10 for LLM Applications
      </p>
      <h1
        style={{
          fontFamily: fontDisplay,
          fontWeight: 800,
          fontSize: 'clamp(32px,6.5vw,54px)',
          lineHeight: 1.04,
          letterSpacing: '-0.02em',
          textWrap: 'balance',
          margin: '0 0 16px',
        }}
      >
        The list just tilted toward <span style={{ color: T.accent }}>agents</span>.
      </h1>
      <p
        style={{
          fontSize: 'clamp(16px,2.4vw,19px)',
          color: T.textDim,
          maxWidth: '62ch',
          margin: 0,
        }}
      >
        OWASP published the 2026 edition of its Top 10 for LLM apps. Prompt injection is still
        number one, unmoved for three years. Underneath it, the risks that climbed are all about
        giving an AI real power to act.
      </p>

      <section style={{ marginTop: 'clamp(36px,6vw,52px)' }}>
        <p
          style={{
            fontFamily: fontMono,
            fontSize: 12,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            color: T.textMuted,
            margin: '0 0 16px',
          }}
        >
          How the ranking moved
        </p>
        <div style={{ ...card, padding: '18px clamp(8px,3vw,20px) 12px', overflowX: 'auto' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              fontFamily: fontMono,
              fontSize: 13,
              fontWeight: 600,
              padding: '0 4px 6px',
            }}
          >
            <span>2025</span>
            <span style={{ color: T.accent }}>2026</span>
          </div>
          <Slopegraph />
          <div
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '8px 20px',
              fontFamily: fontMono,
              fontSize: 12,
              color: T.textMuted,
              marginTop: 12,
              padding: '0 4px',
            }}
          >
            {[
              ['climbed', UP],
              ['fell', DOWN],
              ['held', HELD],
              ['renamed', RENAMED],
            ].map(([label, c]) => (
              <span key={label} style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                <i
                  style={{
                    width: 16,
                    height: 3,
                    borderRadius: 2,
                    background: c,
                    display: 'inline-block',
                  }}
                />
                {label}
              </span>
            ))}
          </div>
        </div>
      </section>

      <section style={{ marginTop: 'clamp(36px,6vw,52px)' }}>
        <p
          style={{
            fontFamily: fontMono,
            fontSize: 12,
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
            color: T.textMuted,
            margin: '0 0 16px',
          }}
        >
          The 2026 Top 10, in plain terms
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {byR26.map((d) => {
            const delta = d.r25 - d.r26;
            const climbed = delta > 0 && !d.renamedFrom;
            const badge = d.renamedFrom
              ? 'renamed'
              : delta > 0
                ? `▲ ${d.r25} → ${d.r26}`
                : delta < 0
                  ? `▼ ${d.r25} → ${d.r26}`
                  : 'held';
            const badgeColor = d.renamedFrom
              ? RENAMED
              : delta > 0
                ? UP
                : delta < 0
                  ? T.textMuted
                  : HELD;
            return (
              <div
                key={d.name}
                style={{
                  ...card,
                  display: 'grid',
                  gridTemplateColumns: '44px 1fr auto',
                  gap: 14,
                  alignItems: 'start',
                  padding: '14px 16px',
                  borderLeft: `3px solid ${climbed ? UP : d.renamedFrom ? RENAMED : T.border}`,
                }}
              >
                <div
                  style={{
                    fontFamily: fontMono,
                    fontSize: 22,
                    fontWeight: 600,
                    color: climbed ? UP : T.text,
                    fontVariantNumeric: 'tabular-nums',
                  }}
                >
                  {String(d.r26).padStart(2, '0')}
                </div>
                <div>
                  <p style={{ fontWeight: 700, fontSize: 16, margin: '1px 0 4px' }}>{d.name}</p>
                  <p style={{ fontSize: 13.5, color: T.textDim, margin: 0, maxWidth: '56ch' }}>
                    {d.desc}
                    {d.renamedFrom ? (
                      <span style={{ color: RENAMED }}> (was “{d.renamedFrom}”)</span>
                    ) : null}
                  </p>
                </div>
                <div
                  style={{
                    fontFamily: fontMono,
                    fontSize: 12,
                    fontWeight: 600,
                    whiteSpace: 'nowrap',
                    alignSelf: 'center',
                    color: badgeColor,
                    border: `1px solid ${badgeColor}`,
                    borderRadius: 999,
                    padding: '4px 9px',
                  }}
                >
                  {badge}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      <section style={{ marginTop: 'clamp(36px,6vw,52px)' }}>
        <div style={{ ...card, padding: 'clamp(22px,4vw,32px)', background: '#0e1730' }}>
          <p
            style={{
              margin: 0,
              fontSize: 'clamp(16px,2.5vw,20px)',
              lineHeight: 1.55,
              maxWidth: '60ch',
            }}
          >
            Two of the three biggest climbers,{' '}
            <strong style={{ color: T.accent }}>Excessive Agency</strong> and{' '}
            <strong style={{ color: T.accent }}>Unbounded Consumption</strong>, are about the same
            thing: wiring an LLM to real actions, a database, a shell, a payment API, and trusting
            it to only ever do the right thing. That is exactly what “just let it build the whole
            thing” produces.
          </p>
        </div>
      </section>

      <ScanCTA />

      <p
        style={{
          fontFamily: fontMono,
          fontSize: 11.5,
          color: T.textMuted,
          marginTop: 32,
          lineHeight: 1.7,
        }}
      >
        Source: OWASP Top 10 for LLM Applications, 2025 and 2026 editions, verified against OWASP's
        own published documents. See also the{' '}
        <Link to="/owasp-agentic-2026" style={{ color: T.accent }}>
          OWASP Agentic Top 10
        </Link>
        .
      </p>
    </div>
  );
}

// Shared funnel CTA. The whole point of the page: land the reader on the free tool.
export function ScanCTA() {
  return (
    <div
      style={{
        marginTop: 'clamp(36px,6vw,52px)',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 18,
        justifyContent: 'space-between',
        background: `linear-gradient(135deg, ${T.navy}, #0e1730)`,
        border: `1px solid ${T.accent}`,
        borderRadius: 8,
        padding: 'clamp(22px,4vw,30px)',
      }}
    >
      <div style={{ maxWidth: '46ch' }}>
        <b
          style={{
            fontFamily: fontDisplay,
            fontWeight: 800,
            fontSize: 20,
            color: T.text,
            display: 'block',
            marginBottom: 5,
          }}
        >
          Check your own app in about a minute.
        </b>
        <span style={{ fontSize: 14, color: T.textDim }}>
          PreFlight is a free, in-browser security check for AI-built apps. No signup, nothing
          leaves your machine. Free, private, and built to keep you and your users safe.
        </span>
      </div>
      <Link
        to="/"
        style={{
          fontFamily: fontMono,
          fontSize: 15,
          fontWeight: 600,
          textDecoration: 'none',
          color: T.bg,
          background: T.accent,
          padding: '13px 22px',
          borderRadius: 6,
          whiteSpace: 'nowrap',
        }}
      >
        Run a free scan →
      </Link>
    </div>
  );
}
