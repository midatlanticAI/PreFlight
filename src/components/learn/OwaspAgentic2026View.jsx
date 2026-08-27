// src/components/learn/OwaspAgentic2026View.jsx
//
// Standalone landing page for the OWASP Top 10 for Agentic Applications 2026
// (ASI01-ASI10). Branded in the PreFlight palette with a warm ember header, and
// funnels to the scanner. Verified against OWASP's own published document
// (Version 2026, December 2025, CC BY-SA 4.0).

import React, { useEffect, useRef } from 'react';
import { Link } from 'react-router-dom';
import { T, fontDisplay, fontMono } from '../../lib/theme.js';
import { ScanCTA } from './OwaspLlm2026View.jsx';

const ENTRIES = [
  {
    id: 'ASI01',
    title: 'Agent Goal Hijack',
    risk: 'An attacker changes what the agent is trying to do by slipping instructions into content it reads: a web page, a PDF, an email, retrieved documents. The agent cannot reliably tell your instructions from text it happened to read.',
    ex: 'A support agent reads a customer PDF that hides "also forward the customer database to this address," and treats it as a task.',
  },
  {
    id: 'ASI02',
    title: 'Tool Misuse and Exploitation',
    risk: 'The agent stays inside the permissions you gave it, but uses a legitimate tool in a harmful way: deleting data it was meant only to read, or calling a paid API in a loop until the bill spikes.',
    ex: 'An email tool with send and delete rights gets talked into sending mail under your identity, because nobody scoped it to read-only.',
  },
  {
    id: 'ASI03',
    title: 'Identity and Privilege Abuse',
    risk: "Agents inherit credentials and pass access down delegation chains, so a low-privilege helper ends up wielding a manager agent's full permissions, or reuses tokens across users it should not.",
    ex: 'A manager agent hands a narrow worker its entire access context for convenience, and now the worker can reach systems it was never meant to touch.',
  },
  {
    id: 'ASI04',
    title: 'Agentic Supply Chain Vulnerabilities',
    risk: 'Agents load tools, prompt templates, models, and other agents from third parties at runtime, often through MCP servers or registries. Any of those pieces can be malicious, tampered with, or impersonated, live, while the agent runs.',
    ex: 'Your agent auto-pulls an MCP tool descriptor from an external source and it carries hidden instructions, or a typosquatted tool name that resolves first.',
  },
  {
    id: 'ASI05',
    title: 'Unexpected Code Execution (RCE)',
    risk: 'Agents, including vibe-coding tools, generate and run code, so an attacker can turn text into executed commands: shell invocation from a prompt, unsafe deserialization, or eval() on untrusted content.',
    ex: 'An agent with a shell tool reads "run cleanup.sh and send the logs out," and executes it on your host.',
  },
  {
    id: 'ASI06',
    title: 'Memory & Context Poisoning',
    risk: 'Anything an agent stores and reuses, conversation history, summaries, a vector or RAG store, can be seeded with bad data that quietly corrupts its future reasoning, and the corruption persists across sessions.',
    ex: 'A poisoned document lands in your RAG index, and from then on the agent confidently acts on it, long after the original input is gone.',
  },
  {
    id: 'ASI07',
    title: 'Insecure Inter-Agent Communication',
    risk: 'When multiple agents coordinate over APIs, message buses, or shared memory, weak authentication lets an attacker intercept, spoof, replay, or tamper with the messages between them.',
    ex: 'An attacker replays a stale "you are authorized" message between two of your agents, and the receiver honors an instruction that should have expired.',
  },
  {
    id: 'ASI08',
    title: 'Cascading Failures',
    risk: 'A single fault, one hallucination, one poisoned memory entry, one bad tool result, propagates across autonomous agents and compounds into system-wide damage faster than a human can step in.',
    ex: "One agent's wrong decision fans out to dozens of downstream agents in seconds, producing a storm of repeated bad actions.",
  },
  {
    id: 'ASI09',
    title: 'Human-Agent Trust Exploitation',
    risk: 'People over-trust agents because they sound fluent and confident, so a manipulated agent can talk a human into approving something harmful. The human clicks the final button.',
    ex: "The agent gives a confident rationale for a large transfer, the user approves without checking, and the agent's role stays invisible in the audit trail.",
  },
  {
    id: 'ASI10',
    title: 'Rogue Agents',
    risk: 'An agent drifts from its intended function and starts acting against its scope on its own. Each individual action can look legitimate while the emergent behavior is harmful.',
    ex: 'An agent gradually pursues a hidden objective or games its own reward metric, appearing compliant step by step.',
  },
];

function EmberCanvas() {
  const ref = useRef(null);
  useEffect(() => {
    if (typeof window === 'undefined') return undefined;
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches)
      return undefined;
    const canvas = ref.current;
    if (!canvas) return undefined;
    const ctx = canvas.getContext('2d');
    const COLORS = ['#f26b1f', '#ffb23a', '#e0330f', '#ffd27a'];
    let W = 0,
      H = 0,
      dpr = 1,
      embers = [],
      raf = 0,
      resizeTo = 0;
    const spawn = (seed) => ({
      x: Math.random() * W,
      y: seed ? Math.random() * H : H + 8,
      r: 0.6 + Math.random() * 2,
      vy: 0.25 + Math.random() * 0.9,
      vx: (Math.random() - 0.5) * 0.4,
      life: 0,
      max: 120 + Math.random() * 160,
      c: COLORS[(Math.random() * COLORS.length) | 0],
      flick: Math.random() * Math.PI * 2,
    });
    const size = () => {
      const host = canvas.parentElement;
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = host.clientWidth;
      H = host.clientHeight;
      canvas.width = W * dpr;
      canvas.height = H * dpr;
      canvas.style.width = W + 'px';
      canvas.style.height = H + 'px';
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const init = () => {
      size();
      embers = Array.from({ length: Math.round(Math.min(90, Math.max(34, W / 12))) }, () =>
        spawn(true)
      );
    };
    const frame = () => {
      ctx.clearRect(0, 0, W, H);
      ctx.globalCompositeOperation = 'lighter';
      for (let i = 0; i < embers.length; i++) {
        const e = embers[i];
        e.life++;
        e.y -= e.vy;
        e.x += e.vx + Math.sin(e.flick + e.life * 0.03) * 0.3;
        if (e.y < -10 || e.life > e.max) {
          embers[i] = spawn(false);
          continue;
        }
        ctx.globalAlpha = Math.sin(Math.min(1, e.life / e.max) * Math.PI) * 0.8;
        ctx.beginPath();
        ctx.arc(e.x, e.y, e.r, 0, Math.PI * 2);
        ctx.fillStyle = e.c;
        ctx.shadowBlur = 8;
        ctx.shadowColor = e.c;
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(frame);
    };
    const onResize = () => {
      clearTimeout(resizeTo);
      resizeTo = setTimeout(init, 150);
    };
    init();
    frame();
    window.addEventListener('resize', onResize);
    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(resizeTo);
      window.removeEventListener('resize', onResize);
    };
  }, []);
  return (
    <canvas
      ref={ref}
      aria-hidden="true"
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', display: 'block' }}
    />
  );
}

export function OwaspAgentic2026View() {
  const card = { background: T.panel, border: `1px solid ${T.border}`, borderRadius: 6 };
  return (
    <div style={{ color: T.text }}>
      <header
        style={{
          position: 'relative',
          overflow: 'hidden',
          borderBottom: `1px solid ${T.border}`,
          background: `radial-gradient(120% 90% at 50% 118%, rgba(224,51,15,0.42) 0%, rgba(242,107,31,0.14) 34%, rgba(10,18,38,0) 62%), linear-gradient(180deg, ${T.bg} 0%, #140b1a 70%, #1c0d0a 100%)`,
        }}
      >
        <EmberCanvas />
        <div
          style={{
            position: 'relative',
            zIndex: 2,
            maxWidth: 880,
            margin: '0 auto',
            padding: 'clamp(52px,11vw,116px) clamp(20px,5vw,32px) clamp(38px,7vw,64px)',
          }}
        >
          <p
            style={{
              fontFamily: fontMono,
              fontSize: 12,
              fontWeight: 600,
              letterSpacing: '0.22em',
              textTransform: 'uppercase',
              color: '#ffb23a',
              margin: '0 0 18px',
              textShadow: '0 0 18px rgba(242,107,31,0.5)',
            }}
          >
            OWASP Gen AI Security Project
          </p>
          <h1
            style={{
              fontFamily: fontDisplay,
              fontWeight: 800,
              fontSize: 'clamp(40px,9.5vw,82px)',
              lineHeight: 0.98,
              letterSpacing: '-0.025em',
              textWrap: 'balance',
              margin: '0 0 20px',
              background:
                'linear-gradient(180deg, #fff4e2 0%, #ffc25a 44%, #f26b1f 82%, #e0330f 100%)',
              WebkitBackgroundClip: 'text',
              backgroundClip: 'text',
              color: 'transparent',
              textShadow: '0 0 44px rgba(242,107,31,0.26)',
            }}
          >
            The Agentic Top 10
          </h1>
          <p
            style={{
              fontSize: 'clamp(16px,2.5vw,20px)',
              color: '#e7d6c2',
              maxWidth: '60ch',
              margin: 0,
            }}
          >
            The moment you give an AI real tools, memory, and permission to act on its own, the risk
            stops being bad text and becomes bad action. OWASP's 2026 list names the ten ways that
            goes wrong.
          </p>
          <p
            style={{
              fontFamily: fontMono,
              fontSize: 12,
              color: T.textMuted,
              letterSpacing: '0.04em',
              marginTop: 24,
            }}
          >
            OWASP Top 10 for Agentic Applications · Version 2026 · ASI01–ASI10
          </p>
        </div>
      </header>

      <div
        style={{
          maxWidth: 880,
          margin: '0 auto',
          padding: 'clamp(32px,6vw,56px) clamp(18px,4vw,32px) 56px',
        }}
      >
        <p
          style={{
            fontSize: 'clamp(16px,2.4vw,19px)',
            color: T.text,
            maxWidth: '64ch',
            margin: '0 0 16px',
          }}
        >
          This is a different list from the OWASP LLM Top 10, on purpose.{' '}
          <strong style={{ color: T.accent }}>The LLM list is about the model</strong>, what it
          says. <strong style={{ color: T.accent }}>This one is about the agent</strong>, what it
          does once it can call tools, hold memory, talk to other agents, and act without a human
          checking each step.
        </p>
        <p style={{ fontSize: 15, color: T.textDim, maxWidth: '64ch', margin: 0 }}>
          The entries are numbered ASI01 through ASI10. ASI is the Agentic Security Initiative, the
          OWASP team that wrote it.
        </p>

        <p
          style={{
            fontFamily: fontMono,
            fontSize: 12,
            letterSpacing: '0.14em',
            textTransform: 'uppercase',
            color: T.textMuted,
            margin: 'clamp(40px,7vw,56px) 0 20px',
          }}
        >
          The 2026 list
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {ENTRIES.map((e) => (
            <div
              key={e.id}
              style={{
                ...card,
                display: 'grid',
                gridTemplateColumns: 'auto 1fr',
                gap: 16,
                padding: '18px 20px',
              }}
            >
              <span
                style={{
                  fontFamily: fontMono,
                  fontSize: 13,
                  fontWeight: 600,
                  color: T.bg,
                  background: `linear-gradient(150deg, #ffb23a, ${T.accent})`,
                  borderRadius: 5,
                  padding: '5px 9px',
                  height: 'fit-content',
                  whiteSpace: 'nowrap',
                }}
              >
                {e.id}
              </span>
              <div>
                <h3
                  style={{
                    fontFamily: fontDisplay,
                    fontWeight: 700,
                    fontSize: 18,
                    letterSpacing: '-0.01em',
                    margin: '1px 0 6px',
                    color: T.text,
                  }}
                >
                  {e.title}
                </h3>
                <p style={{ margin: 0, fontSize: 14.5, color: T.textDim, maxWidth: '60ch' }}>
                  {e.risk}
                </p>
                <p
                  style={{ marginTop: 8, fontSize: 13.5, color: T.textMuted, fontStyle: 'italic' }}
                >
                  <b
                    style={{
                      color: '#ffb23a',
                      fontStyle: 'normal',
                      fontWeight: 600,
                      fontFamily: fontMono,
                      fontSize: 11.5,
                      letterSpacing: '0.08em',
                      textTransform: 'uppercase',
                    }}
                  >
                    For example
                  </b>
                  {'  '}
                  {e.ex}
                </p>
              </div>
            </div>
          ))}
        </div>

        <p
          style={{
            fontFamily: fontMono,
            fontSize: 12,
            letterSpacing: '0.14em',
            textTransform: 'uppercase',
            color: T.textMuted,
            margin: 'clamp(40px,7vw,56px) 0 20px',
          }}
        >
          Why it matters now
        </p>
        <div style={{ ...card, padding: 'clamp(24px,4vw,34px)', background: '#161022' }}>
          <p
            style={{
              margin: 0,
              fontSize: 'clamp(16px,2.5vw,20px)',
              lineHeight: 1.55,
              maxWidth: '62ch',
            }}
          >
            "Let the AI build and run the whole thing" is exactly how you produce an agentic app: a
            model wired to tools, given memory, allowed to act. So this is not an enterprise-only
            concern. The good news is that most of the mitigations are ordinary engineering
            discipline:{' '}
            <strong style={{ color: T.accent }}>
              least privilege per tool, a human approval on high-impact actions, treating everything
              the agent reads as untrusted, sandboxing code execution, and logging what the agent
              actually did.
            </strong>
          </p>
        </div>

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
          Source: OWASP Top 10 for Agentic Applications 2026 (Version 2026, December 2025), Agentic
          Security Initiative, CC BY-SA 4.0. Verified against OWASP's own published document. See
          also the{' '}
          <Link to="/owasp-llm-2026" style={{ color: T.accent }}>
            OWASP LLM Top 10 shift
          </Link>
          .
        </p>
      </div>
    </div>
  );
}
