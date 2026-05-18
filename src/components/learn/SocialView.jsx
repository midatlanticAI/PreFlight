// src/components/learn/SocialView.jsx
//
// The "Social" sub-tab under /learn. Social learning: the communities
// where vibe coders, shippers, and builders actually get better, faster,
// together. Reference register. No marketing prose, no em-dashes, no fear
// framing.
//
// Free, open communities ONLY. There is no paid product referenced here
// or anywhere else on the site. Pre-Flight asks for nothing. To add more
// rooms, append to COMMUNITIES.

import { T, fontMono } from '../../lib/theme.js';

const H2 = ({ children }) => (
  <h2 style={{ fontSize: 16, fontWeight: 700, color: T.text, margin: '26px 0 8px' }}>{children}</h2>
);
const P = ({ children }) => (
  <p
    style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.6, margin: '0 0 10px', maxWidth: 760 }}
  >
    {children}
  </p>
);
const LI = ({ children }) => (
  <li style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.6, marginBottom: 6 }}>{children}</li>
);

// Curated, platform-agnostic. Any free, mission-aligned community or
// social reference John vets goes here, regardless of platform (Facebook,
// Discord, Reddit, forums, newsletters, etc.). `platform` is an optional
// label only. Append entries as they are found.
const COMMUNITIES = [
  {
    name: 'Vibe Coding is Life',
    platform: 'Facebook',
    tagline: 'Learn. Share. Ship.',
    href: 'https://www.facebook.com/groups/1712447172677146',
    body: 'A free group for people building from prompts. Introductions, debugging help, project shares, jobs, and a steady feed of what others are actually shipping. Free to join, free to use, nothing gated.',
  },
];

function CommunityCard({ c }) {
  return (
    <section
      aria-label={`Community: ${c.name}`}
      style={{
        marginTop: 16,
        border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${T.accent}`,
        background: T.panel,
      }}
    >
      <div
        style={{
          padding: '20px 20px 16px',
          background: `linear-gradient(135deg, ${T.bg} 0%, ${T.panel} 100%)`,
          borderBottom: `1px solid ${T.border}`,
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'baseline',
            gap: 10,
            flexWrap: 'wrap',
            marginBottom: 6,
          }}
        >
          <h3
            className="ap-display"
            style={{ margin: 0, fontSize: 26, fontWeight: 700, color: T.text }}
          >
            {c.name}
          </h3>
          {c.platform && (
            <span
              style={{
                fontFamily: fontMono,
                fontSize: 11,
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
                color: T.textDim,
                border: `1px solid ${T.border}`,
                padding: '2px 8px',
              }}
            >
              {c.platform}
            </span>
          )}
        </div>
        <div style={{ fontFamily: fontMono, fontSize: 13, color: T.textDim }}>{c.tagline}</div>
      </div>
      <div style={{ padding: 20 }}>
        <P>{c.body}</P>
        <a
          href={c.href}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            padding: '10px 16px',
            fontFamily: fontMono,
            fontSize: 13,
            fontWeight: 600,
            letterSpacing: '0.04em',
            textDecoration: 'none',
            color: T.bg,
            background: T.accent,
            border: `1px solid ${T.accent}`,
            minHeight: 44,
          }}
        >
          Visit the community, free
        </a>
      </div>
    </section>
  );
}

export function SocialView() {
  return (
    <section aria-labelledby="social-heading">
      <h1
        id="social-heading"
        className="ap-display"
        style={{
          margin: '0 0 6px',
          fontSize: 'clamp(22px, 5vw, 26px)',
          fontWeight: 700,
          color: T.text,
          overflowWrap: 'break-word',
        }}
      >
        Social
      </h1>
      <P>
        You do not get good at shipping alone. The fastest learning loop for a vibe coder is other
        people: someone who already hit the bug you are hitting, someone who will read your repo and
        tell you the truth, someone shipping one step ahead of you. Tools teach you the pattern.
        Communities teach you the judgment.
      </P>
      <P>
        This section is for that side of the work. It is treated with the same weight as the rest of
        Learn, because for most builders it is where the real progress happens. Everything listed
        here is free. Pre-Flight asks for nothing, and it never points you at anything that does.
      </P>

      <H2>What a good builder community gives you</H2>
      <ul style={{ paddingLeft: 18, margin: 0 }}>
        <LI>
          <b>Faster unblocking.</b> A stuck afternoon becomes a ten-minute thread when someone has
          already solved it.
        </LI>
        <LI>
          <b>Honest review.</b> People who will look at what you built and tell you what is weak,
          which is the only feedback that improves you.
        </LI>
        <LI>
          <b>Momentum.</b> Watching peers ship makes you ship. Isolation is the most common reason
          good projects die.
        </LI>
        <LI>
          <b>Pattern exposure.</b> You learn the moves you did not know to ask about by seeing other
          people make them.
        </LI>
      </ul>

      <H2>Featured</H2>
      <P>
        Hand-picked, on any platform, group, server, forum, or feed. A community earns a spot here
        when it is free, treats its members well, and embraces what Pre-Flight is about. The list
        grows as more are found.
      </P>

      {COMMUNITIES.map((c) => (
        <CommunityCard key={c.href} c={c} />
      ))}
    </section>
  );
}
