// src/components/learn/TheClimbView.jsx
//
// The "The Climb" sub-tab under /learn. The 0-to-hero roadmap: from the
// floor of vibe coding to the ceiling of agentic engineering. Reference
// register; the why-it-exists framing and the personal close are John's
// first-person founder voice. No marketing prose, no em-dashes, no fear
// framing. Stats are attributed; aggregate figures are softened.
//
// The community accelerant points only at free, open communities
// (CommunityNote). There is no paid reference anywhere on this page or
// anywhere else on the site: PreFlight asks for nothing. CommunityNote
// is a simple list, more communities get appended to COMMUNITIES.

import { T, fontMono } from '../../lib/theme.js';

const H2 = ({ children }) => (
  <h2 style={{ fontSize: 18, fontWeight: 700, color: T.text, margin: '30px 0 10px' }}>
    {children}
  </h2>
);
const P = ({ children }) => (
  <p
    style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.7, margin: '0 0 12px', maxWidth: 760 }}
  >
    {children}
  </p>
);
const LI = ({ children }) => (
  <li style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.65, marginBottom: 6 }}>
    {children}
  </li>
);
const Field = ({ label, children }) => (
  <p
    style={{ color: T.textMuted, fontSize: 14, lineHeight: 1.65, margin: '0 0 6px', maxWidth: 760 }}
  >
    <strong style={{ color: T.text }}>{label}:</strong> {children}
  </p>
);

const TIERS = [
  {
    id: 'L0',
    name: 'L0: Digital User to Prompt Operator',
    stand: 'Below the floor. Curious. Maybe already using ChatGPT casually.',
    essence: 'Intent without verification.',
    trusted: 'Nothing yet, and that is correct.',
    wall: 'Believing software is magic. Cannot tell "the AI did something" from "the AI did the right thing."',
    leap: 'Reading what comes out. Running it deliberately. Recognizing that errors are information, not failure.',
    learnIntro: 'What you need to learn, the ground floor most curricula skip:',
    learn: [
      'What code is: text instructions that run on a machine. Not magic.',
      'What files, folders, and projects are, and how they organize themselves.',
      'What the command line is and why it exists. You do not need to master it. You need to not be scared of it.',
      'What a browser developer console is. Press F12 or CTRL+SHIFT+J right now. That panel becomes your best friend later.',
      'The difference between writing code and running code.',
      'What an error message is. Errors are information, not failure. This is the most important sentence on this page.',
    ],
    after:
      'Within this tier there is a small sub-climb: from someone who has never touched ChatGPT to someone who uses it daily for ideas, drafts, and one-shot tasks but has not shipped an app yet. That is the prompt operator state, still pre-floor, but oriented.',
    resources:
      "CS50's first two weeks, free, gold standard, lectures only at this stage, do not grind problem sets yet. Codecademy's \"Learn How to Code\" path, free intro, low pressure. freeCodeCamp's responsive web design intro, free, hands-on, gentle.",
    checkpoint:
      'You have crossed L0 when you can open a terminal and type ls or dir without panic, read an error message and identify which file and line it points at, and articulate to yourself what code is, in plain words.',
    time: '5 to 10 hours of focused exploration.',
    dontFall:
      'The failure mode at L0 is skipping it to get to AI tools faster. People who skip L0 never recover their debugging ability later, because they do not have the mental model for what is happening underneath. Spend the 10 hours. Earn the floor.',
  },
  {
    id: 'L1',
    name: 'L1: Vibe Coder',
    stand:
      "On the floor. Karpathy's original vibe coding. This is where most modern builders enter.",
    essence: 'Flow without a safety sense.',
    trusted:
      'Your own projects. Low blast radius. Tools for yourself, personal prototypes, landing pages.',
    wall: 'Cannot distinguish fragile-but-working from sound. Does not see security, edge cases, or how data moves through the app.',
    leap: 'A safety sense. Version control. Reading code. Verifying AI output against intent.',
    before:
      'You can prompt an AI tool and get something that looks like a working app. You ship MVPs. You feel the flow. You are in the right place, and you are one bad ship away from the story of someone shipping an Electronic Health Record system without knowing what HIPAA was. That is a real pattern, not a hypothetical.',
    learnIntro: 'What you need to learn:',
    learn: [
      'Specification is the actual skill. Articulating what you want clearly is harder than it looks. It is what separates good vibe coders from frustrated ones.',
      'Read what the AI produces. Not write it from scratch. Just read it well enough to spot when it is wrong.',
      'Stack traces. How to read one. Errors are still information.',
      'Basic git. What it is, why you commit, how to undo. You do not need branching mastery yet.',
      'Deployment. What it means. How to put something on the internet. Vercel, Netlify, Cloudflare Pages.',
      'Environment variables. What they are. Never put secrets in code. This rule has no exceptions.',
      'APIs at a conceptual level. What a request is, what a response is, what an endpoint means.',
    ],
    resources:
      'The Missing Semester of Your CS Education, free MIT course on the tools (shell, git, debugging) no one teaches you. "Git: the simple guide," short, free, enough to get started. Vercel\'s deployment docs, free, ship something today. OWASP Top 10 (2025) overview, free, read once at a conceptual level.',
    preflight: {
      title: 'PreFlight enters here.',
      body: 'This is the tier where PreFlight becomes a daily tool. Scan your projects. See what is broken. Read the explanations. The findings are the curriculum at this tier. Each one is a rung-climbing moment.',
    },
    checkpoint:
      'You have crossed L1 when you can ship a working app to the internet that does one thing well, read AI output and catch at least one thing that is wrong before you accept it, run your project through PreFlight and understand what the findings mean, and use git to recover from a mistake without panicking.',
    time: '40 to 80 hours of building real things with AI assistance.',
    dontFall:
      'L1 is real, and L1 is a hobby, not a career anymore. The field has moved on. If you want this to be how you make money, you have to keep climbing. The "shipped an app that lost a customer\'s data" stories all stop here. If your project will handle other people\'s data, money, or trust, do not ship it from L1.',
  },
  {
    id: 'L2',
    name: 'L2: AI-Assisted Builder',
    stand: 'Reaching off the floor toward the structural levels above it.',
    essence: 'Verification becoming a habit.',
    trusted:
      "Small-to-medium features under review. SaaS products, tools that handle other people's data, anything with auth, anything that processes money, with appropriate review.",
    wall: 'Thinking AI tools handle the security and reliability layer. They do not.',
    leap: 'Owning failure modes, not just happy paths.',
    before:
      'You read and modify AI code with confidence. You decompose features into prompts and verify each piece. You use git, basic tests, a debugger. You know the common vulnerability classes by name and category.',
    learnIntro: 'What you need to learn:',
    learn: [
      'State. What it is and why it is the source of most bugs.',
      'Auth vs. authz. Authentication is who you are. Authorization is what you are allowed to do. Different problems.',
      'Databases. SQL vs. document stores. When to use which.',
      'HTTPS, TLS, certificates. Why verify=False is a sin. Why secrets in URLs leak through logs.',
      'CORS. Why your frontend cannot just call any API. Why this is intentional.',
      'Rate limiting. Why your app falls over the moment it gets traction.',
      'Input validation. Never trust what users send.',
      'The OWASP Top 10 at a working level. Not memorized. Recognized when you see it.',
      'Logging and observability. How to know what your app is actually doing in production.',
      'Cost awareness. Cloud bills, AI API costs, what "scale" actually means financially.',
    ],
    resources:
      'The Pragmatic Programmer (Hunt & Thomas), paid, every chapter is a tier-climbing tool. OWASP Cheat Sheets, free, reference by topic. Web Security Academy by PortSwigger, free, hands-on, the OWASP Top 10 made tactile. The Twelve-Factor App, free, short, every word matters.',
    preflight: {
      title: 'PreFlight role at L2.',
      body: 'PreFlight is now catching things you partially recognize. The findings should mostly make sense. When they do not, you research, learn, and move up. Auth-config probe, secrets in code, deserialization findings, these are the daily safety net.',
    },
    checkpoint:
      'You have crossed L2 when you can ship a SaaS feature with auth that you would let a friend pay to use, read a stack trace and identify the actual problem in under five minutes, explain why a specific PreFlight finding matters without looking it up, and recover from a deployed bug under pressure without breaking other things.',
    time: '200 to 500 hours of shipping real things and dealing with real failures.',
    dontFall:
      'The failure mode at L2 is overconfidence. You can ship things. You forget that "I can ship this" and "this should be shipped" are different sentences. Healthcare, finance, regulated domains, do not ship there from L2. Get to L3 first.',
  },
  {
    id: 'L3',
    name: 'L3: AI-Assisted Developer',
    stand: 'Standing on the structural levels. Where most working professionals sit.',
    essence: 'Trusted unsupervised.',
    trusted:
      'Whole features and services end to end. Real businesses. Most domains. The work clients pay four figures a day for.',
    wall: 'Thinking in features instead of systems.',
    leap: 'Boundaries, invariants, and what not to build.',
    before:
      'You own whole features and services end to end. You design schemas and APIs. You threat-model. You manage dependencies and CI. You review AI output the way a senior reviews a fast junior. You direct agents with specs and acceptance criteria. You can be left alone with a problem. This is the first tier where the market reliably pays you for what you do. CS grads with degrees still tend to land here, just from a different on-ramp.',
    learnIntro: 'What you need to learn:',
    learn: [
      'System design. Breaking a big problem into small pieces with clear boundaries.',
      'When to use AI generation vs. when to write it yourself. Yes, sometimes you write it yourself.',
      'Trade-offs. Speed vs. maintainability. Simplicity vs. flexibility. Cost vs. performance. Naming the trade-off is half of making the decision.',
      "Reading other people's code. Yours from six months ago counts.",
      'Documentation as a skill, not a chore. It is how you onboard your future self and other people.',
      'Testing as confidence infrastructure. Do not memorize testing frameworks. Understand what testing does for you.',
      'Pre-mortems. What breaks first when this fails?',
      'Scoping. What to build, what to defer, what to never build.',
      'Regulated domains at a conceptual level. HIPAA, PCI-DSS, GDPR. What they are. When they apply. When to bring in a lawyer.',
    ],
    resources:
      'A Philosophy of Software Design (Ousterhout), paid, short, on complexity as the enemy. Designing Data-Intensive Applications (Kleppmann), paid, the database and systems book, read cover to cover at this tier. Software Engineering at Google, free, practices of engineering at scale. The Architecture of Open Source Applications, free, real systems explained by their builders. "Worse is Better" (Gabriel), free essay on simplicity as architecture.',
    checkpoint:
      'You have crossed L3 when you can be handed a problem you have never seen and design a system to solve it within a week, get paid to be trusted unsupervised, look at a codebase you did not write and propose three changes that would improve it with reasoning, and build something that survives contact with real users without you watching it every minute.',
    time: '2,000 to 5,000 hours. This is where most "senior engineers" sit regardless of how they got there.',
    dontFall:
      'The failure mode at L3 is thinking you have arrived because you can ship complex things. The next tier is about knowing what not to build. That is a different muscle.',
  },
  {
    id: 'L4',
    name: 'L4: AI Programming Architect',
    stand: 'Reaching toward the ceiling. The structural design tier.',
    essence: 'Judgment as infrastructure.',
    trusted: 'Defining what "done and safe" means so people below can ship safely and fast.',
    wall: 'Operating solo.',
    leap: 'Force multiplied through other people building inside the constraints you designed.',
    before:
      'You design systems, not features. You define the shapes, the boundaries, the invariants, the data model, the security architecture, the trade-offs. You orchestrate fleets of agents inside guardrails you built. Your multiplier is constraint design: you define what "done and safe" looks like so people below you can ship safely and fast. This is where agentic engineering, Karpathy\'s named successor to vibe coding, fully lives. Multi-agent stack orchestration (Cursor with Claude Code is the common professional stack as of 2026; LangGraph, AutoGen, CrewAI for the more ambitious work) is L4 territory.',
    learnIntro: 'What you need to learn:',
    learn: [
      'Constraint design. Picking the right limits so the system stays coherent as it grows.',
      'Invariants. What must always be true. What must never be true. How you enforce both.',
      'Boundary design. Where one component ends and the next begins. Why this matters more than how the components work.',
      'Multi-agent orchestration. When agents fail and how. How to design guardrails they cannot bypass.',
      'Open source mechanics. Licensing. Community. Contribution flows.',
      'Teaching. Your own learning compounds when you teach. It is also what converts L4 capability into real reach.',
      'The canon. The 60-year history of computing has answers to most problems. Knowing which are old saves you from re-inventing bad solutions.',
    ],
    resources:
      'The Mythical Man-Month (Brooks), paid, on coordination and complexity, written in 1975, still right. "No Silver Bullet" (Brooks), free essay, essential vs. accidental complexity. "The Cathedral and the Bazaar" (Raymond), free, open source as architecture. The Morning Paper, free, summarized CS papers, the canon made accessible. Hillel Wayne\'s writing, free, formal methods and engineering rigor. Will Larson\'s "Staff Engineer," paid, the L3-to-L4 transition mapped explicitly.',
    checkpoint:
      'You have crossed L4 when you can design a system other people can build inside without you in the room, make a constraint decision that others adopt because it makes their work better, teach someone something that becomes part of how they think, and recognize when a problem is one the canon already solved.',
    time: 'Ongoing. This is a posture, not a destination.',
    dontFall:
      'The failure mode at L4 is staying solo. If your constraint design never has other people building inside it, you are operationally still L3 doing L4-shaped work. Reach requires you to share, document, and accept that others will build inside your guardrails differently than you would.',
  },
];

function Tier({ t }) {
  return (
    <section
      aria-label={t.name}
      style={{
        marginTop: 18,
        padding: '18px 20px',
        background: T.panel,
        border: `1px solid ${T.border}`,
        borderLeft: `3px solid ${T.accent}`,
      }}
    >
      <h2
        className="ap-display"
        style={{ margin: '0 0 4px', fontSize: 22, fontWeight: 700, color: T.text }}
      >
        {t.name}
      </h2>
      <Field label="Where you stand">{t.stand}</Field>
      <Field label="Essence">{t.essence}</Field>
      <Field label="Trusted with">{t.trusted}</Field>
      <Field label="The wall">{t.wall}</Field>
      <Field label="The leap">{t.leap}</Field>

      {t.before && <P>{t.before}</P>}
      {t.learnIntro && <P>{t.learnIntro}</P>}
      {t.learn && (
        <ul style={{ paddingLeft: 18, margin: '0 0 12px' }}>
          {t.learn.map((x, i) => (
            <LI key={i}>{x}</LI>
          ))}
        </ul>
      )}
      {t.after && <P>{t.after}</P>}
      {t.preflight && (
        <p
          style={{
            color: T.textDim,
            fontSize: 14,
            lineHeight: 1.7,
            margin: '0 0 12px',
            maxWidth: 760,
            padding: '10px 14px',
            background: T.bg,
            borderLeft: `2px solid ${T.accent}`,
          }}
        >
          <strong style={{ color: T.accent }}>{t.preflight.title}</strong> {t.preflight.body}
        </p>
      )}
      <Field label="Resources">{t.resources}</Field>
      <Field label="Checkpoint">{t.checkpoint}</Field>
      <Field label="Time investment">{t.time}</Field>
      <Field label="Don't fall here">{t.dontFall}</Field>
    </section>
  );
}

// Free, open communities only. No paid product is referenced here or
// anywhere else on the site. Append to COMMUNITIES to add more rooms.
const COMMUNITIES = [
  {
    name: 'Vibe Coding is Life',
    href: 'https://www.facebook.com/groups/1712447172677146',
    blurb:
      'a free group where vibe coders share projects, debug together, and ship in the open. A solid room to be in while you climb the L1 to L3 stretch.',
  },
];
// More free, mission-aligned communities get appended here over time,
// any platform. The full curated list lives in the Social section.

function CommunityNote() {
  return (
    <div
      style={{
        margin: '12px 0',
        padding: '14px 18px',
        background: T.bg,
        border: `1px solid ${T.border}`,
        maxWidth: 760,
      }}
    >
      <p style={{ color: T.textDim, fontSize: 13, lineHeight: 1.7, margin: '0 0 8px' }}>
        Free rooms worth being in:
      </p>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
        {COMMUNITIES.map((c) => (
          <li key={c.href} style={{ marginBottom: 8 }}>
            <a
              href={c.href}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: T.accent, fontWeight: 600, fontSize: 14, textDecoration: 'none' }}
            >
              {c.name}
            </a>
            <span style={{ color: T.textMuted, fontSize: 13, lineHeight: 1.7 }}> {c.blurb}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function TheClimbView() {
  return (
    <section aria-labelledby="theclimb-heading">
      <h1
        id="theclimb-heading"
        className="ap-display"
        style={{
          margin: '0 0 6px',
          fontSize: 'clamp(22px, 5.5vw, 30px)',
          fontWeight: 700,
          color: T.text,
          overflowWrap: 'break-word',
        }}
      >
        The Climb
      </h1>
      <p style={{ fontFamily: fontMono, fontSize: 14, color: T.textDim, margin: '0 0 18px' }}>
        From the floor of vibe coding to the ceiling of agentic engineering.
      </p>

      <H2>Why this map exists</H2>
      <P>
        In 2025, Andrej Karpathy coined "vibe coding," the practice of building software by
        prompting AI tools and iterating on feel. A year later, at Sequoia AI Ascent 2026, he
        retired the term. The successor he named is agentic engineering: you orchestrate agents, you
        act as oversight, and there is real art and science to doing it well.
      </P>
      <P>The two are not rivals. They are floor and ceiling.</P>
      <P>
        Vibe coding raised the floor so anyone can prototype. Agentic engineering preserves the
        ceiling so what gets shipped is secure, production-ready, and trustworthy. This map is the
        climb between them.
      </P>
      <P>
        Every rung on this ladder is a rung of judgment, not typing. AI made producing code nearly
        free. It did nothing to make judging, verifying, and structuring it free. The single skill
        that scales at every level is verification: knowing when to trust the machine and when not
        to.
      </P>
      <P>
        The climb is not optional the way it was. Here is what the field actually looks like right
        now:
      </P>
      <ul style={{ paddingLeft: 18, margin: '0 0 12px' }}>
        <LI>46% of all new code is AI-generated (GitHub, 2026).</LI>
        <LI>
          Analyses across 2025 and 2026 report roughly 45% of AI-generated code shipping with an
          OWASP Top 10 vulnerability.
        </LI>
        <LI>
          AI-co-authored code is reported to carry about 1.7x more major issues and 2.74x more logic
          errors than human-only code.
        </LI>
        <LI>
          Refactoring has reportedly collapsed from about 25% of changed lines to under 10%, which
          means we ship more, fix less, and the bugs compound.
        </LI>
        <LI>
          The METR study (July 2025) found experienced open-source developers were 19% slower with
          AI while predicting they would be 24% faster.
        </LI>
      </ul>
      <P>
        That last one is the whole thesis in a single statistic. People who use AI think they are
        faster. They are not. They are slower and shipping more bugs. The only thing that closes the
        gap is verification skill. That is what this map teaches.
      </P>

      <H2>How to read this</H2>
      <P>
        Do not read it top to bottom. Find where you actually are. Focus on the next rung. Each tier
        names its essence, what you can be trusted with, the wall that keeps people stuck, the leap
        to the next tier, resources (free where possible, cost noted when not), and a checkpoint for
        knowing you have actually crossed. Tiers track where you sit between the floor (anyone can
        prototype) and the ceiling (it ships safely to real users at scale).
      </P>

      {TIERS.map((t) => (
        <Tier key={t.id} t={t} />
      ))}

      <section
        aria-label="L5: Principal Builder"
        style={{
          marginTop: 18,
          padding: '18px 20px',
          background: T.panel,
          border: `1px solid ${T.border}`,
          borderLeft: `3px solid ${T.accent}`,
        }}
      >
        <h2
          className="ap-display"
          style={{ margin: '0 0 4px', fontSize: 22, fontWeight: 700, color: T.text }}
        >
          L5: Principal Builder
        </h2>
        <Field label="Where you stand">
          At the ceiling. The people who design the platforms others build on.
        </Field>
        <Field label="Essence">Taste, depth, and judgment under uncertainty.</Field>
        <Field label="Trusted with">
          Direction. Patterns. The judgment calls that define what comes next.
        </Field>
        <Field label="The wall">
          None you are aware of. The next wall gets invented by whoever reaches it after you.
        </Field>
        <Field label="The leap">Not a leap. A posture you sustain.</Field>
        <P>
          You set direction. You invent patterns others adopt. You can parachute into any level and
          operate. You multiply everyone around you. You know the 60-year canon deeply enough to
          tell timeless from fashionable, and to know exactly what AI changed and what it did not.
          This tier is not about knowing more. It is about knowing what is worth knowing in any
          given moment.
        </P>
        <P>
          <strong style={{ color: T.text }}>Who lives here.</strong> Two distinct paths converge at
          L5.
        </P>
        <P>
          Builders: Carmack, Torvalds, Knuth, Ritchie. The people who shipped the tools the rest of
          us build on. They design platforms, write the books, set the patterns.
        </P>
        <P>
          Researchers: Karpathy, Hinton, Sutskever. The people who advance what is possible at the
          frontier. They write the papers, train the models, name the new things.
        </P>
        <P>
          These are different careers with different skill stacks. Builders ship infrastructure.
          Researchers ship knowledge. Both belong at the ceiling. Do not confuse one path for the
          other when you choose which to walk.
        </P>
        <Field label="Resources">
          L5 has no curriculum. The signal that you are climbing toward it is that you have stopped
          looking for one and started reading whatever you are curious about, in whatever order
          makes sense, while building whatever you cannot stop thinking about. The reading list at
          this level is the one you assemble for yourself based on the problems you are working on.
        </Field>
      </section>

      <H2>What is timeless. What AI changed.</H2>
      <P>
        Timeless, true since the 1960s, AI does not touch it: decomposition, abstraction and
        information hiding, naming, data structures, invariants, testing and feedback loops, version
        control, programs are written for people to read, simplicity is a feature, security is not
        bolt-on, and you do not understand it until you can debug it and explain it.
      </P>
      <P>
        What AI changed: the bottleneck moved from "can you write it" to "can you specify it, verify
        it, and own it." Generation is commodity. The scarce skills are decomposition, verification,
        architecture, and taste. The ladder is now steeper at the top and gentler at the bottom. The
        through-line at every rung is verification. That is the spine of the whole roadmap.
      </P>

      <H2>The industry trajectory</H2>
      <P>Where the field is going, regardless of where you personally stand on the ladder:</P>
      <P>
        Manual Programming (human writes every instruction) to Assisted Programming (AI accelerates
        human coding) to Intent-Based Development (human describes systems) to Autonomous
        Engineering (AI agents implement, refactor, test, deploy) to Cognitive Architecture Design
        (humans design goals, constraints, evaluation systems, and world models while AI handles
        implementation).
      </P>
      <P>
        We are currently somewhere between Assisted and Intent-Based, with leading-edge teams
        already operating in Autonomous Engineering territory. The climb up this ladder is not
        optional. The industry is moving up it whether individual practitioners do or not. PreFlight
        exists because the climb has security gaps the industry has not closed yet.
      </P>

      <H2>How long this used to take versus now</H2>
      <P>
        1990s: L3 in 10 to 20 years. Information was scarce. Tooling was primitive. AI did not
        exist.
      </P>
      <P>
        2026: a motivated person can reach L2 in months, L3 in 1 to 2 years, L4 in 3 to 5 years. The
        condition: build continuously, use AI correctly, study systems deeply, avoid tutorial
        addiction.
      </P>
      <P>The ladder compressed because the floor rose. Climbing past the floor still takes work.</P>

      <H2>How to actually climb</H2>
      <P>Three things matter more than any specific resource or tier.</P>
      <P>
        <strong style={{ color: T.text }}>Ship things.</strong> The map is a guide to what to learn
        next. You learn by building, not by reading. If you are between tiers, you are shipping
        things slightly above your current safety. That is the climb.
      </P>
      <P>
        <strong style={{ color: T.text }}>Community is the accelerant.</strong> The fastest climbers
        are not the ones with the best reading list. They are the ones in a room with people one
        rung above them, shipping in public, getting told the truth about their code. Find that
        room. Be useful in it. Do not be a leech.
      </P>

      <CommunityNote />

      <P>
        <strong style={{ color: T.text }}>Honesty.</strong> Self-assess without flinching.
        Over-claiming costs you trust. Under-claiming costs you opportunities. Knowing the
        difference and naming it accurately is itself part of the climb.
      </P>

      <p
        style={{
          color: T.textDim,
          fontSize: 13,
          lineHeight: 1.7,
          margin: '26px 0 0',
          maxWidth: 760,
          fontStyle: 'italic',
          borderTop: `1px solid ${T.border}`,
          paddingTop: 16,
        }}
      >
        Built by Johnathan Scott Viruet. I am somewhere between L3 and L4, climbing without a CS
        degree, shipping production AI systems mostly solo. This map is the one I wish I had had.
        PreFlight is the tool I built for the L1 to L2 transition, because that is where I watched
        the most people fall. The rest of this map is what I am building toward: PreFlight Learn as
        the climbing infrastructure for vibe coders becoming engineers.
        <br />
        <br />
        Find me: midatlantic.ai · preflight.midatlantic.ai · Vibe Coding is Life on Facebook
      </p>
    </section>
  );
}
