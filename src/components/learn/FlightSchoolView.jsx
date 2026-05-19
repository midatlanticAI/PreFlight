// src/components/learn/FlightSchoolView.jsx
//
// The "FlightSchool" sub-tab under /learn. A curated, role x tier index:
// the structured HOW that complements The Climb's WHY. Six roles, shared
// L0, diverge L1-L4, canon converges L5. Curate canonical free resources,
// never author. Index-only in v1 (pathways are a later conversation).
//
// Voice: reference register, John's first-person in the opener/moat. No
// marketing prose, no em-dashes, no fear framing. Per the locked
// positioning rule: PreFlight SEARCHES FOR the same things day one and
// day one thousand (coverage is constant; what it FINDS depends on your
// code). Never imply the tool tiers up. Each tier note names what becomes
// actionable there and that the rest was already in the report; lower
// tiers reference the AI-fix loop, higher tiers the human-fix maturation.
//
// All roles render stacked (SEO: every role's text is in the DOM and
// prerendered) with a jump nav. To add a role, append to ROLES.

import { T, fontMono } from '../../lib/theme.js';

const H2 = ({ children, id }) => (
  <h2 id={id} style={{ fontSize: 20, fontWeight: 700, color: T.text, margin: '32px 0 10px' }}>
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

function Resource({ r }) {
  return (
    <li style={{ color: T.textMuted, fontSize: 13.5, lineHeight: 1.6, marginBottom: 8 }}>
      {r.href ? (
        <a
          href={r.href}
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: T.accent, fontWeight: 600, textDecoration: 'none' }}
        >
          {r.name}
        </a>
      ) : (
        <strong style={{ color: T.text }}>{r.name}</strong>
      )}{' '}
      <span style={{ color: T.textDim }}>
        ({r.format} · {r.cost} · {r.time})
      </span>{' '}
      {r.why} <span style={{ color: T.textDim, fontSize: 12 }}>verified {r.verified}</span>
    </li>
  );
}

function SafetyNote({ children }) {
  return (
    <p
      style={{
        color: T.textDim,
        fontSize: 13,
        lineHeight: 1.7,
        margin: '4px 0 0',
        maxWidth: 760,
        padding: '10px 14px',
        background: T.bg,
        borderLeft: `2px solid ${T.accent}`,
      }}
    >
      <strong style={{ color: T.accent }}>PreFlight here:</strong> {children}
    </p>
  );
}

function Tier({ label, tier }) {
  return (
    <div style={{ marginTop: 14 }}>
      <h4 style={{ fontSize: 14, fontWeight: 700, color: T.text, margin: '0 0 6px' }}>{label}</h4>
      <ul style={{ paddingLeft: 18, margin: '0 0 6px' }}>
        {tier.resources.map((r, i) => (
          <Resource key={i} r={r} />
        ))}
      </ul>
      <SafetyNote>{tier.safety}</SafetyNote>
    </div>
  );
}

const V = '2026-05-18';

const SHARED_L0 = {
  resources: [
    {
      name: 'CS50, weeks 0 to 2',
      format: 'video lectures',
      cost: 'free',
      time: '~8 hrs',
      why: 'the best on-ramp ever made; watch, do not grind psets yet.',
      href: 'https://cs50.harvard.edu/x/',
      verified: V,
    },
    {
      name: 'The Missing Semester of Your CS Education',
      format: 'video + exercises',
      cost: 'free',
      time: '~6 hrs',
      why: 'the shell, git, and terminal nobody teaches and every role needs.',
      href: 'https://missing.csail.mit.edu/',
      verified: V,
    },
  ],
  safety:
    'Nothing to scan yet. The skill here is reading an error and knowing which file and line it points at. Every safety note below depends on that one habit.',
};

const SHARED_L5 = {
  resources: [
    {
      name: 'Teach Yourself Computer Science',
      format: 'reading list',
      cost: 'free',
      time: 'ongoing',
      why: 'the nine subjects that separate people who use abstractions from people who understand them.',
      href: 'https://teachyourselfcs.com/',
      verified: V,
    },
    {
      name: 'system-design-primer',
      format: 'repo',
      cost: 'free',
      time: 'ongoing',
      why: 'the shared language of scale; every L5 role speaks it.',
      href: 'https://github.com/donnemartin/system-design-primer',
      verified: V,
    },
    {
      name: 'The canon (Brooks, Ousterhout, Kleppmann, Raymond)',
      format: 'books',
      cost: 'mixed',
      time: 'ongoing',
      why: 'at this level you assemble your own list; that is the signal you arrived.',
      verified: V,
    },
  ],
  safety:
    'You now define what "safe to ship" means for everyone below you. PreFlight becomes a gate you wire into other people\'s climb, not a thing you run on yourself.',
};

const ROLES = [
  {
    id: 'ai-engineer',
    name: 'AI Engineer',
    blurb: 'Builds products on top of models and AI tools. The #1-paying tech role in 2026.',
    L1: {
      resources: [
        {
          name: 'roadmap.sh/ai-engineer',
          format: 'interactive roadmap',
          cost: 'free',
          time: '~1 hr',
          why: 'the canonical map of the role; you return every tier.',
          href: 'https://roadmap.sh/ai-engineer',
          verified: V,
        },
        {
          name: 'The Odin Project (Foundations)',
          format: 'project course',
          cost: 'free',
          time: '~50 hrs',
          why: 'you cannot orchestrate AI into an app you cannot run; this gives you the app.',
          href: 'https://www.theodinproject.com/',
          verified: V,
        },
      ],
      safety:
        'Scan your app. You will find more than you expected, and that is the point. You will not be able to hand-fix most of it yet, and you do not need to. Paste the finding back to your AI; it fixes what PreFlight caught, even if it takes a few passes, and you verify it is actually gone. Act first on the obvious: secrets, leaked keys, the model API key you pasted into the client. The rest is in the same report, waiting on a better-read version of you.',
    },
    L2: {
      resources: [
        {
          name: 'OpenAI / Anthropic API docs (ship one real call)',
          format: 'docs',
          cost: 'free',
          time: '~6 hrs',
          why: 'stop tutorial-watching; ship one real structured request and read every field.',
          verified: V,
        },
        {
          name: 'PortSwigger Web Security Academy (auth + access)',
          format: 'labs',
          cost: 'free',
          time: '~10 hrs',
          why: 'your AI app has a backend now; OWASP made tactile.',
          href: 'https://portswigger.net/web-security',
          verified: V,
        },
      ],
      safety:
        'Same scan, same report. What changed is you can now read the auth-config and CORS findings that were always there. "The AI secured nothing" finally means something you can act on.',
    },
    L3: {
      resources: [
        {
          name: 'roadmap.sh/ai-engineer (RAG, agents, evals)',
          format: 'roadmap',
          cost: 'free',
          time: 'ongoing',
          why: 'go deep on the AI-specific spine: retrieval, tool-calling, evals.',
          href: 'https://roadmap.sh/ai-engineer',
          verified: V,
        },
        {
          name: 'Hugging Face AI Agents Course',
          format: 'course + labs',
          cost: 'free',
          time: '~25 hrs',
          why: 'the current canonical agentic course: smolagents, LlamaIndex, LangGraph, agentic RAG, MCP.',
          href: 'https://huggingface.co/learn/agents-course',
          verified: V,
        },
        {
          name: 'Designing Data-Intensive Applications',
          format: 'book',
          cost: 'paid',
          time: '~30 hrs',
          why: 'your AI features touch real data now; this is the systems book.',
          verified: V,
        },
      ],
      safety:
        'Still the same findings. Now the prompt-injection sinks where user input flows into a system prompt, the unsanitized response stores, and the expensive unbounded AI endpoints are legible. They were in your L1 report. You just could not read them yet.',
    },
    L4: {
      resources: [
        {
          name: 'Multi-agent orchestration in practice (LangGraph + agent framework docs)',
          format: 'docs + build',
          cost: 'free',
          time: 'ongoing',
          why: 'agentic engineering is the ceiling of this role; learn where agents fail and how to fence them.',
          verified: V,
        },
        {
          name: 'The canon on constraint and complexity (Brooks, Ousterhout)',
          format: 'books',
          cost: 'paid',
          time: 'ongoing',
          why: 'at L4 the AI is the easy part; the system others build inside is the hard part.',
          verified: V,
        },
      ],
      safety:
        'The findings have not changed since your first scan. Your relationship to them has. You now require the gate of others: PreFlight in CI/CD as a pre-merge check, block on critical, audit trail public to the team.',
    },
  },
  {
    id: 'frontend',
    name: 'Frontend / Web Designer',
    blurb:
      'Owns what the user actually touches. Design literacy and security both, not design alone.',
    L1: {
      resources: [
        {
          name: 'The Odin Project (Foundations)',
          format: 'project course',
          cost: 'free',
          time: '~50 hrs',
          why: 'the canonical free front-end on-ramp, build-first.',
          href: 'https://www.theodinproject.com/',
          verified: V,
        },
        {
          name: 'roadmap.sh/frontend',
          format: 'roadmap',
          cost: 'free',
          time: '~1 hr',
          why: 'the map you return to every tier.',
          href: 'https://roadmap.sh/frontend',
          verified: V,
        },
      ],
      safety:
        'The obvious one on a vibe-coded UI is an API key hardcoded in client JavaScript. Everything in the browser is public. You will not hand-fix it yet; hand it to your AI, it moves the key server-side, you verify it is gone from view-source. The XSS and header findings are in the same report, becoming readable as you climb.',
    },
    L2: {
      resources: [
        {
          name: 'javascript.info',
          format: 'reference + exercises',
          cost: 'free',
          time: '~30 hrs',
          why: 'the deep JavaScript the AI assumes you already know.',
          href: 'https://javascript.info/',
          verified: V,
        },
        {
          name: 'Refactoring UI',
          format: 'book',
          cost: 'paid',
          time: '~6 hrs',
          why: 'why AI-generated UI looks slightly wrong and the specific moves that fix it.',
          href: 'https://www.refactoringui.com/',
          verified: V,
        },
      ],
      safety:
        'Same report. Cross-site scripting is now legible: user content rendered as HTML, dangerouslySetInnerHTML, an unescaped template. It was always flagged; now you can act on it. Frontend is where XSS lives.',
    },
    L3: {
      resources: [
        {
          name: 'Laws of UX',
          format: 'reference',
          cost: 'free',
          time: '~3 hrs',
          why: 'the psychology behind layout decisions you are currently guessing.',
          href: 'https://lawsofux.com/',
          verified: V,
        },
        {
          name: 'web.dev (Performance + Accessibility)',
          format: 'docs + labs',
          cost: 'free',
          time: '~12 hrs',
          why: 'Core Web Vitals and a11y: what gets you ranked and what gets you sued.',
          href: 'https://web.dev/',
          verified: V,
        },
        {
          name: 'Refactoring UI (second pass)',
          format: 'book',
          cost: 'paid',
          time: '~4 hrs',
          why: 're-read once you have shipped real interfaces; it reads differently.',
          verified: V,
        },
      ],
      safety:
        'Still the same findings. Now NEXT_PUBLIC_ leakage into the bundle, source maps shipped to production, and weak Content-Security-Policy are the ones you can read and own. All were in the report from scan one.',
    },
    L4: {
      resources: [
        {
          name: 'Design systems in practice (build one: component API + tokens)',
          format: 'build',
          cost: 'free',
          time: 'ongoing',
          why: 'at L4, frontend is system design: state boundaries, a contract others build inside.',
          verified: V,
        },
        {
          name: 'A Philosophy of Software Design (Ousterhout)',
          format: 'book',
          cost: 'paid',
          time: '~6 hrs',
          why: 'complexity is the enemy on the client too.',
          verified: V,
        },
      ],
      safety:
        'The coverage has not changed. You now own the front-end security contract (CSP, Subresource Integrity, zero client secrets) and require PreFlight as the pre-merge gate for every UI contributor.',
    },
  },
  {
    id: 'backend',
    name: 'Backend Engineer',
    blurb: 'Goes deep where Full-Stack stays shallow: data, APIs, queues, distributed systems.',
    L1: {
      resources: [
        {
          name: 'roadmap.sh/backend',
          format: 'roadmap',
          cost: 'free',
          time: '~1 hr',
          why: 'the role map; return every tier.',
          href: 'https://roadmap.sh/backend',
          verified: V,
        },
        {
          name: 'The Odin Project (Node + Databases)',
          format: 'project course',
          cost: 'free',
          time: '~60 hrs',
          why: 'your first real API backed by a real database.',
          href: 'https://www.theodinproject.com/',
          verified: V,
        },
      ],
      safety:
        'The obvious finding is a database connection string with credentials in a committed config file. The backend is where the real secrets live. Hand it to your AI, it moves it to environment config, you verify nothing sensitive is in the repo. Injection and authz findings are in the same report.',
    },
    L2: {
      resources: [
        {
          name: 'PortSwigger Web Security Academy',
          format: 'labs',
          cost: 'free',
          time: '~25 hrs',
          why: 'OWASP made tactile; the backend is where it bites hardest.',
          href: 'https://portswigger.net/web-security',
          verified: V,
        },
        {
          name: "Your stack's official ORM / SQL guide",
          format: 'docs',
          cost: 'free',
          time: '~8 hrs',
          why: 'understand the query the AI generated before you trust it near a database.',
          verified: V,
        },
      ],
      safety:
        'Same report. SQL and NoSQL injection from template-literal queries, and routes that authenticate but never authorize, are now legible. You can act on the endpoint that checks who you are but never what you may touch.',
    },
    L3: {
      resources: [
        {
          name: 'Designing Data-Intensive Applications',
          format: 'book',
          cost: 'paid',
          time: '~30 hrs',
          why: 'the backend bible: storage, replication, consistency.',
          verified: V,
        },
        {
          name: 'system-design-primer',
          format: 'repo',
          cost: 'free',
          time: 'ongoing',
          why: 'scaling, caching, queues, the shared language of backend at scale.',
          href: 'https://github.com/donnemartin/system-design-primer',
          verified: V,
        },
        {
          name: 'The Twelve-Factor App',
          format: 'guide',
          cost: 'free',
          time: '~2 hrs',
          why: 'the config and process discipline production demands.',
          href: 'https://12factor.net/',
          verified: V,
        },
      ],
      safety:
        'Unchanged coverage. Now TLS verification disabled, unbounded endpoints with no rate limit, stack traces returned to the client, and committed env secrets all read clearly. These were in the first report; they take down backends.',
    },
    L4: {
      resources: [
        {
          name: 'Distributed systems depth (MIT 6.824 lectures / the papers)',
          format: 'lectures',
          cost: 'free',
          time: 'ongoing',
          why: 'at L4 you own data integrity and failure modes for the whole system.',
          verified: V,
        },
        {
          name: 'The Mythical Man-Month (Brooks)',
          format: 'book',
          cost: 'paid',
          time: '~10 hrs',
          why: 'coordination and complexity, still right since 1975.',
          verified: V,
        },
      ],
      safety:
        'You define the data-handling and authorization invariants for every service. PreFlight is the required gate; you own the threshold and the dogfood discipline that keeps it honest.',
    },
  },
  {
    id: 'full-stack',
    name: 'Full-Stack Developer',
    blurb:
      'Not "both, shallower." The generalist who owns a whole vertical slice and knows where to specialize next.',
    L1: {
      resources: [
        {
          name: 'The Odin Project (Full Stack path)',
          format: 'project course',
          cost: 'free',
          time: '~150 hrs',
          why: 'the canonical end-to-end build.',
          href: 'https://www.theodinproject.com/',
          verified: V,
        },
        {
          name: 'roadmap.sh/full-stack',
          format: 'roadmap',
          cost: 'free',
          time: '~1 hr',
          why: 'the map across both ends.',
          href: 'https://roadmap.sh/full-stack',
          verified: V,
        },
      ],
      safety:
        'The obvious finding lives in the seam: a secret the front end reads because it was never kept server-side. Hand it to your AI, verify the boundary holds. Owning a whole slice means owning the line between its halves, and the rest of the report is yours too.',
    },
    L2: {
      resources: [
        {
          name: 'freeCodeCamp (relevant full certifications)',
          format: 'project',
          cost: 'free',
          time: '~60 hrs',
          why: 'ship a full CRUD app with auth, end to end.',
          href: 'https://www.freecodecamp.org/',
          verified: V,
        },
        {
          name: 'PortSwigger Web Security Academy (core)',
          format: 'labs',
          cost: 'free',
          time: '~12 hrs',
          why: 'the appsec baseline a slice owner cannot skip.',
          href: 'https://portswigger.net/web-security',
          verified: V,
        },
      ],
      safety:
        'Same report. The boundary findings are now legible: CORS misconfiguration and a secret crossing from server to client. That seam is the part only a full-stack owner is actually responsible for.',
    },
    L3: {
      resources: [
        {
          name: 'Designing Data-Intensive Applications (selective)',
          format: 'book',
          cost: 'paid',
          time: '~15 hrs',
          why: 'enough systems depth to own a slice without drowning.',
          verified: V,
        },
        {
          name: 'A Philosophy of Software Design',
          format: 'book',
          cost: 'paid',
          time: '~6 hrs',
          why: 'complexity is the enemy across the whole stack.',
          verified: V,
        },
        {
          name: 'roadmap.sh/full-stack (deep branches)',
          format: 'roadmap',
          cost: 'free',
          time: 'ongoing',
          why: 'read it for the signal of where to specialize next.',
          href: 'https://roadmap.sh/full-stack',
          verified: V,
        },
      ],
      safety:
        'Unchanged findings, now readable across the slice: input validated on the client only, an API response stored unsanitized, an auth check living in the UI instead of the API. You are the only one who sees the whole path.',
    },
    L4: {
      resources: [
        {
          name: 'The generalist-architect posture (own a slice; know the tradeoff to specialize)',
          format: 'practice',
          cost: 'free',
          time: 'ongoing',
          why: 'at L4 the full-stack value is judgment about where depth actually matters.',
          verified: V,
        },
        {
          name: 'Software Engineering at Google',
          format: 'book',
          cost: 'free',
          time: 'ongoing',
          why: 'engineering practice across the whole lifecycle.',
          href: 'https://abseil.io/resources/swe-book',
          verified: V,
        },
      ],
      safety:
        'Coverage constant. You own the entire threat surface of the slice; PreFlight gates it pre-merge and you decide what blocks, because no one else has the whole-slice view.',
    },
  },
  {
    id: 'security-deploy',
    name: 'Security and Deployment',
    blurb: 'PreFlight is this learner’s professional instrument. No modesty here.',
    L1: {
      resources: [
        {
          name: 'roadmap.sh/cyber-security',
          format: 'roadmap',
          cost: 'free',
          time: '~1 hr',
          why: 'the security role map.',
          href: 'https://roadmap.sh/cyber-security',
          verified: V,
        },
        {
          name: 'The Missing Semester (shell, git, systems)',
          format: 'video + exercises',
          cost: 'free',
          time: '~10 hrs',
          why: 'you cannot secure or deploy what you cannot operate.',
          href: 'https://missing.csail.mit.edu/',
          verified: V,
        },
      ],
      safety:
        'You are learning to read the finding taxonomy, not to produce clean code yet. Run PreFlight on other people’s sample repos and learn what every finding class means. This is your field’s vocabulary; the report is the same one everyone gets.',
    },
    L2: {
      resources: [
        {
          name: 'PortSwigger Web Security Academy (full path)',
          format: 'labs',
          cost: 'free',
          time: '~40 hrs',
          why: 'the single best free hands-on appsec training that exists; do all of it.',
          href: 'https://portswigger.net/web-security',
          verified: V,
        },
        {
          name: 'OWASP Top 10 + Cheat Sheets',
          format: 'reference',
          cost: 'free',
          time: '~10 hrs',
          why: 'the global baseline, by topic.',
          href: 'https://owasp.org/www-project-top-ten/',
          verified: V,
        },
      ],
      safety:
        'You should be able to explain every PreFlight finding class and reproduce it by hand. The Breakers panel is your practice harness: each adversarial input is a thing you should already know how to type.',
    },
    L3: {
      resources: [
        {
          name: 'OWASP Application Security Curriculum + Secure Coding Dojo',
          format: 'curriculum + labs',
          cost: 'free',
          time: '~30 hrs',
          why: 'the structured, classroom-grade secure-development path.',
          href: 'https://owasp.org/www-project-secure-coding-dojo/',
          verified: V,
        },
        {
          name: 'Supply-chain security (SLSA, Sigstore docs)',
          format: 'docs',
          cost: 'free',
          time: 'ongoing',
          why: 'the 2025 to 2026 attack surface: dependencies, build integrity.',
          href: 'https://slsa.dev/',
          verified: V,
        },
        {
          name: 'The Twelve-Factor App + deployment hardening',
          format: 'guide',
          cost: 'free',
          time: '~3 hrs',
          why: 'the deployment half of the role done right.',
          href: 'https://12factor.net/',
          verified: V,
        },
      ],
      safety:
        'The tool surfaces nothing new at this tier. What changed is that you own the pipeline now. Wiring PreFlight into CI as the gate is literally the job: you tune .preflight.yml, set the block threshold, and own the dogfood discipline. It stops being a tool you run and becomes infrastructure you operate.',
    },
    L4: {
      resources: [
        {
          name: 'Threat modeling + OWASP SAMM',
          format: 'framework',
          cost: 'free',
          time: 'ongoing',
          why: 'you define what "safe to ship" means org-wide.',
          href: 'https://owaspsamm.org/',
          verified: V,
        },
        {
          name: 'The appsec architecture canon',
          format: 'reading',
          cost: 'mixed',
          time: 'ongoing',
          why: 'you set policy, not just catch bugs.',
          verified: V,
        },
      ],
      safety:
        'Coverage is the same as day one. You set org policy, own the audit trail, and make the gate non-bypassable. You are this tool’s power user and its strongest critic; both are the job.',
    },
  },
  {
    id: 'ml-researcher',
    name: 'ML/AI Researcher',
    blurb:
      'Advances the field or builds the models. Not the AI Engineer (who builds products on top). Math, then ML fundamentals, then research track.',
    L1: {
      resources: [
        {
          name: '3Blue1Brown: Linear Algebra + Calculus',
          format: 'video',
          cost: 'free',
          time: '~15 hrs',
          why: 'the math the field actually runs on, made visual.',
          href: 'https://www.3blue1brown.com/',
          verified: V,
        },
        {
          name: 'roadmap.sh/ai-data-scientist',
          format: 'roadmap',
          cost: 'free',
          time: '~1 hr',
          why: 'the research-side map, distinct from ai-engineer.',
          href: 'https://roadmap.sh/ai-data-scientist',
          verified: V,
        },
      ],
      safety:
        'Light here. The safety lesson is reproducibility and data handling, not web vulnerabilities. A result you cannot reproduce is a bug the same way a crash is.',
    },
    L2: {
      resources: [
        {
          name: 'Andrew Ng Machine Learning Specialization (audit free)',
          format: 'course',
          cost: 'free',
          time: '~60 hrs',
          why: 'the canonical ML foundations.',
          href: 'https://www.coursera.org/specializations/machine-learning-introduction',
          verified: V,
        },
        {
          name: 'fast.ai Practical Deep Learning',
          format: 'course',
          cost: 'free',
          time: '~40 hrs',
          why: 'top-down deep learning that gets you training real models fast.',
          href: 'https://course.fast.ai/',
          verified: V,
        },
      ],
      safety:
        'Research code still ships and still leaks. The same report flags an API key committed in a notebook and data-leakage where test data bled into training. Hand them to your AI to fix, verify, and treat reproducibility as your security model.',
    },
    L3: {
      resources: [
        {
          name: 'Deep Learning (Goodfellow, free online)',
          format: 'book',
          cost: 'free',
          time: 'ongoing',
          why: 'the theory under the tools.',
          href: 'https://www.deeplearningbook.org/',
          verified: V,
        },
        {
          name: 'Stanford CS224N / CS229 (lectures free)',
          format: 'lectures',
          cost: 'free',
          time: 'ongoing',
          why: 'the research-grade fundamentals.',
          verified: V,
        },
        {
          name: 'Hugging Face (models, fine-tuning, eval design)',
          format: 'docs + practice',
          cost: 'free',
          time: 'ongoing',
          why: 'where research meets reproducible practice.',
          href: 'https://huggingface.co/learn',
          verified: V,
        },
      ],
      safety:
        'Same coverage. Now the model and data supply chain reads clearly: unsafe deserialization (pickle, torch.load on untrusted files), dataset paths that trust their input, secrets in training scripts. All were in the first report.',
    },
    L4: {
      resources: [
        {
          name: 'Reproduce papers; design evals; contribute',
          format: 'practice',
          cost: 'free',
          time: 'ongoing',
          why: 'at L4 you advance what is possible, and rigor is the whole job.',
          verified: V,
        },
        {
          name: "The field's canon and current conference proceedings",
          format: 'reading',
          cost: 'free',
          time: 'ongoing',
          why: 'you assemble this yourself; that is the signal.',
          verified: V,
        },
      ],
      safety:
        'Reproducibility and supply-chain integrity are your safety surface. You set the standard for safe model and data handling in your group, and the unsafe-deserialization class is the one you make non-negotiable.',
    },
  },
];

export function FlightSchoolView() {
  return (
    <section aria-labelledby="fs-heading">
      <h1
        id="fs-heading"
        className="ap-display"
        style={{
          margin: '0 0 6px',
          fontSize: 'clamp(22px, 5.5vw, 30px)',
          fontWeight: 700,
          color: T.text,
          overflowWrap: 'break-word',
        }}
      >
        FlightSchool
      </h1>
      <p
        style={{
          fontFamily: fontMono,
          fontSize: 15,
          color: T.text,
          fontWeight: 700,
          margin: '0 0 16px',
          maxWidth: 760,
        }}
      >
        Anyone with a pulse, a vibe-capable thing, and a dream can find their path here.
      </p>
      <P>
        You do not need to know what you want to build. Pick the role that sounds like you. You will
        see the whole climb in front of you. You start at L0 with everyone else, and you ship. That
        is what "0 to hero" means when it is infrastructure instead of a slogan.
      </P>
      <P>
        FlightSchool does not teach you. The best free teachers on earth already exist, and you will
        not out-learn them from a page on a security tool. What FlightSchool does is point you at
        exactly the right one for where you are, in the order that works, with a note at every step
        about what to verify before you trust what you built. Curated, not authored. Opinion, not a
        link dump.
      </P>
      <P>
        One thing does not change as you climb: PreFlight. It searches for the same things on day
        one as on day one thousand. Secrets, auth holes, injection, deserialization, all of it, from
        the first scan. The coverage never narrows or widens by tier. What changes is you, and you
        do not have to be able to fix a finding to act on it. Hand the finding to your AI and it
        fixes what PreFlight caught, sometimes first try, sometimes after a few. Early on your job
        is to run the loop and verify the result. Over time you stop needing the loop: you read the
        finding and know the fix, then you apply it yourself, then you write code that does not trip
        it. The map below is not the tool getting deeper. It is you getting deeper, at reading what
        it surfaces and at fixing what you read.
      </P>
      <P>
        How to use it: pick a role. Everyone shares L0. Roles split at L1 and run their own climb
        through L4. At L5 the paths converge back into the canon, because at the top everyone needs
        the same deep things.
      </P>

      <nav
        aria-label="Roles"
        style={{ display: 'flex', flexWrap: 'wrap', gap: 8, margin: '16px 0 8px' }}
      >
        {ROLES.map((r) => (
          <a
            key={r.id}
            href={`#${r.id}`}
            style={{
              fontFamily: fontMono,
              fontSize: 12,
              color: T.accent,
              textDecoration: 'none',
              border: `1px solid ${T.border}`,
              padding: '6px 10px',
            }}
          >
            {r.name}
          </a>
        ))}
      </nav>

      <H2 id="l0">L0: Shared. Everyone starts here.</H2>
      <P>The ground floor, the same for all six roles. Software is made things, not magic.</P>
      <ul style={{ paddingLeft: 18, margin: '0 0 6px' }}>
        {SHARED_L0.resources.map((r, i) => (
          <Resource key={i} r={r} />
        ))}
      </ul>
      <SafetyNote>{SHARED_L0.safety}</SafetyNote>

      {ROLES.map((role) => (
        <section
          key={role.id}
          id={role.id}
          aria-label={role.name}
          style={{
            marginTop: 22,
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
            {role.name}
          </h2>
          <P>{role.blurb}</P>
          <Tier label="L1: Vibe Coder" tier={role.L1} />
          <Tier label="L2: AI-Assisted Builder" tier={role.L2} />
          <Tier label="L3: AI-Assisted Developer" tier={role.L3} />
          <Tier label="L4: AI Programming Architect" tier={role.L4} />
        </section>
      ))}

      <H2 id="l5">L5: Shared. The paths converge.</H2>
      <P>
        At the ceiling there is no curriculum and no role-specific track. Everyone needs the same
        deep canon and the judgment to know which part matters now.
      </P>
      <ul style={{ paddingLeft: 18, margin: '0 0 6px' }}>
        {SHARED_L5.resources.map((r, i) => (
          <Resource key={i} r={r} />
        ))}
      </ul>
      <SafetyNote>{SHARED_L5.safety}</SafetyNote>

      <p
        style={{
          color: T.textDim,
          fontSize: 13,
          lineHeight: 1.7,
          margin: '24px 0 0',
          maxWidth: 760,
        }}
      >
        Pair this with The Climb for where each tier sits in the bigger picture, and the Tools page
        for what to climb with. Everything here is free. PreFlight asks for nothing.
      </p>
    </section>
  );
}
