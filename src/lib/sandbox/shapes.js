// src/lib/sandbox/shapes.js
//
// The shapes the sandbox can show, keyed by slug.
//
// The sandbox used to hold one hardcoded buffer and nothing pointed at it, so
// it read as a demo bolted onto the side of the app. This registry is what
// makes it a destination: a Learn page can say "try it" and a finding can say
// "open this shape", and both land on the same editor with the defect already
// on screen. The loop is meant to be short — see the shape, edit it, watch the
// finding clear — because retrieval is what makes a thing stick, and reading a
// second paragraph is not retrieval.
//
// Every entry carries its own fix. That is the part worth protecting: a
// `fixedBuffer` that still trips something is a lesson that lies, so the test
// asserts the fixed form produces ZERO findings, not merely zero from this
// probe. One shape needed two attempts for exactly that reason — an
// `async function run() {} run()` rewrite cleared the promise finding and
// tripped the fire-and-forget check instead.
//
// Plain data. No React import, no DOM access, no Vite-only syntax, so the
// prerender, the node test runner, and the browser bundle all read the same
// module. Every buffer is verified by test against runSandboxScan: the
// `buffer` must produce at least one finding from `probeId`, and the
// `fixedBuffer` must produce none.
//
// Schema, one entry:
//   slug             required  kebab-case, unique. The value of ?shape=<slug>.
//   title            required  Sentence case. Rendered as the sandbox H1 subject.
//   probeId          required  Must equal a `finding.probe` string the runner emits.
//   buffer           required  Code that fires probeId.
//   fixedBuffer      required  The same code with the defect removed. Fires nothing.
//   note             required  One or two sentences. What to look at.
//   learnSlug        optional  Published Learn pattern this shape illustrates.
//   findingIdPrefix  optional  Prefix of the probe-emitted finding.id, for exact
//                              finding -> shape routing from FindingCard.

export const DEFAULT_SHAPE_SLUG = 'starter';

export const SHAPES = [
  {
    slug: 'starter',
    title: 'A component with four rough edges',
    probeId: 'Code Quality',
    learnSlug: 'code-quality',
    note: 'A fetch with no abort and no status check, a resize listener with no cleanup, a leftover console.log, and index-as-key. Two of the four are things the scanner can see.',
    buffer: `import { useState, useEffect } from 'react';

function UserSearch({ onSelect }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);

  useEffect(() => {
    fetch('/api/search?q=' + query)
      .then((r) => r.json())
      .then(setResults);
  }, [query]);

  useEffect(() => {
    window.addEventListener('resize', () => {
      console.log('resized');
    });
  }, []);

  return (
    <div>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      {results.map((r, i) => (
        <div key={i} onClick={() => onSelect(r)}>
          {r.name}
        </div>
      ))}
    </div>
  );
}
`,
    fixedBuffer: `import { useState, useEffect } from 'react';

function UserSearch({ onSelect }) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch('/api/search?q=' + encodeURIComponent(query), { signal: controller.signal })
      .then((res) => {
        if (!res.ok) throw new Error('search failed: ' + res.status);
        return res.json();
      })
      .then(setResults)
      .catch((err) => {
        if (err.name !== 'AbortError') setError(err.message);
      });
    return () => controller.abort();
  }, [query]);

  useEffect(() => {
    const onResize = () => setResults((prev) => prev.slice());
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  return (
    <div>
      <input value={query} onChange={(e) => setQuery(e.target.value)} />
      {error ? <p role="alert">{error}</p> : null}
      {results.map((r) => (
        <div key={r.id} onClick={() => onSelect(r)}>
          {r.name}
        </div>
      ))}
    </div>
  );
}
`,
  },

  {
    slug: 'jwt-alg-none',
    title: 'Session token signed with alg none',
    probeId: 'Auth Weakness',
    learnSlug: 'auth-weakness',
    findingIdPrefix: 'auth-algnone-',
    note: 'The option object says algorithm: none, so the token carries no signature. Change it to HS256 and the finding clears.',
    buffer: `import jwt from 'jsonwebtoken';

const SECRET = process.env.SESSION_SECRET;

export function issueSession(user) {
  const payload = { sub: user.id, role: user.role };
  return jwt.sign(payload, SECRET, { algorithm: 'none', expiresIn: '1h' });
}
`,
    fixedBuffer: `import jwt from 'jsonwebtoken';

const SECRET = process.env.SESSION_SECRET;

export function issueSession(user) {
  const payload = { sub: user.id, role: user.role };
  return jwt.sign(payload, SECRET, { algorithm: 'HS256', expiresIn: '1h' });
}
`,
  },

  {
    slug: 'plaintext-password-compare',
    title: 'Login that compares passwords with ===',
    probeId: 'Auth Weakness',
    learnSlug: 'auth-weakness',
    findingIdPrefix: 'auth-plainpasswordcompare-',
    note: 'Comparing the submitted password to a stored field with === means the stored field is the password. Swap in bcrypt.compare against a hash column.',
    buffer: `export async function login(req, res) {
  const user = await db.users.findOne({ email: req.body.email });
  if (user && req.body.password === user.password) {
    return res.json({ ok: true, id: user.id });
  }
  return res.status(401).json({ ok: false });
}
`,
    fixedBuffer: `import bcrypt from 'bcrypt';

export async function login(req, res) {
  const user = await db.users.findOne({ email: req.body.email });
  const ok = user ? await bcrypt.compare(req.body.secretInput, user.hash) : false;
  if (!ok) {
    return res.status(401).json({ ok: false });
  }
  return res.json({ ok: true, id: user.id });
}
`,
  },

  {
    slug: 'token-in-url',
    title: 'Auth token sent in the query string',
    probeId: 'Auth Weakness',
    learnSlug: 'auth-weakness',
    findingIdPrefix: 'auth-tokeninurl-',
    note: 'A token in the URL lands in browser history, server access logs, and the Referer header. Move it to an Authorization header.',
    buffer: `export async function loadInvoices(token) {
  const res = await fetch('/api/invoices?token=' + token);
  return res.json();
}
`,
    fixedBuffer: `export async function loadInvoices(token) {
  const res = await fetch('/api/invoices', {
    headers: { Authorization: 'Bearer ' + token },
  });
  return res.json();
}
`,
  },

  {
    slug: 'eval-user-input',
    title: 'Filter expression run through eval',
    probeId: 'Code Injection',
    learnSlug: 'auth-weakness',
    findingIdPrefix: 'code-eval-',
    note: 'The expression comes from the caller and eval runs it as code. Replace the open expression with a fixed table of named predicates.',
    buffer: `export function applyFilter(rows, expression) {
  return rows.filter((row) => eval(expression));
}
`,
    fixedBuffer: `const FILTERS = {
  active: (row) => row.status === 'active',
  archived: (row) => row.status === 'archived',
};

export function applyFilter(rows, name) {
  const predicate = FILTERS[name];
  if (!predicate) {
    return [];
  }
  return rows.filter(predicate);
}
`,
  },

  {
    slug: 'unhandled-promise',
    title: 'A fetch chain with no catch',
    probeId: 'Code Quality',
    learnSlug: 'code-quality',
    findingIdPrefix: 'cq-then-no-catch-',
    note: 'When the request fails this rejects into nothing and the user sees a form that did not save. Add a catch and a status check.',
    buffer: `export function saveDraft(draft) {
  fetch('/api/drafts', {
    method: 'POST',
    body: JSON.stringify(draft),
  }).then((res) => res.json());
}
`,
    fixedBuffer: `export function saveDraft(draft, setSaveError) {
  return fetch('/api/drafts', {
    method: 'POST',
    body: JSON.stringify(draft),
  })
    .then((res) => {
      if (!res.ok) throw new Error('save failed: ' + res.status);
      return res.json();
    })
    .catch((err) => {
      setSaveError(err.message);
      return null;
    });
}
`,
  },

  {
    slug: 'empty-catch',
    title: 'A catch block with nothing in it',
    probeId: 'AI Code Smells',
    learnSlug: 'ai-code-smells',
    findingIdPrefix: 'smell-emptycatch-',
    note: 'The catch swallows every failure, so a bad response and a network drop look the same as success. Handle it or let it propagate.',
    buffer: `export async function loadSettings() {
  try {
    const res = await fetch('/api/settings');
    return await res.json();
  } catch (err) {}
  return DEFAULT_SETTINGS;
}
`,
    fixedBuffer: `export async function loadSettings(onError) {
  try {
    const res = await fetch('/api/settings');
    if (!res.ok) throw new Error('settings request failed: ' + res.status);
    return await res.json();
  } catch (err) {
    onError(err.message);
    return DEFAULT_SETTINGS;
  }
}
`,
  },
];

export const SHAPE_BY_SLUG = SHAPES.reduce((acc, s) => {
  acc[s.slug] = s;
  return acc;
}, {});

// Unknown slug resolves to the default entry. Never throws, never returns
// undefined, so SandboxView has no error branch to render.
export function getShape(slug) {
  return SHAPE_BY_SLUG[slug] || SHAPE_BY_SLUG[DEFAULT_SHAPE_SLUG];
}

// Every shape a Learn pattern page should offer. Excludes the default entry,
// which is the sandbox's own landing state rather than an illustration.
export function shapesForPattern(learnSlug) {
  if (!learnSlug) return [];
  return SHAPES.filter((s) => s.slug !== DEFAULT_SHAPE_SLUG && s.learnSlug === learnSlug);
}

// Exact route from a real scan finding to the shape that demonstrates it.
//
// Matches on findingIdPrefix only, never on probe name. A probe-name fallback
// was tried and rejected: `Code Quality` covers console.*, file size, unhandled
// .then, and fire-and-forget, so a console finding resolved to the unhandled-
// promise shape. Sending someone to the wrong shape is worse than sending them
// nowhere. Returns null when no shape covers the exact check.
export function shapeForFinding(finding) {
  if (!finding || !finding.id) return null;
  const id = String(finding.id);
  // Prefix only, as the note above says. An earlier version also required
  // `s.probeId === finding.probe`, which the comment did not mention and which
  // bought nothing: the prefixes are already per-check and unique, so the probe
  // name can only ever agree. What it did buy was a failure mode, since a
  // caller holding a finding without a `probe` field got null for a shape that
  // exists.
  return SHAPES.find((s) => s.findingIdPrefix && id.startsWith(s.findingIdPrefix)) || null;
}
