// Adversarial PRECISION tests for probeClientAuthStorage.
//
// Goal: drive false-positive rate down. Every fixture in this file is a
// realistic client-side pattern that LOOKS like it could be auth-token storage
// but ISN'T. The probe must not flag these.
//
// Categories (per the precision-test spec):
//   1. localStorage of NON-auth data (theme, prefs, cart, locale, last page)
//   2. Documentation discussing the anti-pattern as a DON'T (.md / Learn copy)
//   3. Comments naming the shape (no real call)
//   4. Test fixtures (paths under src/test/, __tests__/, *.test.js, tests/fixtures/)
//   5. Variable-name placeholder context (SAMPLE_TOKEN-style sentinels)
//   6. HttpOnly cookies set server-side (the CORRECT pattern)
//   7. BYOK key storage with explicit user consent (PreFlight's own pattern)
//   8. Token in JS variable, never persisted (in-memory only)
//   9. OAuth state / nonce / code_verifier stored briefly (CSRF, not a credential)
//  10. Service worker caching NON-auth responses
//
// Ambiguous categories (5, 7, 9) use TOLERANT assertions: at most one finding,
// and if a finding fires it must be low severity. Everything else asserts
// strict zero.

import { describe, it, expect } from 'vitest';
import { probeClientAuthStorage } from '../lib/probes.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const file = (path, content) => ({ path, content });
const run = (...files) => probeClientAuthStorage(files);

const expectClean = (findings) => {
  expect(Array.isArray(findings)).toBe(true);
  expect(findings).toEqual([]);
};

// AMBIGUOUS: accept zero, or at most one low/info-severity finding.
const expectTolerant = (findings) => {
  expect(Array.isArray(findings)).toBe(true);
  expect(findings.length).toBeLessThanOrEqual(1);
  if (findings.length === 1) {
    const sev = String(findings[0].severity || '').toLowerCase();
    expect(['low', 'info', 'informational', 'note', '']).toContain(sev);
  }
};

// ===========================================================================
// CATEGORY 1 — localStorage of NON-auth data (heavy weight)
// ===========================================================================

describe('Cat 1: localStorage of non-auth data should not fire', () => {
  it('stores a theme preference', () => {
    const f = file(
      'src/components/ThemeToggle.jsx',
      `export function ThemeToggle() {
        const onClick = () => {
          localStorage.setItem('theme', 'dark');
        };
        return <button onClick={onClick}>Dark mode</button>;
      }`
    );
    expectClean(run(f));
  });

  it('stores a JSON blob of user preferences', () => {
    const f = file(
      'src/state/preferences.js',
      `export function savePreferences(p) {
        localStorage.setItem('preferences', JSON.stringify(p));
      }
      export function loadPreferences() {
        const raw = localStorage.getItem('preferences');
        return raw ? JSON.parse(raw) : {};
      }`
    );
    expectClean(run(f));
  });

  it('stores a shopping cart array', () => {
    const f = file(
      'src/state/cart.js',
      `export function persistCart(cart) {
        localStorage.setItem('cart', JSON.stringify(cart));
      }`
    );
    expectClean(run(f));
  });

  it('stores last visited page for back-navigation UX', () => {
    const f = file(
      'src/state/router-memory.js',
      `export function rememberRoute(path) {
        localStorage.setItem('last_visited_page', path);
      }`
    );
    expectClean(run(f));
  });

  it('stores user-selected locale', () => {
    const f = file(
      'src/i18n/locale.js',
      `export function setLocale(locale) {
        localStorage.setItem('locale', locale);
      }
      setLocale('en');`
    );
    expectClean(run(f));
  });

  it('stores a feature-flag override map', () => {
    const f = file(
      'src/flags/overrides.js',
      `export function setOverrides(map) {
        localStorage.setItem('feature_flag_overrides', JSON.stringify(map));
      }`
    );
    expectClean(run(f));
  });

  it('stores onboarding-tour progress', () => {
    const f = file(
      'src/onboarding/progress.js',
      `localStorage.setItem('onboarding_step', '3');
      localStorage.setItem('onboarding_dismissed', 'false');`
    );
    expectClean(run(f));
  });

  it('stores draft form input across reloads', () => {
    const f = file(
      'src/components/ContactForm.jsx',
      `useEffect(() => {
        localStorage.setItem('contact_form_draft', JSON.stringify(values));
      }, [values]);`
    );
    expectClean(run(f));
  });

  it('stores recent searches', () => {
    const f = file(
      'src/search/history.js',
      `export function pushRecentSearch(q) {
        const cur = JSON.parse(localStorage.getItem('recent_searches') || '[]');
        cur.unshift(q);
        localStorage.setItem('recent_searches', JSON.stringify(cur.slice(0, 10)));
      }`
    );
    expectClean(run(f));
  });

  it('stores sidebar collapse state', () => {
    const f = file(
      'src/layout/Sidebar.jsx',
      `const toggle = () => {
        const next = !collapsed;
        setCollapsed(next);
        localStorage.setItem('sidebar_collapsed', String(next));
      };`
    );
    expectClean(run(f));
  });

  it('stores analytics counters (PreFlight pattern)', () => {
    const f = file(
      'src/lib/analytics.js',
      `export function bumpScanCounter() {
        const cur = Number(localStorage.getItem('preflight_scan_count') || 0);
        localStorage.setItem('preflight_scan_count', String(cur + 1));
      }`
    );
    expectClean(run(f));
  });

  it('stores suppression list (PreFlight pattern)', () => {
    const f = file(
      'src/lib/suppression.js',
      `export function saveSuppressions(ids) {
        localStorage.setItem('preflight_suppressions', JSON.stringify([...ids]));
      }`
    );
    expectClean(run(f));
  });
});

// ===========================================================================
// CATEGORY 2 — Documentation discussing the anti-pattern (heavy weight)
// ===========================================================================

describe('Cat 2: docs / Learn content discussing the anti-pattern should not fire', () => {
  it("Learn pattern .md with don't-do-this code block", () => {
    const f = file(
      'src/learn/patterns/client-auth-storage.md',
      `---
title: Auth tokens in localStorage
---
The anti-pattern:

\`\`\`ts
localStorage.setItem('jwt', token); // session is now readable by any JS
localStorage.setItem('access_token', token); // same problem
localStorage.setItem('refresh_token', refresh); // same problem
\`\`\`

The fix uses HttpOnly cookies instead.`
    );
    expectClean(run(f));
  });

  it('README explaining the anti-pattern', () => {
    const f = file(
      'README.md',
      `## Common mistakes

Don't do this:

    localStorage.setItem('session', token);

Use httpOnly cookies instead. See [Cookie security](./docs/cookies.md).`
    );
    expectClean(run(f));
  });

  it('architecture doc citing the pattern', () => {
    const f = file(
      'docs/auth-design.md',
      `## Why we use cookies, not localStorage

The vibe-built variant typically does:

    localStorage.setItem('jwt', resp.token);

We rejected that because every XSS becomes session theft. Our login route
sets an HttpOnly cookie server-side.`
    );
    expectClean(run(f));
  });

  it('field-report .md citing a real-world incident', () => {
    const f = file(
      'src/learn/incidents/some-breach.md',
      `The attacker's payload ran \`localStorage.setItem('auth', stolen)\`
to persist a forged session. The fix was to migrate to HttpOnly cookies.`
    );
    expectClean(run(f));
  });

  it('CHANGELOG describing a fix', () => {
    const f = file(
      'CHANGELOG.md',
      `## 2.0.0

Removed legacy code that called \`localStorage.setItem('access_token', ...)\`
on login. Tokens are now httpOnly cookies.`
    );
    expectClean(run(f));
  });

  it('MDX learn page with a fenced TS example', () => {
    const f = file(
      'src/learn/patterns/auth-storage.mdx',
      `# Auth storage

\`\`\`tsx
function BadLoginExample() {
  // illustrative only
  localStorage.setItem('jwt', token);
}
\`\`\``
    );
    expectClean(run(f));
  });

  it('doc explicitly enumerates every shape the probe scans for', () => {
    const f = file(
      'docs/scanner-coverage.md',
      `The probe scans for:
- \`localStorage.setItem('jwt', ...)\`
- \`localStorage.setItem('session', ...)\`
- \`localStorage.setItem('auth', ...)\`
- \`localStorage.setItem('access_token', ...)\`
- \`localStorage.setItem('refresh_token', ...)\`
- \`sessionStorage.setItem('jwt', ...)\``
    );
    expectClean(run(f));
  });
});

// ===========================================================================
// CATEGORY 3 — Comments naming the shape (no live call)
// ===========================================================================

describe('Cat 3: comments naming the shape should not fire', () => {
  it('single-line comment showing the anti-pattern', () => {
    const f = file(
      'src/auth/login.js',
      `export async function login(email, password) {
        const { token } = await api.login(email, password);
        // don't do this: localStorage.setItem('token', token);
        // we set an HttpOnly cookie server-side instead.
        return token;
      }`
    );
    expectClean(run(f));
  });

  it('legacy-code-removed banner comment', () => {
    const f = file(
      'src/auth/legacy.js',
      `// legacy code removed
      // previously: localStorage.setItem('jwt', token);
      // see migration note in docs/auth-migration.md`
    );
    expectClean(run(f));
  });

  it('JSDoc warning about the anti-pattern', () => {
    const f = file(
      'src/auth/session.js',
      `/**
       * Returns the current session.
       * NOTE: never call localStorage.setItem('session', ...) here.
       * The session is a cookie; this getter reads from a memo only.
       */
      export function getSession() {
        return memo.current;
      }`
    );
    expectClean(run(f));
  });

  it('TODO comment about migrating off localStorage', () => {
    const f = file(
      'src/auth/todo.js',
      `// TODO(2026-Q3): the old SDK still calls localStorage.setItem('access_token', t).
      // Ours does not. Once the legacy SDK is removed we can drop this shim.`
    );
    expectClean(run(f));
  });

  it('block comment with multiple anti-pattern shapes', () => {
    const f = file(
      'src/auth/notes.js',
      `/*
       * Patterns we do NOT use:
       *   localStorage.setItem('jwt', token)
       *   localStorage.setItem('refresh_token', refresh)
       *   sessionStorage.setItem('auth', token)
       */
      export const noop = () => {};`
    );
    expectClean(run(f));
  });
});

// ===========================================================================
// CATEGORY 4 — Test fixtures (heavy weight)
// ===========================================================================

describe('Cat 4: test-fixture paths should not fire', () => {
  it('file under src/test/ with a token fixture', () => {
    const f = file(
      'src/test/auth-storage-fixture.test.js',
      `it('flags localStorage tokens', () => {
        const code = "localStorage.setItem('jwt', 'fake-test-token')";
        expect(probe([{ path: 'x.js', content: code }])).toHaveLength(1);
      });`
    );
    expectClean(run(f));
  });

  it('file under __tests__/ with an anti-pattern string literal', () => {
    const f = file(
      '__tests__/auth.test.js',
      `const FIXTURE = \`localStorage.setItem('access_token', token)\`;
      test('detects token storage', () => {
        expect(detect(FIXTURE)).toBe(true);
      });`
    );
    expectClean(run(f));
  });

  it('*.test.js with inline fixture content', () => {
    const f = file(
      'src/auth/login.test.js',
      `const sample = "localStorage.setItem('refresh_token', 'abc.def.ghi')";
      test('login fixture', () => {
        expect(sample).toContain('refresh_token');
      });`
    );
    expectClean(run(f));
  });

  it('tests/fixtures/ JSON fixture quoting the pattern', () => {
    const f = file(
      'tests/fixtures/bad-login.fixture.js',
      `export const badLogin = {
        path: 'src/auth.js',
        content: "const t=await login(); localStorage.setItem('jwt', t);"
      };`
    );
    expectClean(run(f));
  });

  it('vitest spec file with multiple fixture strings', () => {
    const f = file(
      'src/test/probes-auth-storage.spec.js',
      `describe('auth storage', () => {
        const cases = [
          "localStorage.setItem('jwt', t)",
          "localStorage.setItem('session', t)",
          "sessionStorage.setItem('access_token', t)"
        ];
        cases.forEach(c => it(c, () => expect(detect(c)).toBe(true)));
      });`
    );
    expectClean(run(f));
  });

  it('test file under a deeply nested __tests__ dir', () => {
    const f = file(
      'src/features/billing/__tests__/checkout.test.jsx',
      `it('persists draft', () => {
        // sanity fixture, not real auth
        const code = "localStorage.setItem('jwt', 'placeholder')";
        expect(code).toMatch(/jwt/);
      });`
    );
    expectClean(run(f));
  });

  it('cypress e2e spec under cypress/e2e/', () => {
    const f = file(
      'cypress/e2e/login.cy.js',
      `it('login flow', () => {
        cy.window().then(w => {
          // fixture: simulate a legacy app's storage
          w.localStorage.setItem('access_token', 'test-only-token');
        });
      });`
    );
    expectClean(run(f));
  });
});

// ===========================================================================
// CATEGORY 5 — Variable-name placeholder context (AMBIGUOUS)
// ===========================================================================

describe('Cat 5: SAMPLE_TOKEN-style placeholder names (tolerant)', () => {
  // AMBIGUOUS: probe may have to scan for the string "token" in keys; a
  // placeholder convention is hint-only.

  it('SAMPLE_TOKEN constant used as the value', () => {
    const f = file(
      'src/docs/examples.js',
      `const SAMPLE_TOKEN = 'abc';
      const SAMPLE_TOKEN_KEY = 'sample_token';
      // documentation example only
      localStorage.setItem(SAMPLE_TOKEN_KEY, SAMPLE_TOKEN);`
    );
    expectTolerant(run(f));
  });

  it('EXAMPLE_ prefix on both key and value', () => {
    const f = file(
      'src/docs/example-usage.js',
      `const EXAMPLE_KEY = 'example_auth';
      const EXAMPLE_VALUE = 'example_value';
      localStorage.setItem(EXAMPLE_KEY, EXAMPLE_VALUE);`
    );
    expectTolerant(run(f));
  });

  it('PLACEHOLDER_ prefix on the key', () => {
    const f = file(
      'src/docs/placeholders.js',
      `const PLACEHOLDER_TOKEN_KEY = 'placeholder_jwt';
      const PLACEHOLDER_TOKEN_VALUE = 'placeholder';
      localStorage.setItem(PLACEHOLDER_TOKEN_KEY, PLACEHOLDER_TOKEN_VALUE);`
    );
    expectTolerant(run(f));
  });

  it('DUMMY_ prefix used inside a storybook story', () => {
    const f = file(
      'src/components/Login.stories.jsx',
      `const DUMMY_AUTH_KEY = 'dummy_auth';
      const DUMMY_AUTH_VALUE = 'dummy';
      export const Default = () => {
        localStorage.setItem(DUMMY_AUTH_KEY, DUMMY_AUTH_VALUE);
        return <Login />;
      };`
    );
    expectTolerant(run(f));
  });
});

// ===========================================================================
// CATEGORY 6 — HttpOnly cookies set server-side (heavy weight, CORRECT pattern)
// ===========================================================================

describe('Cat 6: HttpOnly cookies set server-side should not fire', () => {
  it('Express route sets an HttpOnly Secure SameSite=strict cookie', () => {
    const f = file(
      'server/routes/login.js',
      `import express from 'express';
      const router = express.Router();
      router.post('/login', async (req, res) => {
        const token = await signJwt(req.body);
        res.cookie('session', token, {
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
          maxAge: 2592000_000,
        });
        res.json({ ok: true });
      });
      export default router;`
    );
    expectClean(run(f));
  });

  it('Next.js app-router API route uses Set-Cookie with HttpOnly', () => {
    const f = file(
      'app/api/login/route.ts',
      `export async function POST(req: Request) {
        const { email, password } = await req.json();
        const user = await verifyCredentials(email, password);
        if (!user) return new Response('Unauthorized', { status: 401 });
        const token = await signJwt({ sub: user.id });
        const res = new Response(JSON.stringify({ ok: true }));
        res.headers.set(
          'Set-Cookie',
          \`session=\${token}; Max-Age=2592000; Path=/; HttpOnly; Secure; SameSite=Lax\`
        );
        return res;
      }`
    );
    expectClean(run(f));
  });

  it('Next.js pages-router API uses res.setHeader Set-Cookie HttpOnly', () => {
    const f = file(
      'pages/api/login.ts',
      `export default async function handler(req, res) {
        const token = await signJwt(req.body);
        res.setHeader('Set-Cookie',
          \`auth=\${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400\`
        );
        res.status(200).json({ ok: true });
      }`
    );
    expectClean(run(f));
  });

  it('Hono handler sets cookie via setCookie with httpOnly', () => {
    const f = file(
      'server/hono/login.ts',
      `import { setCookie } from 'hono/cookie';
      app.post('/login', async (c) => {
        const token = await signJwt(await c.req.json());
        setCookie(c, 'session', token, {
          httpOnly: true, secure: true, sameSite: 'Strict', path: '/'
        });
        return c.json({ ok: true });
      });`
    );
    expectClean(run(f));
  });

  it('Fastify reply.setCookie with httpOnly', () => {
    const f = file(
      'server/fastify/login.js',
      `fastify.post('/login', async (req, reply) => {
        const token = await signJwt(req.body);
        reply.setCookie('jwt', token, {
          httpOnly: true,
          secure: true,
          sameSite: 'lax',
          path: '/',
        });
        return { ok: true };
      });`
    );
    expectClean(run(f));
  });

  it('Koa ctx.cookies.set with httpOnly', () => {
    const f = file(
      'server/koa/login.js',
      `router.post('/login', async (ctx) => {
        const token = await signJwt(ctx.request.body);
        ctx.cookies.set('session', token, {
          httpOnly: true, secure: true, sameSite: 'strict'
        });
        ctx.body = { ok: true };
      });`
    );
    expectClean(run(f));
  });

  it('Cloudflare Worker returns Set-Cookie with HttpOnly', () => {
    const f = file(
      'workers/login.ts',
      `export default {
        async fetch(req: Request): Promise<Response> {
          const token = await signJwt(await req.json());
          return new Response(JSON.stringify({ ok: true }), {
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': \`session=\${token}; HttpOnly; Secure; SameSite=Lax; Path=/\`
            }
          });
        }
      };`
    );
    expectClean(run(f));
  });

  it('Remix loader returns a Response with HttpOnly Set-Cookie', () => {
    const f = file(
      'app/routes/login.tsx',
      `import { redirect } from '@remix-run/node';
      export async function action({ request }) {
        const form = await request.formData();
        const token = await signJwt(Object.fromEntries(form));
        return redirect('/', {
          headers: { 'Set-Cookie': \`session=\${token}; HttpOnly; Secure; SameSite=Lax; Path=/\` }
        });
      }`
    );
    expectClean(run(f));
  });

  it('Django sets HttpOnly cookie via response.set_cookie', () => {
    const f = file(
      'server/views.py',
      `def login_view(request):
          token = sign_jwt(request.POST)
          resp = JsonResponse({'ok': True})
          resp.set_cookie('session', token, httponly=True, secure=True, samesite='Lax')
          return resp`
    );
    expectClean(run(f));
  });
});

// ===========================================================================
// CATEGORY 7 — BYOK key storage with explicit user consent (AMBIGUOUS)
// ===========================================================================

describe('Cat 7: BYOK opt-in key storage (tolerant — PreFlight does this)', () => {
  // AMBIGUOUS: literal storage of an "openai_key" can superficially look like
  // a credential write, but PreFlight ships this exact pattern as a
  // documented, user-controlled BYOK convenience.

  it('PreFlight-style BYOK setter with explicit opt-in path', () => {
    const f = file(
      'src/lib/ai.js',
      `// User pastes their own key in the BYOK panel. Persisted only on
      // explicit opt-in via the "Remember on this device" toggle.
      export function setUserByokKey(provider, key, remember) {
        if (remember) {
          localStorage.setItem(\`\${provider}_user_byok_key\`, key);
        }
      }`
    );
    expectTolerant(run(f));
  });

  it('BYOK setter behind a consent gate (OpenAI)', () => {
    const f = file(
      'src/components/byok/OpenAIPanel.jsx',
      `const onSave = () => {
        if (!userConsented) return;
        localStorage.setItem('openai_user_byok_key', userPastedKey);
      };`
    );
    expectTolerant(run(f));
  });

  it('BYOK setter behind a consent gate (Anthropic)', () => {
    const f = file(
      'src/components/byok/AnthropicPanel.jsx',
      `const onSave = () => {
        if (!userConsented) return;
        localStorage.setItem('anthropic_user_byok_key', userPastedKey);
      };`
    );
    expectTolerant(run(f));
  });

  it('BYOK setter clears on opt-out', () => {
    const f = file(
      'src/components/byok/Panel.jsx',
      `const onForget = () => {
        localStorage.removeItem('openai_user_byok_key');
      };
      const onRemember = () => {
        localStorage.setItem('openai_user_byok_key', value);
      };`
    );
    expectTolerant(run(f));
  });
});

// ===========================================================================
// CATEGORY 8 — Token in JS variable, never persisted (in-memory only)
// ===========================================================================

describe('Cat 8: token used in memory only, never persisted, should not fire', () => {
  it('login returns a token used for one fetch then discarded', () => {
    const f = file(
      'src/api/me.js',
      `export async function fetchMe() {
        const token = await login();
        const res = await fetch('/api/me', {
          headers: { Authorization: \`Bearer \${token}\` }
        });
        return res.json();
      }`
    );
    expectClean(run(f));
  });

  it('token held in a closure, never written anywhere', () => {
    const f = file(
      'src/api/client.js',
      `export function makeClient() {
        let token = null;
        async function login(creds) {
          const r = await fetch('/auth', { method: 'POST', body: JSON.stringify(creds) });
          token = (await r.json()).token;
        }
        async function call(path) {
          return fetch(path, { headers: { Authorization: \`Bearer \${token}\` }});
        }
        return { login, call };
      }`
    );
    expectClean(run(f));
  });

  it('token passed via React context, no storage', () => {
    const f = file(
      'src/auth/AuthProvider.jsx',
      `export function AuthProvider({ children }) {
        const [token, setToken] = useState(null);
        const login = async (c) => setToken((await api.login(c)).token);
        return <Ctx.Provider value={{ token, login }}>{children}</Ctx.Provider>;
      }`
    );
    expectClean(run(f));
  });

  it('token destructured into a function-scoped variable only', () => {
    const f = file(
      'src/api/refresh.js',
      `export async function withFreshToken(cb) {
        const { token } = await refresh();
        return cb({ Authorization: \`Bearer \${token}\` });
      }`
    );
    expectClean(run(f));
  });

  it('token in a useRef, not in localStorage', () => {
    const f = file(
      'src/auth/useToken.js',
      `export function useToken() {
        const tokenRef = useRef(null);
        const setToken = (t) => { tokenRef.current = t; };
        return { tokenRef, setToken };
      }`
    );
    expectClean(run(f));
  });

  it('access_token name appears only as a destructure target, not a storage key', () => {
    const f = file(
      'src/oauth/exchange.js',
      `export async function exchangeCode(code) {
        const { access_token, refresh_token } = await tokenEndpoint(code);
        sendToBackend({ access_token, refresh_token });
      }`
    );
    expectClean(run(f));
  });
});

// ===========================================================================
// CATEGORY 9 — OAuth state / nonce / code_verifier (AMBIGUOUS)
// ===========================================================================

describe('Cat 9: OAuth state/nonce/code_verifier in sessionStorage (tolerant)', () => {
  // AMBIGUOUS: state and code_verifier are CSRF/PKCE values, not credentials,
  // but they are sometimes mistaken for tokens. PKCE explicitly recommends
  // session-storage for code_verifier.

  it('sessionStorage of oauth_state for CSRF protection', () => {
    const f = file(
      'src/oauth/start.js',
      `export function beginOAuth(redirectTo) {
        const state = crypto.randomUUID();
        sessionStorage.setItem('oauth_state', state);
        location.href = \`/oauth/authorize?state=\${state}&redirect=\${redirectTo}\`;
      }`
    );
    expectTolerant(run(f));
  });

  it('sessionStorage of PKCE code_verifier per RFC 7636', () => {
    const f = file(
      'src/oauth/pkce.js',
      `export function startPkce() {
        const verifier = generateCodeVerifier();
        sessionStorage.setItem('pkce_code_verifier', verifier);
        return verifier;
      }`
    );
    expectTolerant(run(f));
  });

  it('sessionStorage of OIDC nonce', () => {
    const f = file(
      'src/oauth/oidc.js',
      `export function rememberNonce(nonce) {
        sessionStorage.setItem('oidc_nonce', nonce);
      }`
    );
    expectTolerant(run(f));
  });

  it('all three stored together as part of an OAuth bootstrap', () => {
    const f = file(
      'src/oauth/bootstrap.js',
      `export function bootstrapOAuth() {
        const state = crypto.randomUUID();
        const verifier = generateCodeVerifier();
        const nonce = crypto.randomUUID();
        sessionStorage.setItem('oauth_state', state);
        sessionStorage.setItem('pkce_code_verifier', verifier);
        sessionStorage.setItem('oidc_nonce', nonce);
        return { state, verifier, nonce };
      }`
    );
    expectTolerant(run(f));
  });
});

// ===========================================================================
// CATEGORY 10 — Service worker caching NON-auth responses
// ===========================================================================

describe('Cat 10: service worker caching non-auth assets should not fire', () => {
  it('caches.put for static image assets', () => {
    const f = file(
      'public/sw.js',
      `self.addEventListener('fetch', (event) => {
        if (event.request.destination === 'image') {
          event.respondWith(
            caches.open('images-v1').then(async (cache) => {
              const res = await fetch(event.request);
              cache.put(event.request, res.clone());
              return res;
            })
          );
        }
      });`
    );
    expectClean(run(f));
  });

  it('caches.put for the app shell', () => {
    const f = file(
      'src/sw/app-shell.js',
      `async function precacheAppShell() {
        const cache = await caches.open('app-shell-v3');
        for (const url of ['/', '/index.html', '/main.css', '/main.js']) {
          const res = await fetch(url);
          await cache.put(url, res);
        }
      }`
    );
    expectClean(run(f));
  });

  it('Workbox-style runtime caching of CSS', () => {
    const f = file(
      'src/sw/workbox-config.js',
      `registerRoute(
        ({ request }) => request.destination === 'style',
        new StaleWhileRevalidate({ cacheName: 'styles-v1' })
      );`
    );
    expectClean(run(f));
  });

  it('caches.put for static font files', () => {
    const f = file(
      'src/sw/fonts.js',
      `addEventListener('fetch', async (event) => {
        if (event.request.url.endsWith('.woff2')) {
          const cache = await caches.open('fonts-v1');
          const res = await fetch(event.request);
          await cache.put(event.request, res.clone());
        }
      });`
    );
    expectClean(run(f));
  });
});
