/**
 * Adversarial RECALL tests for probeClientAuthStorage.
 *
 * Goal: realistic shapes where auth tokens / session credentials are stored
 * client-side in a place an injected script could read. The probe MUST fire
 * on each of these. We assert `findings.length > 0` (severity-agnostic) so
 * the suite measures recall, not the labeling.
 *
 * Constraint: we do not read the probe implementation. The contract is
 *   probeClientAuthStorage([{ path, content }]) -> Finding[]
 * Anything richer than `length > 0` would couple this RECALL suite to
 * implementation details we are deliberately not looking at.
 *
 * Categories (3+ each, 30+ total):
 *   1. localStorage.setItem('token', ...)
 *   2. Named variants: jwt / authToken / accessToken / sessionId / apiKey
 *   3. sessionStorage equivalents
 *   4. IndexedDB writes containing tokens
 *   5. document.cookie = 'token=...' (no HttpOnly path; JS-set is XSS-readable)
 *   6. Token written to window.* globals
 *   7. React state synced to localStorage via useEffect
 *   8. Redux/Zustand persist({ storage: localStorage })
 *   9. Service worker caching responses that carry an auth header
 */

import { describe, it, expect } from 'vitest';
import { probeClientAuthStorage } from '../lib/probes.js';

// Helper: build a single-file input array.
const file = (path, content) => [{ path, content }];

// Helper: assert probe found at least one finding.
const expectFlagged = (findings, label) => {
  // We deliberately don't assert severity / id shape — this is a recall suite.
  // If the probe returns `[]` here we missed a real attack surface.
  if (!Array.isArray(findings)) {
    throw new Error(`[${label}] probe must return an array, got ${typeof findings}`);
  }
  expect(findings.length, `[${label}] expected >=1 finding`).toBeGreaterThan(0);
};

describe('probeClientAuthStorage — Category 1: localStorage.setItem("token", ...)', () => {
  it('flags the bare-bones token write', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/login.js',
        `
        async function login(email, password) {
          const res = await fetch('/api/login', {
            method: 'POST',
            body: JSON.stringify({ email, password }),
          });
          const { token } = await res.json();
          localStorage.setItem('token', token);
        }
      `
      )
    );
    expectFlagged(findings, 'bare token write');
  });

  it('flags token write inside a then() chain (no async/await)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/login.jsx',
        `
        export function doLogin(email, password) {
          return fetch('/api/auth', { method: 'POST', body: JSON.stringify({ email, password }) })
            .then(r => r.json())
            .then(({ token }) => {
              localStorage.setItem('token', token);
              window.location.href = '/dashboard';
            });
        }
      `
      )
    );
    expectFlagged(findings, 'then-chain token');
  });

  it('flags token write with template literal value', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/session.ts',
        `
        export function persistSession(rawToken: string) {
          localStorage.setItem('token', \`Bearer \${rawToken}\`);
        }
      `
      )
    );
    expectFlagged(findings, 'template-literal token');
  });

  it('flags token write where key is a string concat', () => {
    // Ambiguity note: some probes only match string literals. This case
    // uses a fully literal key ('token') but spread as concat to mimic
    // a real obfuscation. Probe should still see 'token'.
    const findings = probeClientAuthStorage(
      file(
        'src/auth/store.js',
        `
        const KEY = 'tok' + 'en';
        localStorage.setItem(KEY, JSON.stringify({ access: t }));
      `
      )
    );
    expectFlagged(findings, 'concat key (token)');
  });
});

describe('probeClientAuthStorage — Category 2: name variants (jwt/authToken/accessToken/sessionId/apiKey)', () => {
  it('flags localStorage.setItem("jwt", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth.js',
        `
        const { jwt } = await loginResponse.json();
        localStorage.setItem('jwt', jwt);
      `
      )
    );
    expectFlagged(findings, 'jwt');
  });

  it('flags localStorage.setItem("authToken", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/session.js',
        `
        export function saveAuth(authToken) {
          localStorage.setItem('authToken', authToken);
        }
      `
      )
    );
    expectFlagged(findings, 'authToken');
  });

  it('flags localStorage.setItem("accessToken", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/api/oauth-callback.ts',
        `
        const { access_token, refresh_token } = await exchangeCode(code);
        localStorage.setItem('accessToken', access_token);
        localStorage.setItem('refreshToken', refresh_token);
      `
      )
    );
    expectFlagged(findings, 'accessToken + refreshToken');
  });

  it('flags localStorage.setItem("sessionId", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/session-bootstrap.js',
        `
        function bootstrapSession(sid) {
          localStorage.setItem('sessionId', sid);
        }
      `
      )
    );
    expectFlagged(findings, 'sessionId');
  });

  it('flags localStorage.setItem("apiKey", ...) — user-pasted secret', () => {
    // Slightly ambiguous: apiKey could be the user's own BYOK key (which is
    // a privacy/local-only decision in some apps), but client-side storage
    // of any credential under that name is still a recall-positive shape.
    const findings = probeClientAuthStorage(
      file(
        'src/settings/byok.jsx',
        `
        function saveKey(e) {
          localStorage.setItem('apiKey', e.target.value);
        }
      `
      )
    );
    expectFlagged(findings, 'apiKey');
  });

  it('flags snake_case access_token key', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/oauth.js',
        `
        localStorage.setItem('access_token', tokenResponse.access_token);
        localStorage.setItem('id_token', tokenResponse.id_token);
      `
      )
    );
    expectFlagged(findings, 'access_token snake_case');
  });

  it('flags "auth" bare key', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/store/auth.js',
        `
        localStorage.setItem('auth', JSON.stringify({ token, user, expires }));
      `
      )
    );
    expectFlagged(findings, 'auth bare key');
  });

  it('flags "session" bare key', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/store/session.js',
        `
        localStorage.setItem('session', sessionJwt);
      `
      )
    );
    expectFlagged(findings, 'session bare key');
  });
});

describe('probeClientAuthStorage — Category 3: sessionStorage equivalents', () => {
  it('flags sessionStorage.setItem("jwt", ...)', () => {
    // sessionStorage is still XSS-readable, just shorter-lived.
    // Probe should fire (severity may be lower — we don't assert that here).
    const findings = probeClientAuthStorage(
      file(
        'src/auth/short-lived.js',
        `
        sessionStorage.setItem('jwt', token);
      `
      )
    );
    expectFlagged(findings, 'sessionStorage jwt');
  });

  it('flags sessionStorage.setItem("token", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/tab-scoped.js',
        `
        function persistForTab(token) {
          sessionStorage.setItem('token', token);
        }
      `
      )
    );
    expectFlagged(findings, 'sessionStorage token');
  });

  it('flags sessionStorage.setItem("authToken", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/login.tsx',
        `
        sessionStorage.setItem('authToken', authToken);
      `
      )
    );
    expectFlagged(findings, 'sessionStorage authToken');
  });

  it('flags sessionStorage.setItem("accessToken", ...) after OAuth', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/oauth-callback.js',
        `
        const { access_token } = JSON.parse(hash);
        sessionStorage.setItem('accessToken', access_token);
      `
      )
    );
    expectFlagged(findings, 'sessionStorage accessToken');
  });
});

describe('probeClientAuthStorage — Category 4: IndexedDB with tokens', () => {
  it('flags db.put("auth", { token })', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/db/auth-store.js',
        `
        async function persistAuth(token, user) {
          const db = await openDB('app');
          await db.put('auth', { token, user, ts: Date.now() });
        }
      `
      )
    );
    expectFlagged(findings, 'idb db.put auth/token');
  });

  it('flags objectStore.put({ jwt }) via raw IDB API', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/db/raw-idb.js',
        `
        const tx = db.transaction('session', 'readwrite');
        const store = tx.objectStore('session');
        store.put({ id: 'current', jwt: tokenString });
      `
      )
    );
    expectFlagged(findings, 'idb objectStore.put jwt');
  });

  it('flags idb wrapper set("authToken", ...)', () => {
    // Some libs (idb-keyval) expose set(key, value). Same exposure.
    const findings = probeClientAuthStorage(
      file(
        'src/db/keyval.js',
        `
        import { set } from 'idb-keyval';
        await set('authToken', authToken);
      `
      )
    );
    expectFlagged(findings, 'idb-keyval set authToken');
  });

  it('flags IDBObjectStore.add({ accessToken })', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/db/add-token.js',
        `
        const req = store.add({ id: 1, accessToken: token, refreshToken: rt });
      `
      )
    );
    expectFlagged(findings, 'idb add accessToken');
  });
});

describe('probeClientAuthStorage — Category 5: document.cookie set without HttpOnly', () => {
  it('flags document.cookie = "token=..."', () => {
    // JS-set cookies cannot be HttpOnly. So even using cookies, this is
    // XSS-readable. Probe should fire.
    const findings = probeClientAuthStorage(
      file(
        'src/auth/cookie-set.js',
        `
        document.cookie = 'token=' + encodeURIComponent(token) + '; path=/; SameSite=Lax';
      `
      )
    );
    expectFlagged(findings, 'document.cookie token=');
  });

  it('flags document.cookie = "jwt=..." with template literal', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/cookie-jwt.js',
        `
        document.cookie = \`jwt=\${jwt}; path=/; Secure; SameSite=Strict\`;
      `
      )
    );
    expectFlagged(findings, 'document.cookie jwt= template');
  });

  it('flags document.cookie = "session=..." even with Secure flag', () => {
    // Secure ≠ HttpOnly. Anything JS sets is JS-readable.
    const findings = probeClientAuthStorage(
      file(
        'src/auth/cookie-session.js',
        `
        document.cookie = 'session=' + sid + '; Secure; Path=/';
      `
      )
    );
    expectFlagged(findings, 'document.cookie session=');
  });

  it('flags Cookies.set("authToken", ...) via js-cookie lib', () => {
    // js-cookie wraps document.cookie. Same exposure model.
    const findings = probeClientAuthStorage(
      file(
        'src/auth/jscookie.js',
        `
        import Cookies from 'js-cookie';
        Cookies.set('authToken', authToken, { expires: 7, sameSite: 'lax' });
      `
      )
    );
    expectFlagged(findings, 'js-cookie set authToken');
  });
});

describe('probeClientAuthStorage — Category 6: Token in window.* globals', () => {
  it('flags window.authToken = token', () => {
    // Lives in global scope, readable by every script on the page.
    const findings = probeClientAuthStorage(
      file(
        'src/auth/window-global.js',
        `
        window.authToken = token;
      `
      )
    );
    expectFlagged(findings, 'window.authToken');
  });

  it('flags window.__JWT__ = token', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/bootstrap.js',
        `
        window.__JWT__ = bootJwt;
      `
      )
    );
    expectFlagged(findings, 'window.__JWT__');
  });

  it('flags globalThis.accessToken = token', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/global-this.js',
        `
        globalThis.accessToken = response.access_token;
      `
      )
    );
    expectFlagged(findings, 'globalThis.accessToken');
  });

  it('flags window.session = { token }', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/auth/window-session.js',
        `
        window.session = { token: jwt, userId: user.id };
      `
      )
    );
    expectFlagged(findings, 'window.session object');
  });
});

describe('probeClientAuthStorage — Category 7: React useEffect syncing token to localStorage', () => {
  it('flags useEffect(() => localStorage.setItem("jwt", token), [token])', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/components/AuthProvider.jsx',
        `
        import { useEffect, useState } from 'react';
        export function AuthProvider({ children }) {
          const [token, setToken] = useState(null);
          useEffect(() => {
            if (token) localStorage.setItem('jwt', token);
          }, [token]);
          return children;
        }
      `
      )
    );
    expectFlagged(findings, 'useEffect setItem jwt');
  });

  it('flags useEffect with authToken sync', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/hooks/useAuth.js',
        `
        import { useEffect } from 'react';
        export function useAuth(authToken) {
          useEffect(() => {
            localStorage.setItem('authToken', authToken ?? '');
          }, [authToken]);
        }
      `
      )
    );
    expectFlagged(findings, 'useEffect setItem authToken');
  });

  it('flags lazy initializer reading + later writing', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/components/SessionBoundary.jsx',
        `
        import { useState, useEffect } from 'react';
        export function SessionBoundary() {
          const [token, setToken] = useState(() => localStorage.getItem('jwt'));
          useEffect(() => {
            if (token) localStorage.setItem('jwt', token);
          }, [token]);
          return null;
        }
      `
      )
    );
    expectFlagged(findings, 'lazy init + setItem jwt');
  });

  it('flags class component componentDidUpdate writing token', () => {
    // Pre-hooks shape; same exposure.
    const findings = probeClientAuthStorage(
      file(
        'src/components/Legacy.jsx',
        `
        class Legacy extends React.Component {
          componentDidUpdate(prevProps) {
            if (prevProps.token !== this.props.token) {
              localStorage.setItem('accessToken', this.props.token);
            }
          }
        }
      `
      )
    );
    expectFlagged(findings, 'class componentDidUpdate setItem');
  });
});

describe('probeClientAuthStorage — Category 8: Redux/Zustand persist to localStorage', () => {
  it('flags zustand persist({ name: "auth", storage: localStorage })', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/store/auth.js',
        `
        import { create } from 'zustand';
        import { persist, createJSONStorage } from 'zustand/middleware';
        export const useAuth = create(
          persist(
            (set) => ({
              token: null,
              setToken: (t) => set({ token: t }),
            }),
            { name: 'auth', storage: createJSONStorage(() => localStorage) }
          )
        );
      `
      )
    );
    expectFlagged(findings, 'zustand persist auth localStorage');
  });

  it('flags redux-persist with key "auth" and localStorage storage', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/store/persist.js',
        `
        import storage from 'redux-persist/lib/storage'; // defaults to localStorage
        import { persistReducer } from 'redux-persist';
        const persistConfig = { key: 'auth', storage };
        export const persistedAuth = persistReducer(persistConfig, authReducer);
      `
      )
    );
    expectFlagged(findings, 'redux-persist auth');
  });

  it('flags jotai atomWithStorage("jwt", ...)', () => {
    const findings = probeClientAuthStorage(
      file(
        'src/store/jotai.js',
        `
        import { atomWithStorage } from 'jotai/utils';
        export const jwtAtom = atomWithStorage('jwt', null);
      `
      )
    );
    expectFlagged(findings, 'jotai atomWithStorage jwt');
  });

  it('flags zustand persist with whitelist including token', () => {
    // Explicit attempt to persist the credential.
    const findings = probeClientAuthStorage(
      file(
        'src/store/auth-explicit.js',
        `
        import { create } from 'zustand';
        import { persist } from 'zustand/middleware';
        export const useAuth = create(
          persist(
            (set) => ({ token: null, user: null }),
            {
              name: 'session-store',
              partialize: (state) => ({ token: state.token }),
            }
          )
        );
      `
      )
    );
    expectFlagged(findings, 'zustand partialize token');
  });
});

describe('probeClientAuthStorage — Category 9: service worker caching auth headers', () => {
  it('flags caches.put(req, res.clone()) where res has Authorization header', () => {
    // The cache entry now contains the Bearer token. Any later page-side
    // caches.match() can read it back. Recall-positive shape.
    const findings = probeClientAuthStorage(
      file(
        'public/sw.js',
        `
        self.addEventListener('fetch', (event) => {
          event.respondWith((async () => {
            const req = event.request;
            const res = await fetch(req, {
              headers: { Authorization: 'Bearer ' + selfToken },
            });
            const cache = await caches.open('api-v1');
            await cache.put(req, res.clone());
            return res;
          })());
        });
      `
      )
    );
    expectFlagged(findings, 'sw caches.put with Authorization');
  });

  it('flags service worker storing token in a Cache via Response body', () => {
    const findings = probeClientAuthStorage(
      file(
        'public/sw-bootstrap.js',
        `
        self.addEventListener('message', async (event) => {
          if (event.data.type === 'SET_TOKEN') {
            const cache = await caches.open('auth');
            await cache.put('/__token', new Response(event.data.token));
          }
        });
      `
      )
    );
    expectFlagged(findings, 'sw cache __token response body');
  });

  it('flags service worker reading then re-caching responses with Set-Cookie / Authorization', () => {
    const findings = probeClientAuthStorage(
      file(
        'public/sw-replay.js',
        `
        async function cacheAuthed(request) {
          const response = await fetch(request, {
            headers: { Authorization: \`Bearer \${self.__jwt}\` },
          });
          const cache = await caches.open('authed-api');
          cache.put(request, response.clone());
          return response;
        }
      `
      )
    );
    expectFlagged(findings, 'sw cacheAuthed Bearer');
  });

  it('flags client code that writes a JWT into a Cache (not just SW)', () => {
    // Cache Storage API is available to window contexts too. Same exposure.
    const findings = probeClientAuthStorage(
      file(
        'src/auth/cache-token.js',
        `
        export async function stashToken(token) {
          const cache = await caches.open('auth-v1');
          await cache.put('/auth/token', new Response(JSON.stringify({ jwt: token })));
        }
      `
      )
    );
    expectFlagged(findings, 'window caches.put jwt body');
  });
});

describe('probeClientAuthStorage — cross-category realistic combinations', () => {
  it('flags a file that does both localStorage jwt and window.token writes', () => {
    // Real apps frequently double-store. Probe should fire (one or more).
    const findings = probeClientAuthStorage(
      file(
        'src/auth/double-store.js',
        `
        export function setSession(token) {
          window.token = token;
          localStorage.setItem('jwt', token);
        }
      `
      )
    );
    expectFlagged(findings, 'window + localStorage double store');
  });

  it('flags Next.js client component persisting an OAuth token to localStorage', () => {
    const findings = probeClientAuthStorage(
      file(
        'app/auth/callback/page.tsx',
        `
        'use client';
        import { useEffect } from 'react';
        export default function Callback({ searchParams }) {
          useEffect(() => {
            const token = searchParams.get('access_token');
            if (token) localStorage.setItem('accessToken', token);
          }, [searchParams]);
          return null;
        }
      `
      )
    );
    expectFlagged(findings, 'next client OAuth callback');
  });
});
