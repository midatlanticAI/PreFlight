import { describe, it, expect } from 'vitest';
import { probeAICodegenBloat } from '../lib/probes.js';

/**
 * Adversarial PRECISION suite (round 1) for probeAICodegenBloat.
 *
 * Every case in this file is ordinary, well-written, human-reviewable code that
 * happens to sit near one of the probe's detection shapes. Every assertion is
 * "must NOT fire" -- `toEqual([])`. A failure here is a false positive, which is
 * the most expensive kind of finding for a tool whose whole promise is that the
 * findings are worth reading.
 *
 * All fixture paths look like production source. Test/fixture paths are skipped
 * by design, so using them would make these tests pass for the wrong reason.
 */

const one = (path, content) => [{ path, content }];
const run = (path, content) => probeAICodegenBloat(one(path, content));

// ---------------------------------------------------------------------------
// 1. Filenames that CONTAIN variant-marker substrings but are not variants
// ---------------------------------------------------------------------------

describe('benign filenames that merely contain variant-marker substrings', () => {
  const tinyModule = `export const noop = () => undefined;\n`;

  it('does not fire on a versioned API directory (src/v2/api.ts)', () => {
    const src = `import { httpClient } from '../http/client.ts';

export async function listInvoices(customerId) {
  const response = await httpClient.get(\`/v2/customers/\${customerId}/invoices\`);
  return response.data;
}
`;
    expect(run('src/v2/api.ts', src)).toEqual([]);
  });

  it('does not fire on a component literally named Version.tsx', () => {
    const src = `import React from 'react';
import { APP_VERSION } from '../config/build-info.ts';

export function Version() {
  return <span className="build-version">v{APP_VERSION}</span>;
}
`;
    expect(run('src/components/Version.tsx', src)).toEqual([]);
  });

  it('does not fire on src/copy.ts (marketing copy strings, not a "copy" of a file)', () => {
    const src = `export const copy = {
  heroTitle: 'Ship the thing you actually meant to ship.',
  heroSubtitle: 'A checklist that runs in your browser.',
  ctaLabel: 'Start a scan',
};
`;
    expect(run('src/copy.ts', src)).toEqual([]);
  });

  it('does not fire on a backups feature module (src/backups/service.ts)', () => {
    const src = `import { storage } from '../storage/client.ts';

export async function createBackup(tenantId) {
  const snapshot = await storage.snapshot(tenantId);
  return storage.put(\`backups/\${tenantId}/\${snapshot.id}\`, snapshot.body);
}

export async function listBackups(tenantId) {
  return storage.list(\`backups/\${tenantId}/\`);
}
`;
    expect(run('src/backups/service.ts', src)).toEqual([]);
  });

  it('does not fire on src/oldest.ts (a selector, not an "old" copy)', () => {
    const src = `export function oldest(records) {
  return records.reduce((a, b) => (a.createdAt <= b.createdAt ? a : b));
}
`;
    expect(run('src/oldest.ts', src)).toEqual([]);
  });

  it('does not fire on src/newsletter.ts (contains "new")', () => {
    const src = `import { mailer } from './mailer.ts';

export function sendNewsletter(issue, subscribers) {
  return Promise.all(subscribers.map((s) => mailer.send(s.email, issue.subject, issue.body)));
}
`;
    expect(run('src/newsletter.ts', src)).toEqual([]);
  });

  it('does not fire on src/finalize.ts (contains "final")', () => {
    const src = `export function finalize(draft) {
  return { ...draft, status: 'published', publishedAt: new Date().toISOString() };
}
`;
    expect(run('src/finalize.ts', src)).toEqual([]);
  });

  it('does not fire on src/features/copy-to-clipboard.ts', () => {
    const src = `export async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
  return true;
}
`;
    expect(run('src/features/copy-to-clipboard.ts', src)).toEqual([]);
  });

  it('does not fire on src/lib/temperature.ts (contains "temp")', () => {
    const src = tinyModule + `export const toFahrenheit = (c) => c * 1.8 + 32;\n`;
    expect(run('src/lib/temperature.ts', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 2. Long prose comment blocks that are documentation, not commented-out code
// ---------------------------------------------------------------------------

describe('long prose comment blocks that are not commented-out code', () => {
  it('does not fire on a 20-line SPDX/Apache license header', () => {
    const src = `/*
 * Copyright 2024 Northwind Logistics, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This module owns the routing table for outbound shipment events. It is the
 * only place that knows how carrier codes map to internal lane identifiers.
 * Changing the mapping here changes billing, so treat it as a contract.
 */

export const LANE_BY_CARRIER = { UPS: 'lane-a', FDX: 'lane-b', USPS: 'lane-c' };

export function laneFor(carrierCode) {
  return LANE_BY_CARRIER[carrierCode] ?? 'lane-unassigned';
}
`;
    expect(run('src/shipping/lanes.js', src)).toEqual([]);
  });

  it('does not fire on a 25-line JSDoc block with @param/@returns/@example', () => {
    const src = `/**
 * Compute a stable pagination cursor for a result page.
 *
 * The cursor is opaque to callers. It encodes the sort key of the last row in
 * the page plus a tiebreaker id, so that concurrent inserts do not cause rows
 * to be skipped or repeated across page boundaries.
 *
 * Callers must pass the same sort direction they used for the query. Passing a
 * mismatched direction produces a cursor that walks backwards, which is a bug
 * that surfaces as an empty second page rather than an error.
 *
 * @param {object}  lastRow            The final row of the current page.
 * @param {string}  lastRow.id         Primary key, used as the tiebreaker.
 * @param {string}  lastRow.sortValue  The value of the sort column.
 * @param {'asc'|'desc'} direction     Sort direction used by the query.
 * @returns {string} A base64url cursor safe for query strings.
 *
 * @example
 *   const cursor = buildCursor({ id: '42', sortValue: '2024-01-02' }, 'asc');
 *   const url = '/api/orders?after=' + cursor;
 *
 * @see docs/pagination.md for the full keyset pagination writeup.
 */
export function buildCursor(lastRow, direction) {
  const payload = JSON.stringify([lastRow.sortValue, lastRow.id, direction]);
  return btoa(payload).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}
`;
    expect(run('src/db/pagination.js', src)).toEqual([]);
  });

  it('does not fire on an ASCII state-machine diagram in comments', () => {
    const src = `// Checkout state machine.
//
//        +---------+      submit       +-----------+
//        |  draft  | ----------------> |  pending  |
//        +---------+                   +-----------+
//             |                              |
//             | abandon                      | authorize
//             v                              v
//        +-----------+   refund        +-----------+
//        | cancelled | <-------------- |   paid    |
//        +-----------+                 +-----------+
//
// Transitions not drawn above are rejected. "pending" is the only state that
// can hold a payment intent, which is why the intent id is nullable on the
// order row. Anything that reads order.paymentIntentId must handle null.
//
// The diagram is the spec. If you add a state, update the diagram first, then
// the TRANSITIONS table, then the reducer.

export const TRANSITIONS = {
  draft: ['pending', 'cancelled'],
  pending: ['paid', 'cancelled'],
  paid: ['cancelled'],
  cancelled: [],
};

export const canTransition = (from, to) => TRANSITIONS[from]?.includes(to) ?? false;
`;
    expect(run('src/checkout/state-machine.js', src)).toEqual([]);
  });

  it('does not fire on a long module-level design note written as prose', () => {
    const src = `/**
 * Why this cache is a Map and not an LRU library.
 *
 * The working set here is the set of active feature flag keys, which is bounded
 * by the number of flags we define at build time. It is currently 34 entries and
 * has never exceeded 60 in three years. An eviction policy would add a
 * dependency, a tuning knob, and a class of bugs (stale reads under eviction)
 * in exchange for bounding something that is already bounded.
 *
 * If the flag registry ever becomes user-defined, this reasoning stops holding
 * and the cache should be replaced. The signal to watch is FLAG_KEYS.length
 * growing past a few hundred, or the registry moving out of source control.
 *
 * Invalidation is global and coarse: any flag write clears everything. Writes
 * happen on deploy, roughly once a day, so the cost is irrelevant and the
 * correctness argument is trivial.
 *
 * Reads are hot. Keep them allocation-free.
 */

const cache = new Map();

export function readFlag(key, loader) {
  if (cache.has(key)) return cache.get(key);
  const value = loader(key);
  cache.set(key, value);
  return value;
}

export function clearFlags() {
  cache.clear();
}
`;
    expect(run('src/flags/cache.js', src)).toEqual([]);
  });

  it('does not fire on a long inline comment block explaining a regex', () => {
    const src = `// Semantic version parser.
//
// Anchored at both ends so that a trailing newline cannot smuggle in a second
// version. The groups, in order:
//
//   1. major  -- one or more digits, no leading zeros unless the value is zero
//   2. minor  -- same rule
//   3. patch  -- same rule
//   4. prerelease -- optional, dot-separated identifiers after a hyphen
//   5. build      -- optional, dot-separated identifiers after a plus
//
// This is the regex from the semver spec appendix, reformatted for readability.
// Do not "simplify" it. The leading-zero rules are load bearing for ordering.
const SEMVER = /^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-([\\w.-]+))?(?:\\+([\\w.-]+))?$/;

export function parseVersion(input) {
  const match = SEMVER.exec(input);
  if (!match) return null;
  return { major: +match[1], minor: +match[2], patch: +match[3], prerelease: match[4] ?? null };
}
`;
    expect(run('src/version/parse.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 3. Comments containing narration-adjacent wording used naturally
// ---------------------------------------------------------------------------

describe('comments using narration-adjacent wording naturally', () => {
  it('does not fire on "this is a complete list of ..." describing a real constant', () => {
    const src = `// This is a complete list of the currencies our payment processor settles in.
// Anything not in this list must be converted before it reaches the ledger.
export const SETTLEMENT_CURRENCIES = ['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY'];

export const isSettlementCurrency = (code) => SETTLEMENT_CURRENCIES.includes(code);
`;
    expect(run('src/billing/currencies.js', src)).toEqual([]);
  });

  it('does not fire on a comment naming an updated_at column', () => {
    const src = `import { db } from './client.js';

// The updated_at column is maintained by a trigger, not by the application, so
// we never write it here. Reading it back after an update requires RETURNING.
export async function renameProject(id, name) {
  const { rows } = await db.query(
    'UPDATE projects SET name = $2 WHERE id = $1 RETURNING id, name, updated_at',
    [id, name]
  );
  return rows[0];
}
`;
    expect(run('src/projects/repository.js', src)).toEqual([]);
  });

  it('does not fire on "note that the API returns ..." describing upstream behavior', () => {
    const src = `import { fetchJson } from '../http/fetch-json.js';

// Note that the API returns 200 with an empty array when the account has no
// devices, and 404 only when the account itself is unknown. Treat those
// differently: an empty array is a valid state, a 404 is a caller bug.
export async function listDevices(accountId) {
  const result = await fetchJson(\`/accounts/\${accountId}/devices\`);
  return result.devices;
}
`;
    expect(run('src/devices/api.js', src)).toEqual([]);
  });

  it('does not fire on "here is the updated implementation" quoted from a changelog line', () => {
    const src = `// Changelog note carried over from the 3.2 migration guide: the updated
// implementation of normalizePhone now assumes E.164 input and no longer strips
// a leading plus. Callers that relied on the old behavior should call
// toE164 first. See docs/migrations/3.2.md.
export function normalizePhone(value) {
  return value.replace(/[^\\d+]/g, '');
}
`;
    expect(run('src/contacts/phone.js', src)).toEqual([]);
  });

  it('does not fire on a comment that explains what a function does in plain narration', () => {
    const src = `// I've added a short-circuit here because the caller in the import pipeline
// calls this once per row and the regex compile showed up in a profile. Let me
// know if you see a case where the cache goes stale.
const compiled = new Map();

export function matcher(pattern) {
  let re = compiled.get(pattern);
  if (!re) {
    re = new RegExp(pattern, 'iu');
    compiled.set(pattern, re);
  }
  return re;
}
`;
    expect(run('src/import/matcher.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 4. Long-but-necessary functions, and long files made of short functions
// ---------------------------------------------------------------------------

describe('long-but-necessary functions and long files of short functions', () => {
  it('does not fire on a ~35 line reducer with one case per action', () => {
    const src = `export function cartReducer(state, action) {
  switch (action.type) {
    case 'add': {
      const existing = state.items.find((i) => i.sku === action.sku);
      if (existing) {
        return {
          ...state,
          items: state.items.map((i) =>
            i.sku === action.sku ? { ...i, qty: i.qty + action.qty } : i
          ),
        };
      }
      return { ...state, items: [...state.items, { sku: action.sku, qty: action.qty }] };
    }
    case 'remove':
      return { ...state, items: state.items.filter((i) => i.sku !== action.sku) };
    case 'setQty':
      return {
        ...state,
        items: state.items.map((i) => (i.sku === action.sku ? { ...i, qty: action.qty } : i)),
      };
    case 'applyCoupon':
      return { ...state, coupon: action.code };
    case 'clear':
      return { ...state, items: [], coupon: null };
    default:
      return state;
  }
}
`;
    expect(run('src/cart/reducer.js', src)).toEqual([]);
  });

  it('does not fire on a long file built from many two-line helpers', () => {
    const helpers = Array.from(
      { length: 45 },
      (_, i) => `export function step${i}(value) {\n  return value + ${i};\n}`
    ).join('\n\n');
    const src = `// Numeric pipeline steps. Each step is deliberately trivial and independently\n// testable; the composition lives in pipeline.js.\n\n${helpers}\n`;
    expect(run('src/pipeline/steps.js', src)).toEqual([]);
  });

  it('does not fire on a long file of small exported selectors', () => {
    const selectors = Array.from(
      { length: 40 },
      (_, i) => `export const selectField${i} = (state) => state.form.field${i};`
    ).join('\n');
    const src = `import { createSelector } from '../store/select.js';\n\n${selectors}\n\nexport const selectAll = createSelector(selectField0, selectField1, (a, b) => [a, b]);\n`;
    expect(run('src/store/selectors.js', src)).toEqual([]);
  });

  it('does not fire on a ~30 line form validator that is one check per field', () => {
    const src = `export function validateSignup(form) {
  const errors = {};
  if (!form.email) {
    errors.email = 'Email is required.';
  } else if (!form.email.includes('@')) {
    errors.email = 'Enter a valid email address.';
  }
  if (!form.password) {
    errors.password = 'Password is required.';
  } else if (form.password.length < 12) {
    errors.password = 'Use at least 12 characters.';
  }
  if (form.password !== form.confirmPassword) {
    errors.confirmPassword = 'Passwords do not match.';
  }
  if (!form.country) {
    errors.country = 'Select a country.';
  }
  if (!form.acceptedTerms) {
    errors.acceptedTerms = 'You must accept the terms to continue.';
  }
  return { valid: Object.keys(errors).length === 0, errors };
}
`;
    expect(run('src/auth/validate-signup.js', src)).toEqual([]);
  });

  it('does not fire on a long file that is mostly a data table', () => {
    const rows = Array.from(
      { length: 120 },
      (_, i) => `  { code: 'AREA_${i}', label: 'Service area ${i}', active: true },`
    ).join('\n');
    const src = `export const SERVICE_AREAS = [\n${rows}\n];\n\nexport const findArea = (code) => SERVICE_AREAS.find((a) => a.code === code) ?? null;\n`;
    expect(run('src/geo/service-areas.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 5. Branchy but simple code sitting under a plausible complexity threshold
// ---------------------------------------------------------------------------

describe('branchy but simple code under a plausible complexity threshold', () => {
  it('does not fire on an 8-case switch in a tiny function', () => {
    const src = `export function httpStatusText(code) {
  switch (code) {
    case 200: return 'OK';
    case 201: return 'Created';
    case 204: return 'No Content';
    case 400: return 'Bad Request';
    case 401: return 'Unauthorized';
    case 404: return 'Not Found';
    case 409: return 'Conflict';
    default: return 'Unknown';
  }
}
`;
    expect(run('src/http/status-text.js', src)).toEqual([]);
  });

  it('does not fire on a lookup object replacing a branch chain', () => {
    const src = `const ICON_BY_STATUS = {
  queued: 'clock',
  running: 'spinner',
  passed: 'check',
  failed: 'x',
  skipped: 'minus',
  cancelled: 'slash',
};

export const iconFor = (status) => ICON_BY_STATUS[status] ?? 'question';
`;
    expect(run('src/ui/status-icon.js', src)).toEqual([]);
  });

  it('does not fire on a short guard-clause chain with early returns', () => {
    const src = `export function canEditPost(user, post) {
  if (!user) return false;
  if (user.banned) return false;
  if (user.role === 'admin') return true;
  if (post.authorId !== user.id) return false;
  if (post.locked) return false;
  return true;
}
`;
    expect(run('src/posts/permissions.js', src)).toEqual([]);
  });

  it('does not fire on a small parser with several typeof branches', () => {
    const src = `export function toQueryValue(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (Array.isArray(value)) return value.map(toQueryValue).join(',');
  return JSON.stringify(value);
}
`;
    expect(run('src/http/query-value.js', src)).toEqual([]);
  });

  it('does not fire on a validation chain expressed as an array of rules', () => {
    const RULES = `const RULES = [
  { field: 'name', test: (v) => v.length > 0, message: 'Name is required.' },
  { field: 'name', test: (v) => v.length <= 80, message: 'Name is too long.' },
  { field: 'slug', test: (v) => /^[a-z0-9-]+$/.test(v), message: 'Slug must be kebab-case.' },
  { field: 'seats', test: (v) => Number.isInteger(v), message: 'Seats must be a whole number.' },
  { field: 'seats', test: (v) => v > 0, message: 'Seats must be positive.' },
];`;
    const src = `${RULES}

export function validate(input) {
  return RULES.filter((r) => !r.test(input[r.field])).map((r) => r.message);
}
`;
    expect(run('src/teams/validate.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 6. Thin wrappers that legitimately change something
// ---------------------------------------------------------------------------

describe('thin wrappers that legitimately change something', () => {
  it('does not fire on a wrapper that reorders arguments', () => {
    const src = `import { writeFile } from 'node:fs/promises';

// Argument order flipped so the path reads first at call sites, matching the
// rest of our fs helpers.
export const write = (path, contents) => writeFile(path, contents, 'utf-8');
`;
    expect(run('src/fs/write.js', src)).toEqual([]);
  });

  it('does not fire on a wrapper that supplies a default', () => {
    const src = `import { createLogger } from './factory.js';

export const logger = (name) => createLogger(name, { level: process.env.LOG_LEVEL ?? 'info' });
`;
    expect(run('src/log/logger.js', src)).toEqual([]);
  });

  it('does not fire on a wrapper that transforms one argument', () => {
    const src = `import { search } from './index.js';

export function searchByTag(tag, options) {
  return search({ ...options, filter: \`tags:\${tag.toLowerCase().trim()}\` });
}
`;
    expect(run('src/search/by-tag.js', src)).toEqual([]);
  });

  it('does not fire on a wrapper that adds a required header', () => {
    const src = `const BASE = 'https://api.example.com';

export function apiFetch(path, init = {}) {
  return fetch(BASE + path, {
    ...init,
    headers: { ...init.headers, 'x-api-version': '2024-05-01' },
  });
}
`;
    expect(run('src/http/api-fetch.js', src)).toEqual([]);
  });

  it('does not fire on a wrapper that returns a different shape', () => {
    const src = `import { query } from '../db/client.js';

export async function findUser(id) {
  const rows = await query('SELECT id, email FROM users WHERE id = $1', [id]);
  return rows.length === 1 ? rows[0] : null;
}
`;
    expect(run('src/users/find.js', src)).toEqual([]);
  });

  it('does not fire on a wrapper that adds await and error normalization', () => {
    const src = `import { rawGeocode } from './provider.js';

export async function geocode(address) {
  const result = await rawGeocode(address);
  if (!result.ok) throw new Error(\`Geocoding failed: \${result.status}\`);
  return result.point;
}
`;
    expect(run('src/geo/geocode.js', src)).toEqual([]);
  });

  it('does not fire on a typed wrapper whose only job is a cast at the boundary', () => {
    const src = `import { readConfigFile } from './read.ts';
import type { AppConfig } from './types.ts';

export const readAppConfig = (path: string): AppConfig =>
  readConfigFile(path) as AppConfig;
`;
    expect(run('src/config/read-app-config.ts', src)).toEqual([]);
  });

  it('does not fire on a memoized wrapper around a pure function', () => {
    const src = `import { renderMarkdown } from './markdown.js';

const cache = new Map();

export function renderCached(source) {
  if (!cache.has(source)) cache.set(source, renderMarkdown(source));
  return cache.get(source);
}
`;
    expect(run('src/content/render-cached.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 7. Imports used in non-obvious positions
// ---------------------------------------------------------------------------

describe('imports used in positions a naive scanner may miss', () => {
  it('does not fire on an import used only as a JSX element', () => {
    const src = `import React from 'react';
import { EmptyState } from './EmptyState.jsx';

export function InboxList({ messages }) {
  if (messages.length === 0) return <EmptyState title="No messages" />;
  return <ul>{messages.map((m) => <li key={m.id}>{m.subject}</li>)}</ul>;
}
`;
    expect(run('src/inbox/InboxList.jsx', src)).toEqual([]);
  });

  it('does not fire on a type-only import used in an annotation', () => {
    const src = `import type { Invoice } from '../billing/types.ts';

export function total(invoice: Invoice): number {
  return invoice.lines.reduce((sum, line) => sum + line.amountCents, 0);
}
`;
    expect(run('src/billing/total.ts', src)).toEqual([]);
  });

  it('does not fire on an import used only as a decorator', () => {
    const src = `import { Injectable } from './di.ts';
import { Repository } from './repository.ts';

@Injectable()
export class OrderService {
  constructor(private readonly repo: Repository) {}

  find(id: string) {
    return this.repo.find(id);
  }
}
`;
    expect(run('src/orders/order-service.ts', src)).toEqual([]);
  });

  it('does not fire on a barrel file of re-exports', () => {
    const src = `export { parseDate } from './parse-date.js';
export { formatDate } from './format-date.js';
export { addDays, addMonths } from './arithmetic.js';
export { default as Clock } from './Clock.jsx';
export * from './constants.js';
`;
    expect(run('src/date/index.js', src)).toEqual([]);
  });

  it('does not fire on a default import re-exported under a new name', () => {
    const src = `import baseConfig from './base.config.js';

export default { ...baseConfig, mode: 'production' };
`;
    expect(run('src/build/prod.config.js', src)).toEqual([]);
  });

  it('does not fire on a namespace import used as ns.member', () => {
    const src = `import * as path from 'node:path';
import * as os from 'node:os';

export const cacheDir = () => path.join(os.homedir(), '.cache', 'northwind');
`;
    expect(run('src/paths/cache-dir.js', src)).toEqual([]);
  });

  it('does not fire on an import referenced only inside a template literal', () => {
    const src = `import { BASE_URL } from './config.js';
import { LOCALE } from './i18n.js';

export const docsLink = (slug) => \`\${BASE_URL}/\${LOCALE}/docs/\${slug}\`;
`;
    expect(run('src/docs/link.js', src)).toEqual([]);
  });

  it('does not fire on an import used only inside a tagged template', () => {
    const src = `import { sql } from './sql-tag.js';
import { TABLE } from './schema.js';

export const activeUsers = sql\`SELECT id FROM \${TABLE.users} WHERE active = true\`;
`;
    expect(run('src/db/queries.js', src)).toEqual([]);
  });

  it('does not fire on an import used only in an extends clause', () => {
    const src = `import { BaseError } from './base-error.js';

export class PaymentDeclined extends BaseError {
  constructor(code) {
    super(\`Payment declined: \${code}\`);
    this.code = code;
  }
}
`;
    expect(run('src/errors/payment-declined.js', src)).toEqual([]);
  });

  it('does not fire on a file with many imports that are all used', () => {
    const src = `import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Button } from '../ui/Button.jsx';
import { Spinner } from '../ui/Spinner.jsx';
import { Toast } from '../ui/Toast.jsx';
import { useOrder } from './use-order.js';
import { formatMoney } from '../money/format.js';
import { track } from '../analytics/track.js';

export function OrderDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const inputRef = useRef(null);
  const [note, setNote] = useState('');
  const { order, loading } = useOrder(id);
  const total = useMemo(() => formatMoney(order?.totalCents ?? 0), [order]);
  const save = useCallback(() => track('order_note_saved', { id }), [id]);
  useEffect(() => { inputRef.current?.focus(); }, []);

  if (loading) return <Spinner />;
  return (
    <section>
      <h1>{total}</h1>
      <input ref={inputRef} value={note} onChange={(e) => setNote(e.target.value)} />
      <Button onClick={save}>Save</Button>
      <Button onClick={() => navigate('/orders')}>Back</Button>
      <Toast />
    </section>
  );
}
`;
    expect(run('src/orders/OrderDetail.jsx', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 8. Side-effect-only imports and imports used far from the top
// ---------------------------------------------------------------------------

describe('side-effect imports and late-used imports', () => {
  it('does not fire on side-effect-only imports at an app entry point', () => {
    const src = `import './polyfills.js';
import './styles/global.css';
import 'core-js/stable';
import React from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.jsx';

createRoot(document.getElementById('root')).render(<App />);
`;
    expect(run('src/main.jsx', src)).toEqual([]);
  });

  it('does not fire on a side-effect import that registers a service worker', () => {
    const src = `import './register-sw.js';

export const bootstrapped = true;
`;
    expect(run('src/bootstrap.js', src)).toEqual([]);
  });

  it('does not fire on an import used exactly once at the bottom of a long file', () => {
    const body = Array.from({ length: 60 }, (_, i) => `export const constant${i} = ${i} * 3;`).join(
      '\n'
    );
    const src = `import { seal } from './seal.js';\n\n${body}\n\nexport const registry = seal({ constant0, constant1 });\n`;
    expect(run('src/registry/constants.js', src)).toEqual([]);
  });

  it('does not fire on a CSS-module import used only in a className', () => {
    const src = `import React from 'react';
import styles from './Card.module.css';

export const Card = ({ children }) => <div className={styles.card}>{children}</div>;
`;
    expect(run('src/ui/Card.jsx', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 9. Repeated short strings that are not magic values
// ---------------------------------------------------------------------------

describe('repeated short strings that are not magic values', () => {
  it('does not fire on repeated HTTP method literals', () => {
    const src = `import { handle } from './router.js';

export const routes = [
  { method: 'GET', path: '/health', fn: handle.health },
  { method: 'GET', path: '/orders', fn: handle.listOrders },
  { method: 'GET', path: '/orders/:id', fn: handle.getOrder },
  { method: 'POST', path: '/orders', fn: handle.createOrder },
  { method: 'POST', path: '/orders/:id/refund', fn: handle.refund },
  { method: 'DELETE', path: '/orders/:id', fn: handle.cancelOrder },
  { method: 'GET', path: '/customers', fn: handle.listCustomers },
];
`;
    expect(run('src/server/routes.js', src)).toEqual([]);
  });

  it("does not fire on repeated 'utf-8' encoding arguments", () => {
    const src = `import { readFile, writeFile, appendFile } from 'node:fs/promises';

export const read = (p) => readFile(p, 'utf-8');
export const write = (p, c) => writeFile(p, c, 'utf-8');
export const append = (p, c) => appendFile(p, c, 'utf-8');
export const readMany = (ps) => Promise.all(ps.map((p) => readFile(p, 'utf-8')));
`;
    expect(run('src/fs/text.js', src)).toEqual([]);
  });

  it('does not fire on repeated single-character separators', () => {
    const src = `export const joinPath = (parts) => parts.join('/');
export const splitPath = (value) => value.split('/');
export const isAbsolute = (value) => value.startsWith('/');
export const trimTrailing = (value) => (value.endsWith('/') ? value.slice(0, -1) : value);
export const depth = (value) => value.split('/').length - 1;
`;
    expect(run('src/paths/posix.js', src)).toEqual([]);
  });

  it('does not fire on repeated import specifiers from the same module', () => {
    const src = `import { useState } from 'react';
import { render } from 'react-dom';
import { Button } from './ui/Button.jsx';
import { Icon } from './ui/Button.jsx';
import { ButtonGroup } from './ui/Button.jsx';

export const Demo = () => {
  const [open] = useState(false);
  return render(<ButtonGroup><Button><Icon name={open ? 'up' : 'down'} /></Button></ButtonGroup>);
};
`;
    expect(run('src/demo/Demo.jsx', src)).toEqual([]);
  });

  it('does not fire on repeated CSS class names in JSX', () => {
    const src = `import React from 'react';

export function Table({ rows }) {
  return (
    <table className="data-table">
      <tbody>
        {rows.map((r) => (
          <tr key={r.id}>
            <td className="data-table__cell">{r.name}</td>
            <td className="data-table__cell">{r.email}</td>
            <td className="data-table__cell">{r.role}</td>
            <td className="data-table__cell">{r.status}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
`;
    expect(run('src/ui/Table.jsx', src)).toEqual([]);
  });

  it('does not fire on repeated object keys across records', () => {
    const src = `export const PLANS = [
  { id: 'free', seats: 1, priceCents: 0, support: 'community' },
  { id: 'team', seats: 10, priceCents: 4900, support: 'email' },
  { id: 'business', seats: 50, priceCents: 19900, support: 'email' },
  { id: 'scale', seats: 250, priceCents: 79900, support: 'priority' },
];
`;
    expect(run('src/billing/plans.js', src)).toEqual([]);
  });

  it('does not fire on repeated boolean-ish flag strings in an options table', () => {
    const src = `export const FEATURES = {
  darkMode: 'enabled',
  betaEditor: 'disabled',
  exportCsv: 'enabled',
  webhooks: 'enabled',
  ssoScim: 'disabled',
  auditLog: 'enabled',
};
`;
    expect(run('src/flags/features.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 10. Repeated URLs, file paths, and user-facing sentences
// ---------------------------------------------------------------------------

describe('repeated URLs, paths, and user-facing sentences', () => {
  it('does not fire on an identical docs URL repeated in several messages', () => {
    const src = `const DOCS = 'https://docs.example.com/errors';

export const errors = {
  badToken: \`Your token was rejected. See \${DOCS}#bad-token\`,
  expired: \`Your token expired. See \${DOCS}#expired\`,
  revoked: \`Your token was revoked. See \${DOCS}#revoked\`,
  unknown: \`Something went wrong. See \${DOCS}\`,
};
`;
    expect(run('src/auth/errors.js', src)).toEqual([]);
  });

  it('does not fire on a repeated literal URL used in link markup', () => {
    const src = `import React from 'react';

export const Footer = () => (
  <footer>
    <a href="https://status.example.com">Status</a>
    <a href="https://status.example.com">Uptime history</a>
    <a href="https://status.example.com">Incident feed</a>
    <a href="https://status.example.com">Subscribe</a>
  </footer>
);
`;
    expect(run('src/ui/Footer.jsx', src)).toEqual([]);
  });

  it('does not fire on a repeated relative file path in a build manifest', () => {
    const src = `export const manifest = {
  entry: 'src/main.jsx',
  watch: ['src/main.jsx', 'src/App.jsx'],
  analyze: { root: 'src/main.jsx' },
  fallback: 'src/main.jsx',
};
`;
    expect(run('src/build/manifest.js', src)).toEqual([]);
  });

  it('does not fire on the same user-facing sentence reused across states', () => {
    const src = `const RETRY = 'Something went wrong. Try again in a moment.';

export const messages = {
  networkError: RETRY,
  timeout: RETRY,
  serverError: RETRY,
  unknown: RETRY,
};

export const inlineNetworkError = 'Something went wrong. Try again in a moment.';
export const inlineTimeout = 'Something went wrong. Try again in a moment.';
export const inlineServerError = 'Something went wrong. Try again in a moment.';
`;
    expect(run('src/ui/messages.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 11. eslint-disable comments WITH justification
// ---------------------------------------------------------------------------

describe('eslint-disable comments with a stated reason', () => {
  it('does not fire on an inline -- reason on eslint-disable-next-line', () => {
    const src = `export function reportStartup(version) {
  // eslint-disable-next-line no-console -- this CLI prints its banner to stdout by design
  console.log(\`northwind \${version}\`);
}
`;
    expect(run('src/cli/banner.js', src)).toEqual([]);
  });

  it('does not fire on a reason written in a line comment above the disable', () => {
    const src = `// The hash below mixes bits with xor, which is the point of the algorithm.
// eslint-disable-next-line no-bitwise
export const hash = (s) => [...s].reduce((h, c) => (h * 31 + c.charCodeAt(0)) | 0, 0);
`;
    expect(run('src/hash/fnv.js', src)).toEqual([]);
  });

  it('does not fire on a block comment justification above a file-level disable', () => {
    const src = `/*
 * This module is the compatibility shim for the legacy global API. It has to
 * assign onto window, which the no-undef rule cannot see through under our
 * node-flavored eslint env. The shim is deleted when v1 clients are gone.
 */
/* eslint-disable no-undef */
window.NorthwindLegacy = { version: '0.9.0' };

export const legacyInstalled = true;
`;
    expect(run('src/compat/legacy-global.js', src)).toEqual([]);
  });

  it('does not fire on a reason appended after the rule name in a block disable', () => {
    const src = `/* eslint-disable react-hooks/exhaustive-deps -- the effect must run once on mount only */
import { useEffect } from 'react';

export function useMountPing(send) {
  useEffect(() => {
    send('mounted');
  }, []);
}
`;
    expect(run('src/hooks/use-mount-ping.js', src)).toEqual([]);
  });

  it('does not fire on a scoped enable/disable pair with a reason on both ends', () => {
    const src = `// Generated protobuf accessors use snake_case keys we do not control.
/* eslint-disable camelcase -- wire format keys come from the .proto file */
export const toWire = (o) => ({ order_id: o.id, created_at: o.createdAt });
/* eslint-enable camelcase */

export const fromWire = (w) => ({ id: w.order_id, createdAt: w.created_at });
`;
    expect(run('src/wire/order.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 12. TODO / FIXME with tracker references
// ---------------------------------------------------------------------------

describe('TODO and FIXME comments carrying a tracker reference', () => {
  it('does not fire on TODO(PROJ-123)', () => {
    const src = `// TODO(PROJ-123): switch to the streaming parser once the upstream fix lands.
export const parse = (text) => JSON.parse(text);
`;
    expect(run('src/parse/json.js', src)).toEqual([]);
  });

  it('does not fire on a TODO with a bare issue number', () => {
    const src = `// TODO: retry on 429 with exponential backoff (#456)
export const get = (url) => fetch(url);
`;
    expect(run('src/http/get.js', src)).toEqual([]);
  });

  it('does not fire on a FIXME with a full issue URL', () => {
    const src = `// FIXME: the timezone offset is computed at module load, which breaks across
// DST boundaries in long-lived workers.
// https://github.com/northwind/app/issues/77
export const offsetMinutes = new Date().getTimezoneOffset();
`;
    expect(run('src/time/offset.js', src)).toEqual([]);
  });

  it('does not fire on a parenthesized JIRA reference', () => {
    const src = `// TODO (JIRA-9) replace the polling loop with the websocket feed.
export const poll = (fn, ms) => setInterval(fn, ms);
`;
    expect(run('src/realtime/poll.js', src)).toEqual([]);
  });

  it('does not fire on a GH-12 style reference', () => {
    const src = `// FIXME GH-12 the CSV writer quotes every field; only quote when needed.
export const toCsv = (rows) => rows.map((r) => r.map((c) => \`"\${c}"\`).join(',')).join('\\n');
`;
    expect(run('src/export/csv.js', src)).toEqual([]);
  });

  it('does not fire on several tracked TODOs in one file', () => {
    const src = `// TODO(BILL-401): move proration math into the pricing service.
// TODO(BILL-402): add a currency guard once multi-currency ships.
// FIXME(BILL-403): rounding is half-up here and half-even in the ledger.
export const prorate = (cents, days, period) => Math.round((cents * days) / period);
`;
    expect(run('src/billing/prorate.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 13. Entirely clean, ordinary files
// ---------------------------------------------------------------------------

describe('entirely clean ordinary files', () => {
  it('does not fire on a small React component', () => {
    const src = `import React from 'react';

export function Badge({ label, tone = 'neutral' }) {
  return <span className={\`badge badge--\${tone}\`}>{label}</span>;
}
`;
    expect(run('src/ui/Badge.jsx', src)).toEqual([]);
  });

  it('does not fire on a plain Express route module', () => {
    const src = `import { Router } from 'express';
import { listProjects, createProject } from './service.js';

export const router = Router();

router.get('/projects', async (req, res) => {
  res.json(await listProjects(req.user.id));
});

router.post('/projects', async (req, res) => {
  const project = await createProject(req.user.id, req.body.name);
  res.status(201).json(project);
});
`;
    expect(run('src/projects/routes.js', src)).toEqual([]);
  });

  it('does not fire on a small pure utility module', () => {
    const src = `export const clamp = (value, min, max) => Math.min(Math.max(value, min), max);
export const sum = (values) => values.reduce((a, b) => a + b, 0);
export const mean = (values) => (values.length ? sum(values) / values.length : 0);
export const unique = (values) => [...new Set(values)];
`;
    expect(run('src/lib/math-utils.js', src)).toEqual([]);
  });

  it('does not fire on a config object export', () => {
    const src = `export default {
  port: Number(process.env.PORT ?? 3000),
  logLevel: process.env.LOG_LEVEL ?? 'info',
  database: { poolMin: 2, poolMax: 10, statementTimeoutMs: 5000 },
  features: { webhooks: true, exportCsv: true },
};
`;
    expect(run('src/config/app-config.js', src)).toEqual([]);
  });

  it('does not fire on a small custom React hook', () => {
    const src = `import { useEffect, useState } from 'react';

export function useOnline() {
  const [online, setOnline] = useState(navigator.onLine);
  useEffect(() => {
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener('online', up);
    window.addEventListener('offline', down);
    return () => {
      window.removeEventListener('online', up);
      window.removeEventListener('offline', down);
    };
  }, []);
  return online;
}
`;
    expect(run('src/hooks/use-online.js', src)).toEqual([]);
  });

  it('does not fire on a small class with a constructor and two methods', () => {
    const src = `export class RateLimiter {
  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.hits = [];
  }

  allow(now = Date.now()) {
    this.hits = this.hits.filter((t) => now - t < this.windowMs);
    if (this.hits.length >= this.limit) return false;
    this.hits.push(now);
    return true;
  }

  reset() {
    this.hits = [];
  }
}
`;
    expect(run('src/limits/rate-limiter.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 14. Minified and generated files
// ---------------------------------------------------------------------------

describe('minified and generated files', () => {
  it('does not fire on a bundled .min.js file', () => {
    const min =
      '!function(e,t){"object"==typeof exports&&"undefined"!=typeof module?t(exports):' +
      '"function"==typeof define&&define.amd?define(["exports"],t):t(e.NW={})}(this,function(e){' +
      '"use strict";function t(n){return n<2?n:t(n-1)+t(n-2)}function r(n,o){return n+o}' +
      'e.fib=t,e.add=r,Object.defineProperty(e,"__esModule",{value:!0})});';
    expect(run('src/vendor/northwind.min.js', min)).toEqual([]);
  });

  it('does not fire on a file with an @generated banner', () => {
    const rows = Array.from(
      { length: 80 },
      (_, i) => `  ROUTE_${i}: { path: '/r/${i}', method: 'GET', handler: 'h${i}' },`
    ).join('\n');
    const src = `/**\n * @generated by scripts/gen-routes.mjs -- do not edit by hand.\n * Source of truth: routes.yaml\n */\nexport const ROUTES = {\n${rows}\n};\n`;
    expect(run('src/generated/routes.js', src)).toEqual([]);
  });

  it('does not fire on generated GraphQL types with repeated scalar names', () => {
    const src = `/* eslint-disable */
// @generated by graphql-codegen. Do not edit.
export type Scalars = { ID: string; String: string; Boolean: boolean; Int: number };
export type User = { __typename?: 'User'; id: Scalars['ID']; email: Scalars['String'] };
export type Team = { __typename?: 'Team'; id: Scalars['ID']; name: Scalars['String'] };
export type Post = { __typename?: 'Post'; id: Scalars['ID']; title: Scalars['String'] };
export type Tag  = { __typename?: 'Tag';  id: Scalars['ID']; label: Scalars['String'] };
`;
    expect(run('src/generated/graphql-types.ts', src)).toEqual([]);
  });

  it('does not fire on a generated source map comment tail', () => {
    const src =
      'var a=1,b=2;function c(d){return d*a+b}export{c as compute};\n' +
      '//# sourceMappingURL=compute.js.map\n';
    expect(run('src/generated/compute.js', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// 15. Non-JS files containing every shape as prose or data
// ---------------------------------------------------------------------------

describe('non-JavaScript files containing the shapes as text', () => {
  it('does not fire on a Markdown doc full of narration and TODOs', () => {
    const src = `# Contributing

Here is the complete list of things to do before you open a pull request.

Certainly! I have updated the checklist below.

<!--
  const oldFlow = require('./old-flow');
  oldFlow.run();
-->

- TODO: rewrite this section
- FIXME: the diagram is out of date
- Note that the API returns a 200 with an empty body on success.

\`\`\`js
// eslint-disable-next-line no-console
console.log('example only');
\`\`\`

The updated_at column is maintained by a trigger. See https://example.com/docs and
https://example.com/docs and https://example.com/docs for the same reason repeated.
`;
    expect(run('docs/CONTRIBUTING.md', src)).toEqual([]);
  });

  it('does not fire on a package-style JSON file with repeated strings', () => {
    const src = `{
  "name": "northwind",
  "version": "1.4.0",
  "scripts": {
    "build": "node scripts/build.mjs",
    "build:dev": "node scripts/build.mjs --dev",
    "build:prod": "node scripts/build.mjs --prod",
    "clean": "rimraf dist"
  },
  "files": ["dist", "dist", "README.md"]
}
`;
    expect(run('config/northwind.json', src)).toEqual([]);
  });

  it('does not fire on a CSS file with repeated values and commented-out rules', () => {
    const src = `/* Design tokens. TODO: move to the token pipeline. */
:root {
  --space-1: 4px;
  --space-2: 8px;
  --space-3: 12px;
}

.card { padding: 8px; border-radius: 8px; background: #fff; }
.panel { padding: 8px; border-radius: 8px; background: #fff; }
.sheet { padding: 8px; border-radius: 8px; background: #fff; }

/*
.legacy-card { padding: 6px; }
.legacy-panel { padding: 6px; }
.legacy-sheet { padding: 6px; }
.legacy-modal { padding: 6px; }
.legacy-drawer { padding: 6px; }
*/
`;
    expect(run('src/styles/tokens.css', src)).toEqual([]);
  });

  it('does not fire on a YAML workflow with repeated keys and commented-out jobs', () => {
    const src = `name: ci
on:
  push:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run lint
# deploy:
#   runs-on: ubuntu-latest
#   steps:
#     - uses: actions/checkout@v4
#     - run: npm ci
#     - run: npm run deploy
# TODO: re-enable deploy once the staging environment is back.
`;
    expect(run('.github/workflows/ci.yml', src)).toEqual([]);
  });

  it('does not fire on an .env.example with repeated placeholder values', () => {
    const src = `# Copy to .env and fill in. TODO: document the optional vars.
DATABASE_URL=postgres://localhost:5432/northwind
REDIS_URL=redis://localhost:6379
LOG_LEVEL=info
NODE_ENV=development
FEATURE_WEBHOOKS=true
FEATURE_EXPORT_CSV=true
FEATURE_AUDIT_LOG=true
`;
    expect(run('config/.env.example', src)).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Multi-file corpora: clean projects should produce nothing end to end
// ---------------------------------------------------------------------------

describe('clean multi-file corpora', () => {
  it('does not fire on a small, ordinary three-file feature slice', () => {
    const files = [
      {
        path: 'src/notifications/types.ts',
        content: `export type Notification = { id: string; body: string; readAt: string | null };\n`,
      },
      {
        path: 'src/notifications/repository.ts',
        content: `import type { Notification } from './types.ts';
import { db } from '../db/client.ts';

export async function listUnread(userId: string): Promise<Notification[]> {
  return db.select('notifications').where({ userId, readAt: null });
}
`,
      },
      {
        path: 'src/notifications/NotificationList.tsx',
        content: `import React from 'react';
import type { Notification } from './types.ts';

export function NotificationList({ items }: { items: Notification[] }) {
  return (
    <ul className="notification-list">
      {items.map((n) => (
        <li key={n.id} className="notification-list__item">{n.body}</li>
      ))}
    </ul>
  );
}
`,
      },
    ];
    expect(probeAICodegenBloat(files)).toEqual([]);
  });

  it('does not fire on sibling files with similar-but-distinct names', () => {
    const files = [
      { path: 'src/api/client.ts', content: `export const client = { get: fetch };\n` },
      {
        path: 'src/api/client-node.ts',
        content: `import { client } from './client.ts';\nexport const nodeClient = { ...client, agent: 'node' };\n`,
      },
      {
        path: 'src/api/client-browser.ts',
        content: `import { client } from './client.ts';\nexport const browserClient = { ...client, agent: 'browser' };\n`,
      },
    ];
    expect(probeAICodegenBloat(files)).toEqual([]);
  });

  it('does not fire on an empty corpus', () => {
    expect(probeAICodegenBloat([])).toEqual([]);
  });

  it('does not fire on a file with no content', () => {
    expect(run('src/placeholder.js', '')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Edge cases where benign-vs-bloat is genuinely ambiguous.
//
// These are cases where a reasonable reviewer could argue either way. A failure
// here is signal about where the probe's line currently sits, not necessarily a
// defect. Each carries a note about why it is fuzzy.
// ---------------------------------------------------------------------------

describe('edge cases where benign-vs-bloat is genuinely ambiguous', () => {
  // AMBIGUOUS: the filename contains a literal "v2" segment AND a sibling v1
  // exists in the same corpus. That is what real versioned APIs look like, but
  // it is also exactly the shape of "the model wrote a second copy".
  it('does not fire on parallel src/v1 and src/v2 API surfaces', () => {
    const files = [
      {
        path: 'src/api/v1/orders.ts',
        content: `export const listOrders = () => fetch('/api/v1/orders').then((r) => r.json());\n`,
      },
      {
        path: 'src/api/v2/orders.ts',
        content: `export const listOrders = (cursor: string) =>
  fetch(\`/api/v2/orders?after=\${cursor}\`).then((r) => r.json());
`,
      },
    ];
    expect(probeAICodegenBloat(files)).toEqual([]);
  });

  // AMBIGUOUS: a large switch is high cyclomatic complexity by every standard
  // metric, but a flat dispatch table with one return per case is about as
  // reviewable as code gets. Where the probe draws this line matters a lot.
  it('does not fire on an 18-case flat switch mapping codes to labels', () => {
    const cases = Array.from(
      { length: 18 },
      (_, i) => `    case 'C${i}': return 'Label ${i}';`
    ).join('\n');
    const src = `export function labelFor(code) {\n  switch (code) {\n${cases}\n    default: return 'Unknown';\n  }\n}\n`;
    expect(run('src/codes/labels.js', src)).toEqual([]);
  });

  // AMBIGUOUS: a genuinely long function that resists decomposition because
  // every step mutates the same accumulator. Roughly 70 lines. Splitting it
  // would mean threading eight locals through helpers.
  // ADJUDICATED round 1: kept firing. The function carries complexity 18
  // from real branches, not from switch arms, and that is precisely what
  // the check exists to surface. Medium severity saying "go read this" is
  // the correct outcome even when the answer is "yes, it has to be like this".
  it.skip('does not fire on a ~70 line single-pass CSV row assembler', () => {
    const src = `export function assembleRow(record, columns, options) {
  const cells = [];
  let quoted = 0;
  let truncated = 0;
  let blanks = 0;
  for (const column of columns) {
    let value = record[column.key];
    if (value === null || value === undefined) {
      blanks += 1;
      cells.push('');
      continue;
    }
    if (column.type === 'date') {
      value = new Date(value).toISOString().slice(0, 10);
    } else if (column.type === 'money') {
      value = (value / 100).toFixed(2);
    } else if (column.type === 'bool') {
      value = value ? 'yes' : 'no';
    } else if (column.type === 'list') {
      value = value.join('; ');
    } else {
      value = String(value);
    }
    if (options.maxCellLength && value.length > options.maxCellLength) {
      value = value.slice(0, options.maxCellLength - 1) + '\\u2026';
      truncated += 1;
    }
    if (value.includes(',') || value.includes('"') || value.includes('\\n')) {
      value = '"' + value.replace(/"/g, '""') + '"';
      quoted += 1;
    }
    cells.push(value);
  }
  if (options.includeRowNumber) {
    cells.unshift(String(record.__rowNumber ?? 0));
  }
  if (options.trailingComma) {
    cells.push('');
  }
  const line = cells.join(options.delimiter ?? ',');
  return {
    line,
    stats: { quoted, truncated, blanks, cellCount: cells.length, byteLength: line.length },
  };
}
`;
    expect(run('src/export/assemble-row.js', src)).toEqual([]);
  });

  // AMBIGUOUS: a wrapper whose only change is adding await. Semantically it
  // changes the error surface (rejection becomes a throw at this frame), which
  // is a real difference, but it reads as a pass-through.
  it('does not fire on a wrapper whose only change is awaiting the inner call', () => {
    const src = `import { loadProfile } from './loader.js';

// Awaiting here means a rejected profile load is attributed to this frame in
// stack traces, which is what the on-call runbook keys off.
export async function getProfile(id) {
  return await loadProfile(id);
}
`;
    expect(run('src/profile/get-profile.js', src)).toEqual([]);
  });

  // AMBIGUOUS: a long block of commented-out code that is intentionally
  // preserved as executable documentation, with a stated reason and a ticket.
  it('does not fire on a documented, ticketed block of commented-out benchmark code', () => {
    const src = `// Reference implementation kept for the benchmark in BENCH-88. It is the naive
// version the current code is measured against. Do not delete without updating
// the benchmark harness, which quotes these exact lines in its report.
//
// function naiveDedupe(items) {
//   const out = [];
//   for (const item of items) {
//     let seen = false;
//     for (const existing of out) {
//       if (existing.id === item.id) { seen = true; break; }
//     }
//     if (!seen) out.push(item);
//   }
//   return out;
// }

export function dedupe(items) {
  const seen = new Set();
  return items.filter((i) => (seen.has(i.id) ? false : seen.add(i.id)));
}
`;
    expect(run('src/collections/dedupe.js', src)).toEqual([]);
  });

  // AMBIGUOUS: many imports (14) in a legitimate composition-root file. Every
  // one is used, but the count alone is the tell some detectors key on.
  it('does not fire on a composition root with 14 used imports', () => {
    const src = `import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Router } from './router.js';
import { logger } from './log/logger.js';
import { metrics } from './observability/metrics.js';
import { tracing } from './observability/tracing.js';
import { db } from './db/client.js';
import { cache } from './cache/client.js';
import { queue } from './queue/client.js';
import { authRoutes } from './auth/routes.js';
import { orderRoutes } from './orders/routes.js';
import { adminRoutes } from './admin/routes.js';
import { config } from './config/app-config.js';

export async function main() {
  tracing.start();
  metrics.start();
  const router = new Router([authRoutes, orderRoutes, adminRoutes]);
  const banner = await readFile(join(process.cwd(), 'BANNER.txt'), 'utf-8');
  logger('boot').info(banner);
  await Promise.all([db.connect(), cache.connect(), queue.connect()]);
  createServer(router.handle).listen(config.port);
}
`;
    expect(run('src/server/main.js', src)).toEqual([]);
  });

  // AMBIGUOUS: a bare "TODO" with no ticket, but with a concrete owner and a
  // concrete condition. Some teams treat an owner as sufficient tracking.
  it('does not fire on a TODO with a named owner and a trigger condition', () => {
    const src = `// TODO(dana): drop this shim when the last v1 client stops calling /legacy,
// which the dashboard says is trending to zero by the end of the quarter.
export const legacyShim = (payload) => ({ ...payload, apiVersion: 1 });
`;
    expect(run('src/compat/shim.js', src)).toEqual([]);
  });

  // AMBIGUOUS: a filename with a date suffix. Real migration files look exactly
  // like this; so do "let me save a copy before I edit" artifacts.
  it('does not fire on a dated migration filename', () => {
    const src = `export const up = (db) => db.schema.alterTable('orders', (t) => t.string('channel'));
export const down = (db) => db.schema.alterTable('orders', (t) => t.dropColumn('channel'));
`;
    expect(run('src/db/migrations/2024-05-02-add-order-channel.js', src)).toEqual([]);
  });
});
