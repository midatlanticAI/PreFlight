// Adversarial RECALL suite r1 for probeAICodeSmells.
// Derived ONLY from the spec: src/learn/patterns/ai-code-smells.md
// Spec promises under test:
//   1. Empty catch blocks: `catch {}` or `catch (e) {}` with no body other
//      than whitespace or a comment. (CWE-390 is the cited class.)
//   2. `: any` in TypeScript function parameters (handlers, route handlers,
//      webhook endpoints called out as the important cases).
//   3. The probe is informational (surfaces patterns worth a second look).
//   4. The documented fixes (logged/rethrown catch bodies, `unknown` +
//      schema validation) must NOT fire.
// Comments and string literals are masked before matching, so smell shapes
// that exist only inside comments/strings must not fire.

import { describe, it, expect } from 'vitest';
import { probeAICodeSmells } from '../lib/probes.js';

const mk = (path, lines) => ({ path, content: lines.join('\n') });

const run = (...files) => probeAICodeSmells(files);

// ---------------------------------------------------------------------------
// 1. Empty catch blocks - positives
// ---------------------------------------------------------------------------

describe('empty catch blocks: positives promised by the spec', () => {
  it('flags a same-line bare `catch {}` in a .js file', () => {
    const res = run(
      mk('src/app.js', [
        'async function submitOrder(amount) {',
        '  try {',
        '    await chargeCard(amount);',
        '  } catch {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  it('flags a same-line `catch (e) {}` in a .js file', () => {
    const res = run(
      mk('src/lib/service.js', [
        'function persistSession(session) {',
        '  try {',
        '    store.write(session);',
        '  } catch (e) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  it('flags `catch (err) {}` in a .ts file', () => {
    const res = run(
      mk('src/lib/service.ts', [
        'export async function verifySignature(sig: string) {',
        '  try {',
        '    await crypto.verify(sig);',
        '  } catch (err) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  it('flags `catch (error) {}` in a .tsx file', () => {
    const res = run(
      mk('src/components/OrderPanel.tsx', [
        'export function useOrderRefresh(orderId: string) {',
        '  try {',
        '    refreshOrder(orderId);',
        '  } catch (error) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  it('flags `catch{}` with no whitespace before the braces', () => {
    const res = run(
      mk('src/app.js', [
        'function syncProfile(user) {',
        '  try {',
        '    pushProfile(user);',
        '  } catch{}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  it('flags a multi-line catch whose body is only whitespace', () => {
    const res = run(
      mk('src/lib/payments.js', [
        'async function settleInvoice(id) {',
        '  try {',
        '    await gateway.settle(id);',
        '  } catch (e) {',
        '',
        '  }',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  // Round-1 adjudication: the original spec text promised comment-only
  // bodies fire; the settled precision rounds (v3/v5) had already pinned
  // them QUIET (a comment is documented intent) and the Pattern page was
  // corrected to match. These two flipped from positive to negative.
  it('does not flag a catch whose only body is a line comment (documented intent)', () => {
    const res = run(
      mk('src/lib/webhooks.js', [
        'async function processDelivery(evt) {',
        '  try {',
        '    await verifyAndApply(evt);',
        '  } catch (error) {',
        '    // swallow for now',
        '  }',
        '}',
      ])
    );
    expect(res).toEqual([]);
  });

  it('does not flag a catch whose only body is a block comment on the same line', () => {
    const res = run(
      mk('src/lib/queue.js', [
        'function drainQueue(q) {',
        '  try {',
        '    q.flush();',
        '  } catch (e) { /* ignore */ }',
        '}',
      ])
    );
    expect(res).toEqual([]);
  });

  it('flags an empty catch inside a class method', () => {
    const res = run(
      mk('src/lib/payment-service.js', [
        'class PaymentService {',
        '  async settle(id) {',
        '    try {',
        '      await this.gateway.settle(id);',
        '    } catch (e) {}',
        '  }',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });

  it('reports two findings when a file contains two independent empty catches', () => {
    const res = run(
      mk('src/lib/sync.js', [
        'async function pushAll(items) {',
        '  try {',
        '    await push(items);',
        '  } catch {}',
        '}',
        'async function pullAll() {',
        '  try {',
        '    await pull();',
        '  } catch (e) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(2);
  });

  it('flags the empty inner catch of a nested try/catch', () => {
    const res = run(
      mk('src/lib/importer.js', [
        'async function importBatch(rows) {',
        '  try {',
        '    for (const row of rows) {',
        '      try {',
        '        await insertRow(row);',
        '      } catch (rowErr) {}',
        '    }',
        '  } catch (batchErr) {',
        '    log.error(String(batchErr));',
        '    throw batchErr;',
        '  }',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// 2. Empty catch blocks - suppressions promised by the spec
// ---------------------------------------------------------------------------

describe('empty catch blocks: negatives promised by the spec', () => {
  it('does not flag the spec fix shape: log with context then rethrow', () => {
    const res = run(
      mk('src/lib/payments.js', [
        'async function charge(amount, userId) {',
        '  try {',
        '    await chargeCard(amount);',
        '  } catch (e) {',
        "    log.error('charge failed', { error: e, amount, userId });",
        '    throw new ChargeFailedError({ cause: e });',
        '  }',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag a catch with a deliberate compensating action', () => {
    const res = run(
      mk('src/lib/retry.js', [
        'async function fetchWithRetry(url, retries) {',
        '  try {',
        '    return await fetch(url);',
        '  } catch (e) {',
        '    retries.count += 1;',
        '    return scheduleRetry(url, retries);',
        '  }',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag a narrowed catch that rethrows unexpected error types', () => {
    const res = run(
      mk('src/lib/timeouts.js', [
        'async function poll(job) {',
        '  try {',
        '    await job.tick();',
        '  } catch (e) {',
        '    if (!(e instanceof TimeoutError)) throw e;',
        '    metrics.timeouts += 1;',
        '  }',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag an empty-catch shape that exists only inside a line comment', () => {
    const res = run(
      mk('src/app.js', ['// previously: try { run(); } catch {}', 'runWithReporting();'])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag an empty-catch shape that exists only inside a string literal', () => {
    const res = run(
      mk('src/lib/lint-help.js', [
        "const badShape = 'try { a(); } catch (e) {}';",
        'export function describeSmell() {',
        '  return badShape;',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag an empty-catch shape that exists only inside a template literal', () => {
    const res = run(
      mk('src/lib/docs-render.js', [
        'const snippet = `try { risky(); } catch {}`;',
        'export function renderSnippet() {',
        '  return snippet;',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 3. `: any` in TypeScript function parameters - positives
// ---------------------------------------------------------------------------

// Round-1 adjudication: the original spec text read as per-parameter
// detection; the settled precision rounds (v3/v5) had pinned sparse
// idiomatic any QUIET, and the Pattern page was corrected to the density
// contract (five or more any-bearing lines per file). The single-occurrence
// positives below flipped to below-threshold negatives; the density
// positives carry the recall load.
describe('`: any` density: the corrected spec contract', () => {
  it('does not flag a single any parameter (below the density threshold)', () => {
    const res = run(
      mk('src/lib/webhook.ts', [
        'export async function handleWebhook(payload: any) {',
        '  const order = payload.order;',
        '  await db.orders.update({ id: order.id, paid: order.paid });',
        '}',
      ])
    );
    expect(res).toEqual([]);
  });

  it('does not flag two sparse any parameters across a file', () => {
    const res = run(
      mk('src/lib/bus.ts', [
        'const onMessage = (msg: any) => {',
        '  dispatch(msg.body);',
        '};',
        'const onClose = (evt: any) => {',
        '  teardown(evt.code);',
        '};',
      ])
    );
    expect(res).toEqual([]);
  });

  it('does not flag four any-bearing lines (still below threshold)', () => {
    const res = run(
      mk('src/lib/hook-router.ts', [
        'export class HookRouter {',
        '  dispatch(event: any) {',
        '    return this.routes[event.kind];',
        '  }',
        '  register(route: any) {',
        '    this.routes[route.kind] = route;',
        '  }',
        '  unregister(route: any) {',
        '    delete this.routes[route.kind];',
        '  }',
        '  inspect(probe: any) {',
        '    return probe.describe(this.routes);',
        '  }',
        '}',
      ])
    );
    expect(res).toEqual([]);
  });

  it('flags a file with five any-bearing lines (at the density threshold)', () => {
    const res = run(
      mk('src/lib/legacy-adapter.ts', [
        'export function readOrder(raw: any) {',
        '  return raw.order;',
        '}',
        'export function readCustomer(raw: any) {',
        '  return raw.customer;',
        '}',
        'export function readTotals(raw: any) {',
        '  return raw.total;',
        '}',
        'export function readMeta(raw: any) {',
        '  return raw.meta;',
        '}',
        'export function readFlags(raw: any) {',
        '  return raw.flags;',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(res[0].title).toMatch(/any/i);
  });

  it('flags dense mixed ": any" and "as any" usage in a route file', () => {
    const res = run(
      mk('src/server/routes.ts', [
        "app.post('/hooks/payments', (req: any, res: any) => {",
        '  const body = req.body as any;',
        '  const meta = (req.headers as any).meta;',
        '  applyDelivery(body);',
        '  audit(meta as any);',
        '  const outcome: any = settle(body);',
        "  res.send(outcome.status ?? 'ok');",
        '});',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// 4. `: any` in TypeScript function parameters - suppressions
// ---------------------------------------------------------------------------

describe('`: any` parameters: negatives promised by the spec', () => {
  it('does not flag the spec fix shape: `unknown` parameter', () => {
    const res = run(
      mk('src/lib/webhook.ts', [
        'export function handleWebhook(payload: unknown) {',
        '  const validated = WebhookSchema.parse(payload);',
        '  return db.orders.update({ id: validated.order.id, paid: validated.order.paid });',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag a parameter with a concrete named type', () => {
    const res = run(
      mk('src/lib/orders.ts', [
        'export function applyRefund(ticket: RefundTicket) {',
        '  return db.refunds.create(ticket);',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag the full zod boundary-validation fix from the spec', () => {
    const res = run(
      mk('src/lib/webhook-validated.ts', [
        "import { z } from 'zod';",
        'const WebhookSchema = z.object({',
        '  order: z.object({',
        '    id: z.string(),',
        '    paid: z.boolean(),',
        '  }),',
        '});',
        'export async function handleWebhook(payload: unknown) {',
        '  const validated = WebhookSchema.parse(payload);',
        '  await db.orders.update({ id: validated.order.id, paid: validated.order.paid });',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag `: any` appearing only inside a comment', () => {
    const res = run(
      mk('src/lib/orders.ts', [
        '// old signature took payload: any, now typed below',
        'export function applyOrder(payload: OrderInput) {',
        '  return db.orders.create(payload);',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag `: any` appearing only inside a string literal', () => {
    const res = run(
      mk('src/lib/lint-messages.ts', [
        "const guidance = 'never type a handler parameter: any is not a contract';",
        'export function lintMessage() {',
        '  return guidance;',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('does not flag a type name that merely starts with the letters any', () => {
    const res = run(
      mk('src/lib/schema-utils.ts', [
        'export function pickBranch(cfg: anyOfSchemaNode) {',
        '  return cfg.branches[0];',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 5. Structural promises: probe name, severity, cwe, line, field population
// ---------------------------------------------------------------------------

describe('structural promises from the spec and finding contract', () => {
  it('stamps findings with probe "AI Code Smells"', () => {
    const res = run(
      mk('src/app.js', [
        'function save(doc) {',
        '  try {',
        '    persist(doc);',
        '  } catch {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    for (const f of res) {
      expect(f.probe).toBe('AI Code Smells');
    }
  });

  it('marks empty-catch findings informational (spec: "the AI Code Smells probe is informational")', () => {
    const res = run(
      mk('src/app.js', [
        'function save(doc) {',
        '  try {',
        '    persist(doc);',
        '  } catch (e) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(String(res[0].severity).toLowerCase()).toContain('info');
  });

  it('marks any-density findings informational', () => {
    const res = run(
      mk('src/lib/service.ts', [
        'export function acceptDelivery(body: any) {',
        '  return route(body.kind);',
        '}',
        'export function acceptRetry(body: any) {',
        '  return route(body.kind);',
        '}',
        'export function acceptReplay(body: any) {',
        '  return route(body.kind);',
        '}',
        'export function acceptBatch(body: any) {',
        '  return route(body.kind);',
        '}',
        'export function acceptProbe(body: any) {',
        '  return route(body.kind);',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(String(res[0].severity).toLowerCase()).toContain('info');
  });

  it('cites CWE-390 on the empty-catch finding (the class the spec sources)', () => {
    const res = run(
      mk('src/lib/verify.js', [
        'async function verify(sig) {',
        '  try {',
        '    await checkSignature(sig);',
        '  } catch (e) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(String(res[0].cwe)).toMatch(/390/);
  });

  it('points the line number at the catch, not line 1', () => {
    const res = run(
      mk('src/lib/persist.js', [
        'export async function persistOrder(order) {', // line 1
        '  try {', // line 2
        '    await db.save(order);', // line 3
        '  } catch (e) {}', // line 4
        '}', // line 5
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(res[0].line).toBe(4);
  });

  it('points the line number of a multi-line empty catch within the catch block', () => {
    const res = run(
      mk('src/lib/flush.js', [
        'export function flushAll(buf) {', // 1
        '  try {', // 2
        '    buf.flush();', // 3
        '  } catch (err) {', // 4
        '', // 5 (whitespace-only body per the corrected spec)
        '  }', // 6
        '}', // 7
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(res[0].line).toBeGreaterThanOrEqual(4);
    expect(res[0].line).toBeLessThanOrEqual(6);
    expect(res[0].line).not.toBe(1);
  });

  it('reports the occurrence count in the any-density finding title', () => {
    const res = run(
      mk('src/lib/refunds.ts', [
        'export function applyRefund(ticket: any) {',
        '  return db.refunds.create(ticket as any);',
        '}',
        'export function voidRefund(ticket: any) {',
        '  return db.refunds.void(ticket as any);',
        '}',
        'export function auditRefund(ticket: any) {',
        '  return db.audit.log(ticket);',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    expect(res[0].title).toMatch(/\d+/);
  });

  it('populates file, id, title, evidence, and remediation on every finding', () => {
    const res = run(
      mk('src/lib/service.ts', [
        'export function acceptHook(body: any) {',
        '  try {',
        '    apply(body);',
        '  } catch {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(1);
    for (const f of res) {
      expect(f.file).toBe('src/lib/service.ts');
      expect(typeof f.id).toBe('string');
      expect(f.id.length).toBeGreaterThan(0);
      expect(typeof f.title).toBe('string');
      expect(f.title.length).toBeGreaterThan(0);
      expect(typeof f.evidence).toBe('string');
      expect(f.evidence.length).toBeGreaterThan(0);
      expect(typeof f.remediation).toBe('string');
      expect(f.remediation.length).toBeGreaterThan(0);
    }
  });
});

// ---------------------------------------------------------------------------
// 6. Multi-file behavior and aggregation
// ---------------------------------------------------------------------------

describe('multi-file behavior', () => {
  it('attributes findings to the smelly file, not the clean one', () => {
    const clean = mk('src/lib/clean.js', ['export function ping() {', '  return Date.now();', '}']);
    const smelly = mk('src/lib/smelly.js', [
      'export function pull(feed) {',
      '  try {',
      '    return feed.read();',
      '  } catch (e) {}',
      '}',
    ]);
    const res = run(clean, smelly);
    expect(res.length).toBeGreaterThanOrEqual(1);
    for (const f of res) {
      expect(f.file).toBe('src/lib/smelly.js');
    }
  });

  it('detects both smell classes when they co-occur in one .ts file', () => {
    const res = run(
      mk('src/lib/gateway.ts', [
        'export async function receive(body: any) {',
        '  const payload = body as any;',
        '  const meta = (body.headers as any).meta;',
        '  const outcome: any = route(payload);',
        '  const trace: any = audit(meta);',
        '  try {',
        '    await apply(outcome, trace);',
        '  } catch (e) {}',
        '}',
      ])
    );
    expect(res.length).toBeGreaterThanOrEqual(2);
  });

  it('detects smells independently across multiple files', () => {
    const a = mk('src/lib/a-hooks.ts', [
      'export function onEvent(evt: any) {',
      '  return (evt as any).id;',
      '}',
      'export function onError(evt: any) {',
      '  return (evt as any).error;',
      '}',
      'export function onClose(evt: any) {',
      '  return evt.code;',
      '}',
    ]);
    const b = mk('src/lib/b-sync.js', [
      'function sync(store) {',
      '  try {',
      '    store.push();',
      '  } catch {}',
      '}',
    ]);
    const res = run(a, b);
    const files = new Set(res.map((f) => f.file));
    expect(files.has('src/lib/a-hooks.ts')).toBe(true);
    expect(files.has('src/lib/b-sync.js')).toBe(true);
  });

  it('returns no findings for a clean, well-typed file', () => {
    const res = run(
      mk('src/lib/clean-service.ts', [
        'export async function charge(amount: number, userId: string) {',
        '  try {',
        '    await chargeCard(amount);',
        '  } catch (e) {',
        "    log.error('charge failed', { error: e, amount, userId });",
        '    throw new ChargeFailedError({ cause: e });',
        '  }',
        '}',
      ])
    );
    expect(res).toHaveLength(0);
  });

  it('returns an empty array for empty input', () => {
    const res = probeAICodeSmells([]);
    expect(Array.isArray(res)).toBe(true);
    expect(res).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// 7. Edge cases the spec does not pin down
// ---------------------------------------------------------------------------

describe('edge cases the spec does not pin down', () => {
  // EDGE: spec says "no body other than whitespace or a comment". An empty
  // statement `;` is neither, so firing or not firing are both defensible.
  // We only assert the probe handles it without crashing.
  it('handles a catch whose body is a lone empty statement', () => {
    const res = run(
      mk('src/lib/edge-semicolon.js', [
        'function tick(clock) {',
        '  try {',
        '    clock.advance();',
        '  } catch (e) { ; }',
        '}',
      ])
    );
    expect(Array.isArray(res)).toBe(true);
  });

  // EDGE: spec scopes `: any` to "function parameters". A variable
  // annotation is outside that scope; the spec does not say either way.
  it('handles a variable annotated any without asserting a verdict', () => {
    const res = run(
      mk('src/lib/edge-var.ts', [
        'let cache: any = null;',
        'export function warm(v: CacheSeed) {',
        '  cache = v;',
        '}',
      ])
    );
    expect(Array.isArray(res)).toBe(true);
  });

  // EDGE: an empty promise rejection handler `.catch(() => {})` swallows
  // errors the same way, but the spec only documents try/catch shapes.
  it('handles an empty promise .catch handler without asserting a verdict', () => {
    const res = run(
      mk('src/lib/edge-promise.js', [
        'export function fire(url) {',
        '  fetch(url).catch(() => {});',
        '}',
      ])
    );
    expect(Array.isArray(res)).toBe(true);
  });

  // EDGE: spec says `: any` "in TypeScript". Whether the probe also matches
  // the shape in a .js file (where it is not valid syntax) is not pinned.
  it('handles a .js file containing a `: any`-shaped token without crashing', () => {
    const res = run(
      mk('src/lib/edge-js-any.js', [
        'const routeTable = { kind: anyRouteDefault };',
        'export function route(k) {',
        '  return routeTable[k];',
        '}',
      ])
    );
    expect(Array.isArray(res)).toBe(true);
  });

  // EDGE: spec scopes to parameters; a return type of any is a different
  // position. Not pinned down, so no verdict asserted.
  it('handles an any return type without asserting a verdict', () => {
    const res = run(
      mk('src/lib/edge-return.ts', [
        'export function loadRaw(key: string): any {',
        '  return store.get(key);',
        '}',
      ])
    );
    expect(Array.isArray(res)).toBe(true);
  });
});
