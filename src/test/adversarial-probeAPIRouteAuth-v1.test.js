// Adversarial RECALL test suite for probeAPIRouteAuth.
//
// Goal: produce realistic API-route-without-auth-check shapes that resemble
// AI-generated code and assert that probeAPIRouteAuth FLAGS them.
//
// Contract assumed from src/learn/patterns/api-route-auth.md:
//   - Destructive HTTP methods (DELETE/PUT/PATCH) with no auth function call
//   - admin/dashboard/internal paths with no auth function call
//   - jwt.verify(token) single-arg counted as NOT real auth
//
// Probe signature (per task spec):
//   probeAPIRouteAuth([{ path, content }]) -> Finding[]
//
// Each test pushes a single realistic vulnerable shape through the probe and
// asserts the result is a non-empty Finding[]. We deliberately keep file
// PATHS conventional (app/api/.../route.ts, pages/api/*.ts, +server.ts, etc.)
// because real codebases organize them this way and the probe likely uses
// path heuristics in addition to body content.
//
// AMBIGUITIES (documented in-line where they apply):
//   - We do NOT know whether the probe reads file path for framework hints,
//     so each test uses the framework's canonical path layout. If a probe
//     only inspects body content, the tests with admin/payments/etc. paths
//     should still trip via path + destructive-method heuristics.
//   - We do NOT know whether the probe recognizes the SvelteKit `locals.user`
//     check or Hono `c.get('user')` etc. as auth. Vulnerable tests omit those.
//   - We do NOT know how the probe handles JS vs TS extensions; tests cover
//     both .ts and .js to be safe.
//   - The probe may or may not treat handler-less files (e.g., utility files
//     at api/* paths) as routes. We only test actual handler shapes.

import { describe, it, expect } from 'vitest';
import { probeAPIRouteAuth } from '../lib/probes.js';

// Helper: tighten the assertion. A finding shows the probe correctly recalled
// the missing-auth shape. We don't assert on severity / message — recall only.
function expectDetected(files) {
  const findings = probeAPIRouteAuth(files);
  expect(Array.isArray(findings)).toBe(true);
  expect(findings.length).toBeGreaterThan(0);
  return findings;
}

// ---------------------------------------------------------------------------
// Category 1 — Next.js App Router (weighted heavy)
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Next.js App Router', () => {
  it('flags app/api/users/route.ts POST with no auth at all', () => {
    expectDetected([
      {
        path: 'app/api/users/route.ts',
        content: `
import { db } from '@/lib/db';

export async function POST(req: Request) {
  const body = await req.json();
  const user = await db.users.create({ data: body });
  return Response.json(user);
}
`,
      },
    ]);
  });

  it('flags app/api/users/[id]/route.ts DELETE with no auth', () => {
    expectDetected([
      {
        path: 'app/api/users/[id]/route.ts',
        content: `
import { db } from '@/lib/db';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });

  it('flags app/api/users/[id]/route.ts PATCH with no auth', () => {
    expectDetected([
      {
        path: 'app/api/users/[id]/route.ts',
        content: `
import { db } from '@/lib/db';

export async function PATCH(req: Request, { params }: { params: { id: string } }) {
  const body = await req.json();
  await db.users.update({ where: { id: params.id }, data: body });
  return Response.json({ ok: true });
}
`,
      },
    ]);
  });

  it('flags app/api/users/[id]/route.ts PUT with no auth', () => {
    expectDetected([
      {
        path: 'app/api/users/[id]/route.ts',
        content: `
export async function PUT(req: Request, { params }: { params: { id: string } }) {
  const body = await req.json();
  await db.users.update({ where: { id: params.id }, data: body });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });

  it('flags app/api/posts/route.ts with multiple destructive handlers and no auth', () => {
    expectDetected([
      {
        path: 'app/api/posts/route.ts',
        content: `
export async function POST(req: Request) {
  const data = await req.json();
  return Response.json(await db.posts.create({ data }));
}

export async function DELETE(req: Request) {
  const { id } = await req.json();
  await db.posts.delete({ where: { id } });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });

  it('flags app/api/admin/promote/route.ts POST — privilege escalation, no auth', () => {
    // From the Learn pattern doc verbatim shape.
    expectDetected([
      {
        path: 'app/api/admin/promote/route.ts',
        content: `
export async function POST(req: Request) {
  const { userId } = await req.json();
  await db.users.update({ where: { id: userId }, data: { role: 'admin' } });
  return Response.json({ ok: true });
}
`,
      },
    ]);
  });

  it('flags App Router handler whose ONLY "auth" is jwt.verify(token) single-arg', () => {
    // Per pattern doc: single-arg jwt.verify is treated as NOT real auth.
    expectDetected([
      {
        path: 'app/api/users/[id]/route.ts',
        content: `
import jwt from 'jsonwebtoken';

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const token = req.headers.get('authorization')?.split(' ')[1] ?? '';
  const decoded = jwt.verify(token); // no secret — decorative
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });

  it('flags App Router with TODO comment instead of auth', () => {
    expectDetected([
      {
        path: 'app/api/orders/route.ts',
        content: `
export async function POST(req: Request) {
  // TODO: add auth before launch
  const body = await req.json();
  await db.orders.create({ data: body });
  return Response.json({ ok: true });
}
`,
      },
    ]);
  });

  it('flags App Router .js (not .ts) variant', () => {
    expectDetected([
      {
        path: 'app/api/comments/route.js',
        content: `
export async function DELETE(req) {
  const { id } = await req.json();
  await db.comments.delete({ where: { id } });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 2 — Next.js Pages Router (weighted heavy)
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Next.js Pages Router', () => {
  it('flags pages/api/users.ts handler with no session check', () => {
    expectDetected([
      {
        path: 'pages/api/users.ts',
        content: `
import type { NextApiRequest, NextApiResponse } from 'next';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    const user = await db.users.create({ data: req.body });
    return res.json(user);
  }
  if (req.method === 'DELETE') {
    await db.users.delete({ where: { id: req.body.id } });
    return res.status(204).end();
  }
  res.status(405).end();
}
`,
      },
    ]);
  });

  it('flags pages/api/admin/promote.ts with no auth (admin path)', () => {
    expectDetected([
      {
        path: 'pages/api/admin/promote.ts',
        content: `
export default async function handler(req, res) {
  const { userId } = req.body;
  await db.users.update({ where: { id: userId }, data: { role: 'admin' } });
  res.json({ ok: true });
}
`,
      },
    ]);
  });

  it('flags pages/api/users/[id].ts DELETE-only handler', () => {
    expectDetected([
      {
        path: 'pages/api/users/[id].ts',
        content: `
export default async function handler(req, res) {
  if (req.method !== 'DELETE') return res.status(405).end();
  await db.users.delete({ where: { id: req.query.id } });
  return res.status(204).end();
}
`,
      },
    ]);
  });

  it('flags pages/api/posts/[id].ts PUT-only update', () => {
    expectDetected([
      {
        path: 'pages/api/posts/[id].ts',
        content: `
export default async function handler(req, res) {
  if (req.method !== 'PUT') return res.status(405).end();
  await db.posts.update({ where: { id: req.query.id }, data: req.body });
  return res.json({ ok: true });
}
`,
      },
    ]);
  });

  it('flags pages/api/dashboard/stats.ts that reads sensitive aggregate with no auth', () => {
    expectDetected([
      {
        path: 'pages/api/dashboard/stats.ts',
        content: `
export default async function handler(req, res) {
  const revenue = await db.orders.sum({ field: 'amount' });
  const users = await db.users.count();
  res.json({ revenue, users });
}
`,
      },
    ]);
  });

  it('flags Pages Router with single-arg jwt.verify masquerading as auth', () => {
    expectDetected([
      {
        path: 'pages/api/users/[id].ts',
        content: `
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
  const token = (req.headers.authorization ?? '').replace('Bearer ', '');
  jwt.verify(token); // looks like auth, isn't
  if (req.method === 'PATCH') {
    await db.users.update({ where: { id: req.query.id }, data: req.body });
    return res.json({ ok: true });
  }
  res.status(405).end();
}
`,
      },
    ]);
  });

  it('flags pages/api/internal/sync.ts with no auth (internal path)', () => {
    expectDetected([
      {
        path: 'pages/api/internal/sync.ts',
        content: `
export default async function handler(req, res) {
  await db.cache.flush();
  await db.queue.replay();
  res.json({ replayed: true });
}
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 3 — Express (weighted heavy)
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Express handlers', () => {
  it('flags app.post(/api/admin, ...) with no requireAuth', () => {
    expectDetected([
      {
        path: 'server/routes/admin.js',
        content: `
const express = require('express');
const app = express();

app.post('/api/admin', (req, res) => {
  db.delete(req.body.id);
  res.json({ ok: true });
});
`,
      },
    ]);
  });

  it('flags app.delete(/api/users/:id, ...) with no auth middleware', () => {
    expectDetected([
      {
        path: 'server/routes/users.js',
        content: `
app.delete('/api/users/:id', async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } });
  res.status(204).end();
});
`,
      },
    ]);
  });

  it('flags app.put(/api/posts/:id, ...) update with no auth', () => {
    expectDetected([
      {
        path: 'server/routes/posts.js',
        content: `
app.put('/api/posts/:id', async (req, res) => {
  await db.posts.update({ where: { id: req.params.id }, data: req.body });
  res.json({ ok: true });
});
`,
      },
    ]);
  });

  it('flags router.delete on an admin-prefixed route with no requireAuth', () => {
    expectDetected([
      {
        path: 'server/routes/admin.js',
        content: `
const router = require('express').Router();

router.delete('/admin/users/:id', async (req, res) => {
  await db.users.delete({ where: { id: req.params.id } });
  res.status(204).end();
});

module.exports = router;
`,
      },
    ]);
  });

  it('flags Express app.patch with single-arg jwt.verify only', () => {
    expectDetected([
      {
        path: 'server/routes/profile.js',
        content: `
const jwt = require('jsonwebtoken');

app.patch('/api/profile', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  jwt.verify(token); // single-arg, not real
  db.users.update({ where: { id: req.body.id }, data: req.body });
  res.json({ ok: true });
});
`,
      },
    ]);
  });

  it('flags Express POST handler under /api/admin/* with no requireAuth and no passport.authenticate', () => {
    expectDetected([
      {
        path: 'server/routes/admin.js',
        content: `
app.post('/api/admin/promote', (req, res) => {
  db.users.update({ where: { id: req.body.userId }, data: { role: 'admin' } });
  res.json({ promoted: true });
});
`,
      },
    ]);
  });

  it('flags Express handler with no auth and inline destructive db op', () => {
    expectDetected([
      {
        path: 'server/index.js',
        content: `
app.delete('/api/projects/:id', (req, res) => {
  db.projects.delete({ where: { id: req.params.id } });
  db.tasks.deleteMany({ where: { projectId: req.params.id } });
  res.status(204).end();
});
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 4 — Fastify
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Fastify', () => {
  it('flags fastify.post(/api/v2/payments, ...) without onRequest auth hook', () => {
    expectDetected([
      {
        path: 'server/routes/payments.ts',
        content: `
fastify.post('/api/v2/payments', async (req, reply) => {
  const charge = await stripe.charges.create(req.body);
  await db.payments.create({ data: charge });
  return charge;
});
`,
      },
    ]);
  });

  it('flags fastify.delete(/api/users/:id, ...) without preHandler', () => {
    expectDetected([
      {
        path: 'server/routes/users.ts',
        content: `
fastify.delete('/api/users/:id', async (req) => {
  await db.users.delete({ where: { id: req.params.id } });
  return { ok: true };
});
`,
      },
    ]);
  });

  it('flags fastify.patch on admin path without preHandler', () => {
    expectDetected([
      {
        path: 'server/routes/admin.ts',
        content: `
fastify.patch('/api/admin/users/:id', async (req) => {
  await db.users.update({ where: { id: req.params.id }, data: req.body });
  return { ok: true };
});
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 5 — SvelteKit endpoints
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: SvelteKit endpoints', () => {
  it('flags +server.ts POST that never touches locals.user', () => {
    expectDetected([
      {
        path: 'src/routes/api/users/+server.ts',
        content: `
import { json } from '@sveltejs/kit';

export async function POST({ request }) {
  const body = await request.json();
  const user = await db.users.create({ data: body });
  return json(user);
}
`,
      },
    ]);
  });

  it('flags +server.ts DELETE with no locals/auth check', () => {
    expectDetected([
      {
        path: 'src/routes/api/users/[id]/+server.ts',
        content: `
export async function DELETE({ params }) {
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });

  it('flags +server.ts PATCH on admin path with no locals check', () => {
    expectDetected([
      {
        path: 'src/routes/api/admin/users/[id]/+server.ts',
        content: `
import { json } from '@sveltejs/kit';

export async function PATCH({ params, request }) {
  const body = await request.json();
  await db.users.update({ where: { id: params.id }, data: body });
  return json({ ok: true });
}
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 6 — Astro endpoints
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Astro endpoints', () => {
  it('flags Astro pages/api POST endpoint with no locals.user check', () => {
    expectDetected([
      {
        path: 'src/pages/api/users.ts',
        content: `
import type { APIRoute } from 'astro';

export const POST: APIRoute = async ({ request }) => {
  const body = await request.json();
  await db.users.create({ data: body });
  return new Response(JSON.stringify({ ok: true }));
};
`,
      },
    ]);
  });

  it('flags Astro pages/api DELETE endpoint with no locals.user check', () => {
    expectDetected([
      {
        path: 'src/pages/api/users/[id].ts',
        content: `
import type { APIRoute } from 'astro';

export const DELETE: APIRoute = async ({ params }) => {
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
};
`,
      },
    ]);
  });

  it('flags Astro PATCH endpoint on admin path with no locals.user check', () => {
    expectDetected([
      {
        path: 'src/pages/api/admin/users/[id].ts',
        content: `
export const PATCH = async ({ params, request }) => {
  const body = await request.json();
  await db.users.update({ where: { id: params.id }, data: body });
  return new Response(JSON.stringify({ ok: true }));
};
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 7 — Hono
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Hono', () => {
  it('flags app.delete(/users/:id) with no jwt() middleware or auth import', () => {
    expectDetected([
      {
        path: 'src/server/routes.ts',
        content: `
import { Hono } from 'hono';

const app = new Hono();

app.delete('/users/:id', async (c) => {
  await db.users.delete({ where: { id: c.req.param('id') } });
  return c.json({ ok: true });
});
`,
      },
    ]);
  });

  it('flags app.post(/admin/promote) with no auth middleware', () => {
    expectDetected([
      {
        path: 'src/server/routes.ts',
        content: `
import { Hono } from 'hono';
const app = new Hono();

app.post('/admin/promote', async (c) => {
  const body = await c.req.json();
  await db.users.update({ where: { id: body.userId }, data: { role: 'admin' } });
  return c.json({ ok: true });
});
`,
      },
    ]);
  });

  it('flags app.patch(/users/:id) with single-arg jwt.verify decoration', () => {
    expectDetected([
      {
        path: 'src/server/routes.ts',
        content: `
import { Hono } from 'hono';
import jwt from 'jsonwebtoken';
const app = new Hono();

app.patch('/users/:id', async (c) => {
  const token = c.req.header('authorization')?.replace('Bearer ', '') ?? '';
  jwt.verify(token); // single-arg
  const body = await c.req.json();
  await db.users.update({ where: { id: c.req.param('id') }, data: body });
  return c.json({ ok: true });
});
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 8 — Cloudflare Workers
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: Cloudflare Workers', () => {
  it('flags fetch handler POST with no Authorization header read', () => {
    expectDetected([
      {
        path: 'workers/api.ts',
        content: `
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'POST') {
      const body = await request.json();
      await env.DB.prepare('INSERT INTO users (data) VALUES (?)').bind(JSON.stringify(body)).run();
      return new Response('ok');
    }
    return new Response('method not allowed', { status: 405 });
  },
};
`,
      },
    ]);
  });

  it('flags fetch handler DELETE with no Authorization header read', () => {
    expectDetected([
      {
        path: 'workers/users.ts',
        content: `
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'DELETE') {
      const url = new URL(request.url);
      const id = url.pathname.split('/').pop();
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
      return new Response(null, { status: 204 });
    }
    return new Response('method not allowed', { status: 405 });
  },
};
`,
      },
    ]);
  });

  it('flags fetch handler PUT with no Authorization header read', () => {
    expectDetected([
      {
        path: 'workers/posts.ts',
        content: `
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'PUT') {
      const body = await request.json();
      const url = new URL(request.url);
      const id = url.pathname.split('/').pop();
      await env.DB.prepare('UPDATE posts SET body=? WHERE id=?').bind(body.text, id).run();
      return new Response('ok');
    }
    return new Response('method not allowed', { status: 405 });
  },
};
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 9 — Sensitive operation handlers (weighted heavy)
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: sensitive operation handlers', () => {
  it('flags app/api/admin/users/[id]/route.ts DELETE with no auth', () => {
    expectDetected([
      {
        path: 'app/api/admin/users/[id]/route.ts',
        content: `
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
`,
      },
    ]);
  });

  it('flags app/api/dashboard/billing/route.ts GET-style sensitive data with no auth', () => {
    // Dashboard path triggers per pattern doc even on non-destructive methods.
    expectDetected([
      {
        path: 'app/api/dashboard/billing/route.ts',
        content: `
export async function POST(req: Request) {
  const body = await req.json();
  await db.subscriptions.update({ where: { userId: body.userId }, data: body });
  return Response.json({ ok: true });
}
`,
      },
    ]);
  });

  it('flags app/api/checkout/route.ts payment endpoint with no auth', () => {
    expectDetected([
      {
        path: 'app/api/checkout/route.ts',
        content: `
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const { amount, customerId } = await req.json();
  const charge = await stripe.charges.create({ amount, customer: customerId });
  return Response.json(charge);
}
`,
      },
    ]);
  });

  it('flags pages/api/payments/refund.ts with no auth', () => {
    expectDetected([
      {
        path: 'pages/api/payments/refund.ts',
        content: `
export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();
  const refund = await stripe.refunds.create({ charge: req.body.chargeId });
  await db.refunds.create({ data: refund });
  res.json(refund);
}
`,
      },
    ]);
  });

  it('flags Express app.post(/admin/settings, ...) with no auth', () => {
    expectDetected([
      {
        path: 'server/routes/admin.js',
        content: `
app.post('/admin/settings', (req, res) => {
  db.settings.update({ where: { id: 'global' }, data: req.body });
  res.json({ ok: true });
});
`,
      },
    ]);
  });

  it('flags app/api/internal/migrate/route.ts POST with no auth', () => {
    expectDetected([
      {
        path: 'app/api/internal/migrate/route.ts',
        content: `
export async function POST(req: Request) {
  await db.$executeRaw\`ALTER TABLE users ADD COLUMN reset_token TEXT\`;
  return new Response('migrated', { status: 200 });
}
`,
      },
    ]);
  });

  it('flags app/api/admin/impersonate/route.ts POST with no auth', () => {
    expectDetected([
      {
        path: 'app/api/admin/impersonate/route.ts',
        content: `
export async function POST(req: Request) {
  const { targetUserId } = await req.json();
  const session = await db.sessions.create({ data: { userId: targetUserId } });
  return Response.json({ sessionToken: session.token });
}
`,
      },
    ]);
  });

  it('flags app/api/billing/cancel-subscription/route.ts POST with no auth', () => {
    expectDetected([
      {
        path: 'app/api/billing/cancel-subscription/route.ts',
        content: `
export async function POST(req: Request) {
  const { subscriptionId } = await req.json();
  await stripe.subscriptions.del(subscriptionId);
  await db.subscriptions.delete({ where: { id: subscriptionId } });
  return Response.json({ cancelled: true });
}
`,
      },
    ]);
  });
});

// ---------------------------------------------------------------------------
// Category 10 — GraphQL resolvers without context.user check
// ---------------------------------------------------------------------------

describe('probeAPIRouteAuth recall: GraphQL resolvers', () => {
  it('flags Mutation.deleteUser resolver with no context.user check', () => {
    // AMBIGUITY: probe may or may not parse GraphQL resolver maps. If not,
    // this test will fail; document and continue per task instructions.
    expectDetected([
      {
        path: 'server/graphql/resolvers.ts',
        content: `
export const resolvers = {
  Mutation: {
    deleteUser: (parent, args, context) => {
      return db.users.delete({ where: { id: args.id } });
    },
  },
};
`,
      },
    ]);
  });

  it('flags Mutation.promoteToAdmin resolver with no context.user check', () => {
    expectDetected([
      {
        path: 'server/graphql/resolvers.ts',
        content: `
export const resolvers = {
  Mutation: {
    promoteToAdmin: async (_parent, args) => {
      await db.users.update({ where: { id: args.userId }, data: { role: 'admin' } });
      return true;
    },
  },
};
`,
      },
    ]);
  });

  it('flags Mutation.refundOrder resolver with no context.user check', () => {
    expectDetected([
      {
        path: 'server/graphql/resolvers.ts',
        content: `
export const resolvers = {
  Mutation: {
    refundOrder: async (_parent, args, _ctx) => {
      const order = await db.orders.findUnique({ where: { id: args.orderId } });
      const refund = await stripe.refunds.create({ charge: order.chargeId });
      return refund;
    },
  },
};
`,
      },
    ]);
  });
});
