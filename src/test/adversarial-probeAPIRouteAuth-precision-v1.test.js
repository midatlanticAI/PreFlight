// Precision (false-positive) tests for `probeAPIRouteAuth`.
//
// Goal: assert ZERO findings on realistic API-route-shaped inputs that look
// risky on a skim but are not actual missing-auth bugs. Adversarial-precision
// counterpart to the recall suite. Public-by-design endpoints, routes that
// DO have an auth check (in many idiomatic forms), middleware-protected
// routes, webhook signature verification, OAuth callbacks, docs/fixtures,
// static-export targets, and CORS preflight handlers should all pass clean.
//
// Tolerant assertions are used on genuinely AMBIGUOUS shapes (test fixtures
// inside source trees, // TODO: add auth scaffolds) where either zero or a
// low-severity advisory is defensible.

import { describe, it, expect } from 'vitest';
import { probeAPIRouteAuth } from '../lib/probes.js';

const run = (files) => probeAPIRouteAuth(files);

// Filter to findings this probe actually owns. Used as a defensive guard
// in case the probe ever returns findings from a different family.
const apiAuthFindings = (findings) =>
  (findings || []).filter((f) => {
    const blob =
      `${f?.probe || ''} ${f?.id || ''} ${f?.title || ''} ${f?.category || ''}`.toLowerCase();
    return blob.includes('api') || blob.includes('auth') || blob.includes('route');
  });

describe('probeAPIRouteAuth — precision (public-read-only GET handlers)', () => {
  it('does not fire on app/api/health/route.ts returning { ok: true }', () => {
    const file = {
      path: 'app/api/health/route.ts',
      content: `
        export async function GET() {
          return Response.json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on pages/api/version.ts returning build hash', () => {
    const file = {
      path: 'pages/api/version.ts',
      content: `
        import type { NextApiRequest, NextApiResponse } from 'next';
        export default function handler(_req: NextApiRequest, res: NextApiResponse) {
          res.status(200).json({ version: process.env.BUILD_HASH ?? 'dev' });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on /api/sitemap.xml.ts returning a sitemap', () => {
    const file = {
      path: 'pages/api/sitemap.xml.ts',
      content: `
        export default function handler(_req, res) {
          res.setHeader('Content-Type', 'application/xml');
          res.status(200).send('<?xml version="1.0"?><urlset></urlset>');
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on app/api/robots/route.ts returning robots.txt', () => {
    const file = {
      path: 'app/api/robots/route.ts',
      content: `
        export async function GET() {
          return new Response('User-agent: *\\nAllow: /', {
            headers: { 'Content-Type': 'text/plain' },
          });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a marketing /api/og GET returning a generated card', () => {
    const file = {
      path: 'app/api/og/route.tsx',
      content: `
        import { ImageResponse } from 'next/og';
        export const runtime = 'edge';
        export async function GET() {
          return new ImageResponse(<div>preflight</div>, { width: 1200, height: 630 });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (routes WITH explicit auth check)', () => {
  it('does not fire when the handler uses getServerSession(authOptions)', () => {
    const file = {
      path: 'app/api/users/[id]/route.ts',
      content: `
        import { getServerSession } from 'next-auth';
        import { authOptions } from '@/lib/auth';
        export async function DELETE(req: Request, { params }: { params: { id: string } }) {
          const session = await getServerSession(authOptions);
          if (!session) return new Response('Unauthorized', { status: 401 });
          await db.users.delete({ where: { id: params.id } });
          return new Response(null, { status: 204 });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire when the handler uses await auth() (Auth.js v5)', () => {
    const file = {
      path: 'app/api/posts/[id]/route.ts',
      content: `
        import { auth } from '@/auth';
        export async function PATCH(req: Request, { params }) {
          const session = await auth();
          if (!session?.user) return new Response('Unauthorized', { status: 401 });
          const body = await req.json();
          await db.posts.update({ where: { id: params.id }, data: body });
          return Response.json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire when the handler uses a requireAuth(req) helper', () => {
    const file = {
      path: 'app/api/billing/cancel/route.ts',
      content: `
        import { requireAuth } from '@/lib/auth';
        export async function POST(req: Request) {
          const user = await requireAuth(req);
          await billing.cancel(user.id);
          return Response.json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire when the handler uses passport.authenticate("jwt")', () => {
    const file = {
      path: 'server/routes/profile.ts',
      content: `
        import express from 'express';
        import passport from 'passport';
        const router = express.Router();
        router.put(
          '/profile',
          passport.authenticate('jwt', { session: false }),
          async (req, res) => {
            await db.profile.update({ where: { id: req.user.id }, data: req.body });
            res.json({ ok: true });
          }
        );
        export default router;
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire when the handler uses Clerk auth() in a Next route', () => {
    const file = {
      path: 'app/api/orders/route.ts',
      content: `
        import { auth } from '@clerk/nextjs/server';
        export async function DELETE(req: Request) {
          const { userId } = auth();
          if (!userId) return new Response('Unauthorized', { status: 401 });
          await db.orders.deleteMany({ where: { userId } });
          return new Response(null, { status: 204 });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire when the handler uses Supabase getUser()', () => {
    const file = {
      path: 'app/api/notes/[id]/route.ts',
      content: `
        import { createRouteHandlerClient } from '@supabase/auth-helpers-nextjs';
        import { cookies } from 'next/headers';
        export async function PUT(req: Request, { params }) {
          const supabase = createRouteHandlerClient({ cookies });
          const { data: { user } } = await supabase.auth.getUser();
          if (!user) return new Response('Unauthorized', { status: 401 });
          await db.notes.update({ where: { id: params.id, userId: user.id }, data: await req.json() });
          return Response.json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on jwt.verify(token, secret) (2-arg, recognized as legitimate)', () => {
    const file = {
      path: 'pages/api/account.ts',
      content: `
        import jwt from 'jsonwebtoken';
        export default async function handler(req, res) {
          const token = req.headers.authorization?.split(' ')[1];
          const payload = jwt.verify(token, process.env.JWT_SECRET);
          if (!payload) return res.status(401).end();
          if (req.method === 'DELETE') {
            await db.users.delete({ where: { id: payload.sub } });
            return res.status(204).end();
          }
          return res.status(405).end();
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (middleware-level auth)', () => {
  it('does not fire on a route relying on top-level middleware.ts matcher', () => {
    const middleware = {
      path: 'middleware.ts',
      content: `
        import { NextResponse } from 'next/server';
        import { auth } from '@/auth';
        export default auth((req) => {
          if (!req.auth) return NextResponse.redirect(new URL('/signin', req.url));
        });
        export const config = { matcher: ['/api/:path*'] };
      `,
    };
    const route = {
      path: 'app/api/projects/[id]/route.ts',
      content: `
        export async function DELETE(req, { params }) {
          await db.projects.delete({ where: { id: params.id } });
          return new Response(null, { status: 204 });
        }
      `,
    };
    expect(apiAuthFindings(run([middleware, route]))).toEqual([]);
  });

  it('does not fire when middleware uses clerkMiddleware() guarding /api/:path*', () => {
    const middleware = {
      path: 'middleware.ts',
      content: `
        import { clerkMiddleware } from '@clerk/nextjs/server';
        export default clerkMiddleware();
        export const config = { matcher: ['/api/:path*'] };
      `,
    };
    const route = {
      path: 'app/api/teams/[id]/route.ts',
      content: `
        export async function PATCH(req, { params }) {
          const body = await req.json();
          await db.teams.update({ where: { id: params.id }, data: body });
          return Response.json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([middleware, route]))).toEqual([]);
  });

  it('does not fire when Express attaches authMiddleware app-wide', () => {
    const server = {
      path: 'server/index.ts',
      content: `
        import express from 'express';
        import { authMiddleware } from './auth';
        const app = express();
        app.use('/api', authMiddleware);
        app.use('/api/users', usersRouter);
        export default app;
      `,
    };
    const route = {
      path: 'server/routes/users.ts',
      content: `
        import { Router } from 'express';
        const router = Router();
        router.delete('/:id', async (req, res) => {
          await db.users.delete({ where: { id: req.params.id } });
          res.status(204).end();
        });
        export default router;
      `,
    };
    expect(apiAuthFindings(run([server, route]))).toEqual([]);
  });

  it('does not fire when a Hono app uses .use("*", jwt({secret})) before routes', () => {
    const file = {
      path: 'server/api.ts',
      content: `
        import { Hono } from 'hono';
        import { jwt } from 'hono/jwt';
        const app = new Hono();
        app.use('*', jwt({ secret: process.env.JWT_SECRET! }));
        app.delete('/items/:id', async (c) => {
          await db.items.delete({ where: { id: c.req.param('id') } });
          return c.body(null, 204);
        });
        export default app;
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (documentation files)', () => {
  it('does not fire on a README that shows insecure and secure handler shapes', () => {
    const file = {
      path: 'README.md',
      content: `
# API routes

A bad example:

\`\`\`ts
// app/api/users/[id]/route.ts
export async function DELETE(req, { params }) {
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
\`\`\`

A good example:

\`\`\`ts
export async function DELETE(req, { params }) {
  const session = await getServerSession();
  if (!session) return new Response('Unauthorized', { status: 401 });
  await db.users.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
\`\`\`
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a Learn pattern markdown showing insecure code blocks', () => {
    const file = {
      path: 'src/learn/patterns/api-route-auth.md',
      content: `
---
title: API routes without server-side auth
slug: api-route-auth
---

\`\`\`ts
export async function POST(req) {
  const { userId } = await req.json();
  await db.users.update({ where: { id: userId }, data: { role: 'admin' } });
  return Response.json({ ok: true });
}
\`\`\`
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a CHANGELOG entry quoting a handler snippet', () => {
    const file = {
      path: 'CHANGELOG.md',
      content: `
## 0.4.0
- Added auth check to \`app/api/admin/promote/route.ts\`. Previously:

\`\`\`ts
export async function POST(req) {
  const { userId } = await req.json();
  await db.users.update({ where: { id: userId }, data: { role: 'admin' } });
  return Response.json({ ok: true });
}
\`\`\`
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on docs/architecture writeup describing route patterns', () => {
    const file = {
      path: 'docs/api-architecture.md',
      content: `
        The shape we follow:

        \`\`\`ts
        // app/api/foo/route.ts
        export async function DELETE() {
          // implementation
        }
        \`\`\`

        See middleware.ts for the auth wrapper.
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (webhook receivers)', () => {
  it('does not fire on a Stripe webhook that verifies the signature', () => {
    const file = {
      path: 'app/api/webhooks/stripe/route.ts',
      content: `
        import Stripe from 'stripe';
        const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
        export async function POST(req: Request) {
          const sig = req.headers.get('stripe-signature')!;
          const body = await req.text();
          let event;
          try {
            event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
          } catch {
            return new Response('Bad signature', { status: 400 });
          }
          switch (event.type) {
            case 'checkout.session.completed':
              await fulfillOrder(event.data.object);
              break;
          }
          return new Response(null, { status: 204 });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a GitHub webhook that verifies HMAC SHA-256', () => {
    const file = {
      path: 'app/api/webhooks/github/route.ts',
      content: `
        import crypto from 'crypto';
        export async function POST(req: Request) {
          const sig = req.headers.get('x-hub-signature-256') ?? '';
          const body = await req.text();
          const mac = crypto
            .createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!)
            .update(body)
            .digest('hex');
          if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from('sha256=' + mac))) {
            return new Response('Bad signature', { status: 401 });
          }
          // process event
          return new Response(null, { status: 204 });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a Slack webhook receiver verifying X-Slack-Signature', () => {
    const file = {
      path: 'pages/api/webhooks/slack.ts',
      content: `
        import crypto from 'crypto';
        export default async function handler(req, res) {
          const ts = req.headers['x-slack-request-timestamp'];
          const sig = req.headers['x-slack-signature'];
          const base = 'v0:' + ts + ':' + req.rawBody;
          const mac = 'v0=' + crypto
            .createHmac('sha256', process.env.SLACK_SIGNING_SECRET)
            .update(base)
            .digest('hex');
          if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(mac))) {
            return res.status(401).end();
          }
          res.status(200).json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a Svix-verified webhook', () => {
    const file = {
      path: 'app/api/webhooks/clerk/route.ts',
      content: `
        import { Webhook } from 'svix';
        export async function POST(req: Request) {
          const headers = Object.fromEntries(req.headers);
          const body = await req.text();
          const wh = new Webhook(process.env.CLERK_WEBHOOK_SECRET!);
          try {
            wh.verify(body, headers);
          } catch {
            return new Response('Bad signature', { status: 400 });
          }
          return new Response(null, { status: 204 });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (public OAuth callbacks)', () => {
  it('does not fire on NextAuth catch-all callback handler', () => {
    const file = {
      path: 'app/api/auth/[...nextauth]/route.ts',
      content: `
        import NextAuth from 'next-auth';
        import { authOptions } from '@/lib/auth';
        const handler = NextAuth(authOptions);
        export { handler as GET, handler as POST };
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on app/api/auth/callback/google/route.ts', () => {
    const file = {
      path: 'app/api/auth/callback/google/route.ts',
      content: `
        export async function GET(req: Request) {
          const url = new URL(req.url);
          const code = url.searchParams.get('code');
          if (!code) return new Response('Missing code', { status: 400 });
          const token = await exchangeCodeForToken(code);
          await createSession(token);
          return Response.redirect(new URL('/dashboard', req.url));
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on Supabase auth callback exchanging the code', () => {
    const file = {
      path: 'app/auth/callback/route.ts',
      content: `
        import { createRouteHandlerClient } from '@supabase/auth-helpers-nextjs';
        import { cookies } from 'next/headers';
        export async function GET(req: Request) {
          const code = new URL(req.url).searchParams.get('code');
          if (code) {
            const supabase = createRouteHandlerClient({ cookies });
            await supabase.auth.exchangeCodeForSession(code);
          }
          return Response.redirect(new URL('/', req.url));
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (static-export routes)', () => {
  it('does not fire on a route in a project with next.config.js output: "export"', () => {
    const nextConfig = {
      path: 'next.config.js',
      content: `
        /** @type {import('next').NextConfig} */
        const nextConfig = { output: 'export' };
        export default nextConfig;
      `,
    };
    const route = {
      path: 'app/api/data/route.ts',
      content: `
        export const dynamic = 'force-static';
        export async function GET() {
          return Response.json({ items: [] });
        }
      `,
    };
    expect(apiAuthFindings(run([nextConfig, route]))).toEqual([]);
  });

  it('does not fire on a route with export const dynamic = "force-static"', () => {
    const file = {
      path: 'app/api/featured/route.ts',
      content: `
        export const dynamic = 'force-static';
        export async function GET() {
          return Response.json({ featured: [] });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on getStaticProps-style pages exporter (no real server)', () => {
    const file = {
      path: 'pages/api/static.ts',
      content: `
        // Project uses next export — these handlers compile out at build time.
        export const config = { runtime: 'edge' };
        export default function handler(_req, res) {
          res.status(200).json({ ok: true });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (CORS preflight OPTIONS handlers)', () => {
  it('does not fire on a standalone OPTIONS handler returning CORS headers', () => {
    const file = {
      path: 'app/api/messages/route.ts',
      content: `
        export async function OPTIONS() {
          return new Response(null, {
            status: 204,
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
              'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            },
          });
        }
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on an Express-style app.options("*") preflight responder', () => {
    const file = {
      path: 'server/cors.ts',
      content: `
        import express from 'express';
        const app = express();
        app.options('*', (req, res) => {
          res.set('Access-Control-Allow-Origin', '*');
          res.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
          res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          res.status(204).end();
        });
        export default app;
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });

  it('does not fire on a Hono OPTIONS preflight handler', () => {
    const file = {
      path: 'server/cors-hono.ts',
      content: `
        import { Hono } from 'hono';
        const app = new Hono();
        app.options('*', (c) => {
          c.header('Access-Control-Allow-Origin', '*');
          c.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
          c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
          return c.body(null, 204);
        });
        export default app;
      `,
    };
    expect(apiAuthFindings(run([file]))).toEqual([]);
  });
});

describe('probeAPIRouteAuth — precision (test fixtures)', () => {
  // AMBIGUOUS: fixtures sometimes intentionally contain the bad shape so a
  // test can assert the probe catches it. Excluding them entirely is the
  // common precision posture, but a low-severity advisory would also be
  // defensible. Use a tolerant assertion: at most informational, never high.
  const tolerant = (findings) => {
    const owned = apiAuthFindings(findings);
    for (const f of owned) {
      const sev = String(f?.severity || '').toLowerCase();
      expect(['', 'info', 'informational', 'low']).toContain(sev);
    }
  };

  it('does not fire (or fires tolerantly) on files under __tests__/', () => {
    const file = {
      path: '__tests__/api/users.test.ts',
      content: `
        import { DELETE } from '@/app/api/users/[id]/route';
        // Fixture handler used by the test below; intentionally bare.
        async function exampleHandler(req, { params }) {
          await db.users.delete({ where: { id: params.id } });
          return new Response(null, { status: 204 });
        }
        test('DELETE removes the user', async () => {
          const res = await exampleHandler(new Request('http://x'), { params: { id: '1' } });
          expect(res.status).toBe(204);
        });
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });

  it('does not fire (or fires tolerantly) on files under tests/fixtures/', () => {
    const file = {
      path: 'tests/fixtures/bare-delete-handler.ts',
      content: `
        export async function DELETE(req, { params }) {
          await db.things.delete({ where: { id: params.id } });
          return new Response(null, { status: 204 });
        }
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });

  it('does not fire (or fires tolerantly) on *.test.ts files containing example handlers', () => {
    const file = {
      path: 'app/api/admin/promote/route.test.ts',
      content: `
        // Intentionally insecure fixture inlined into the test file to assert
        // the probe catches the real route. Not deployed.
        const fixture = \`
          export async function POST(req) {
            const { userId } = await req.json();
            await db.users.update({ where: { id: userId }, data: { role: 'admin' } });
            return Response.json({ ok: true });
          }
        \`;
        test('matches the bad shape', () => {
          expect(fixture).toContain('admin');
        });
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });

  it('does not fire (or fires tolerantly) on a vitest mock under src/test/', () => {
    const file = {
      path: 'src/test/mocks/handler-fixtures.ts',
      content: `
        export const insecureDelete = \`
          export async function DELETE() { return new Response(null, { status: 204 }); }
        \`;
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });
});

describe('probeAPIRouteAuth — precision (comment-only auth scaffolds)', () => {
  // AMBIGUOUS: a TODO comment is not an actual auth check. The probe could
  // reasonably either fire (it's still missing auth at runtime) or stay
  // quiet (the developer has flagged it). We tolerate either as long as the
  // severity is not high+ — a TODO is at most a low-confidence advisory.
  const tolerant = (findings) => {
    const owned = apiAuthFindings(findings);
    for (const f of owned) {
      const sev = String(f?.severity || '').toLowerCase();
      expect(['', 'info', 'informational', 'low', 'medium']).toContain(sev);
    }
  };

  it('TODO-add-auth scaffold on DELETE: tolerant', () => {
    const file = {
      path: 'app/api/things/[id]/route.ts',
      content: `
        export async function DELETE(req, { params }) {
          // TODO: add auth before shipping
          await db.things.delete({ where: { id: params.id } });
          return new Response(null, { status: 204 });
        }
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });

  it('FIXME-auth scaffold on PATCH: tolerant', () => {
    const file = {
      path: 'app/api/things/[id]/route.ts',
      content: `
        export async function PATCH(req, { params }) {
          // FIXME(auth): wire requireAuth(req) before launch
          const body = await req.json();
          await db.things.update({ where: { id: params.id }, data: body });
          return Response.json({ ok: true });
        }
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });

  it('XXX-auth-missing scaffold: tolerant', () => {
    const file = {
      path: 'pages/api/things.ts',
      content: `
        export default async function handler(req, res) {
          // XXX: auth missing — gated by Cloudflare Access in prod
          if (req.method === 'PUT') {
            await db.things.update({ where: { id: req.query.id }, data: req.body });
            return res.status(200).json({ ok: true });
          }
          res.status(405).end();
        }
      `,
    };
    // AMBIGUOUS: tolerant
    tolerant(run([file]));
  });
});

describe('probeAPIRouteAuth — precision (smoke: returns an array)', () => {
  it('returns an array even for an empty input', () => {
    expect(Array.isArray(run([]))).toBe(true);
  });

  it('returns an array for a single non-API file', () => {
    const file = {
      path: 'src/components/Button.tsx',
      content: `export const Button = () => <button>click</button>;`,
    };
    expect(Array.isArray(run([file]))).toBe(true);
  });
});
