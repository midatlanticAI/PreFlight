// Supabase RLS, second phase: tables this code reads from the browser that
// nothing in the repo protects.
//
// The migration checks only ever ran on .sql files, which meant the probe said
// nothing about the population that actually gets breached. CVE-2025-48757
// found 170 of 1,645 Lovable showcase apps (10.3%) leaking PII through
// unprotected tables, and those apps mostly have no migrations in the repo at
// all: the schema was created by clicking around a dashboard. A probe named
// "Supabase RLS" returning zero on exactly those repos is not neutral. It
// reads as an all-clear.
//
// The risk running the other way is firing on every query builder with a
// .from() method, so the precision cases below carry as much weight as the
// recall ones. Knex is the specific hazard: same call shape, different world.

import { describe, it, expect } from 'vitest';
import { probeSupabaseRLS } from '../lib/probes/database.js';

const PKG = {
  path: 'package.json',
  content: JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2.45.0' } }),
};
const CLIENT = {
  path: 'src/lib/supabase.js',
  content: `import { createClient } from '@supabase/supabase-js';
export const supabase = createClient(import.meta.env.VITE_URL, import.meta.env.VITE_ANON_KEY);`,
};

const run = (files) =>
  probeSupabaseRLS(files).filter((f) => /nothing in this repo enables RLS/.test(f.title));

describe('client reads of tables with no RLS in the repo', () => {
  it('fires on the dashboard-schema case: queries, no migrations at all', () => {
    const found = run([
      PKG,
      CLIENT,
      {
        path: 'src/Profile.jsx',
        content: `import { supabase } from './lib/supabase';
export async function load() {
  const { data } = await supabase.from('profiles').select('*');
  return data;
}`,
      },
    ]);
    expect(found).toHaveLength(1);
    expect(found[0].title).toContain('profiles');
    expect(found[0].severity).toBe('high');
  });

  it('says so when the repo has migrations that simply do not protect the table', () => {
    const found = run([
      PKG,
      CLIENT,
      { path: 'supabase/migrations/001_init.sql', content: 'create table orders (id uuid);' },
      {
        path: 'src/Orders.jsx',
        content: `import { supabase } from './lib/supabase';
const { data } = await supabase.from('orders').select('id, total');`,
      },
    ]);
    expect(found).toHaveLength(1);
    expect(found[0].remediation).toMatch(/This repo has migrations/);
  });

  it('reports one finding per table, not one per query site', () => {
    const content = `import { supabase } from './lib/supabase';
export const a = () => supabase.from('profiles').select('*');
export const b = () => supabase.from('profiles').select('id');
export const c = () => supabase.from('profiles').update({ seen: true });`;
    expect(run([PKG, CLIENT, { path: 'src/many.js', content }])).toHaveLength(1);
  });

  it('covers writes as well as reads', () => {
    const found = run([
      PKG,
      CLIENT,
      {
        path: 'src/w.js',
        content: `import { supabase } from './lib/supabase';
await supabase.from('audit_log').insert({ event: 'x' });`,
      },
    ]);
    expect(found).toHaveLength(1);
  });

  it('teaches that a client-side .eq filter is not the protection', () => {
    const found = run([
      PKG,
      CLIENT,
      {
        path: 'src/mine.js',
        content: `import { supabase } from './lib/supabase';
const { data } = await supabase.from('notes').select('*').eq('user_id', user.id);`,
      },
    ]);
    expect(found).toHaveLength(1);
    expect(found[0].remediation).toMatch(/attacker simply does not send it/);
  });
});

describe('the shapes current Supabase projects actually use', () => {
  it('fires on @supabase/ssr createBrowserClient, the App Router default', () => {
    // A current Next.js project may never name supabase-js directly. Matching
    // only the classic package would miss the newest half of the ecosystem,
    // which is also the half most likely to have been generated.
    const found = run([
      {
        path: 'package.json',
        content: JSON.stringify({ dependencies: { '@supabase/ssr': '^0.5.1' } }),
      },
      {
        path: 'utils/supabase/client.ts',
        content: `import { createBrowserClient } from '@supabase/ssr';
export const client = createBrowserClient(process.env.NEXT_PUBLIC_URL, process.env.NEXT_PUBLIC_ANON);`,
      },
      {
        path: 'app/dashboard/page.tsx',
        content: `import { client } from '@/utils/supabase/client';
const { data } = await client.from('customers').select('*');`,
      },
    ]);
    expect(found).toHaveLength(1);
    expect(found[0].title).toContain('customers');
  });

  it('fires on the older auth-helpers factories', () => {
    const found = run([
      {
        path: 'package.json',
        content: JSON.stringify({
          dependencies: { '@supabase/auth-helpers-nextjs': '^0.10.0' },
        }),
      },
      {
        path: 'pages/api/list.js',
        content: `import { createPagesServerClient } from '@supabase/auth-helpers-nextjs';
const sbc = createPagesServerClient({ req, res });
const { data } = await sbc.from('invoices').select('*');`,
      },
    ]);
    expect(found).toHaveLength(1);
  });

  it('follows a chain that prettier has split across lines', () => {
    const found = run([
      PKG,
      CLIENT,
      {
        path: 'src/long.js',
        content: `import { supabase } from './lib/supabase';
const { data, error } = await supabase
  .from('subscriptions')
  .select('id, plan, current_period_end')
  .order('created_at', { ascending: false });`,
      },
    ]);
    expect(found).toHaveLength(1);
    expect(found[0].title).toContain('subscriptions');
  });
});

describe('tables the repo does protect', () => {
  it('stays quiet when a migration enables RLS on that table', () => {
    expect(
      run([
        PKG,
        CLIENT,
        {
          path: 'supabase/migrations/002_rls.sql',
          content: `create table profiles (id uuid);
alter table public.profiles enable row level security;`,
        },
        {
          path: 'src/Profile.jsx',
          content: `import { supabase } from './lib/supabase';
const { data } = await supabase.from('profiles').select('*');`,
        },
      ])
    ).toEqual([]);
  });

  it('matches the table regardless of schema qualifier or case', () => {
    expect(
      run([
        PKG,
        CLIENT,
        {
          path: 'db/rls.sql',
          content: 'alter table "Profiles" enable row level security;',
        },
        {
          path: 'src/p.js',
          content: `import { supabase } from './lib/supabase';
await supabase.from('profiles').select('*');`,
        },
      ])
    ).toEqual([]);
  });
});

describe('things that are not Supabase', () => {
  it('does not fire on Knex, which has the same call shape', () => {
    expect(
      run([
        {
          path: 'package.json',
          content: JSON.stringify({ dependencies: { knex: '^3.1.0' } }),
        },
        {
          path: 'src/repo.js',
          content: `const knex = require('knex')(config);
const rows = await knex.from('users').select('*');`,
        },
      ])
    ).toEqual([]);
  });

  it('does not fire when the project has no Supabase dependency at all', () => {
    expect(
      run([
        {
          path: 'src/q.js',
          content: `const rows = await db.from('users').select('*');`,
        },
      ])
    ).toEqual([]);
  });

  it('does not fire on an unrecognised receiver even in a Supabase project', () => {
    // A Supabase project can still use another builder. The receiver has to
    // look like a Supabase handle before this says anything.
    expect(
      run([
        PKG,
        CLIENT,
        {
          path: 'src/analytics.js',
          content: `const rows = await clickhouseQueryBuilder.from('events').select('*');`,
        },
      ])
    ).toEqual([]);
  });

  it('ignores test files', () => {
    expect(
      run([
        PKG,
        CLIENT,
        {
          path: 'src/__tests__/profile.test.js',
          content: `import { supabase } from '../lib/supabase';
await supabase.from('profiles').select('*');`,
        },
      ])
    ).toEqual([]);
  });
});

describe('the migration checks still work', () => {
  it('still reports a created table with no ENABLE RLS', () => {
    const all = probeSupabaseRLS([
      { path: 'db/001.sql', content: 'create table secrets (id uuid, value text);' },
    ]);
    expect(all.some((f) => /missing ENABLE ROW LEVEL SECURITY/.test(f.title))).toBe(true);
  });

  it('still reports a permissive USING (true) policy', () => {
    const all = probeSupabaseRLS([
      {
        path: 'db/002.sql',
        content: `create table t (id uuid);
alter table t enable row level security;
create policy p on t for select using (true);`,
      },
    ]);
    expect(all.some((f) => /USING \(true\)/.test(f.title))).toBe(true);
  });
});
