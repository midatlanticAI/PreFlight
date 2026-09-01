// RLS enabled by a loop rather than one statement per table.
//
// A schema with a dozen tenant-scoped tables does not write the same statement
// a dozen times. It writes:
//
//   do $$ declare t text; begin
//     foreach t in array array['sites','vehicles', ...] loop
//       execute format('alter table %I enable row level security', t);
//
// The probe matched only literal `alter table X enable row level security`, so
// every table in that list came back missing RLS. On a real production schema
// that was eleven CRITICAL findings and a security score of zero for a database
// where all nineteen tables had RLS on and policies attached, verified against
// the live catalog. A tool that reports a correct schema as a total breach is
// one people stop reading.
//
// The other direction matters just as much: this must not become a way to look
// protected. A list nothing enables, an enable in a different block, and a
// commented-out enable all still have to fail.

import { describe, it, expect } from 'vitest';
import { probeSupabaseRLS } from '../lib/probes/database.js';

const missing = (findings, table) =>
  findings.some(
    (f) =>
      f.severity === 'critical' && f.title === `Table "${table}" missing ENABLE ROW LEVEL SECURITY`
  );

const sql = (content) => [{ path: 'supabase/migrations/0001_init.sql', content }];

const CREATES = `
create table sites (id uuid primary key, tenant_id uuid);
create table vehicles (id uuid primary key, tenant_id uuid);
create table audit_log (id uuid primary key);
`;

describe('RLS enabled inside a PL/pgSQL loop', () => {
  it('credits every table named in the array the block enables', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
do $$
declare t text;
begin
  foreach t in array array['sites','vehicles']
  loop
    execute format('alter table %I enable row level security', t);
  end loop;
end $$;`)
    );
    expect(missing(f, 'sites')).toBe(false);
    expect(missing(f, 'vehicles')).toBe(false);
  });

  it('still reports a table the loop does not cover', () => {
    // audit_log is created but never appears in the array.
    const f = probeSupabaseRLS(
      sql(`${CREATES}
do $$
declare t text;
begin
  foreach t in array array['sites','vehicles']
  loop
    execute format('alter table %I enable row level security', t);
  end loop;
end $$;`)
    );
    expect(missing(f, 'audit_log')).toBe(true);
  });

  it('handles the concatenated form as well as format()', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
do $$
declare t text;
begin
  foreach t in array array['sites','vehicles']
  loop
    execute 'alter table ' || quote_ident(t) || ' enable row level security';
  end loop;
end $$;`)
    );
    expect(missing(f, 'sites')).toBe(false);
  });

  it('works with a named dollar-quote tag', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
do $body$
begin
  foreach t in array array['sites']
  loop
    execute format('alter table %I enable row level security', t);
  end loop;
end $body$;`)
    );
    expect(missing(f, 'sites')).toBe(false);
  });
});

describe('the loop resolution cannot be used to look protected', () => {
  it('a table list that enables nothing vouches for nothing', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
do $$
declare t text;
begin
  foreach t in array array['sites','vehicles']
  loop
    execute format('grant select on %I to authenticated', t);
  end loop;
end $$;`)
    );
    expect(missing(f, 'sites')).toBe(true);
    expect(missing(f, 'vehicles')).toBe(true);
  });

  it('a list in one block is not vouched for by an enable in another', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
do $$
begin
  foreach t in array array['sites','vehicles']
  loop
    execute format('grant select on %I to authenticated', t);
  end loop;
end $$;

do $$
begin
  foreach t in array array['audit_log']
  loop
    execute format('alter table %I enable row level security', t);
  end loop;
end $$;`)
    );
    expect(missing(f, 'sites')).toBe(true);
    expect(missing(f, 'audit_log')).toBe(false);
  });

  it('a commented-out loop protects nothing', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
-- do $$
-- begin
--   foreach t in array array['sites','vehicles']
--   loop
--     execute format('alter table %I enable row level security', t);
--   end loop;
-- end $$;`)
    );
    expect(missing(f, 'sites')).toBe(true);
    expect(missing(f, 'vehicles')).toBe(true);
  });

  it('a commented-out literal enable protects nothing', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
-- alter table sites enable row level security;
/* alter table vehicles enable row level security; */`)
    );
    expect(missing(f, 'sites')).toBe(true);
    expect(missing(f, 'vehicles')).toBe(true);
  });
});

describe('SQL comment masking does not eat real statements', () => {
  it('a double hyphen inside a string literal is not a comment', () => {
    const f = probeSupabaseRLS(
      sql(`${CREATES}
insert into audit_log (id) values ('a--b');
alter table sites enable row level security;
alter table vehicles enable row level security;
alter table audit_log enable row level security;`)
    );
    expect(missing(f, 'sites')).toBe(false);
    expect(missing(f, 'vehicles')).toBe(false);
    expect(missing(f, 'audit_log')).toBe(false);
  });

  it('reports the line of the create statement, not a shifted one', () => {
    const f = probeSupabaseRLS(
      sql(`-- a leading comment line
-- another one
create table sites (id uuid primary key);`)
    );
    const hit = f.find((x) => x.title === 'Table "sites" missing ENABLE ROW LEVEL SECURITY');
    expect(hit).toBeDefined();
    expect(hit.line).toBe(3);
  });
});
