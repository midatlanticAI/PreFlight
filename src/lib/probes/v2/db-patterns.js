// src/lib/probes/v2/db-patterns.js
//
// F12: Database patterns (docs/preflight-v2-spec.md §F12, 10-probe roster).
// The statements that behave until the data does: UPDATE with no WHERE,
// migrations that cannot run twice, multi-step writes with no transaction.
//
// Severity ceiling: MEDIUM — deliberately matching F7. The risk TIER takes
// the worst severity present, and a correctness finding must not brand a
// repo HIGH RISK (pinned by calibration-acceptance-v1). Whether health-axis
// findings should ever reach high is the parked class-ceiling decision;
// until it is made, these families teach at medium and below.
//
// Roster entries deliberately not built, with reasons:
//   supabase_rls checks — owned outright by the existing Supabase RLS
//       probe (policy-resolving, loop-aware).
//   raw_sql_with_string_interpolation — owned by the SQL injection probes
//       (template-literal, f-string, Sprintf and adapter families).
//   query_in_loop_orm_n_plus_1 — owned by Async Correctness.
//   prisma_findunique_on_non_unique_field — needs the schema to know which
//       fields are unique.
//   race_condition_on_read_then_write — needs cross-statement flow; the
//       transaction check below covers the observable slice.
//   select_star — SELECT * in application code is a style argument until
//       column count and payload size are known; declined as FP-dominated.

import { isTestFile, isScannerSelfSource } from '../../file-filter.js';
import { maskCommentsForPath } from '../_internal/masking.js';

export const DB_FILE_RE = /\.(?:[jt]sx?|mjs|cjs|py|sql)$/i;

const finding = (o) => ({
  probe: 'Database Patterns',
  category: 'Data Integrity',
  severity: 'medium',
  cwe: 'CWE-1288',
  ...o,
});

export function probeDbPatterns(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!DB_FILE_RE.test(file.path)) return;
    const content = file.content || '';
    if (!content.trim()) return;
    if (
      !/UPDATE|DELETE|CREATE\s+TABLE|\.\$transaction|\.(?:create|update|delete)|\.del\s*\(/i.test(
        content
      )
    )
      return;
    const code = maskCommentsForPath(file.path, content);
    const codeLines = code.split('\n');
    const rawLines = content.split('\n');
    const push = (i, o) =>
      findings.push(
        finding({
          file: file.path,
          line: i + 1,
          evidence: (rawLines[i] ?? '').trim().slice(0, 160),
          ...o,
        })
      );

    const isMigrationPath = /(^|\/)(?:migrations?|migrate)\//i.test(file.path);
    const isMigration = isMigrationPath && /\.sql$/i.test(file.path);
    // Gate-1: reset/seed/demo scripts clear whole tables as their stated
    // job, and migration backfills touch every row by definition.
    const isMaintenancePath =
      isMigrationPath ||
      /(^|\/)(?:scripts?|seeds?|fixtures)\//i.test(file.path) ||
      /seed|reset|demo/i.test(file.path.split('/').pop() || '');

    codeLines.forEach((line, i) => {
      // UPDATE / DELETE with no WHERE. The statement window joins Prettier's
      // string-concatenation wrap ('UPDATE … ' + 'WHERE id = $2') so a
      // clause on the next fragment is seen (Gate-1: a parameterized
      // two-line UPDATE was reported as an all-rows write).
      const stmtWindow = (
        line +
        ' ' +
        (codeLines[i + 1] || '') +
        ' ' +
        (codeLines[i + 2] || '')
      ).replace(/['"`]\s*\+\s*['"`]/g, ' ');
      const um = line.match(/['"`]\s*(UPDATE\s+\w+\s+SET\b[^'"`]*|DELETE\s+FROM\s+\w+\s*)['"`]/i);
      const wm = stmtWindow.match(/['"`]\s*(?:UPDATE\s+\w+\s+SET|DELETE\s+FROM\s+\w+)\b([^'"`]*)/i);
      if (!isMaintenancePath && um && wm && !/\bWHERE\b/i.test(wm[0])) {
        push(i, {
          id: `db-no-where-${file.path}-${i}`,
          title: `${/DELETE/i.test(um[1]) ? 'DELETE' : 'UPDATE'} with no WHERE clause`,
          severity: 'medium',
          cwe: 'CWE-1288',
          remediation:
            'This statement touches every row in the table, every time it runs — the classic "reset one user, reset them all". If all-rows is truly intended, say so in the statement (WHERE 1=1 with a comment); otherwise add the WHERE and, for one-row intent, verify affected-rows === 1.',
        });
      }
      // Gate-2 (C17): the ORM spellings of the same defect. Prisma/Mongo
      // updateMany/deleteMany with no where touches every row; a knex
      // update/del chain with no .where() is UPDATE with no WHERE.
      const om = line.match(/\.(?:updateMany|deleteMany)\s*\(/);
      if (!isMaintenancePath && om) {
        const w = codeLines.slice(i, Math.min(codeLines.length, i + 5)).join(' ');
        if (!/\bwhere\s*:/.test(w) && !/\bfilter\s*:/.test(w)) {
          push(i, {
            id: `db-orm-no-where-${file.path}-${i}`,
            title: `${om[0].includes('delete') ? 'deleteMany' : 'updateMany'} with no where`,
            severity: 'medium',
            cwe: 'CWE-1288',
            remediation:
              'Without a where, this call touches every row of the model, every time it runs. If all-rows is truly intended, write where: {} explicitly with a comment saying so; otherwise scope it and check the returned count matches what you expected to change.',
          });
        }
      }
      const usesKnex = /knex\s*\(|from\s+['"]knex['"]|require\s*\(\s*['"]knex['"]/.test(code);
      if (!isMaintenancePath && usesKnex && /\.(?:update|del|delete)\s*\(/.test(line)) {
        const w = codeLines.slice(Math.max(0, i - 1), Math.min(codeLines.length, i + 4)).join(' ');
        const km = /knex\s*\([^)]*\)\s*(?:\.\w+\s*\([^)]*\)\s*)*\.(?:update|del|delete)\s*\(/.test(
          w
        );
        if (km && !/\.where/i.test(w)) {
          push(i, {
            id: `db-knex-no-where-${file.path}-${i}`,
            title: 'knex update/delete with no .where()',
            severity: 'medium',
            cwe: 'CWE-1288',
            remediation:
              'A knex builder with no .where() compiles to UPDATE or DELETE over the whole table. Chain .where() before awaiting, and for one-row intent check the affected-row count the call returns.',
          });
        }
      }
      // Migration statements that cannot run twice.
      // Gate-1: Prisma/Drizzle generate these files and prevent re-runs
      // with their version tables — IF NOT EXISTS is not theirs to add.
      const toolManaged =
        /(^|\/)(?:prisma|drizzle)\//i.test(file.path) || /-- CreateTable/.test(code);
      if (isMigration && !toolManaged && /^\s*CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)/i.test(line)) {
        push(i, {
          id: `db-migration-rerun-${file.path}-${i}`,
          title: 'Migration CREATE TABLE is not re-runnable',
          severity: 'medium',
          remediation:
            'The first retry after a half-applied deploy hits "relation already exists" and the migration chain wedges. Write CREATE TABLE IF NOT EXISTS (and the matching IF EXISTS on drops), or run migrations through a tool that records applied versions.',
        });
      }
    });

    // Multi-step related writes with no transaction: the failure between
    // them leaves half the change.
    if (/\.(?:[jt]sx?|mjs|cjs)$/i.test(file.path) && /prisma\.|\.query\s*\(/.test(code)) {
      const fnRe = /(?:async\s+function\s+\w+|=\s*async\s*\([^)]*\)\s*=>)\s*\{/g;
      let fm;
      while ((fm = fnRe.exec(code)) !== null) {
        let depth = 0;
        let end = -1;
        for (let k = fm.index + fm[0].length - 1; k < Math.min(code.length, fm.index + 5000); k++) {
          if (code[k] === '{') depth++;
          else if (code[k] === '}') {
            depth--;
            if (depth === 0) {
              end = k;
              break;
            }
          }
        }
        if (end === -1) continue;
        const span = code.slice(fm.index, end);
        const writes = [
          ...span.matchAll(
            /await\s+(?:prisma\.\w+|\w+)\.(?:create|update|delete|upsert|insertOne|updateOne|deleteOne)\s*\(/g
          ),
        ];
        // Gate-1: an analytics/audit row beside a user-field update is two
        // independent best-effort writes; atomicity would add contention
        // for nothing. Telemetry-shaped models do not count toward a pair.
        const nonTelemetry = writes.filter(
          (w) => !/pageview|event|log|audit|metric|visit|analytic|history|activity/i.test(w[0])
        );
        if (
          nonTelemetry.length >= 2 &&
          !/\$transaction|\.transaction\s*\(|BEGIN|startSession|withTransaction/i.test(span)
        ) {
          const ln = code.slice(0, fm.index).split('\n').length;
          push(ln - 1, {
            id: `db-no-transaction-${file.path}-${ln}`,
            title: `${writes.length} dependent writes with no transaction`,
            severity: 'medium',
            remediation:
              "If the second write fails, the first one stays: an order without its items, a debit without its credit. Wrap the related writes in one transaction (prisma.$transaction([...]) or your driver's equivalent) so they land together or not at all.",
          });
          break; // one lesson per file
        }
      }
    }
  });
  return findings;
}
