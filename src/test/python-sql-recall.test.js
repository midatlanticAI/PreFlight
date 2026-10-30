import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { PY_SQL_RAW_001 } from '../lib/probes/v05/adapters/python/py-sql-raw-001-interpolation.js';

const detect = (probe, content, path = 'app/views.py') => probe.detect([{ path, content }]);

describe('Python SQL interpolation recall regressions', () => {
  it('detects every original SQL positive at its original line', () => {
    const content = readFileSync(PY_SQL_RAW_001.fixtures_v05.positive, 'utf8');
    expect(detect(PY_SQL_RAW_001, content).map((finding) => finding.line)).toEqual([
      11, 16, 20, 24, 28,
    ]);
  });

  it.each([
    `User.objects.extra(where=[f"status = '{status}'"])`,
    `User.objects.extra(where=[f'status = "{status}"'])`,
    `User.objects.extra(where=["status = '%s'" % status])`,
    `User.objects.extra(where=['status = "%s"' % status])`,
    `User.objects.extra(where=["status = '{}'".format(status)])`,
    `User.objects.extra(where=['status = "{}"'.format(status)])`,
    String.raw`User.objects.extra(where=[f"status = \"{status}\""])`,
    `cursor.execute("SELECT * FROM t WHERE status = '" + status)`,
    `cursor.execute(f"SELECT {status}", params=[other])`,
  ])('detects interpolation in %s', (code) => {
    expect(detect(PY_SQL_RAW_001, code)).toHaveLength(1);
  });

  it.each([
    `User.objects.extra(where=["status = %s"], params=[status])`,
    `User.objects.extra(where=["status = '{}' "])`,
    `cursor.execute(f"SELECT '{{status}}'")`,
    `cursor.execute("SELECT * FROM t WHERE status = %s", [status])`,
    `cursor.execute("SELECT 1") # f"{status}"`,
    `# User.objects.extra(where=[f"status = '{status}'"])`,
  ])('preserves literal, parameterized and comment protections: %s', (code) => {
    expect(detect(PY_SQL_RAW_001, code)).toHaveLength(0);
  });
});

it('retains Python test-file exclusions', () => {
  expect(detect(PY_SQL_RAW_001, 'cursor.execute(f"SELECT {uid}")', 'tests/test_db.py')).toEqual([]);
});
