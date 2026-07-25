// F7 AI Codegen Bloat (v2 spec). Detection tests plus the suppressions that
// keep a maintainability probe from becoming noise.
import { describe, it, expect } from 'vitest';
import { probeAICodegenBloat } from '../lib/probes/v2/bloat.js';

const f = (path, content) => ({ path, content });
const run = (...files) => probeAICodegenBloat(files);
const has = (res, re) => res.some((x) => re.test(x.title));

describe('backup and variant files', () => {
  it.each([
    'src/Dashboard.backup.tsx',
    'src/api.old.js',
    'src/routes.orig.ts',
    'src/page-v2.tsx',
    'src/handler_final.js',
    'src/Widget-copy.jsx',
  ])('flags %s', (path) => {
    const res = run(f(path, 'export const x = 1;'));
    expect(has(res, /Backup or variant file/)).toBe(true);
  });

  it('rates variant files medium (the old auth check lives there)', () => {
    const res = run(f('src/api.old.js', 'export const x = 1;'));
    expect(res.find((x) => /Backup or variant/.test(x.title)).severity).toBe('medium');
  });

  it.each([
    'src/v2/index.ts',
    'src/components/Version.tsx',
    'src/oldest-first.js',
    'src/copywriting.ts',
    'src/backups/service.ts',
  ])('does NOT flag %s', (path) => {
    const res = run(f(path, 'export const x = 1;'));
    expect(has(res, /Backup or variant file/)).toBe(false);
  });
});

describe('commented-out code', () => {
  it('flags a long run of commented-out statements', () => {
    const block = Array.from({ length: 12 }, (_, i) => `// const step${i} = compute(${i});`);
    const res = run(f('src/svc.js', ['export const live = 1;', ...block].join('\n')));
    expect(has(res, /consecutive lines of commented-out code/)).toBe(true);
  });

  it('does NOT flag a long prose comment block', () => {
    const prose = Array.from(
      { length: 14 },
      () => '// This module reconciles ledger entries against the upstream feed.'
    );
    const res = run(f('src/svc.js', [...prose, 'export const live = 1;'].join('\n')));
    expect(has(res, /commented-out code/)).toBe(false);
  });

  it('does NOT flag a short commented-out snippet', () => {
    const block = Array.from({ length: 4 }, (_, i) => `// const step${i} = compute(${i});`);
    const res = run(f('src/svc.js', block.join('\n')));
    expect(has(res, /commented-out code/)).toBe(false);
  });
});

describe('assistant narration in comments', () => {
  it.each([
    "// Here's a robust implementation of the retry logic",
    "// I've updated the function to handle the edge case",
    '// Feel free to adjust the timeout to suit your needs',
    '// Let me know if you need anything else',
    '// Replace this with your actual API key',
  ])('flags %s', (line) => {
    const res = run(f('src/a.js', `${line}\nexport const x = 1;`));
    expect(has(res, /narration left in a code comment/)).toBe(true);
  });

  it('rates narration info, not a defect', () => {
    const res = run(f('src/a.js', "// Here's a complete implementation\nexport const x = 1;"));
    expect(res.find((x) => /narration/.test(x.title)).severity).toBe('info');
  });

  it('does NOT flag ordinary explanatory comments', () => {
    const res = run(
      f(
        'src/a.js',
        '// Retries twice because the upstream returns 502 on cold start\nexport const x = 1;'
      )
    );
    expect(has(res, /narration/)).toBe(false);
  });
});

describe('function size and complexity', () => {
  it('flags a function over the line threshold', () => {
    const body = Array.from({ length: 120 }, (_, i) => `  const v${i} = ${i};`).join('\n');
    const res = run(f('src/big.js', `function build(input) {\n${body}\n  return input;\n}`));
    expect(has(res, /Function "build" is \d+ lines/)).toBe(true);
  });

  it('does NOT flag a short function', () => {
    const res = run(f('src/ok.js', 'function add(a, b) {\n  return a + b;\n}'));
    expect(has(res, /is \d+ lines/)).toBe(false);
  });

  it('flags high cyclomatic complexity', () => {
    const branches = Array.from({ length: 14 }, (_, i) => `  if (x === ${i}) return ${i};`).join(
      '\n'
    );
    const res = run(f('src/br.js', `function pick(x) {\n${branches}\n  return -1;\n}`));
    expect(has(res, /cyclomatic complexity \d+/)).toBe(true);
  });

  it('does NOT flag a simple function with a couple of branches', () => {
    const res = run(
      f('src/ok.js', 'function pick(x) {\n  if (x) return 1;\n  if (!x) return 2;\n  return 3;\n}')
    );
    expect(has(res, /cyclomatic/)).toBe(false);
  });
});

describe('pass-through wrappers', () => {
  it('flags a function that only forwards its arguments', () => {
    const res = run(f('src/w.js', 'function saveUser(id, data) {\n  return db.save(id, data);\n}'));
    expect(has(res, /only forwards its arguments/)).toBe(true);
  });

  it('does NOT flag a wrapper that transforms an argument', () => {
    const res = run(
      f('src/w.js', 'function saveUser(id, data) {\n  return db.save(id, normalize(data));\n}')
    );
    expect(has(res, /only forwards/)).toBe(false);
  });

  it('does NOT flag a wrapper that adds an argument', () => {
    const res = run(
      f(
        'src/w.js',
        'function saveUser(id, data) {\n  return db.save(id, data, { audit: true });\n}'
      )
    );
    expect(has(res, /only forwards/)).toBe(false);
  });

  it('does NOT flag a zero-argument call', () => {
    const res = run(f('src/w.js', 'function refresh() {\n  return store.refresh();\n}'));
    expect(has(res, /only forwards/)).toBe(false);
  });
});

describe('dead imports', () => {
  it('flags an imported binding that is never referenced', () => {
    const res = run(f('src/a.js', "import { unused } from './x';\nexport const y = 1;"));
    expect(has(res, /Imported "unused" is never used/)).toBe(true);
  });

  it('does NOT flag an import used in code', () => {
    const res = run(f('src/a.js', "import { used } from './x';\nexport const y = used(1);"));
    expect(has(res, /never used/)).toBe(false);
  });

  it('does NOT flag an import used only as a JSX component', () => {
    const res = run(
      f('src/a.jsx', "import { Badge } from './b';\nexport const A = () => <Badge />;")
    );
    expect(has(res, /never used/)).toBe(false);
  });

  it('does NOT flag a bare side-effect import', () => {
    const res = run(f('src/a.js', "import './styles.css';\nexport const y = 1;"));
    expect(has(res, /never used/)).toBe(false);
  });

  it('does NOT confuse a property name with an import binding', () => {
    const res = run(f('src/a.js', "import { thing } from './x';\nexport const o = { thing: 1 };"));
    expect(has(res, /Imported "thing" is never used/)).toBe(true);
  });
});

describe('eslint-disable justification', () => {
  it('flags a disable with no reason', () => {
    const res = run(f('src/a.js', '// eslint-disable-next-line no-eval\nconst x = 1;'));
    expect(has(res, /with no stated reason/)).toBe(true);
  });

  it('does NOT flag a disable with an inline -- reason', () => {
    const res = run(
      f('src/a.js', '// eslint-disable-next-line no-eval -- vendor types are wrong\nconst x = 1;')
    );
    expect(has(res, /no stated reason/)).toBe(false);
  });

  it('does NOT flag a disable explained on the previous line', () => {
    const res = run(
      f(
        'src/a.js',
        '// The vendor SDK requires it here.\n// eslint-disable-next-line no-eval\nconst x = 1;'
      )
    );
    expect(has(res, /no stated reason/)).toBe(false);
  });
});

describe('untracked TODOs', () => {
  it('flags a bare TODO', () => {
    const res = run(f('src/a.js', '// TODO: handle the refund path\nconst x = 1;'));
    expect(has(res, /no ticket reference/)).toBe(true);
  });

  it.each([
    '// TODO(PROJ-482): handle the refund path',
    '// FIXME #1421 handle the refund path',
    '// TODO https://tracker.example.com/i/9 handle refunds',
  ])('does NOT flag %s', (line) => {
    const res = run(f('src/a.js', `${line}\nconst x = 1;`));
    expect(has(res, /no ticket reference/)).toBe(false);
  });
});

describe('repeated magic strings', () => {
  it('flags a literal repeated three times', () => {
    const src = [
      "const a = cookies.get('app_session_v2');",
      "const b = cookies.set('app_session_v2', t);",
      "const c = cookies.del('app_session_v2');",
    ].join('\n');
    expect(has(run(f('src/a.js', src)), /is repeated 3 times/)).toBe(true);
  });

  it('does NOT flag a literal used twice', () => {
    const src = ["const a = get('app_session_v2');", "const b = set('app_session_v2');"].join('\n');
    expect(has(run(f('src/a.js', src)), /is repeated/)).toBe(false);
  });

  it('does NOT flag repeated import paths or URLs', () => {
    const src = [
      "fetch('https://api.example.com/v1');",
      "fetch('https://api.example.com/v1');",
      "fetch('https://api.example.com/v1');",
    ].join('\n');
    expect(has(run(f('src/a.js', src)), /is repeated/)).toBe(false);
  });

  it('does NOT flag repeated sentence-shaped UI copy', () => {
    const src = Array.from({ length: 3 }, () => "toast('Something went wrong here');").join('\n');
    expect(has(run(f('src/a.js', src)), /is repeated/)).toBe(false);
  });
});

describe('family contract', () => {
  it('never exceeds medium severity', () => {
    const res = run(f('src/Dashboard.backup.tsx', 'function x(a){ return y(a); }\n// TODO: fix\n'));
    expect(res.length).toBeGreaterThan(0);
    for (const x of res) expect(['info', 'low', 'medium']).toContain(x.severity);
  });

  it('stamps every finding with the family probe name', () => {
    const res = run(f('src/api.old.js', 'export const x = 1;'));
    for (const x of res) expect(x.probe).toBe('AI Codegen Bloat');
  });

  it('skips test files entirely', () => {
    expect(run(f('src/a.test.js', '// TODO: fix\nexport const x = 1;'))).toEqual([]);
    expect(run(f('integration-tests/a.ts', '// TODO: fix\nexport const x = 1;'))).toEqual([]);
  });

  it('returns an array on empty input', () => {
    expect(probeAICodegenBloat([])).toEqual([]);
  });

  it('does not crash on unparseable source', () => {
    expect(Array.isArray(run(f('src/broken.js', 'function ( { [[[')))).toBe(true);
  });

  it('produces nothing for a clean, ordinary module', () => {
    const src = [
      "import { formatMoney } from './money';",
      '',
      '// Charges the card and returns the receipt id.',
      'export async function charge(amount, userId) {',
      '  const receipt = await gateway.charge(amount, userId);',
      '  return formatMoney(receipt.total);',
      '}',
    ].join('\n');
    expect(run(f('src/charge.js', src))).toEqual([]);
  });
});
