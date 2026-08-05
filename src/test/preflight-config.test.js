import { describe, it, expect } from 'vitest';
import {
  findPreflightConfigFile,
  parsePreflightYaml,
  parsePreflightConfig,
  findingMatchesRule,
  configToSuppressions,
} from '../lib/preflight-config.js';

const file = (path, content) => ({ path, content });

describe('findPreflightConfigFile', () => {
  it('finds .preflight.yml at project root', () => {
    const files = [file('package.json', '{}'), file('.preflight.yml', 'schema: preflight/v1')];
    expect(findPreflightConfigFile(files)?.path).toBe('.preflight.yml');
  });
  it('also finds .preflight.yaml and .preflight.json', () => {
    expect(findPreflightConfigFile([file('.preflight.yaml', '')]).path).toBe('.preflight.yaml');
    expect(findPreflightConfigFile([file('.preflight.json', '')]).path).toBe('.preflight.json');
  });
  it('returns undefined when none present', () => {
    expect(findPreflightConfigFile([file('package.json', '{}')])).toBeUndefined();
  });
});

describe('parsePreflightYaml', () => {
  it('parses top-level scalars', () => {
    expect(parsePreflightYaml('schema: preflight/v1')).toEqual({ schema: 'preflight/v1' });
  });
  it('parses list of scalars', () => {
    const yaml = `self_domains:\n  - one.example.com\n  - two.example.com`;
    expect(parsePreflightYaml(yaml)).toEqual({
      self_domains: ['one.example.com', 'two.example.com'],
    });
  });
  it('parses list of objects', () => {
    const yaml = `suppress:\n  - id: abc\n    reason: 'because'\n  - probe: X\n    file: 'a.js'`;
    expect(parsePreflightYaml(yaml)).toEqual({
      suppress: [
        { id: 'abc', reason: 'because' },
        { probe: 'X', file: 'a.js' },
      ],
    });
  });
  it('strips # comments', () => {
    const yaml = `# top comment\nschema: preflight/v1\n# another\nsuppress:\n  - id: x  # inline\n    reason: y`;
    const parsed = parsePreflightYaml(yaml);
    expect(parsed.schema).toBe('preflight/v1');
    expect(parsed.suppress[0]).toEqual({ id: 'x', reason: 'y' });
  });
  it('handles ~ as null and bare true/false', () => {
    const parsed = parsePreflightYaml(`a: ~\nb: true\nc: false`);
    expect(parsed).toEqual({ a: null, b: true, c: false });
  });
  it('handles quoted strings with colons inside', () => {
    const parsed = parsePreflightYaml(`title: 'foo: bar'`);
    expect(parsed.title).toBe('foo: bar');
  });
});

describe('parsePreflightConfig', () => {
  it('parses a valid YAML config', () => {
    const cfg = parsePreflightConfig(
      '.preflight.yml',
      'schema: preflight/v1\nself_domains:\n  - example.com'
    );
    expect(cfg.schema).toBe('preflight/v1');
    expect(cfg.self_domains).toEqual(['example.com']);
    expect(cfg.suppress).toEqual([]);
  });
  it('parses a valid JSON config', () => {
    const cfg = parsePreflightConfig(
      '.preflight.json',
      JSON.stringify({
        schema: 'preflight/v1',
        self_domains: ['x.com'],
        suppress: [{ id: 'abc', reason: 'r' }],
      })
    );
    expect(cfg.self_domains).toEqual(['x.com']);
    expect(cfg.suppress).toEqual([{ id: 'abc', reason: 'r' }]);
  });
  it('rejects unknown schema versions', () => {
    const cfg = parsePreflightConfig('.preflight.yml', 'schema: bogus/v9');
    expect(cfg.error).toMatch(/unknown schema/);
  });
  it('returns { error } on malformed YAML rather than throwing', () => {
    const cfg = parsePreflightConfig('.preflight.yml', 'not: a\n  valid:\nstructure');
    expect(typeof cfg.error === 'string' || cfg.schema === 'preflight/v1').toBe(true);
  });
});

describe('findingMatchesRule', () => {
  const f = {
    stableId: 'abc123',
    probe: 'Auth Weakness',
    file: 'src/App.jsx',
    title: 'JWT signed with algorithm "none"',
  };

  it('matches by stableId exact', () => {
    expect(findingMatchesRule(f, { id: 'abc123' })).toBe(true);
  });

  it('does not match different stableId', () => {
    expect(findingMatchesRule(f, { id: 'xyz' })).toBe(false);
  });

  it('matches by probe + file + title-pattern', () => {
    expect(
      findingMatchesRule(f, {
        probe: 'Auth Weakness',
        file: 'src/App.jsx',
        'title-pattern': 'algorithm',
      })
    ).toBe(true);
  });

  it('respects file glob with **', () => {
    expect(findingMatchesRule(f, { probe: 'Auth Weakness', file: 'src/**/*.jsx' })).toBe(true);
    expect(findingMatchesRule(f, { probe: 'Auth Weakness', file: 'dist/**/*.jsx' })).toBe(false);
  });

  it('respects single * wildcard (no slash)', () => {
    expect(findingMatchesRule(f, { probe: 'Auth Weakness', file: 'src/*.jsx' })).toBe(true);
    expect(
      findingMatchesRule(
        { ...f, file: 'src/lib/foo.jsx' },
        { probe: 'Auth Weakness', file: 'src/*.jsx' }
      )
    ).toBe(false);
  });

  it('honors title-pattern substring', () => {
    expect(
      findingMatchesRule(f, { probe: 'Auth Weakness', 'title-pattern': 'algorithm "none"' })
    ).toBe(true);
    expect(findingMatchesRule(f, { probe: 'Auth Weakness', 'title-pattern': 'unrelated' })).toBe(
      false
    );
  });

  it('treats past expiry as not-applicable', () => {
    expect(findingMatchesRule(f, { id: 'abc123', expires: '2020-01-01' })).toBe(false);
  });

  it('treats ~ / null / future expiry as applicable', () => {
    expect(findingMatchesRule(f, { id: 'abc123', expires: '~' })).toBe(true);
    expect(findingMatchesRule(f, { id: 'abc123', expires: '2099-01-01' })).toBe(true);
  });
});

describe('configToSuppressions', () => {
  it('returns {} for empty config or no findings', () => {
    expect(configToSuppressions({ suppress: [] }, [])).toEqual({});
    expect(configToSuppressions(null, [])).toEqual({});
    expect(configToSuppressions({ error: 'bad' }, [{}])).toEqual({});
  });

  it('produces a suppressions map keyed by stableId', () => {
    const findings = [
      { stableId: 'a', probe: 'X', file: 'src/foo.js', title: 'one' },
      { stableId: 'b', probe: 'Y', file: 'src/bar.js', title: 'two' },
    ];
    const config = {
      suppress: [
        { id: 'a', reason: 'documentation' },
        { probe: 'Y', file: 'src/**/*.js', reason: 'intentional' },
      ],
    };
    const out = configToSuppressions(config, findings);
    expect(Object.keys(out).sort()).toEqual(['a', 'b']);
    expect(out.a.note).toBe('documentation');
    expect(out.a.source).toBe('.preflight config');
    expect(out.b.note).toBe('intentional');
  });

  it('matches the first applicable rule and stops', () => {
    const findings = [{ stableId: 'a', probe: 'X', file: 'src/foo.js', title: 't' }];
    const config = {
      suppress: [
        { id: 'a', reason: 'first' },
        { id: 'a', reason: 'second' },
      ],
    };
    expect(configToSuppressions(config, findings).a.note).toBe('first');
  });
});

// A repo config is untrusted: it arrives inside the project being scanned. A
// wrong-typed field used to throw out of configToSuppressions, which runs
// outside the per-probe try/catch, so one malformed rule aborted the whole
// scan instead of degrading. Found by an embedder whose server process exited
// on a single request carrying such a config.
describe('malformed rule fields', () => {
  const findings = [{ stableId: 'a', probe: 'X', file: 'src/foo.js', title: 'one' }];

  it('does not throw when title-pattern is not a string', () => {
    for (const bad of [1, true, null, {}, [], 0]) {
      const config = { suppress: [{ probe: 'X', 'title-pattern': bad }] };
      expect(() => configToSuppressions(config, findings)).not.toThrow();
      expect(() => findingMatchesRule(findings[0], config.suppress[0])).not.toThrow();
    }
  });

  it('does not throw for any wrong-typed rule field', () => {
    const fields = ['id', 'probe', 'file', 'title', 'title-pattern', 'reason', 'expires'];
    for (const field of fields) {
      for (const bad of [1, true, {}, []]) {
        const config = { suppress: [{ probe: 'X', [field]: bad }] };
        expect(() => configToSuppressions(config, findings)).not.toThrow();
      }
    }
  });

  it('survives a parsed config, the path an actual repo takes', () => {
    const json = '{"schema":"preflight/v1","suppress":[{"probe":"X","title-pattern":1}]}';
    const cfg = parsePreflightConfig('.preflight.json', json);
    expect(cfg.error).toBeUndefined();
    expect(() => configToSuppressions(cfg, findings)).not.toThrow();
  });

  it('drops a wrong-typed field rather than keeping it', () => {
    const cfg = parsePreflightConfig(
      '.preflight.json',
      '{"schema":"preflight/v1","suppress":[{"probe":"X","title-pattern":1,"reason":"r"}]}'
    );
    expect(cfg.suppress[0]['title-pattern']).toBeUndefined();
    expect(cfg.suppress[0].probe).toBe('X');
    expect(cfg.suppress[0].reason).toBe('r');
  });

  it('a rule stripped of a bad filter still applies its remaining filters', () => {
    // Dropping title-pattern widens the rule to probe-only. That is the
    // documented behaviour of a probe-only rule, not a silent no-op.
    const cfg = parsePreflightConfig(
      '.preflight.json',
      '{"schema":"preflight/v1","suppress":[{"probe":"X","title-pattern":1,"reason":"r"}]}'
    );
    expect(Object.keys(configToSuppressions(cfg, findings))).toEqual(['a']);
    const other = [{ stableId: 'b', probe: 'Z', file: 'src/z.js', title: 'z' }];
    expect(Object.keys(configToSuppressions(cfg, other))).toEqual([]);
  });

  it('still honours a well-formed title-pattern', () => {
    const cfg = parsePreflightConfig(
      '.preflight.json',
      '{"schema":"preflight/v1","suppress":[{"probe":"X","title-pattern":"one","reason":"r"}]}'
    );
    expect(Object.keys(configToSuppressions(cfg, findings))).toEqual(['a']);
    const noMatch = parsePreflightConfig(
      '.preflight.json',
      '{"schema":"preflight/v1","suppress":[{"probe":"X","title-pattern":"nope","reason":"r"}]}'
    );
    expect(Object.keys(configToSuppressions(noMatch, findings))).toEqual([]);
  });

  it('rejects a suppress entry that is an array rather than an object', () => {
    const cfg = parsePreflightConfig(
      '.preflight.json',
      '{"schema":"preflight/v1","suppress":[[1,2]]}'
    );
    expect(cfg.suppress).toEqual([]);
  });
});
