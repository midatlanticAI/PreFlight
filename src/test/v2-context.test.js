// F0 context detectors (v2 spec §1.10): framework, host, hook-context,
// async-context. These route every downstream v2 family, so their edges get
// tested harder than their happy paths.
import { describe, it, expect } from 'vitest';
import {
  detectFrameworks,
  detectHost,
  getHookContextRanges,
  hookContextAt,
  getAsyncContextRanges,
  parseModule,
  probeHostDetection,
} from '../lib/probes/v2/context.js';

const file = (path, content) => ({ path, content });
const pkg = (deps, extra = {}) =>
  file('package.json', JSON.stringify({ name: 'app', dependencies: deps, ...extra }));

describe('detectFrameworks', () => {
  it('detects react from the dependency', () => {
    const r = detectFrameworks([pkg({ react: '^18.0.0' })]);
    expect(r.primary).toBe('react');
    expect(r.all).toContain('react');
  });

  it('prefers next over react as primary and implies react', () => {
    const r = detectFrameworks([pkg({ next: '^14.0.0', react: '^18.0.0' })]);
    expect(r.primary).toBe('next');
    expect(r.all).toContain('react');
  });

  it('detects next from next.config.mjs without a package.json', () => {
    const r = detectFrameworks([file('next.config.mjs', 'export default {};')]);
    expect(r.primary).toBe('next');
  });

  it('detects vue from .vue source files', () => {
    const r = detectFrameworks([file('src/App.vue', '<template><div/></template>')]);
    expect(r.primary).toBe('vue');
  });

  it('detects svelte, astro, solid from deps', () => {
    expect(detectFrameworks([pkg({ svelte: '^4.0.0' })]).primary).toBe('svelte');
    expect(detectFrameworks([pkg({ astro: '^4.0.0' })]).primary).toBe('astro');
    expect(detectFrameworks([pkg({ 'solid-js': '^1.8.0' })]).primary).toBe('solid');
  });

  it('infers react from bare jsx files when no deps are visible', () => {
    const r = detectFrameworks([file('src/App.jsx', 'export const App = () => <div/>;')]);
    expect(r.primary).toBe('react');
  });

  it('returns none for a plain node project', () => {
    const r = detectFrameworks([pkg({ express: '^4.0.0' })]);
    expect(r.primary).toBe('none');
    expect(r.all).toEqual([]);
  });

  it('ignores package.json under node_modules', () => {
    const r = detectFrameworks([
      file('node_modules/x/package.json', JSON.stringify({ dependencies: { react: '1' } })),
    ]);
    expect(r.primary).toBe('none');
  });
});

describe('detectHost', () => {
  it('detects lovable from the lovable-tagger dependency', () => {
    const r = detectHost([pkg({ react: '1' }, { devDependencies: { 'lovable-tagger': '^1' } })]);
    expect(r.primary).toBe('lovable');
  });

  it('detects lovable from the gptengineer script marker in HTML', () => {
    const r = detectHost([
      file('index.html', '<script src="https://cdn.gpteng.co/gptengineer.js"></script>'),
    ]);
    expect(r.primary).toBe('lovable');
  });

  it('detects bolt, replit, windsurf, cursor from marker files', () => {
    expect(detectHost([file('.bolt/config.json', '{}')]).primary).toBe('bolt');
    expect(detectHost([file('.replit', 'run = "npm start"')]).primary).toBe('replit');
    expect(detectHost([file('.windsurfrules', 'be nice')]).primary).toBe('windsurf');
    expect(detectHost([file('.cursorrules', 'be nice')]).primary).toBe('cursor');
  });

  it('detects claude-code / gemini-cli / codex from agent config files', () => {
    expect(detectHost([file('CLAUDE.md', '# project')]).primary).toBe('claude-code');
    expect(detectHost([file('GEMINI.md', '# project')]).primary).toBe('gemini-cli');
    expect(detectHost([file('AGENTS.md', '# project')]).primary).toBe('codex');
  });

  it('the generator outranks the editor when both are present', () => {
    const r = detectHost([
      file('.cursorrules', 'x'),
      file('index.html', '<script src="https://cdn.gpteng.co/gptengineer.js"></script>'),
    ]);
    expect(r.primary).toBe('lovable');
    expect(r.all).toContain('cursor');
  });

  it('returns unknown with no signals', () => {
    const r = detectHost([file('src/index.js', 'console.log(1)')]);
    expect(r.primary).toBe('unknown');
    expect(r.all).toEqual([]);
  });

  it('does not detect claude-code from a lowercase claude.md path segment mismatch', () => {
    // Path regexes for agent files are case-sensitive on purpose: CLAUDE.md
    // is the convention; a doc named docs/claude.md is prose about Claude.
    const r = detectHost([file('docs/claude.md', 'notes')]);
    expect(r.primary).toBe('unknown');
  });
});

describe('getHookContextRanges / hookContextAt', () => {
  it('marks a PascalCase function declaration as a component range', () => {
    const src = `function Profile() { const [n] = useState(0); return <div>{n}</div>; }`;
    const ranges = getHookContextRanges(src);
    expect(ranges).toHaveLength(1);
    expect(ranges[0].kind).toBe('component');
    expect(ranges[0].name).toBe('Profile');
  });

  it('marks a const arrow custom hook as a hook range', () => {
    const src = `const useThing = () => { return useState(null); };`;
    const ranges = getHookContextRanges(src);
    expect(ranges.some((r) => r.kind === 'hook' && r.name === 'useThing')).toBe(true);
  });

  it('reports the innermost context for nested functions', () => {
    const src = `function Page() { const useLocal = () => { return 1; }; return useLocal(); }`;
    const ranges = getHookContextRanges(src);
    const inner = src.indexOf('return 1');
    const ctx = hookContextAt(ranges, inner);
    expect(ctx.kind).toBe('hook');
    expect(ctx.name).toBe('useLocal');
  });

  it('gives no context for a lowercase helper function', () => {
    const src = `function formatDate(d) { return d.toISOString(); }`;
    const ranges = getHookContextRanges(src);
    expect(hookContextAt(ranges, src.indexOf('toISOString'))).toBeNull();
  });

  it('resolves names through export default and object properties', () => {
    const src = `export default function App() { return null; }
const api = { useFetch: function () { return 1; } };`;
    const ranges = getHookContextRanges(src);
    expect(ranges.some((r) => r.name === 'useFetch' && r.kind === 'hook')).toBe(true);
  });

  it('returns [] on unparseable content', () => {
    expect(getHookContextRanges('%%% not js %%%')).toEqual([]);
  });
});

describe('getAsyncContextRanges', () => {
  it('collects async function ranges with names', () => {
    const src = `async function load() { await fetch('/x'); }`;
    const { asyncRanges } = getAsyncContextRanges(src);
    expect(asyncRanges).toHaveLength(1);
    expect(asyncRanges[0].name).toBe('load');
  });

  it('flags forEach with an async callback as a hazard', () => {
    const src = `items.forEach(async (item) => { await save(item); });`;
    const { hazards } = getAsyncContextRanges(src);
    expect(hazards).toHaveLength(1);
    expect(hazards[0].kind).toBe('async-forEach-callback');
    expect(hazards[0].line).toBe(1);
  });

  it('does not flag map with an async callback (Promise.all is legitimate)', () => {
    const src = `const all = await Promise.all(items.map(async (i) => fetchOne(i)));`;
    const { hazards } = getAsyncContextRanges(src);
    expect(hazards).toEqual([]);
  });

  it('does not flag forEach with a sync callback', () => {
    const src = `items.forEach((item) => save(item));`;
    const { hazards } = getAsyncContextRanges(src);
    expect(hazards).toEqual([]);
  });
});

describe('parseModule', () => {
  it('parses JSX', () => {
    expect(parseModule('const A = () => <div/>;')).not.toBeNull();
  });
  it('falls back to loose parse on syntax errors', () => {
    expect(parseModule('function f( {')).not.toBeNull();
  });
  it('returns null on empty content', () => {
    expect(parseModule('')).toBeNull();
  });
});

describe('probeHostDetection', () => {
  it('emits one info finding when a host is detected', () => {
    const f = probeHostDetection([file('.cursorrules', 'x')]);
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('info');
    expect(f[0].title).toContain('Cursor');
    expect(f[0].evidence).toContain('.cursorrules');
  });

  it('lists every detected host in the evidence when several match', () => {
    const f = probeHostDetection([file('.cursorrules', 'x'), file('CLAUDE.md', 'x')]);
    expect(f).toHaveLength(1);
    expect(f[0].evidence).toContain('Claude Code');
  });

  it('stays silent when no host is detected', () => {
    expect(probeHostDetection([file('src/a.js', 'x')])).toEqual([]);
  });

  it('returns an array on empty input (registry contract)', () => {
    expect(probeHostDetection([])).toEqual([]);
  });
});
