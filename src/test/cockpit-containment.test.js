// Containment proof for the host embedding seam: force an engine stage to
// throw and assert scan() returns a degraded result with the stage recorded,
// rather than letting the throw escape to the embedding host. Lives in its own
// file because vi.mock is module-wide — cockpit-scan.test.js needs the real
// app-shape module for its parity proof.
import { describe, it, expect, vi } from 'vitest';

vi.mock('../lib/probes/v2/app-shape.js', async (importOriginal) => {
  const real = await importOriginal();
  return {
    ...real,
    applyAppShape: () => {
      throw new Error('forced: app-shape stage exploded');
    },
  };
});

import { scan } from '../lib/cockpit-scan.js';

const FILES = [
  {
    path: 'src/config.js',
    content:
      'const OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu";\nexport const db = { url: process.env.DB };\n',
  },
];

describe('cockpit-scan: engine stage containment (forced failure)', () => {
  it('a throwing stage degrades and is recorded, and the scan still returns', () => {
    let result;
    expect(() => {
      result = scan(FILES);
    }).not.toThrow();
    expect(result.engineFailures).toEqual([
      { stage: 'app-shape', error: 'forced: app-shape stage exploded' },
    ]);
    // Fallback is the unshaped findings — present, never dropped.
    expect(result.findings.length).toBeGreaterThan(0);
    // Later stages still ran over the fallback: score is a real number.
    expect(typeof result.score).toBe('number');
  });

  it('opts.onEngineError hears about the stage, like onProbeError for probes', () => {
    const heard = [];
    scan(FILES, { onEngineError: (stage, err) => heard.push([stage, err.message]) });
    expect(heard).toEqual([['app-shape', 'forced: app-shape stage exploded']]);
  });

  it('a throwing onEngineError callback is dropped, never allowed to escape', () => {
    // The callback is the error channel; its own bug replacing the stage error
    // and escaping scan() was the exact hole the failure contract forbids.
    let result;
    expect(() => {
      result = scan(FILES, {
        onEngineError: () => {
          throw new Error('host logger bug');
        },
      });
    }).not.toThrow();
    expect(result.engineFailures).toEqual([
      { stage: 'app-shape', error: 'forced: app-shape stage exploded' },
    ]);
  });

  it('opts: null survives the engine-failure path', () => {
    // A default param does not catch an explicit null, and opts is read in
    // contained()'s catch — the worst place to throw.
    expect(() => scan(FILES, null)).not.toThrow();
  });
});
