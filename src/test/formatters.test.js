import { describe, it, expect } from 'vitest';
import {
  formatJSON,
  formatMarkdown,
  formatAgentPrompt,
  formatPRComment,
  buildSnippet,
  computeDiffAgainstPrior,
  makeHistoryEntry,
} from '../App.jsx';

const sampleResults = () => ({
  findings: [
    {
      id: 'a',
      probe: 'Secret Scanner',
      title: 'AWS Access Key found',
      severity: 'critical',
      category: 'Data Breach',
      cwe: 'CWE-798',
      file: 'src/config.js',
      line: 7,
      evidence: 'const k = "AK...XXXX"',
      remediation: 'Rotate the key.',
      snippet: buildSnippet('a\nb\nc\nd\ne\nf\ng\nh\ni\nj', 7, 2),
    },
    {
      id: 'b',
      probe: 'CORS',
      title: 'Wildcard CORS',
      severity: 'medium',
      category: 'Misconfiguration',
      cwe: 'CWE-942',
      file: 'src/api.ts',
      line: 1,
      evidence: '*',
      remediation: 'Use an allowlist.',
      snippet: null,
    },
  ],
  score: 65,
  scannedAt: new Date('2026-05-10T12:00:00Z'),
  filesScanned: 2,
  source: 'https://github.com/owner/repo',
});

describe('formatJSON', () => {
  it('produces valid JSON with the expected schema', () => {
    const out = formatJSON(sampleResults());
    const parsed = JSON.parse(out);
    expect(parsed.schema).toBe('midatlantic-audit/v1');
    expect(parsed.score).toBe(65);
    expect(parsed.summary.total).toBe(2);
    expect(parsed.summary.bySeverity.critical).toBe(1);
    expect(parsed.summary.bySeverity.medium).toBe(1);
    expect(parsed.findings).toHaveLength(2);
  });

  it('serializes scannedAt as ISO string', () => {
    const parsed = JSON.parse(formatJSON(sampleResults()));
    expect(parsed.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('includes snippet text in findings that have one', () => {
    const parsed = JSON.parse(formatJSON(sampleResults()));
    expect(parsed.findings[0].snippet).not.toBeNull();
    expect(parsed.findings[0].snippet.text).toContain('> g'); // line 7 of "a..j"
    expect(parsed.findings[1].snippet).toBeNull();
  });
});

describe('formatMarkdown', () => {
  it('contains the headline and risk tier', () => {
    const md = formatMarkdown(sampleResults());
    expect(md).toMatch(/^# Pre-Flight Security Audit/);
    // Severity-aware: the fixture has a critical finding, so the tier is
    // CRITICAL regardless of the 65 numeric score (the old code mislabelled
    // this MODERATE, the reverse of the cosmetic-only false alarm).
    expect(md).toMatch(/CRITICAL RISK/);
    expect(md).toMatch(/score 65/);
  });

  it('includes a section per finding with file path and severity', () => {
    const md = formatMarkdown(sampleResults());
    expect(md).toMatch(/\[CRITICAL\] AWS Access Key found/);
    expect(md).toMatch(/`src\/config.js:7`/);
    expect(md).toMatch(/\[MEDIUM\] Wildcard CORS/);
  });

  it('embeds code snapshot in a fenced block', () => {
    const md = formatMarkdown(sampleResults());
    expect(md).toMatch(/```[\s\S]*?> g[\s\S]*?```/);
  });
});

describe('formatPRComment', () => {
  it('starts with a summary heading and severity counts', () => {
    const md = formatPRComment(sampleResults());
    expect(md).toMatch(/^## .* CRITICAL RISK \(65\/100\)/m);
    expect(md).toMatch(/1 critical/);
    expect(md).toMatch(/1 medium/);
  });

  it('wraps findings in a collapsible <details> block', () => {
    const md = formatPRComment(sampleResults());
    expect(md).toContain('<details>');
    expect(md).toContain('</details>');
  });

  it('groups findings by file', () => {
    const md = formatPRComment(sampleResults());
    expect(md).toMatch(/`src\/config\.js`/);
    expect(md).toMatch(/`src\/api\.ts`/);
  });

  it('reports cleanly when no findings', () => {
    const clean = { ...sampleResults(), findings: [], score: 100 };
    const md = formatPRComment(clean);
    expect(md).toMatch(/No findings/);
  });
});

describe('computeDiffAgainstPrior', () => {
  const finding = (id, severity, file, title) => ({
    id,
    severity,
    file,
    line: 1,
    title,
    probe: 'X',
    category: 'Data Breach',
    cwe: 'CWE-1',
    evidence: 'e',
    remediation: 'r',
  });

  const mkCurrent = (findings, score = 80, source = 'https://github.com/a/b') => ({
    findings,
    score,
    scannedAt: new Date('2026-05-11T10:00:00Z'),
    filesScanned: 5,
    source,
  });

  it('returns null when there is no prior history', () => {
    const cur = mkCurrent([]);
    expect(computeDiffAgainstPrior(cur, [])).toBeNull();
  });

  it('returns null when prior history is for a different source', () => {
    const cur = mkCurrent([], 80, 'https://github.com/a/b');
    const prior = makeHistoryEntry(
      {
        findings: [],
        score: 100,
        scannedAt: new Date('2026-05-10T10:00:00Z'),
        filesScanned: 5,
        source: 'https://github.com/different/repo',
      },
      'github'
    );
    expect(computeDiffAgainstPrior(cur, [prior])).toBeNull();
  });

  it('counts introduced, fixed, and persisted findings', () => {
    const cur = mkCurrent(
      [finding('a', 'critical', 'x.js', 'Persists'), finding('b', 'high', 'y.js', 'New')],
      65
    );
    const priorEntry = makeHistoryEntry(
      {
        findings: [
          finding('a2', 'critical', 'x.js', 'Persists'), // same key → persisted
          finding('c', 'medium', 'z.js', 'Fixed'), // gone now → fixed
        ],
        score: 80,
        scannedAt: new Date('2026-05-10T10:00:00Z'),
        filesScanned: 5,
        source: 'https://github.com/a/b',
      },
      'github'
    );
    const diff = computeDiffAgainstPrior(cur, [priorEntry]);
    expect(diff.introduced.count).toBe(1);
    expect(diff.fixed.count).toBe(1);
    expect(diff.persisted.count).toBe(1);
    expect(diff.deltaScore).toBe(65 - 80);
  });
});

describe('formatAgentPrompt', () => {
  it('starts with role-setting language', () => {
    const p = formatAgentPrompt(sampleResults());
    expect(p).toMatch(/senior application-security engineer/i);
  });

  it('lists findings with file:line', () => {
    const p = formatAgentPrompt(sampleResults());
    expect(p).toContain('src/config.js:7');
    expect(p).toContain('src/api.ts:1');
  });

  it('truncates very long finding lists with a note', () => {
    const big = sampleResults();
    big.findings = Array.from({ length: 50 }, (_, i) => ({
      ...big.findings[0],
      id: `f${i}`,
      title: `Finding ${i}`,
    }));
    const p = formatAgentPrompt(big);
    expect(p).toMatch(/\d+ additional findings omitted/);
  });
});
