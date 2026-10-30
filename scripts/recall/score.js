// Pure benchmark validation and scoring. No scanner imports or title heuristics.
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
export const canonical = (value) => JSON.stringify(value);
const validPath = (p) =>
  typeof p === 'string' &&
  p.length > 0 &&
  !p.includes('\\') &&
  !p.startsWith('/') &&
  !p.split('/').some((s) => !s || s === '.' || s === '..');
const requireValue = (ok, message) => {
  if (!ok) throw new Error(message);
};

export function validateManifest(manifest) {
  requireValue(manifest?.schemaVersion === 1, 'Unsupported manifest schemaVersion');
  requireValue(Array.isArray(manifest.cases) && manifest.cases.length > 0, 'Empty cases');
  const ids = new Set();
  for (const c of manifest.cases) {
    requireValue(typeof c.id === 'string' && c.id && !ids.has(c.id), 'Invalid/duplicate case id');
    ids.add(c.id);
    requireValue(['independent', 'preflight-fixture'].includes(c.provenance), 'Invalid provenance');
    for (const key of ['corpus', 'language', 'source', 'license', 'labelBasis']) {
      requireValue(typeof c[key] === 'string' && c[key].trim(), `Missing ${key}: ${c.id}`);
    }
    requireValue(Array.isArray(c.files) && c.files.length > 0, `Empty files: ${c.id}`);
    const paths = new Set();
    for (const f of c.files) {
      requireValue(
        validPath(f.path) && validPath(f.scanPath) && !paths.has(f.scanPath),
        'Invalid/duplicate file path'
      );
      requireValue(/^[a-f0-9]{64}$/.test(f.sha256), 'Missing file sha256');
      paths.add(f.scanPath);
    }
    requireValue(Array.isArray(c.labels) && c.labels.length > 0, `Empty labels: ${c.id}`);
    const labelIds = new Set();
    for (const l of c.labels) {
      requireValue(
        typeof l.id === 'string' && l.id && !labelIds.has(l.id),
        'Invalid/duplicate label id'
      );
      labelIds.add(l.id);
      requireValue(paths.has(l.file) && /^CWE-[1-9]\d*$/.test(l.cwe), 'Invalid label file/CWE');
      requireValue(
        Number.isInteger(l.startLine) &&
          Number.isInteger(l.endLine) &&
          l.startLine > 0 &&
          l.endLine >= l.startLine,
        'Invalid label range'
      );
      requireValue(['positive', 'negative', 'excluded'].includes(l.kind), 'Invalid label kind');
      requireValue(
        l.kind !== 'excluded' || (typeof l.reason === 'string' && l.reason.trim()),
        'Exclusion requires reason'
      );
    }
    for (let i = 0; i < c.labels.length; i++) {
      for (const b of c.labels.slice(i + 1)) {
        const a = c.labels[i];
        requireValue(
          !(
            a.file === b.file &&
            a.cwe === b.cwe &&
            a.startLine <= b.endLine &&
            b.startLine <= a.endLine
          ),
          'Ambiguous overlapping labels'
        );
      }
    }
  }
  return manifest;
}

export function normalizeFinding(f) {
  return {
    file: typeof f.file === 'string' ? f.file.replace(/\\/g, '/').replace(/^\.\//, '') : null,
    line: Number.isInteger(f.line) && f.line > 0 ? f.line : null,
    cwe: /^CWE-[1-9]\d*$/.test(f.cwe) ? f.cwe : null,
    probe: typeof f.probe === 'string' ? f.probe : null,
    title: typeof f.title === 'string' ? f.title : null,
  };
}

export function scoreCase(c, rawFindings) {
  const findings = rawFindings
    .map(normalizeFinding)
    .sort((a, b) => cmp(canonical(a), canonical(b)));
  const results = [...c.labels]
    .sort((a, b) => cmp(a.id, b.id))
    .map((l) => {
      const matches = findings.filter(
        (f) => f.file === l.file && f.cwe === l.cwe && f.line >= l.startLine && f.line <= l.endLine
      );
      return {
        ...l,
        status:
          l.kind === 'excluded'
            ? 'excluded'
            : l.kind === 'positive'
              ? matches.length
                ? 'detected'
                : 'missed'
              : matches.length
                ? 'false-positive'
                : 'clear',
        findings: matches,
      };
    });
  const matched = new Set(results.flatMap((r) => r.findings));
  return {
    id: c.id,
    corpus: c.corpus,
    provenance: c.provenance,
    language: c.language,
    results,
    unadjudicated: findings.filter((f) => !matched.has(f)),
  };
}

export function scoreBenchmark(manifest, observations) {
  validateManifest(manifest);
  requireValue(
    observations && Object.keys(observations).length === manifest.cases.length,
    'Observations must cover exactly the manifest cases'
  );
  const cases = [...manifest.cases]
    .sort((a, b) => cmp(a.id, b.id))
    .map((c) => {
      requireValue(
        Object.hasOwn(observations, c.id) && Array.isArray(observations[c.id]),
        `Missing observations: ${c.id}`
      );
      return scoreCase(c, observations[c.id]);
    });
  const groups = new Map();
  for (const c of cases) {
    for (const r of c.results) {
      const key = canonical([c.corpus, c.provenance, c.language, r.cwe]);
      if (!groups.has(key))
        groups.set(key, {
          corpus: c.corpus,
          provenance: c.provenance,
          language: c.language,
          cwe: r.cwe,
          detected: 0,
          missed: 0,
          falsePositives: 0,
          clearNegatives: 0,
          excluded: 0,
          duplicateFindings: 0,
        });
      const row = groups.get(key);
      const field = {
        detected: 'detected',
        missed: 'missed',
        'false-positive': 'falsePositives',
        clear: 'clearNegatives',
        excluded: 'excluded',
      }[r.status];
      row[field]++;
      if (r.kind !== 'excluded') row.duplicateFindings += Math.max(0, r.findings.length - 1);
    }
  }
  const scorecards = [...groups.entries()]
    .sort(([a], [b]) => cmp(a, b))
    .map(([, row]) => ({
      ...row,
      positives: row.detected + row.missed,
      recall: row.detected + row.missed ? row.detected / (row.detected + row.missed) : null,
    }));
  return { schemaVersion: 1, scorecards, cases };
}
