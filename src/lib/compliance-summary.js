// src/lib/compliance-summary.js
//
// Aggregates per-finding compliance_refs into a scan-level view for the
// compliance / GRC persona. A non-coder cannot assemble the regulatory
// picture from individual FindingCard chips; this rolls them up by
// framework and clause.
//
// This is an INTERPRETATION layer over findings the scanner already
// emits, never a certification. The summary preserves the honest
// direct|indicative relationship and never collapses an indicative
// mapping into a stated violation. SCAN scope only — FERPA / SOX / FDA /
// FTC / EU-AI-Act never appear here (they are education-scope; the
// scanner does not detect them).

/**
 * @param {Array<{compliance_refs?: Array<{framework,clause,url,relationship}>}>} findings
 * @returns {{
 *   mappedFindingCount: number,
 *   frameworkCount: number,
 *   frameworks: Array<{framework:string, findingCount:number,
 *     clauses: Array<{clause:string,url:string,relationship:string,count:number}>}>,
 *   hasDirect: boolean,
 *   hasIndicative: boolean,
 * }}
 */
export function summarizeCompliance(findings) {
  const byFw = {};
  let mapped = 0;
  for (const f of findings || []) {
    const refs = f && f.compliance_refs;
    if (!Array.isArray(refs) || refs.length === 0) continue;
    mapped += 1;
    for (const r of refs) {
      if (!r || !r.framework) continue;
      const fw = (byFw[r.framework] ||= {
        framework: r.framework,
        findingCount: 0,
        clauses: {},
      });
      fw.findingCount += 1;
      const c = (fw.clauses[r.clause] ||= {
        clause: r.clause,
        url: r.url,
        relationship: r.relationship,
        count: 0,
      });
      c.count += 1;
      // 'direct' dominates the displayed relationship for a clause: if any
      // mapping is direct the pattern itself is the clause failure.
      if (r.relationship === 'direct') c.relationship = 'direct';
    }
  }
  const frameworks = Object.values(byFw)
    .map((fw) => ({
      ...fw,
      clauses: Object.values(fw.clauses).sort((a, b) => b.count - a.count),
    }))
    .sort((a, b) => b.findingCount - a.findingCount);
  return {
    mappedFindingCount: mapped,
    frameworkCount: frameworks.length,
    frameworks,
    hasDirect: frameworks.some((fw) => fw.clauses.some((c) => c.relationship === 'direct')),
    hasIndicative: frameworks.some((fw) => fw.clauses.some((c) => c.relationship === 'indicative')),
  };
}

const DISCLAIMER =
  'Interpretation layer, not a compliance determination or legal advice. ' +
  '"indicative" mappings need human judgement in context. Pre-Flight scans ' +
  'only code-detectable technical safeguards (HIPAA 164.312, PCI-DSS, GDPR ' +
  'Art.32/25, SOC2 readiness). It does not scan FERPA, SOX, FDA 21 CFR 11, ' +
  'FTC, or the EU AI Act; those are taught in the compliance Learn pages, ' +
  'not detected.';

export { DISCLAIMER as COMPLIANCE_DISCLAIMER };

/**
 * Plain-text / markdown auditor handoff. Deterministic; no PII; mirrors
 * the on-screen summary so a GRC reviewer can attach it to a workpaper.
 * @param {ReturnType<typeof summarizeCompliance>} summary
 * @param {string} [scannedAt]
 * @returns {string}
 */
export function formatComplianceExport(summary, scannedAt) {
  const lines = [];
  lines.push('# Pre-Flight regulatory mapping (scan-scope)');
  lines.push('');
  if (scannedAt) lines.push(`Scan: ${scannedAt}`);
  lines.push(
    `${summary.mappedFindingCount} finding(s) map to ${summary.frameworkCount} framework(s).`
  );
  lines.push('');
  for (const fw of summary.frameworks) {
    lines.push(`## ${fw.framework} (${fw.findingCount} finding-refs)`);
    for (const c of fw.clauses) {
      lines.push(`- ${c.clause} [${c.relationship}] x${c.count} — ${c.url}`);
    }
    lines.push('');
  }
  lines.push('---');
  lines.push(DISCLAIMER);
  return lines.join('\n');
}
