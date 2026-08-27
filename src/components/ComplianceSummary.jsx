// src/components/ComplianceSummary.jsx
//
// The compliance / GRC lens. Collapsible roll-up of every finding's
// compliance_refs, grouped by framework -> clause, shown ABOVE the
// findings list so a non-coder can read the regulatory picture without
// expanding 40 cards.
//
// Safety / honesty contract:
//   - Declare nothing, get nothing: with no declared scope this renders
//     nothing at all, which is the un-regulated default.
//   - Declare a regime and map nothing, and it says so explicitly rather
//     than disappearing. A vanished panel is indistinguishable from a
//     broken one, and an absent regulatory report reads as a clean one.
//   - Preserves direct|indicative; never states a violation.
//   - Carries the not-a-certification / not-legal-advice disclaimer and
//     the scan-scope-vs-education line inline.
//   - Text children only (no dangerouslySetInnerHTML); export is
//     copy-to-clipboard (no fetch, consistent with the privacy contract).

import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, Copy, ChevronDown, ChevronRight } from 'lucide-react';
import {
  summarizeCompliance,
  formatComplianceExport,
  COMPLIANCE_DISCLAIMER,
} from '../lib/compliance-summary.js';
import { T, fontMono } from '../lib/theme.js';
import { copyToClipboard } from '../lib/clipboard.js';
import { log } from '../lib/logger.js';

export function ComplianceSummary({ findings, scope, scannedAt }) {
  const summary = useMemo(() => summarizeCompliance(findings, scope), [findings, scope]);
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  // How many of the MAPPED findings are critical or high. Counted over the same
  // scope filter the summary uses, so the badge and the roll-up never disagree.
  const severeMappedCount = useMemo(() => {
    const inScope = new Set(Array.isArray(scope) ? scope : []);
    if (inScope.size === 0) return 0;
    return (findings || []).filter(
      (f) =>
        (f?.severity === 'critical' || f?.severity === 'high') &&
        Array.isArray(f?.compliance_refs) &&
        f.compliance_refs.some((r) => r && inScope.has(r.framework))
    ).length;
  }, [findings, scope]);

  // Declared a regime and nothing mapped: SAY SO. Rendering nothing here is the
  // same failure as a mapping filed under a name that never fires, one layer up
  // in the UI. The user selected SOC2, the panel vanished, and there is no way
  // to tell "no findings mapped" apart from "the feature is broken". Silence
  // reads as a clean result, which is the one thing this panel must never imply.
  const declared = summary?.declaredScope || [];
  if (!summary || summary.mappedFindingCount === 0) {
    if (declared.length === 0) return null; // un-regulated default: no output at all
    return (
      <section
        aria-label="Regulatory mapping summary"
        className="ap-card"
        style={{ padding: '12px 16px', marginBottom: 16, border: `1px solid ${T.border}` }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontFamily: fontMono }}>
          <ShieldCheck size={15} style={{ color: T.textDim }} />
          <span style={{ fontSize: 13, fontWeight: 600, color: T.text }}>Regulatory mapping</span>
          <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
            {declared.join(', ')} declared · nothing mapped
          </span>
        </div>
        <div style={{ fontSize: 12, color: T.textDim, lineHeight: 1.6, marginTop: 8 }}>
          No finding in this scan maps to a scan-scope clause for{' '}
          {declared.length === 1 ? 'this regime' : 'these regimes'}. That is not a clean compliance
          result. PreFlight reads code, so it sees a narrow set of technical safeguards and cannot
          observe access decisions made at runtime, infrastructure policy, or anything about how the
          organisation operates.{' '}
          <Link to="/learn/patterns" style={{ color: T.accentAlt }}>
            Compliance Learn pages
          </Link>
          .
        </div>
      </section>
    );
  }

  return (
    <section
      aria-label="Regulatory mapping summary"
      className="ap-card"
      style={{ padding: 0, marginBottom: 16, border: `1px solid ${T.border}` }}
    >
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        style={{
          width: '100%',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          textAlign: 'left',
          color: T.text,
          fontFamily: fontMono,
        }}
      >
        <ShieldCheck size={15} style={{ color: T.textDim }} />
        <span style={{ fontSize: 13, fontWeight: 600 }}>Regulatory mapping</span>
        <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
          {summary.mappedFindingCount} finding{summary.mappedFindingCount === 1 ? '' : 's'} ·{' '}
          {summary.frameworks.map((f) => f.framework).join(', ')}
        </span>
        {/* Collapsed, "6 findings · SOC2" reads the same whether those six are
            informational or six criticals. The severity is the part that decides
            whether this panel is worth opening before an audit. */}
        {severeMappedCount > 0 && (
          <span
            className="ap-mono"
            style={{
              fontSize: 10,
              color: T.sev?.critical?.fg || T.textDim,
              border: `1px solid ${T.sev?.critical?.fg || T.border}`,
              borderRadius: 2,
              padding: '1px 6px',
              letterSpacing: '0.04em',
            }}
          >
            {severeMappedCount} CRITICAL/HIGH
          </span>
        )}
        <span style={{ marginLeft: 'auto', color: T.textMuted }}>
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 16px 16px 16px', borderTop: `1px solid ${T.border}` }}>
          {summary.frameworks.map((fw) => (
            <div key={fw.framework} style={{ marginTop: 14 }}>
              <div
                className="ap-mono"
                style={{
                  fontSize: 12,
                  color: T.text,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  marginBottom: 4,
                }}
              >
                {fw.framework}
              </div>

              {fw.direct.length > 0 && (
                <>
                  <div
                    className="ap-mono"
                    style={{ fontSize: 11, color: T.text, fontWeight: 600, margin: '4px 0 2px' }}
                  >
                    Direct — the pattern is itself the clause failure
                  </div>
                  {fw.direct.map((c) => (
                    <div
                      key={c.clause}
                      className="ap-mono"
                      style={{ fontSize: 12, color: T.text, marginBottom: 2 }}
                    >
                      {c.clause}
                      {c.count > 1 ? ` ·${c.count}` : ''}{' '}
                      <a
                        href={c.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        style={{ color: T.textDim }}
                      >
                        source
                      </a>
                    </div>
                  ))}
                </>
              )}

              {fw.indicative.length > 0 && (
                <>
                  <div
                    className="ap-mono"
                    style={{ fontSize: 11, color: T.textMuted, margin: '6px 0 2px' }}
                  >
                    Indicative — needs human judgement in context
                  </div>
                  {fw.indicative.map((c) => (
                    <div
                      key={c.clause}
                      className="ap-mono"
                      style={{ fontSize: 12, color: T.textMuted, marginBottom: 2 }}
                    >
                      {c.clause}
                      {c.count > 1 ? ` ·${c.count}` : ''}{' '}
                      <a
                        href={c.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        style={{ color: T.textDim }}
                      >
                        source
                      </a>
                    </div>
                  ))}
                </>
              )}
            </div>
          ))}

          <p style={{ fontSize: 11, color: T.textMuted, marginTop: 14, lineHeight: 1.5 }}>
            {COMPLIANCE_DISCLAIMER}{' '}
            <Link to="/learn/patterns" style={{ color: T.textDim }}>
              Compliance Learn pages
            </Link>
            .
          </p>

          <button
            onClick={async () => {
              try {
                const ok = await copyToClipboard(formatComplianceExport(summary, scannedAt));
                if (ok) {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                } else {
                  log.warn('compliance: export copy failed');
                }
              } catch (e) {
                log.warn('compliance: export copy threw', { error: e?.message });
              }
            }}
            className="ap-mono"
            style={{
              marginTop: 12,
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              fontSize: 11,
              padding: '4px 10px',
              cursor: 'pointer',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 6,
            }}
          >
            <Copy size={12} />
            {copied ? 'Copied' : 'Copy auditor handoff'}
          </button>
        </div>
      )}
    </section>
  );
}
