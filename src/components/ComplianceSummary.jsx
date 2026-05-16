// src/components/ComplianceSummary.jsx
//
// The compliance / GRC lens. Collapsible roll-up of every finding's
// compliance_refs, grouped by framework -> clause, shown ABOVE the
// findings list so a non-coder can read the regulatory picture without
// expanding 40 cards.
//
// Safety / honesty contract:
//   - Renders nothing unless >=1 finding carries a scan-scope mapping.
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

export function ComplianceSummary({ findings, scannedAt }) {
  const summary = useMemo(() => summarizeCompliance(findings), [findings]);
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  if (!summary || summary.mappedFindingCount === 0) return null;

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
        <span style={{ marginLeft: 'auto', color: T.textMuted }}>
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 16px 16px 16px', borderTop: `1px solid ${T.border}` }}>
          {summary.frameworks.map((fw) => (
            <div key={fw.framework} style={{ marginTop: 12 }}>
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
              {fw.clauses.map((c) => (
                <div
                  key={c.clause}
                  className="ap-mono"
                  style={{ fontSize: 12, color: T.textMuted, marginBottom: 2 }}
                >
                  <span style={{ color: c.relationship === 'direct' ? T.text : T.textMuted }}>
                    [{c.relationship}]
                  </span>{' '}
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
              const ok = await copyToClipboard(formatComplianceExport(summary, scannedAt));
              if (ok) {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              } else {
                log.warn('compliance: export copy failed');
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
