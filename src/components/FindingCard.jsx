// src/components/FindingCard.jsx
// Renders one finding row. Collapsed: severity chip, category badge, CWE label, title.
// Expanded: the evidence string, the ±5-line code snapshot with a copy-to-clipboard
// button, the remediation copy, and the action footer (suppress dispositions and the
// Explain & Verify BYOK trigger).
//
// State is owned by the parent App (expanded set, suppression store, AI responses).
// This component is pure-presentational + callback driven.

import { ChevronDown, ChevronRight, Copy, MessageSquare, RefreshCw } from 'lucide-react';
import { T, fontMono } from '../lib/theme.js';
import { log } from '../lib/logger.js';
import { copyToClipboard, timeAgo } from '../lib/clipboard.js';
import { snippetToText } from '../lib/snippet.js';
import { SeverityChip } from './ScoreDisplay.jsx';
import { BreakersPanel } from './BreakersPanel.jsx';

export function FindingCard({
  finding,
  complianceScope,
  expanded,
  onToggle,
  onSuppress,
  onUnsuppress,
  aiResponse,
  onExplainVerify,
  aiEnabled,
}) {
  const c = T.sev[finding.severity];
  return (
    <div className="ap-finding" style={{ borderLeftColor: c.fg, marginBottom: 8 }}>
      <button
        onClick={onToggle}
        style={{
          width: '100%',
          background: 'transparent',
          border: 'none',
          cursor: 'pointer',
          padding: '14px 16px',
          display: 'flex',
          alignItems: 'flex-start',
          gap: 12,
          textAlign: 'left',
          color: T.text,
          fontFamily: fontMono,
        }}
      >
        <div style={{ marginTop: 2, color: T.textMuted }}>
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: 'flex',
              gap: 8,
              alignItems: 'center',
              flexWrap: 'wrap',
              marginBottom: 6,
            }}
          >
            <SeverityChip severity={finding.severity} />
            <span
              className="ap-mono"
              style={{
                fontSize: 11,
                color: T.cat[finding.category],
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              {finding.category}
            </span>
            <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
              {finding.cwe}
            </span>
            {finding.owasp && finding.owasp.length > 0 && (
              <span
                className="ap-mono"
                title={`Maps to OWASP ${finding.owasp.join(', ')}`}
                style={{
                  fontSize: 11,
                  color: T.textDim,
                  background: T.panelAlt,
                  border: `1px solid ${T.border}`,
                  padding: '1px 6px',
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                }}
              >
                OWASP {finding.owasp.join(', ')}
              </span>
            )}
            {finding.confidence && (
              <span
                className="ap-mono"
                title={
                  finding.confidence === 'high'
                    ? 'High confidence — deterministic pattern match'
                    : finding.confidence === 'medium'
                      ? 'Medium confidence — regex match that benefits from a glance'
                      : 'Heuristic — path / structural inference; manual review recommended'
                }
                style={{
                  fontSize: 11,
                  color: T.textDim,
                  background: T.panelAlt,
                  border: `1px solid ${T.border}`,
                  padding: '1px 6px',
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase',
                }}
              >
                {finding.confidence === 'heuristic' ? 'heur.' : finding.confidence}
              </span>
            )}
            {finding.autofix && (
              <span
                className="ap-mono"
                title={
                  finding.autofix === 'mechanical'
                    ? 'Mechanical — a one-or-two-line drop-in patch fixes it'
                    : finding.autofix === 'review-needed'
                      ? 'Review needed — clear remediation path, requires reading surrounding code'
                      : 'Manual — architectural / scope-dependent; no canned fix'
                }
                style={{
                  fontSize: 11,
                  // Mint highlight on "mechanical" — easy-win signal.
                  color:
                    finding.autofix === 'mechanical'
                      ? T.bg
                      : finding.autofix === 'review-needed'
                        ? T.textDim
                        : T.textMuted,
                  background: finding.autofix === 'mechanical' ? T.accentAlt : T.panelAlt,
                  border: `1px solid ${finding.autofix === 'mechanical' ? T.accentAlt : T.border}`,
                  padding: '1px 6px',
                  letterSpacing: '0.08em',
                  textTransform: 'uppercase',
                  fontWeight: finding.autofix === 'mechanical' ? 600 : 400,
                }}
              >
                {finding.autofix === 'mechanical'
                  ? 'easy fix'
                  : finding.autofix === 'review-needed'
                    ? 'review'
                    : 'manual'}
              </span>
            )}
            {(() => {
              // Compliance chip is gated by the user's DECLARED regulatory
              // scope. No declaration => no chip, even though the family
              // carries refs. This is the fix for "a plain email app should
              // not be told it fails HIPAA/SOC2".
              const declared = Array.isArray(complianceScope) ? complianceScope : [];
              if (declared.length === 0) return null;
              const refs = Array.isArray(finding.compliance_refs)
                ? finding.compliance_refs.filter((r) => declared.includes(r.framework))
                : [];
              if (refs.length === 0) return null;
              const hasDirect = refs.some((r) => r.relationship === 'direct');
              return (
                <span
                  className="ap-mono"
                  title={
                    refs
                      .map((r) => `${r.framework} ${r.clause} (${r.relationship}) — ${r.url}`)
                      .join('\n') +
                    '\n\nYou declared this regulatory scope. Interpretation layer, ' +
                    'not a compliance determination. "indicative" needs human ' +
                    'judgement in context. Not legal advice.'
                  }
                  style={{
                    fontSize: 11,
                    color: hasDirect ? T.text : T.textMuted,
                    background: T.panelAlt,
                    border: `1px solid ${T.border}`,
                    padding: '1px 6px',
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase',
                    fontWeight: hasDirect ? 600 : 400,
                  }}
                >
                  MAPS TO {[...new Set(refs.map((r) => r.framework))].join(', ')}
                </span>
              );
            })()}
          </div>
          <div style={{ fontSize: 14, color: T.text, marginBottom: 4, fontWeight: 500 }}>
            {finding.title}
          </div>
          <div
            className="ap-mono"
            style={{ fontSize: 12, color: T.textMuted, wordBreak: 'break-all' }}
          >
            {finding.file}
            {finding.line ? `:${finding.line}` : ''}
          </div>
        </div>
      </button>
      {expanded && (
        <div
          className="ap-fade-in"
          style={{
            padding: '0 16px 16px 42px',
            borderTop: `1px solid ${T.border}`,
            marginTop: 4,
            paddingTop: 14,
          }}
        >
          <div className="ap-eyebrow" style={{ marginBottom: 6 }}>
            EVIDENCE
          </div>
          <pre
            style={{
              margin: 0,
              padding: 12,
              background: T.bg,
              border: `1px solid ${T.border}`,
              fontSize: 13,
              color: T.textDim,
              overflowX: 'auto',
              fontFamily: fontMono,
              whiteSpace: 'pre-wrap',
              wordBreak: 'break-all',
            }}
          >
            {finding.evidence || '(no snippet captured)'}
          </pre>
          {finding.snippet && (
            <>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginTop: 14,
                  marginBottom: 6,
                }}
              >
                <div className="ap-eyebrow">
                  CODE SNAPSHOT (lines {finding.snippet.startLine}–{finding.snippet.endLine})
                </div>
                <button
                  onClick={async () => {
                    try {
                      const ok = await copyToClipboard(snippetToText(finding.snippet));
                      if (ok) {
                        // brief visual confirmation via title on the button itself
                      }
                    } catch (e) {
                      log.debug('snippet: copy failed', { error: e?.message });
                    }
                  }}
                  className="ap-mono"
                  style={{
                    background: 'transparent',
                    border: `1px solid ${T.border}`,
                    color: T.textMuted,
                    cursor: 'pointer',
                    fontSize: 11,
                    padding: '3px 8px',
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                  }}
                  title="Copy snippet"
                >
                  <Copy
                    size={10}
                    style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
                  />
                  copy
                </button>
              </div>
              <pre
                style={{
                  margin: 0,
                  padding: 12,
                  background: T.bg,
                  border: `1px solid ${T.border}`,
                  fontSize: 13,
                  overflowX: 'auto',
                  fontFamily: fontMono,
                  whiteSpace: 'pre',
                  lineHeight: 1.5,
                }}
              >
                {finding.snippet.lines.map((l) => (
                  <div
                    key={l.n}
                    aria-label={l.isHit ? `Offending line ${l.n}` : undefined}
                    style={{
                      display: 'flex',
                      // Stronger hit-line distinction: solid panelAlt background (was severity.bg ~ 1.13:1)
                      // plus a thicker 4px left border in the severity color.
                      background: l.isHit ? T.panelAlt : 'transparent',
                      borderLeft: l.isHit
                        ? `4px solid ${T.sev[finding.severity].fg}`
                        : '4px solid transparent',
                      paddingLeft: 6,
                      fontWeight: l.isHit ? 600 : 400,
                    }}
                  >
                    {/* Non-color marker for screen-reader / accessibility — a visible chevron pointing at the hit line. */}
                    <span
                      aria-hidden="true"
                      style={{
                        width: 14,
                        flexShrink: 0,
                        color: l.isHit ? T.sev[finding.severity].fg : 'transparent',
                        fontWeight: 700,
                      }}
                    >
                      {l.isHit ? '▶' : ' '}
                    </span>
                    <span
                      style={{
                        color: l.isHit ? T.sev[finding.severity].fg : T.textMuted,
                        width: 36,
                        flexShrink: 0,
                        textAlign: 'right',
                        paddingRight: 10,
                        userSelect: 'none',
                      }}
                    >
                      {l.n}
                    </span>
                    <span style={{ color: l.isHit ? T.text : T.textDim }}>{l.text || ' '}</span>
                  </div>
                ))}
              </pre>
            </>
          )}
          <div className="ap-eyebrow" style={{ marginTop: 14, marginBottom: 6 }}>
            REMEDIATION
          </div>
          <div style={{ fontSize: 14, color: T.textDim, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
            {finding.remediation}
          </div>
          {/* Breakers — adversarial inputs (v1, feature/breakers-v1 branch).
              Static-only display of what an attacker would type to exploit this finding.
              Pre-Flight never executes the payloads; they ship as strings with copy buttons
              and explanations of where and how the input is processed. */}
          <BreakersPanel probeName={finding.probe} xlFamily={finding.xl_family} />
          {/* Explain & Verify — BYOK AI feature.
              The button calls the user's chosen provider with the user's key. The response is
              visually segregated (panel-alt background, provider eyebrow) so users always know
              when they are reading the scanner's voice vs. the model's. */}
          {onExplainVerify && (
            <div style={{ marginTop: 14 }}>
              <div className="ap-eyebrow" style={{ marginBottom: 6 }}>
                AI ASSIST · uses your own key, sent only to the provider you chose
              </div>
              <button
                onClick={() => onExplainVerify(finding)}
                className="ap-btn ap-btn-ghost"
                disabled={aiResponse?.status === 'streaming'}
                style={{ fontSize: 12, padding: '6px 14px' }}
              >
                <MessageSquare
                  size={11}
                  aria-hidden="true"
                  style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                />
                {aiResponse?.status === 'streaming'
                  ? 'Streaming…'
                  : aiResponse?.status === 'done'
                    ? 'Re-run Explain & Verify'
                    : aiEnabled
                      ? 'Explain & Verify'
                      : 'Configure AI to enable'}
              </button>
              {aiResponse && (
                <div
                  role="region"
                  aria-label="AI-generated explanation and verification"
                  style={{
                    marginTop: 10,
                    padding: 14,
                    background: T.panelAlt,
                    border: `1px solid ${T.borderAlt}`,
                    borderLeft: `3px solid ${T.accentAlt}`,
                  }}
                >
                  <div
                    className="ap-mono"
                    style={{
                      fontSize: 11,
                      color: T.accentAlt,
                      marginBottom: 8,
                      letterSpacing: '0.1em',
                      textTransform: 'uppercase',
                    }}
                  >
                    AI · {aiResponse.provider || 'unknown provider'} · {aiResponse.model || '?'}
                    {aiResponse.status === 'streaming' && (
                      <span className="ap-pulse" style={{ marginLeft: 8 }}>
                        streaming…
                      </span>
                    )}
                  </div>
                  {aiResponse.status === 'error' ? (
                    <div style={{ fontSize: 13, color: T.sev.critical.fg }}>{aiResponse.error}</div>
                  ) : (
                    <div
                      style={{
                        fontSize: 14,
                        color: T.textDim,
                        lineHeight: 1.7,
                        whiteSpace: 'pre-wrap',
                      }}
                    >
                      {aiResponse.text || ' '}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
          <div style={{ marginTop: 12 }}>
            <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
              probe: {finding.probe}
            </span>
          </div>
          {/* Disposition row: lets the user decide what to do with this finding on future scans. */}
          {finding.suppression ? (
            <div style={{ marginTop: 14 }}>
              <div className="ap-eyebrow" style={{ marginBottom: 6 }}>
                DISPOSITION
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span
                  className="ap-mono"
                  style={{
                    fontSize: 11,
                    padding: '3px 8px',
                    background: T.panelAlt,
                    border: `1px solid ${T.borderAlt}`,
                    color: T.textDim,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                  }}
                >
                  {finding.suppression.disposition.replace(/-/g, ' ')}
                </span>
                <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
                  set {timeAgo(finding.suppression.at)}
                </span>
                {finding.suppression.note && (
                  <span style={{ fontSize: 12, color: T.textDim, fontStyle: 'italic' }}>
                    “{finding.suppression.note}”
                  </span>
                )}
                {onUnsuppress && (
                  <button
                    onClick={() => onUnsuppress(finding)}
                    className="ap-btn ap-btn-ghost"
                    style={{ padding: '4px 10px', fontSize: 11 }}
                  >
                    <RefreshCw
                      size={10}
                      aria-hidden="true"
                      style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                    />
                    Un-suppress
                  </button>
                )}
              </div>
            </div>
          ) : onSuppress ? (
            <div style={{ marginTop: 14 }}>
              <div className="ap-eyebrow" style={{ marginBottom: 6 }}>
                DISPOSITION · hide on future scans
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                <button
                  onClick={() => onSuppress(finding, 'false-positive')}
                  className="ap-btn ap-btn-ghost"
                  style={{ padding: '4px 10px', fontSize: 11 }}
                  title="The scanner is wrong — this is not a real issue"
                >
                  False positive
                </button>
                <button
                  onClick={() => onSuppress(finding, 'wont-fix')}
                  className="ap-btn ap-btn-ghost"
                  style={{ padding: '4px 10px', fontSize: 11 }}
                  title="Real issue but intentionally not fixing"
                >
                  Won't fix
                </button>
                <button
                  onClick={() => onSuppress(finding, 'accepted-risk')}
                  className="ap-btn ap-btn-ghost"
                  style={{ padding: '4px 10px', fontSize: 11 }}
                  title="Real risk that's been formally accepted"
                >
                  Accepted risk
                </button>
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
