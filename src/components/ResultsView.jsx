// src/components/ResultsView.jsx
// The whole post-scan view: top-nav back-button, baseline-diff card, risk header with
// score gauge, category bars, top-3 findings preview, export/share toolbar, the filtered
// findings list, and the suppressed-findings section. Renders only when both `results`
// and `tier` are populated; the parent App gates with  to preserve the pre-extraction render contract.

import {
  AlertTriangle,
  Check,
  ChevronLeft,
  Copy,
  Download,
  FileJson,
  Github,
  MessageSquare,
  Minus,
  RefreshCw,
  ShieldCheck,
  TrendingDown,
  TrendingUp,
} from 'lucide-react';
import { T } from '../lib/theme.js';
import { SEV_ORDER } from '../lib/scoring.js';
import { timeAgo } from '../lib/clipboard.js';
import { PROBES } from '../lib/probes.js';
import { ScoreGauge, CategoryBar } from './ScoreDisplay.jsx';
import { FindingCard } from './FindingCard.jsx';
import { ComplianceSummary } from './ComplianceSummary.jsx';

export function ResultsView({
  // result data
  results,
  tier,
  liveScore,
  partitioned,
  sevCounts,
  catCounts,
  maxCat,
  diff,
  topFindings,
  filteredFindings,
  complianceScope,
  // navigation
  reset,
  // filter state
  filter,
  setFilter,
  // finding expansion
  expanded,
  setExpanded,
  // suppression
  handleSuppress,
  handleUnsuppress,
  showSuppressed,
  setShowSuppressed,
  // export
  handleExport,
  copied,
  // ai (BYOK Explain & Verify)
  aiResponses,
  handleExplainVerify,
  aiConfig,
  // probe runtime errors (when a probe throws during scan)
  probeErrors,
}) {
  return (
    <div className="ap-fade-in">
      {/* TOP NAV: clear way back to the input screen */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 16,
          gap: 12,
          flexWrap: 'wrap',
        }}
      >
        <button
          onClick={() => {
            reset();
            window.scrollTo({ top: 0, behavior: 'smooth' });
          }}
          className="ap-btn ap-btn-ghost"
          style={{ padding: '8px 14px', fontSize: 12 }}
          title="Go back to the input screen"
          type="button"
        >
          <ChevronLeft
            size={12}
            style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            aria-hidden="true"
          />
          Back to Home · New Scan
        </button>
        <span className="ap-mono" style={{ fontSize: 12, color: T.textMuted }}>
          Source: <span style={{ color: T.textDim, wordBreak: 'break-all' }}>{results.source}</span>
        </span>
      </div>

      {/* SCAN COVERAGE BANNER — fires when GitHub-URL mode sliced files off the
          bottom of the rank by the count cap, or skipped oversized blobs.
          Pre-2026-06 this was silent: a 158-file repo could lose 58 files to
          the cap with no UI signal. Folder/Files upload mode has no count
          cap, so coverage is null and the banner does not render. */}
      {results.coverage &&
        (results.coverage.droppedByCap > 0 || results.coverage.oversizedDropped > 0) && (
          <div
            className="ap-card"
            style={{
              padding: 12,
              marginBottom: 16,
              borderLeft: `3px solid ${T.sev.medium.fg}`,
            }}
          >
            <div className="ap-eyebrow" style={{ marginBottom: 6 }}>
              SCAN COVERAGE
            </div>
            <div className="ap-mono" style={{ fontSize: 13, color: T.textDim, lineHeight: 1.5 }}>
              Scanned {results.coverage.scanned} of {results.coverage.matched} matching files in
              this repo.{' '}
              {results.coverage.droppedByCap > 0 && (
                <>
                  {results.coverage.droppedByCap} were sliced off the bottom of the rank by the
                  per-scan cap of {results.coverage.capacityCap}.{' '}
                </>
              )}
              {results.coverage.oversizedDropped > 0 && (
                <>{results.coverage.oversizedDropped} were skipped as oversized. </>
              )}
              For complete coverage on a repo this size, use Files / Folder upload (no count cap).
            </div>
          </div>
        )}

      {/* BASELINE DIFF — only when there is a prior scan of the same source */}
      {diff && (
        <div className="ap-card" style={{ padding: 16, marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <span className="ap-eyebrow">
              DELTA SINCE {timeAgo(diff.priorScannedAt).toUpperCase()}
            </span>
            <span className="ap-mono" style={{ fontSize: 13, color: T.textDim }}>
              Prior score: {diff.priorScore} → {liveScore}
              {liveScore - diff.priorScore !== 0 && (
                <span
                  style={{
                    marginLeft: 8,
                    color: liveScore - diff.priorScore > 0 ? T.good : T.sev.critical.fg,
                    fontWeight: 600,
                  }}
                >
                  {liveScore - diff.priorScore > 0 ? (
                    <TrendingUp
                      size={11}
                      aria-hidden="true"
                      style={{
                        display: 'inline-block',
                        verticalAlign: '-1px',
                        marginRight: 2,
                      }}
                    />
                  ) : liveScore - diff.priorScore < 0 ? (
                    <TrendingDown
                      size={11}
                      aria-hidden="true"
                      style={{
                        display: 'inline-block',
                        verticalAlign: '-1px',
                        marginRight: 2,
                      }}
                    />
                  ) : (
                    <Minus
                      size={11}
                      aria-hidden="true"
                      style={{
                        display: 'inline-block',
                        verticalAlign: '-1px',
                        marginRight: 2,
                      }}
                    />
                  )}
                  {liveScore - diff.priorScore > 0 ? '+' : ''}
                  {liveScore - diff.priorScore}
                </span>
              )}
            </span>
          </div>
          <div style={{ display: 'flex', gap: 18, marginTop: 10, flexWrap: 'wrap' }}>
            <div>
              <span className="ap-mono" style={{ fontSize: 12, color: T.sev.critical.fg }}>
                NEW:
              </span>
              <span className="ap-mono" style={{ fontSize: 13, color: T.text, marginLeft: 6 }}>
                {diff.introduced.count}
              </span>
              {SEV_ORDER.filter((s) => diff.introduced.bySeverity[s]).map((s) => (
                <span
                  key={s}
                  className="ap-mono"
                  style={{
                    marginLeft: 6,
                    fontSize: 11,
                    padding: '1px 5px',
                    color: T.sev[s].fg,
                    background: T.sev[s].bg,
                    border: `1px solid ${T.sev[s].border}`,
                  }}
                >
                  {diff.introduced.bySeverity[s]} {s}
                </span>
              ))}
            </div>
            <div>
              <span className="ap-mono" style={{ fontSize: 12, color: T.good }}>
                FIXED:
              </span>
              <span className="ap-mono" style={{ fontSize: 13, color: T.text, marginLeft: 6 }}>
                {diff.fixed.count}
              </span>
              {SEV_ORDER.filter((s) => diff.fixed.bySeverity[s]).map((s) => (
                <span
                  key={s}
                  className="ap-mono"
                  style={{
                    marginLeft: 6,
                    fontSize: 11,
                    padding: '1px 5px',
                    color: T.sev[s].fg,
                    background: T.sev[s].bg,
                    border: `1px solid ${T.sev[s].border}`,
                  }}
                >
                  {diff.fixed.bySeverity[s]} {s}
                </span>
              ))}
            </div>
            <div>
              <span className="ap-mono" style={{ fontSize: 12, color: T.textMuted }}>
                STILL OPEN:
              </span>
              <span className="ap-mono" style={{ fontSize: 13, color: T.text, marginLeft: 6 }}>
                {partitioned.visible.length}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* RISK HEADER */}
      <div
        className="ap-card"
        style={{
          padding: 28,
          marginBottom: 16,
          borderColor: tier.ring,
          background: `linear-gradient(135deg, ${T.panel} 0%, ${T.bg} 100%)`,
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: 24,
          }}
        >
          <div style={{ flex: '1 1 320px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 16 }}>
              <AlertTriangle size={22} color={tier.color} strokeWidth={1.5} />
              <span
                className="ap-display"
                style={{
                  fontSize: 39,
                  color: tier.color,
                }}
              >
                {tier.label}
              </span>
              <span
                className="ap-mono"
                style={{
                  fontSize: 12,
                  color: tier.color,
                  background: 'rgba(0,0,0,0.3)',
                  border: `1px solid ${tier.ring}`,
                  padding: '4px 10px',
                  letterSpacing: '0.1em',
                }}
              >
                {partitioned.visible.length} OPEN
              </span>
            </div>

            {topFindings.length > 0 && (
              <>
                <div className="ap-eyebrow" style={{ marginBottom: 10 }}>
                  WHAT ATTACKERS CAN DO RIGHT NOW
                </div>
                <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                  {topFindings.map((f) => (
                    <li
                      key={f.id}
                      style={{
                        fontSize: 15,
                        color: T.text,
                        padding: '4px 0',
                        paddingLeft: 18,
                        position: 'relative',
                      }}
                    >
                      <span
                        aria-hidden="true"
                        style={{
                          position: 'absolute',
                          left: 0,
                          top: 10,
                          width: 6,
                          height: 6,
                          background: T.sev[f.severity].fg,
                          borderRadius: '50%',
                        }}
                      />
                      <span className="ap-sr-only">{f.severity}: </span>
                      <span
                        className="ap-mono"
                        style={{
                          fontSize: 11,
                          color: T.sev[f.severity].fg,
                          marginRight: 8,
                          textTransform: 'uppercase',
                          letterSpacing: '0.1em',
                          fontWeight: 600,
                        }}
                      >
                        {f.severity}
                      </span>
                      {f.title}
                    </li>
                  ))}
                </ul>
              </>
            )}

            {results.findings.length === 0 && results.filesScanned > 0 && (
              <div style={{ fontSize: 15, color: T.good, marginTop: 8 }}>
                <ShieldCheck
                  size={16}
                  aria-hidden="true"
                  style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-3px' }}
                />
                No findings from this probe set across {results.filesScanned} file
                {results.filesScanned === 1 ? '' : 's'}. This does not mean the app is fully secure;
                manual IDOR testing and runtime probing remain out of scope.
              </div>
            )}
            {results.filesScanned === 0 && (
              <div
                role="alert"
                style={{
                  fontSize: 15,
                  color: T.sev.high.fg,
                  marginTop: 8,
                  padding: 12,
                  background: T.sev.high.bg,
                  border: `1px solid ${T.sev.high.border}`,
                }}
              >
                <AlertTriangle
                  size={16}
                  aria-hidden="true"
                  style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-3px' }}
                />
                <strong>0 files were scanned</strong> — the score of {results.score}/100 is not
                real. The project may not contain any files matching our include patterns (.env,
                package.json, .ts/.tsx/.js/.jsx, .html, .py, .sql, firestore.rules, next.config.*,
                GitHub workflows, MCP configs). If this is an HTML-only or static project, the new
                HTML Hygiene probe should still find things — check that .html files were actually
                selected.
              </div>
            )}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
            <ScoreGauge score={liveScore} />
            {partitioned.suppressed.length > 0 && (
              <button
                onClick={() => setShowSuppressed((v) => !v)}
                className="ap-mono"
                style={{
                  background: 'transparent',
                  border: `1px solid ${T.border}`,
                  color: T.textMuted,
                  cursor: 'pointer',
                  fontSize: 11,
                  padding: '4px 10px',
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                }}
                title="Toggle the list of suppressed findings"
              >
                Score excludes {partitioned.suppressed.length} suppressed
              </button>
            )}
          </div>
        </div>
      </div>

      {/* META + CATEGORIES */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: 16,
          marginBottom: 24,
        }}
      >
        <div className="ap-card" style={{ padding: 20 }}>
          <div className="ap-eyebrow" style={{ marginBottom: 16 }}>
            RISK BY CATEGORY
          </div>
          {Object.keys(T.cat).map((cat) => (
            <CategoryBar
              key={cat}
              name={cat}
              count={catCounts[cat] || 0}
              max={maxCat}
              color={T.cat[cat]}
            />
          ))}
        </div>
        <div className="ap-card" style={{ padding: 20 }}>
          <div className="ap-eyebrow" style={{ marginBottom: 16 }}>
            SEVERITY DISTRIBUTION
          </div>
          {SEV_ORDER.map((s) => (
            <div
              key={s}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                padding: '8px 0',
                borderBottom: `1px solid ${T.border}`,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span
                  style={{
                    width: 8,
                    height: 8,
                    background: T.sev[s].fg,
                    display: 'inline-block',
                  }}
                />
                <span
                  className="ap-mono"
                  style={{ fontSize: 13, textTransform: 'uppercase', color: T.text }}
                >
                  {s}
                </span>
              </div>
              <span
                className="ap-mono"
                style={{ fontSize: 14, color: sevCounts[s] ? T.sev[s].fg : T.textMuted }}
              >
                {sevCounts[s] || 0}
              </span>
            </div>
          ))}
        </div>
        <div className="ap-card" style={{ padding: 20 }}>
          <div className="ap-eyebrow" style={{ marginBottom: 16 }}>
            SCAN META
          </div>
          <div style={{ fontSize: 13, color: T.textDim, lineHeight: 2 }}>
            <div>
              <span style={{ color: T.textMuted }}>Source: </span>
              <span className="ap-mono" style={{ wordBreak: 'break-all' }}>
                {results.source}
              </span>
            </div>
            <div>
              <span style={{ color: T.textMuted }}>Files: </span>
              {results.filesScanned}
            </div>
            <div>
              <span style={{ color: T.textMuted }}>Probes: </span>
              {PROBES.length}
            </div>
            <div>
              <span style={{ color: T.textMuted }}>Time: </span>
              {results.scannedAt.toLocaleString()}
            </div>
          </div>
          <button
            className="ap-btn ap-btn-ghost"
            onClick={reset}
            style={{ marginTop: 14, width: '100%' }}
          >
            <RefreshCw
              size={12}
              style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-1px' }}
            />
            New Scan
          </button>
        </div>
      </div>

      {/* PROBE FAILURE BANNER */}
      {probeErrors.length > 0 && (
        <div
          role="alert"
          style={{
            padding: 14,
            marginBottom: 16,
            background: T.sev.medium.bg,
            border: `1px solid ${T.sev.medium.border}`,
            borderLeft: `3px solid ${T.sev.medium.fg}`,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
            <AlertTriangle size={14} color={T.sev.medium.fg} />
            <span className="ap-eyebrow" style={{ color: T.sev.medium.fg }}>
              {probeErrors.length} probe{probeErrors.length === 1 ? '' : 's'} hit a snag · results
              may be incomplete
            </span>
          </div>
          <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.6 }}>
            The remaining probes ran successfully. Open the Diagnostics panel for stack traces.
          </div>
          <ul style={{ margin: '8px 0 0', padding: 0, listStyle: 'none' }}>
            {probeErrors.map((p, i) => (
              <li
                key={i}
                className="ap-mono"
                style={{ fontSize: 12, color: T.textDim, padding: '2px 0' }}
              >
                <span style={{ color: T.sev.medium.fg }}>·</span> <strong>{p.probe}</strong>:{' '}
                {p.error}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* EXPORT / SHARE TOOLBAR */}
      {results.findings.length > 0 && (
        <div className="ap-card" style={{ padding: 16, marginBottom: 16 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 12,
            }}
          >
            <div>
              <div className="ap-eyebrow" style={{ marginBottom: 4 }}>
                EXPORT / SHARE
              </div>
              <div style={{ fontSize: 13, color: T.textMuted }}>
                Each export includes a ±5-line code snapshot per finding so an agent or dev has
                enough context to fix.
              </div>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              <button
                className="ap-btn ap-btn-ghost"
                onClick={() => handleExport('json-dl')}
                title="Download a machine-readable JSON report"
              >
                <Download
                  size={12}
                  style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                />
                JSON
              </button>
              <button
                className="ap-btn ap-btn-ghost"
                onClick={() => handleExport('md-dl')}
                title="Download a human-readable Markdown report"
              >
                <Download
                  size={12}
                  style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                />
                Markdown
              </button>
              <button
                className="ap-btn ap-btn-ghost"
                onClick={() => handleExport('pr-copy')}
                title="Copy a Markdown block formatted for a GitHub PR comment (collapsible <details>)"
              >
                {copied === 'pr-copy' ? (
                  <Check
                    size={12}
                    aria-hidden="true"
                    style={{
                      display: 'inline-block',
                      marginRight: 6,
                      verticalAlign: '-1px',
                      color: T.good,
                    }}
                  />
                ) : (
                  <Github
                    size={12}
                    aria-hidden="true"
                    style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                  />
                )}
                {copied === 'pr-copy' ? 'Copied' : 'Copy PR Comment'}
              </button>
              <button
                className="ap-btn ap-btn-ghost"
                onClick={() => handleExport('agent-copy')}
                title="Copy a fix-this prompt formatted for Claude / GPT / Cursor"
              >
                {copied === 'agent-copy' ? (
                  <Check
                    size={12}
                    style={{
                      display: 'inline-block',
                      marginRight: 6,
                      verticalAlign: '-1px',
                      color: T.good,
                    }}
                  />
                ) : (
                  <MessageSquare
                    size={12}
                    style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                  />
                )}
                {copied === 'agent-copy' ? 'Copied' : 'Copy Agent Prompt'}
              </button>
              <button
                className="ap-btn ap-btn-ghost"
                onClick={() => handleExport('md-copy')}
                title="Copy the Markdown report to clipboard"
              >
                {copied === 'md-copy' ? (
                  <Check
                    size={12}
                    style={{
                      display: 'inline-block',
                      marginRight: 6,
                      verticalAlign: '-1px',
                      color: T.good,
                    }}
                  />
                ) : (
                  <Copy
                    size={12}
                    style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                  />
                )}
                {copied === 'md-copy' ? 'Copied' : 'Copy MD'}
              </button>
              <button
                className="ap-btn ap-btn-ghost"
                onClick={() => handleExport('json-copy')}
                title="Copy raw JSON to clipboard"
              >
                {copied === 'json-copy' ? (
                  <Check
                    size={12}
                    style={{
                      display: 'inline-block',
                      marginRight: 6,
                      verticalAlign: '-1px',
                      color: T.good,
                    }}
                  />
                ) : (
                  <FileJson
                    size={12}
                    style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
                  />
                )}
                {copied === 'json-copy' ? 'Copied' : 'Copy JSON'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FINDINGS */}
      {results.findings.length > 0 && (
        <>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 14,
              flexWrap: 'wrap',
              gap: 12,
            }}
          >
            <h2
              className="ap-display"
              style={{
                margin: 0,
                fontSize: 35,
                fontWeight: 400,
                color: T.text,
              }}
            >
              Findings
            </h2>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {['all', ...SEV_ORDER].map((s) => (
                <button
                  key={s}
                  onClick={() => setFilter(s)}
                  className="ap-mono"
                  style={{
                    fontSize: 11,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    padding: '6px 10px',
                    background: filter === s ? T.accent : 'transparent',
                    color: filter === s ? T.bg : T.textDim,
                    border: `1px solid ${filter === s ? T.accent : T.border}`,
                    cursor: 'pointer',
                    fontWeight: 600,
                  }}
                >
                  {s} {s !== 'all' && sevCounts[s] ? `(${sevCounts[s]})` : ''}
                </button>
              ))}
            </div>
          </div>

          <ComplianceSummary
            findings={filteredFindings}
            scope={complianceScope}
            scannedAt={results && results.scannedAt}
          />

          <div>
            {filteredFindings.map((f) => (
              <FindingCard
                key={f.id}
                finding={f}
                complianceScope={complianceScope}
                expanded={expanded.has(f.id)}
                onToggle={() => {
                  const next = new Set(expanded);
                  next.has(f.id) ? next.delete(f.id) : next.add(f.id);
                  setExpanded(next);
                }}
                onSuppress={handleSuppress}
                aiResponse={f.stableId ? aiResponses[f.stableId] : undefined}
                onExplainVerify={handleExplainVerify}
                aiEnabled={!!aiConfig}
              />
            ))}
            {filteredFindings.length === 0 && (
              <div style={{ padding: 32, textAlign: 'center', color: T.textMuted, fontSize: 14 }}>
                No findings match the current filter.
              </div>
            )}
          </div>

          {/* Suppressed-findings block — collapsed by default, shown via the score-area toggle. */}
          {showSuppressed && partitioned.suppressed.length > 0 && (
            <div style={{ marginTop: 32 }}>
              <h3
                className="ap-display"
                style={{
                  margin: '0 0 12px',
                  fontSize: 22,
                  fontWeight: 700,
                  color: T.textDim,
                }}
              >
                Suppressed ({partitioned.suppressed.length})
              </h3>
              <p style={{ fontSize: 13, color: T.textMuted, marginBottom: 12 }}>
                These findings are excluded from the score and the filtered list above. Click to
                expand and un-suppress.
              </p>
              {partitioned.suppressed.map((f) => (
                <FindingCard
                  key={f.id}
                  finding={f}
                  complianceScope={complianceScope}
                  expanded={expanded.has(f.id)}
                  onToggle={() => {
                    const next = new Set(expanded);
                    next.has(f.id) ? next.delete(f.id) : next.add(f.id);
                    setExpanded(next);
                  }}
                  onUnsuppress={handleUnsuppress}
                  aiResponse={f.stableId ? aiResponses[f.stableId] : undefined}
                  onExplainVerify={handleExplainVerify}
                  aiEnabled={!!aiConfig}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}
