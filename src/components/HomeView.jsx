// src/components/HomeView.jsx
// The three cards shown on the landing view (when no scan results are displayed):
//   - SCAN HISTORY:  newest-first list of past runs with re-run / view / remove actions.
//   - PROBE LEGEND:  enumerates every probe in the registry so users know what they get.
//   - FAQ:           plain-language answers that double as the source-of-truth for the
//                    JSON-LD FAQPage schema in index.html (Google 2026 anti-schema-drift).
//
// Each block keeps its own `{!results && ...}` gate internally so behavior matches the
// pre-extraction version exactly. The parent App passes `results` so the gates still work.

import { Github, Folder, History, Clock, RefreshCw, Trash2, Eye } from 'lucide-react';
import { T, riskTier } from '../lib/theme.js';
import { SEV_ORDER } from '../lib/scoring.js';
import { HISTORY_MAX } from '../lib/history.js';
import { timeAgo } from '../lib/clipboard.js';
import { PROBES } from '../lib/probes.js';

export function HomeView({
  results,
  history,
  showAllHistory,
  setShowAllHistory,
  clearHistory,
  loadFromHistory,
  rerunFromHistory,
  removeHistoryEntry,
  scanning,
}) {
  return (
    <>
      {/* SCAN HISTORY (always shown when not viewing results — empty state if needed) */}
      {!results && (
        <div className="ap-card ap-fade-in" style={{ padding: 24, marginBottom: 32 }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              marginBottom: 14,
              flexWrap: 'wrap',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <History size={14} color={T.accent} />
              <span className="ap-eyebrow">
                SCAN HISTORY · {history.length} / {HISTORY_MAX}
              </span>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              {history.length > 5 && (
                <button
                  onClick={() => setShowAllHistory((s) => !s)}
                  className="ap-mono"
                  style={{
                    background: 'transparent',
                    border: `1px solid ${T.border}`,
                    color: T.textDim,
                    cursor: 'pointer',
                    fontSize: 10,
                    padding: '4px 10px',
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                  }}
                >
                  {showAllHistory ? 'Show recent' : `Show all (${history.length})`}
                </button>
              )}
              <button
                onClick={clearHistory}
                className="ap-mono"
                style={{
                  background: 'transparent',
                  border: `1px solid ${T.border}`,
                  color: T.textDim,
                  cursor: 'pointer',
                  fontSize: 10,
                  padding: '4px 10px',
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                }}
              >
                <Trash2
                  size={10}
                  style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
                />
                Clear
              </button>
            </div>
          </div>
          {history.length === 0 && (
            <div
              style={{
                padding: '24px 16px',
                textAlign: 'center',
                background: T.bg,
                border: `1px dashed ${T.border}`,
                color: T.textDim,
                fontSize: 13,
                lineHeight: 1.7,
              }}
            >
              <Clock size={20} color={T.textMuted} aria-hidden="true" style={{ marginBottom: 8 }} />
              <div style={{ marginBottom: 4 }}>No scans yet.</div>
              <div style={{ fontSize: 12, color: T.textMuted }}>
                Run an audit above and the result lands here. Up to {HISTORY_MAX} scans are kept
                locally so you can re-view or re-run them without retyping the URL.
              </div>
            </div>
          )}
          <div>
            {(showAllHistory ? history : history.slice(0, 5)).map((entry) => {
              const tier = riskTier(entry.score);
              return (
                <div
                  key={entry.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '10px 12px',
                    marginBottom: 6,
                    background: T.bg,
                    border: `1px solid ${T.border}`,
                    borderLeft: `3px solid ${tier.ring}`,
                  }}
                >
                  {/* Score chip */}
                  <div
                    style={{
                      flexShrink: 0,
                      width: 44,
                      height: 44,
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      background: T.panel,
                      border: `1px solid ${T.border}`,
                    }}
                  >
                    <span
                      className="ap-display"
                      style={{ fontSize: 18, color: tier.color, lineHeight: 1 }}
                    >
                      {entry.score}
                    </span>
                  </div>
                  {/* Source + meta */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                      {entry.sourceType === 'github' ? (
                        <Github size={11} color={T.textMuted} style={{ flexShrink: 0 }} />
                      ) : (
                        <Folder size={11} color={T.textMuted} style={{ flexShrink: 0 }} />
                      )}
                      <span
                        className="ap-mono"
                        style={{
                          fontSize: 12,
                          color: T.text,
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {entry.source}
                      </span>
                    </div>
                    <div
                      style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}
                    >
                      <span className="ap-mono" style={{ fontSize: 10, color: T.textMuted }}>
                        <Clock
                          size={9}
                          style={{
                            display: 'inline-block',
                            marginRight: 3,
                            verticalAlign: '-1px',
                          }}
                        />
                        {timeAgo(entry.scannedAt)}
                      </span>
                      <span className="ap-mono" style={{ fontSize: 10, color: T.textMuted }}>
                        {entry.filesScanned} files
                      </span>
                      <span style={{ display: 'flex', gap: 4 }}>
                        {SEV_ORDER.filter((s) => entry.bySeverity?.[s]).map((s) => (
                          <span
                            key={s}
                            className="ap-mono"
                            title={`${entry.bySeverity[s]} ${s}`}
                            aria-label={`${entry.bySeverity[s]} ${s}`}
                            style={{
                              fontSize: 10,
                              padding: '1px 5px',
                              color: T.sev[s].fg,
                              background: T.sev[s].bg,
                              border: `1px solid ${T.sev[s].border}`,
                            }}
                          >
                            {entry.bySeverity[s]} {s.toUpperCase()}
                          </span>
                        ))}
                        {(!entry.bySeverity || Object.keys(entry.bySeverity).length === 0) && (
                          <span className="ap-mono" style={{ fontSize: 10, color: T.good }}>
                            clean
                          </span>
                        )}
                      </span>
                    </div>
                  </div>
                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button
                      onClick={() => loadFromHistory(entry)}
                      className="ap-mono"
                      title="Load cached findings (no rescan)"
                      style={{
                        background: 'transparent',
                        border: `1px solid ${T.borderAlt}`,
                        color: T.accent,
                        cursor: 'pointer',
                        fontSize: 10,
                        padding: '5px 10px',
                        letterSpacing: '0.1em',
                        textTransform: 'uppercase',
                        fontWeight: 600,
                      }}
                    >
                      <Eye
                        size={10}
                        style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
                      />
                      View
                    </button>
                    <button
                      onClick={() => rerunFromHistory(entry)}
                      disabled={scanning || entry.sourceType !== 'github'}
                      className="ap-mono"
                      title={
                        entry.sourceType !== 'github'
                          ? 'Re-run only works for GitHub URL scans (upload sources are not stored)'
                          : 'Re-fetch this repo and rescan with current probe set'
                      }
                      style={{
                        // Use explicit color blend for disabled (avoid opacity to keep WCAG 3:1).
                        background:
                          scanning || entry.sourceType !== 'github' ? T.panelAlt : 'transparent',
                        border: `1px solid ${T.borderAlt}`,
                        color: scanning || entry.sourceType !== 'github' ? T.textDim : T.good,
                        cursor:
                          scanning || entry.sourceType !== 'github' ? 'not-allowed' : 'pointer',
                        fontSize: 10,
                        padding: '5px 10px',
                        letterSpacing: '0.1em',
                        textTransform: 'uppercase',
                        fontWeight: 600,
                      }}
                    >
                      <RefreshCw
                        size={10}
                        style={{ display: 'inline-block', marginRight: 4, verticalAlign: '-1px' }}
                      />
                      Re-run
                    </button>
                    <button
                      onClick={() => removeHistoryEntry(entry.id)}
                      title="Remove from history"
                      aria-label={`Remove scan of ${entry.source} from history`}
                      style={{
                        background: 'transparent',
                        border: `1px solid ${T.border}`,
                        color: T.textMuted,
                        cursor: 'pointer',
                        padding: '5px 8px',
                      }}
                    >
                      <Trash2 size={11} aria-hidden="true" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 10, fontSize: 11, color: T.textMuted }}>
            Stored locally in your browser (localStorage). Capped at {HISTORY_MAX} entries; oldest
            is dropped automatically. GitHub URLs from history autocomplete in the URL input above.
          </div>
        </div>
      )}

      {/* PROBE LEGEND (shown only before scan) */}
      {!results && (
        <div className="ap-card" style={{ padding: 24 }}>
          <div className="ap-eyebrow" style={{ marginBottom: 16 }}>
            ACTIVE PROBES
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: 12,
            }}
          >
            {PROBES.map((p) => (
              <div
                key={p.name}
                style={{
                  padding: 12,
                  background: T.bg,
                  border: `1px solid ${T.border}`,
                  fontSize: 12,
                  color: T.textDim,
                }}
              >
                <div
                  className="ap-mono"
                  style={{ color: T.text, fontWeight: 500, marginBottom: 2 }}
                >
                  {p.name}
                </div>
              </div>
            ))}
          </div>
          <div style={{ marginTop: 18, fontSize: 11, color: T.textMuted, lineHeight: 1.6 }}>
            v0.4 release. Static analysis only. 32 probes covering OWASP Top 10 2025 + OWASP LLM
            Top 10 2025 + 2026 supply-chain incidents (Shai-Hulud, Axios/Sapphire Sleet, Mini
            Shai-Hulud TanStack) + MCP attack surface + AI-tooling rules-file injection +
            post-infection malicious-artifact detection. Does not perform live endpoint probing,
            IDOR testing, or runtime authentication checks. Findings are evidence-backed but
            should be verified manually before treating as confirmed vulnerabilities.
          </div>
        </div>
      )}

      {/* VISIBLE FAQ — mirrors JSON-LD FAQPage schema (Google 2026 anti-schema-drift guidance).
            Shown only on the home view (not over results) to keep the input surface uncluttered. */}
      {!results && (
        <section
          aria-labelledby="faq-heading"
          className="ap-card"
          style={{
            padding: 28,
            marginTop: 32,
            marginBottom: 24,
          }}
        >
          <h2
            id="faq-heading"
            className="ap-display"
            style={{
              margin: '0 0 18px',
              fontSize: 28,
              fontWeight: 700,
              color: T.text,
            }}
          >
            Frequently asked questions
          </h2>
          <dl style={{ margin: 0, padding: 0 }}>
            {[
              {
                q: 'Does the Pre-Flight Audit Tool send my source code to a server?',
                a: "No. All scanning happens in your browser tab. When you select files or a folder, contents are read locally with the File API and never uploaded. When you scan a public GitHub URL, the tool fetches raw blobs from raw.githubusercontent.com directly from your browser — the tool's origin never sees them. No analytics beacons, no remote storage.",
              },
              {
                q: 'What does the Pre-Flight Audit Tool check?',
                a: '32 probes covering hardcoded secrets (AWS, Stripe, OpenAI, Anthropic, GitHub, etc.), NEXT_PUBLIC_ leak of server secrets, Supabase Row-Level-Security misconfigurations, Firebase permissive rules, JWT alg-none unsigned tokens, package.json supply-chain hooks, 170+ known-compromised package versions including the May 11, 2026 Mini Shai-Hulud TanStack worm by TeamPCP (42 @tanstack/* packages plus @mistralai, @opensearch-project, @uipath, @squawk and others), post-infection IOCs the same worm drops on disk (the Claude Code / VS Code config-hijack files, the GitHub-token-monitor dead-man-switch service, the daemon-guard variable, and Session-messenger exfil endpoints), typosquatted and LLM-hallucinated package names, MCP server command-injection patterns, Cursor / Copilot rules-file backdoors, Trojan Source Unicode, prompt-injection sinks, system-prompt leakage to client bundles, missing security headers, CORS wildcards, SSRF and open-redirect patterns, and HTML hygiene.',
              },
              {
                q: 'Is the Pre-Flight Audit Tool free?',
                a: 'Yes. No signup, no credit card, no usage limits. Free forever for the browser tool itself.',
              },
              {
                q: 'What kind of tool is this — and what is it NOT?',
                a: 'This is a free, in-browser static security audit. You drop in a folder or paste a GitHub URL; you get a report. It focuses on the failure modes specific to AI-generated code — prompt-injection sinks, MCP server misconfig, Cursor/Copilot rules-file backdoors, slopsquatted packages, system prompts leaked to client bundles — plus 2025-2026 supply-chain incidents (Shai-Hulud, Axios / Sapphire Sleet, Mini Shai-Hulud) by exact version. It is NOT a continuously-running enterprise AppSec platform with seat counts, dashboards, ticket integrations, and runtime protection. It is a free pre-merge gate you can run before you commit, with no signup and no data leaving your tab.',
              },
              {
                q: 'Can the tool catch supply-chain attacks from 2025-2026?',
                a: 'Yes, by exact version. We hard-code known-compromised versions from Shai-Hulud (Sept 2025), Axios / Sapphire Sleet (March 2026), Mini Shai-Hulud (April 2026), Bitwarden CLI 2026.4.0, and more. Sources: CISA, GTIG/Mandiant, Socket, Wiz, Unit 42, OX Security.',
              },
              {
                q: 'Does the tool work with apps not built by AI?',
                a: 'Yes. Most probes are framework-agnostic and apply to any JavaScript, TypeScript, Python, Go, Ruby, HTML, or SQL project. The branding emphasizes "vibe-coded apps" because that cohort has the highest density of the specific vulnerabilities we catch.',
              },
            ].map((item, i) => (
              <div
                key={i}
                style={{
                  paddingBottom: 14,
                  marginBottom: 14,
                  borderBottom: i < 5 ? `1px solid ${T.border}` : 'none',
                }}
              >
                <dt style={{ fontWeight: 600, color: T.text, marginBottom: 6, fontSize: 14 }}>
                  {item.q}
                </dt>
                <dd style={{ margin: 0, color: T.textDim, fontSize: 13, lineHeight: 1.7 }}>
                  {item.a}
                </dd>
              </div>
            ))}
          </dl>
          <p style={{ fontSize: 11, color: T.textMuted, marginTop: 12, marginBottom: 0 }}>
            Last updated 2026-05-11 · machine-readable index at{' '}
            <a href="/llms.txt" style={{ color: T.textMuted }}>
              llms.txt
            </a>
          </p>
        </section>
      )}
    </>
  );
}
