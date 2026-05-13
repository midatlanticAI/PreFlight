// src/components/AuditView.jsx
// Default route content. The complete home/results experience: scan input pane (Files /
// Folder OR GitHub URL), the HomeView landing cards when there are no results, the
// ResultsView when there are, plus the page footer.
//
// Every piece of scan state lives in App.jsx and is passed in here as props. Keeping
// state in App lets the user navigate Settings ↔ Learn ↔ Audit without losing in-flight
// scan state.

import { useRef } from 'react';
import { Upload, Github, Loader2, FileText, AlertCircle, Zap, Folder } from 'lucide-react';
import { T, fontMono, fontUI } from '../lib/theme.js';
import { log } from '../lib/logger.js';
import { track } from '../lib/analytics.js';
import { HomeView } from './HomeView.jsx';
import { ResultsView } from './ResultsView.jsx';

export function AuditView({
  // results + computed
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
  // navigation
  reset,
  filter,
  setFilter,
  expanded,
  setExpanded,
  // suppression
  handleSuppress,
  handleUnsuppress,
  showSuppressed,
  setShowSuppressed,
  // export / ai / errors
  handleExport,
  copied,
  aiResponses,
  handleExplainVerify,
  aiConfig,
  probeErrors,
  // home (history)
  history,
  showAllHistory,
  setShowAllHistory,
  clearHistory,
  loadFromHistory,
  rerunFromHistory,
  removeHistoryEntry,
  // scan input
  scanning,
  mode,
  setMode,
  files,
  setFiles,
  handleFiles,
  githubUrl,
  setGithubUrl,
  handleScan,
  progress,
  error,
  urlSuggestions,
  urlOpen,
  setUrlOpen,
  urlIndex,
  setUrlIndex,
}) {
  // File / folder picker refs — live here because the hidden <input type="file"> elements
  // they're attached to are also rendered here. They don't need to survive route changes.
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  return (
    <>
      {/* HERO — only shown on the home view (no results yet). When results are loaded, the
          ResultsView component takes over and we skip the hero so the user gets straight to
          their score / findings instead of reading marketing copy again. */}
      {!results && (
        <header style={{ marginBottom: 36 }} className="ap-hero">
          <div className="ap-eyebrow" style={{ marginBottom: 12, fontSize: 13 }}>
            <span style={{ color: T.accent }}>MID-ATLANTIC AI</span>
            <span style={{ color: T.textMuted }}> · PRE-FLIGHT AUDIT TOOL</span>
          </div>
          <h1
            className="ap-display"
            style={{
              margin: 0,
              // Fluid type via clamp(min, preferred, max) — scales from 32 px on phones
              // up to 56 px on desktop without manual breakpoints, keeping the wordmark
              // readable everywhere.
              fontSize: 'clamp(35px, 7vw, 60px)',
              fontWeight: 700,
              letterSpacing: '-0.02em',
              lineHeight: 1.05,
              color: T.text,
            }}
          >
            <span style={{ fontStyle: 'italic', color: T.accent }}>Pre-Flight</span>
            <br />
            <span
              style={{
                fontSize: 'clamp(22px, 4vw, 35px)',
                fontWeight: 700,
                lineHeight: 1.2,
                display: 'inline-block',
                marginTop: 4,
              }}
            >
              An educational audit tool for vibers
              <br />
              building vibeware.
            </span>
          </h1>
          <p
            style={{
              maxWidth: 620,
              marginTop: 20,
              fontSize: 17,
              color: T.text,
              lineHeight: 1.6,
              fontFamily: fontUI,
              fontWeight: 600,
            }}
          >
            Pre-Flight catches what your AI probably missed:
          </p>
          <p
            style={{
              maxWidth: 620,
              marginTop: 8,
              fontSize: 16,
              color: T.textDim,
              lineHeight: 1.75,
              fontFamily: fontUI,
            }}
          >
            Exposed secrets, misconfigured RLS, supply-chain compromises, unprotected admin routes.
            Then we explain each finding so you can learn why it matters and how to avoid it in the
            future. All scanning runs locally in browser and is only saved in your browser, it never
            goes anywhere else, ever.
          </p>
          <p
            style={{
              marginTop: 14,
              fontSize: 13,
              color: T.textMuted,
              fontFamily: fontMono,
            }}
          >
            <time dateTime="2026-05-12">Updated 2026-05-12</time> · 43 probes · v0.5 · OWASP Top 10
            2025 + OWASP LLM Top 10 2025 · Free, no signup
          </p>
        </header>
      )}
      {/* INPUT SECTION */}
      {!results && (
        <div className="ap-card ap-fade-in" style={{ marginBottom: 32 }}>
          <div style={{ display: 'flex', borderBottom: `1px solid ${T.border}` }}>
            <button
              className={`ap-tab ${mode === 'upload' ? 'ap-tab-active' : ''}`}
              onClick={() => setMode('upload')}
            >
              <Upload
                size={12}
                style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-1px' }}
              />
              Files / Folder
            </button>
            <button
              className={`ap-tab ${mode === 'github' ? 'ap-tab-active' : ''}`}
              onClick={() => setMode('github')}
            >
              <Github
                size={12}
                style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-1px' }}
              />
              GitHub URL
            </button>
          </div>

          <div style={{ padding: 28 }}>
            {mode === 'upload' && (
              <div>
                <div className="ap-eyebrow" style={{ marginBottom: 14 }}>
                  UPLOAD SOURCE
                </div>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 14 }}>
                  <button
                    className="ap-btn ap-btn-ghost"
                    onClick={() => fileInputRef.current?.click()}
                  >
                    <FileText
                      size={14}
                      style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-2px' }}
                    />
                    Select Files
                  </button>
                  <button
                    className="ap-btn ap-btn-ghost"
                    onClick={() => folderInputRef.current?.click()}
                  >
                    <Folder
                      size={14}
                      style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-2px' }}
                    />
                    Select Folder
                  </button>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      log.info('file input change fired', {
                        filesAttached: e.target.files?.length || 0,
                      });
                      handleFiles(e.target.files);
                    }}
                  />
                  <input
                    ref={folderInputRef}
                    type="file"
                    multiple
                    // webkitdirectory is the only universally-implemented folder-picker attr
                    // (Chrome, Edge, Safari). Firefox does not support folder upload via
                    // <input>, so the obsolete `directory` / `mozdirectory` attrs would
                    // only add unknown-prop warnings, not gain coverage.
                    webkitdirectory=""
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      log.info('folder input change fired', {
                        filesAttached: e.target.files?.length || 0,
                      });
                      handleFiles(e.target.files);
                    }}
                  />
                </div>
                <div style={{ fontSize: 13, color: T.textMuted, lineHeight: 1.6 }}>
                  Scans .env files, package.json, source files (.ts/.tsx/.js/.jsx), Supabase
                  migrations, Firebase rules, next.config, vercel.json. node_modules and build
                  outputs are skipped automatically. Files stay in this tab — nothing uploads.
                </div>
                {files.length > 0 && (
                  <div
                    style={{
                      marginTop: 16,
                      padding: 12,
                      background: T.bg,
                      border: `1px solid ${T.border}`,
                      fontSize: 13,
                      color: T.textDim,
                    }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        marginBottom: 8,
                      }}
                    >
                      <span className="ap-eyebrow">{files.length} FILES STAGED</span>
                      <button
                        onClick={() => setFiles([])}
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: T.textMuted,
                          cursor: 'pointer',
                          fontFamily: fontMono,
                          fontSize: 12,
                        }}
                      >
                        clear
                      </button>
                    </div>
                    <div style={{ maxHeight: 120, overflowY: 'auto' }}>
                      {files.slice(0, 10).map((f) => (
                        <div
                          key={f.path}
                          className="ap-mono"
                          style={{ fontSize: 12, padding: '2px 0', wordBreak: 'break-all' }}
                        >
                          {f.path}
                        </div>
                      ))}
                      {files.length > 10 && (
                        <div style={{ fontSize: 12, color: T.textMuted, marginTop: 4 }}>
                          + {files.length - 10} more
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {mode === 'github' && (
              <div>
                <label
                  htmlFor="gh-url-input"
                  className="ap-eyebrow"
                  style={{ display: 'block', marginBottom: 14 }}
                >
                  PUBLIC REPOSITORY URL
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    id="gh-url-input"
                    className="ap-input"
                    placeholder="https://github.com/owner/repo"
                    value={githubUrl}
                    autoComplete="off"
                    role="combobox"
                    aria-autocomplete="list"
                    aria-expanded={urlOpen && urlSuggestions.length > 0}
                    aria-controls="url-suggestion-listbox"
                    aria-activedescendant={urlIndex >= 0 ? `url-sugg-${urlIndex}` : undefined}
                    onChange={(e) => {
                      setGithubUrl(e.target.value);
                      setUrlOpen(true);
                      setUrlIndex(-1);
                    }}
                    onFocus={() => setUrlOpen(true)}
                    onBlur={() => setTimeout(() => setUrlOpen(false), 150)}
                    onKeyDown={(e) => {
                      if (e.key === 'Escape') {
                        if (urlOpen) e.stopPropagation();
                        setUrlOpen(false);
                        setUrlIndex(-1);
                        return;
                      }
                      if (e.key === 'ArrowDown') {
                        // Always open the dropdown on ArrowDown if there are suggestions, even when closed.
                        if (urlSuggestions.length) {
                          e.preventDefault();
                          setUrlOpen(true);
                          setUrlIndex((i) => Math.min(i + 1, urlSuggestions.length - 1));
                        }
                      } else if (e.key === 'ArrowUp' && urlSuggestions.length) {
                        e.preventDefault();
                        setUrlIndex((i) => Math.max(i - 1, -1));
                      } else if (e.key === 'Enter' && urlIndex >= 0 && urlSuggestions.length) {
                        e.preventDefault();
                        setGithubUrl(urlSuggestions[urlIndex]);
                        setUrlOpen(false);
                        setUrlIndex(-1);
                        track('url_autocomplete_used');
                      } else if (e.key === 'Home' && urlSuggestions.length) {
                        e.preventDefault();
                        setUrlIndex(0);
                      } else if (e.key === 'End' && urlSuggestions.length) {
                        e.preventDefault();
                        setUrlIndex(urlSuggestions.length - 1);
                      }
                    }}
                  />
                  {urlOpen && urlSuggestions.length > 0 && (
                    <div
                      id="url-suggestion-listbox"
                      role="listbox"
                      aria-label="GitHub URLs from scan history"
                      className="ap-fade-in"
                      style={{
                        position: 'absolute',
                        top: '100%',
                        left: 0,
                        right: 0,
                        marginTop: 4,
                        background: T.panel,
                        border: `1px solid ${T.borderAlt}`,
                        zIndex: 20,
                        maxHeight: 240,
                        overflowY: 'auto',
                        boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                      }}
                      onMouseDown={(e) => e.preventDefault()}
                    >
                      <div style={{ padding: '6px 12px', borderBottom: `1px solid ${T.border}` }}>
                        <span className="ap-eyebrow">
                          FROM HISTORY · {urlSuggestions.length} match
                          {urlSuggestions.length === 1 ? '' : 'es'}
                        </span>
                      </div>
                      {urlSuggestions.map((u, i) => (
                        <button
                          key={u}
                          id={`url-sugg-${i}`}
                          role="option"
                          aria-selected={i === urlIndex}
                          type="button"
                          onClick={() => {
                            setGithubUrl(u);
                            setUrlOpen(false);
                            setUrlIndex(-1);
                            track('url_autocomplete_used');
                          }}
                          onMouseEnter={() => setUrlIndex(i)}
                          style={{
                            width: '100%',
                            textAlign: 'left',
                            padding: '10px 12px',
                            // Stronger active highlight (was panelHover ~1.5:1; now adds left border).
                            background: i === urlIndex ? T.panelAlt : 'transparent',
                            borderLeft:
                              i === urlIndex ? `3px solid ${T.accent}` : '3px solid transparent',
                            color: T.text,
                            borderTop: 'none',
                            borderRight: 'none',
                            borderBottom:
                              i < urlSuggestions.length - 1 ? `1px solid ${T.border}` : 'none',
                            cursor: 'pointer',
                            fontFamily: fontMono,
                            fontSize: 13,
                            fontWeight: i === urlIndex ? 600 : 400,
                            wordBreak: 'break-all',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 8,
                          }}
                        >
                          <Github
                            size={12}
                            color={T.textMuted}
                            aria-hidden="true"
                            style={{ flexShrink: 0 }}
                          />
                          <span>{u}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <div style={{ fontSize: 13, color: T.textMuted, lineHeight: 1.6, marginTop: 12 }}>
                  Public repos only. Reads up to 80 security-relevant files via the unauthenticated
                  GitHub API (60 requests per hour limit per IP). If the fetch fails — sandboxed
                  iframes sometimes block cross-origin requests — download the repo as a zip from
                  GitHub, expand it, and use the Files / Folder tab instead. Start typing to
                  autocomplete from prior scans.
                </div>
              </div>
            )}

            <div style={{ marginTop: 24, display: 'flex', gap: 10, alignItems: 'center' }}>
              <button
                className="ap-btn"
                onClick={() => handleScan()}
                disabled={
                  scanning ||
                  (mode === 'upload' && files.length === 0) ||
                  (mode === 'github' && !githubUrl)
                }
              >
                {scanning ? (
                  <>
                    <Loader2
                      size={12}
                      className="ap-spin"
                      style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-1px' }}
                    />
                    Scanning
                  </>
                ) : (
                  <>
                    <Zap
                      size={12}
                      style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-1px' }}
                    />
                    Run Audit
                  </>
                )}
              </button>
              {scanning && progress.stage && (
                <span
                  className="ap-mono ap-pulse"
                  role="status"
                  aria-live="polite"
                  aria-atomic="true"
                  style={{ fontSize: 12, color: T.textDim }}
                >
                  [{progress.current}/{progress.total}] {progress.stage}
                </span>
              )}
              {!scanning && mode === 'upload' && files.length === 0 && (
                <span style={{ fontSize: 13, color: T.textMuted }} role="status">
                  ← Select files or a folder first.
                </span>
              )}
              {!scanning && mode === 'github' && !githubUrl && (
                <span style={{ fontSize: 13, color: T.textMuted }} role="status">
                  ← Enter a GitHub repo URL first.
                </span>
              )}
            </div>

            {error && (
              <div
                role="alert"
                aria-live="assertive"
                aria-atomic="true"
                style={{
                  marginTop: 16,
                  padding: 12,
                  background: T.sev.critical.bg,
                  border: `1px solid ${T.sev.critical.border}`,
                  color: T.sev.critical.fg,
                  fontSize: 13,
                }}
              >
                <AlertCircle
                  size={14}
                  aria-hidden="true"
                  style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-2px' }}
                />
                {error}
              </div>
            )}
          </div>
        </div>
      )}

      {results && tier && (
        <ResultsView
          results={results}
          tier={tier}
          liveScore={liveScore}
          partitioned={partitioned}
          sevCounts={sevCounts}
          catCounts={catCounts}
          maxCat={maxCat}
          diff={diff}
          topFindings={topFindings}
          filteredFindings={filteredFindings}
          reset={reset}
          filter={filter}
          setFilter={setFilter}
          expanded={expanded}
          setExpanded={setExpanded}
          handleSuppress={handleSuppress}
          handleUnsuppress={handleUnsuppress}
          showSuppressed={showSuppressed}
          setShowSuppressed={setShowSuppressed}
          handleExport={handleExport}
          copied={copied}
          aiResponses={aiResponses}
          handleExplainVerify={handleExplainVerify}
          aiConfig={aiConfig}
          probeErrors={probeErrors}
        />
      )}

      <HomeView
        results={results}
        history={history}
        showAllHistory={showAllHistory}
        setShowAllHistory={setShowAllHistory}
        clearHistory={clearHistory}
        loadFromHistory={loadFromHistory}
        rerunFromHistory={rerunFromHistory}
        removeHistoryEntry={removeHistoryEntry}
        scanning={scanning}
      />

      {/* FOOTER */}
      <footer
        style={{
          marginTop: 64,
          paddingTop: 24,
          borderTop: `1px solid ${T.border}`,
          fontSize: 13,
          color: T.textMuted,
          lineHeight: 1.7,
          display: 'flex',
          flexWrap: 'wrap',
          gap: 24,
          justifyContent: 'space-between',
        }}
      >
        <div>
          <strong style={{ color: T.textDim }}>Mid-Atlantic AI · Pre-Flight Audit Tool</strong>
          <br />
          Static security review for vibe-coded apps. All scanning runs in your browser — no upload,
          no signup.
        </div>
        <nav aria-label="Footer links" style={{ display: 'flex', gap: 18 }}>
          <a href="mailto:John@midatlantic.ai" style={{ color: T.textDim, textDecoration: 'none' }}>
            Contact
          </a>
          <a
            href="https://midatlantic.ai"
            style={{ color: T.textDim, textDecoration: 'none' }}
            rel="noopener noreferrer"
          >
            Mid-Atlantic AI
          </a>
          <a href="/llms.txt" style={{ color: T.textDim, textDecoration: 'none' }}>
            llms.txt
          </a>
        </nav>
      </footer>
    </>
  );
}
