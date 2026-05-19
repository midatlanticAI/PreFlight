// SPDX-License-Identifier: MIT
import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { Routes, Route, Link, useNavigate } from 'react-router-dom';
import { log, subscribe as subscribeLogs } from './lib/logger.js';
import { track, timing } from './lib/analytics.js';

// Theme, scoring, snippets, formatters, clipboard helpers, history, and the GitHub fetcher
// live in src/lib/*. They were extracted to keep this file focused on the App component
// itself. The re-exports just below preserve the historical import surface for tests and
// any external caller that imported them from App.jsx.
import {
  T,
  fontDisplay,
  fontUI,
  fontCondensed,
  fontEyebrow,
  fontMono,
  riskTier,
} from './lib/theme.js';
import { SEV_ORDER, SEV_WEIGHT, computeScore } from './lib/scoring.js';
import { buildSnippet, snippetToText } from './lib/snippet.js';
import { downloadFile, copyToClipboard, timestampSlug, timeAgo } from './lib/clipboard.js';
import {
  loadComplianceScope,
  saveComplianceScope,
  SELECTABLE_FRAMEWORKS,
} from './lib/compliance-scope.js';
import {
  HISTORY_KEY,
  HISTORY_MAX,
  loadHistory,
  persistHistory,
  makeHistoryEntry,
  computeDiffAgainstPrior,
  historyEntryToResults,
} from './lib/history.js';
import {
  formatJSON,
  formatMarkdown,
  formatPRComment,
  formatAgentPrompt,
} from './lib/formatters.js';
import { fetchGitHubRepo } from './lib/github.js';
export {
  T,
  fontDisplay,
  fontUI,
  fontCondensed,
  fontEyebrow,
  fontMono,
  riskTier,
  SEV_ORDER,
  SEV_WEIGHT,
  computeScore,
  buildSnippet,
  snippetToText,
  downloadFile,
  copyToClipboard,
  timestampSlug,
  timeAgo,
  HISTORY_KEY,
  HISTORY_MAX,
  loadHistory,
  persistHistory,
  makeHistoryEntry,
  computeDiffAgainstPrior,
  historyEntryToResults,
  formatJSON,
  formatMarkdown,
  formatPRComment,
  formatAgentPrompt,
  fetchGitHubRepo,
};

// All scanning logic lives in ./lib/probes.js. We re-export everything so
// existing imports (tests, App body) keep working without churn.
export {
  SECRET_PATTERNS,
  COMPROMISED_PACKAGES,
  TYPOSQUATS,
  SLOPSQUAT_GENERIC_RE,
  BIDI_CONTROL_RE,
  FILE_INCLUDE,
  FILE_EXCLUDE,
  URL_SAFE_HOSTS,
  URL_SUSPICIOUS_TLD_RE,
  URL_RAW_IP_RE,
  URL_SHORTENERS,
  AI_CRAWLER_BOTS,
  FILE_SIZE_WARN_LINES,
  FILE_SIZE_FAIL_LINES,
  shouldScanFile,
  classifyProject,
  probeSecrets,
  probeNextPublic,
  probeSupabaseRLS,
  probeFirebaseRules,
  probePackageJson,
  probeEnvFiles,
  probeAuthWeakness,
  probeAdminRoutes,
  probeMissingHeaders,
  probeCORS,
  probeLLMSecurity,
  probeWebhookValidation,
  probeGitHubActions,
  probeClientAuthStorage,
  probeSSRFOpenRedirect,
  probeCookieFlags,
  probeAPIRouteAuth,
  probeCompromisedPackages,
  probeSlopsquatting,
  probeMCPSecurity,
  probeTrojanSource,
  probeAIRulesFiles,
  probeMaliciousArtifacts,
  probeAICodeSmells,
  probeNpmrcHygiene,
  probeExternalURLs,
  probeHTML,
  probeSEOHygiene,
  probeGEOHygiene,
  probeA11yLandmarks,
  probeCodeQuality,
  probeArchitecture,
  PROBES,
  PROBE_META,
  stableId,
  attachStableIds,
  attachProbeMeta,
  SUPPRESSION_KEY,
  SUPPRESSION_DISPOSITIONS,
  loadSuppressions,
  saveSuppressions,
  suppressFinding,
  unsuppressFinding,
  partitionFindings,
} from './lib/probes.js';
// Bring shouldScanFile into local scope for fetchGitHubRepo and handleFiles below.
import {
  shouldScanFile,
  PROBES,
  attachStableIds,
  attachProbeMeta,
  loadSuppressions,
  saveSuppressions,
  suppressFinding,
  unsuppressFinding,
  partitionFindings,
} from './lib/probes.js';
import { loadAIConfig, explainAndVerify } from './lib/ai.js';
import {
  findPreflightConfigFile,
  parsePreflightConfig,
  configToSuppressions,
} from './lib/preflight-config.js';

// Definitions of computeScore, riskTier, fetchGitHubRepo, snippet helpers, formatters,
// clipboard utils, and history utilities used to live in this file. They were extracted
// to src/lib/* — see the import + re-export block at the top of this file. Tests and
// historical callers keep importing them from App.jsx unchanged.

// ==========================================================================
// COMPONENTS
// ==========================================================================

import { GlobalStyle } from './components/GlobalStyle.jsx';
export { GlobalStyle };

import { ScoreGauge, CategoryBar, SeverityChip } from './components/ScoreDisplay.jsx';
export { ScoreGauge, CategoryBar, SeverityChip };

import { FindingCard } from './components/FindingCard.jsx';
export { FindingCard };

import { HomeView } from './components/HomeView.jsx';
import { ResultsView } from './components/ResultsView.jsx';
import { AuditView } from './components/AuditView.jsx';
import { Nav } from './components/Nav.jsx';
export { HomeView, ResultsView, AuditView, Nav };

// v0.4: Learn + Settings trees are lazy-loaded so the main bundle stays under the 500 KB
// budget. react-markdown + remark-gfm + gray-matter + every .md file in src/learn/ all
// ship in the Learn chunk; the Settings chunk holds the BYOK / BYOT forms. Users on the
// Audit page never download either chunk.
//
// lazyNamed() wraps React.lazy with a named-export adapter + a .catch that logs the
// failure to our diagnostics buffer before re-throwing. Re-throwing is required so the
// surrounding <ErrorBoundary> still surfaces the failure to the user instead of leaving
// a blank route element when a chunk 404s.
function lazyNamed(loader, name) {
  return React.lazy(() =>
    loader()
      .then((m) => ({ default: m[name] }))
      .catch((e) => {
        log.error('[lazy] chunk load failed', { component: name, error: e?.message });
        throw e;
      })
  );
}
const LearnPage = lazyNamed(() => import('./components/learn/LearnPage.jsx'), 'LearnPage');
const ManifestoView = lazyNamed(
  () => import('./components/learn/ManifestoView.jsx'),
  'ManifestoView'
);
const IndexView = lazyNamed(() => import('./components/learn/IndexView.jsx'), 'IndexView');
const EntryView = lazyNamed(() => import('./components/learn/EntryView.jsx'), 'EntryView');
const ResourcesView = lazyNamed(
  () => import('./components/learn/ResourcesView.jsx'),
  'ResourcesView'
);
const OwaspCoverageView = lazyNamed(
  () => import('./components/learn/OwaspCoverageView.jsx'),
  'OwaspCoverageView'
);
const GlossaryView = lazyNamed(() => import('./components/learn/GlossaryView.jsx'), 'GlossaryView');
const PrivacyView = lazyNamed(() => import('./components/PrivacyView.jsx'), 'PrivacyView');
const TermsView = lazyNamed(() => import('./components/TermsView.jsx'), 'TermsView');
const BreakersInfoView = lazyNamed(
  () => import('./components/learn/BreakersInfoView.jsx'),
  'BreakersInfoView'
);
const HowToView = lazyNamed(() => import('./components/learn/HowToView.jsx'), 'HowToView');
const SocialView = lazyNamed(() => import('./components/learn/SocialView.jsx'), 'SocialView');
const TheClimbView = lazyNamed(() => import('./components/learn/TheClimbView.jsx'), 'TheClimbView');
const FlightSchoolView = lazyNamed(
  () => import('./components/learn/FlightSchoolView.jsx'),
  'FlightSchoolView'
);
const ToolsView = lazyNamed(() => import('./components/learn/ToolsView.jsx'), 'ToolsView');
const SettingsPage = lazyNamed(
  () => import('./components/settings/SettingsPage.jsx'),
  'SettingsPage'
);
const GeneralTab = lazyNamed(() => import('./components/settings/GeneralTab.jsx'), 'GeneralTab');
const ExplainVerifyTab = lazyNamed(
  () => import('./components/settings/ExplainVerifyTab.jsx'),
  'ExplainVerifyTab'
);
const PrivateReposTab = lazyNamed(
  () => import('./components/settings/PrivateReposTab.jsx'),
  'PrivateReposTab'
);
const DiagnosticsTab = lazyNamed(
  () => import('./components/settings/DiagnosticsTab.jsx'),
  'DiagnosticsTab'
);
const AboutTab = lazyNamed(() => import('./components/settings/AboutTab.jsx'), 'AboutTab');

// Tiny 404 view for unmatched routes.
function NotFoundView() {
  return (
    <div className="ap-card" style={{ padding: 28 }}>
      <h2
        className="ap-display"
        style={{ margin: '0 0 8px', fontSize: 24, color: T.text, fontWeight: 700 }}
      >
        Nothing here.
      </h2>
      <p style={{ margin: '0 0 14px', fontSize: 14, color: T.textDim, lineHeight: 1.7 }}>
        The URL you opened doesn&apos;t match any PreFlight route.
      </p>
      <Link to="/" style={{ color: T.accent, fontFamily: fontMono, fontSize: 13 }}>
        Back to Audit →
      </Link>
    </div>
  );
}

// =========================================================================
// MAIN APP
// ==========================================================================
export default function App() {
  const [mode, setMode] = useState('upload');
  const [files, setFiles] = useState([]);
  const [githubUrl, setGithubUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState({ stage: '', current: 0, total: 0 });
  const [results, setResults] = useState(null);
  const [complianceScope, setComplianceScopeRaw] = useState(loadComplianceScope);
  const setComplianceScope = (next) => setComplianceScopeRaw(saveComplianceScope(next));
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState(new Set());
  const [copied, setCopied] = useState(null); // which export was just copied
  const [history, setHistory] = useState(() => loadHistory());
  const [showAllHistory, setShowAllHistory] = useState(false);
  const [urlOpen, setUrlOpen] = useState(false);
  const [urlIndex, setUrlIndex] = useState(-1);
  const [probeErrors, setProbeErrors] = useState([]);
  const [suppressions, setSuppressions] = useState(() => loadSuppressions());
  // Default to *showing* suppressed findings — they're still useful context (".preflight.yml
  // says this is intentional, here's why") and hiding them by default obscures the workflow.
  const [showSuppressed, setShowSuppressed] = useState(true);
  // Persist suppressions whenever they change.
  useEffect(() => {
    saveSuppressions(suppressions);
  }, [suppressions]);

  // AI settings (BYOK). aiConfig is null until the user configures a provider in
  // Settings → Explain & Verify. We re-read from localStorage whenever the user
  // navigates back to the Audit view ('/') so freshly-saved configuration takes
  // effect without a full reload.
  const [aiConfig, setAiConfig] = useState(() => loadAIConfig());
  const navigate = useNavigate();
  // Per-finding AI responses, keyed by stableId. Session-only — not persisted, so users
  // re-running can choose to re-spend tokens or not. The shape is:
  //   { [stableId]: { status: 'streaming' | 'done' | 'error', text: string, error?: string, provider, model } }
  const [aiResponses, setAiResponses] = useState({});

  // Re-read aiConfig from localStorage when the Settings tab saves it. We listen
  // to a custom event the Settings save dispatches and to the cross-tab `storage`
  // event so an AI-config change in any tab updates this one too.
  useEffect(() => {
    const refresh = () => setAiConfig(loadAIConfig());
    window.addEventListener('preflight:ai-config-changed', refresh);
    window.addEventListener('storage', refresh);
    return () => {
      window.removeEventListener('preflight:ai-config-changed', refresh);
      window.removeEventListener('storage', refresh);
    };
  }, []);

  const handleExplainVerify = async (finding) => {
    if (!finding?.stableId) return;
    if (!aiConfig) {
      // No provider configured yet — send the user to the Settings page that explains
      // what's about to happen and lets them paste a key.
      navigate('/settings/ai');
      return;
    }
    track(`ai.explain_verify.start.${aiConfig.provider}`);
    setAiResponses((prev) => ({
      ...prev,
      [finding.stableId]: {
        status: 'streaming',
        text: '',
        provider: aiConfig.provider,
        model: aiConfig.model,
      },
    }));
    const t0 = performance.now();
    try {
      await explainAndVerify(finding, (chunk, total) => {
        setAiResponses((prev) => ({
          ...prev,
          [finding.stableId]: {
            ...(prev[finding.stableId] || {}),
            status: 'streaming',
            text: total,
            provider: aiConfig.provider,
            model: aiConfig.model,
          },
        }));
      });
      setAiResponses((prev) => ({
        ...prev,
        [finding.stableId]: { ...(prev[finding.stableId] || {}), status: 'done' },
      }));
      timing(`ai.explain_verify.ms`, performance.now() - t0);
      track(`ai.explain_verify.done.${aiConfig.provider}`);
    } catch (e) {
      log.error('Explain & Verify failed', { error: e?.message });
      setAiResponses((prev) => ({
        ...prev,
        [finding.stableId]: {
          ...(prev[finding.stableId] || {}),
          status: 'error',
          error: e?.message || 'AI call failed',
        },
      }));
      track('ai.explain_verify.error');
    }
  };
  // logsTick exists only as a re-render trigger when the logger emits new entries.
  // The value itself is unread — we just bump it from the subscriber callback.
  const [, setLogsTick] = useState(0);
  // (The file/folder input refs moved into AuditView in v0.4 — they live with the
  // hidden <input type="file"> elements they trigger. App keeps the `files` state but
  // not the refs.)
  // React 18 silently no-ops setState on unmounted components, so we don't need a
  // mountedRef gate around every setter — that approach actually deadlocked the UI
  // when StrictMode's dev unmount/remount cycle made the ref false at the wrong moment.
  // Use the raw setters directly. (Keeping safe* aliases for grep continuity.)
  const safeSetResults = setResults;
  const safeSetError = setError;
  const safeSetScanning = setScanning;
  const safeSetProgress = setProgress;
  const safeSetProbeErrors = setProbeErrors;
  const safeSetHistory = setHistory;

  // Subscribe to logger updates so the Diagnostics panel re-renders live.
  useEffect(() => subscribeLogs(() => setLogsTick((t) => t + 1)), []);

  // Persist history whenever it changes (cheap; entries are bounded). If it fails (quota exceeded),
  // surface a visible warning instead of silently dropping the new entry on reload.
  useEffect(() => {
    if (history.length === 0) return;
    const ok = persistHistory(history);
    if (!ok) {
      log.warn('History persistence failed — likely localStorage quota');
      // Defer the setState out of the effect tick — React 18+ flags synchronous setState in
      // effects as a re-render trigger. queueMicrotask runs after the current batch.
      queueMicrotask(() => {
        setError(
          'Could not save this scan to history (browser storage is full). Older entries are kept in memory but will be lost on reload. Clear history or other site data to fix.'
        );
      });
    }
  }, [history]);

  const urlSuggestions = useMemo(() => {
    const seen = new Set();
    const out = [];
    for (const h of history) {
      if (h.sourceType !== 'github' || !h.source) continue;
      if (seen.has(h.source)) continue;
      seen.add(h.source);
      out.push(h.source);
    }
    const q = githubUrl.trim().toLowerCase();
    return q ? out.filter((u) => u.toLowerCase().includes(q) && u.toLowerCase() !== q) : out;
  }, [history, githubUrl]);

  const loadFromHistory = useCallback((entry) => {
    setResults(historyEntryToResults(entry));
    setError(null);
    setExpanded(new Set());
    setFilter('all');
    if (entry.sourceType === 'github') setMode('github');
  }, []);

  const removeHistoryEntry = useCallback((id) => {
    setHistory((prev) => prev.filter((e) => e.id !== id));
  }, []);

  const clearHistory = useCallback(() => {
    if (
      typeof window !== 'undefined' &&
      !window.confirm('Clear all scan history? This cannot be undone.')
    )
      return;
    setHistory([]);
  }, []);

  const flashCopy = useCallback((label) => {
    setCopied(label);
    setTimeout(() => setCopied((c) => (c === label ? null : c)), 1500);
  }, []);

  const handleExport = useCallback(
    async (kind) => {
      if (!results) return;
      const stamp = timestampSlug(results.scannedAt);
      try {
        if (kind === 'json-dl') {
          downloadFile(formatJSON(results), `audit-${stamp}.json`, 'application/json');
        } else if (kind === 'md-dl') {
          downloadFile(formatMarkdown(results), `audit-${stamp}.md`, 'text/markdown');
        } else if (kind === 'json-copy') {
          const ok = await copyToClipboard(formatJSON(results));
          if (ok) flashCopy('json-copy');
        } else if (kind === 'md-copy') {
          const ok = await copyToClipboard(formatMarkdown(results));
          if (ok) flashCopy('md-copy');
        } else if (kind === 'agent-copy') {
          const ok = await copyToClipboard(formatAgentPrompt(results));
          if (ok) flashCopy('agent-copy');
          track('export.agent_prompt');
        } else if (kind === 'pr-copy') {
          const ok = await copyToClipboard(formatPRComment(results));
          if (ok) flashCopy('pr-copy');
          track('export.pr_comment');
        } else if (kind === 'pr-dl') {
          downloadFile(formatPRComment(results), `pr-comment-${stamp}.md`, 'text/markdown');
          track('export.pr_comment');
        }
      } catch (e) {
        log.warn('export: failed', { kind, error: e?.message });
      }
    },
    [results, flashCopy]
  );

  const handleFiles = useCallback(async (fileList) => {
    setError(null);
    const fileLog = log.child('files');
    try {
      const arr = Array.from(fileList || []);
      fileLog.info('handleFiles received list', { totalFiles: arr.length });
      // Sample first few paths so we can see WHY filtering rejects, without leaking too much.
      const samplePaths = arr.slice(0, 8).map((f) => ({
        path: f.webkitRelativePath || f.name,
        sizeKb: Math.round((f.size || 0) / 1024),
      }));
      fileLog.debug('handleFiles sample paths', { samplePaths });
      const filtered = arr.filter((f) => {
        const path = f.webkitRelativePath || f.name;
        const matchesPattern = shouldScanFile(path);
        const okSize = f.size < 500000;
        return matchesPattern && okSize;
      });
      fileLog.info('handleFiles after filter', {
        kept: filtered.length,
        dropped: arr.length - filtered.length,
      });
      if (filtered.length === 0) {
        fileLog.warn(
          'No security-relevant files after filtering — folder may not contain code, or every match exceeded 500KB'
        );
        setError(
          arr.length === 0
            ? 'No files were attached. The folder may have been empty, or the browser blocked access.'
            : `Selected ${arr.length} file(s), but none matched security patterns (looking for .env, package.json, .ts/.tsx/.js/.jsx, .py, .sql, firestore.rules, next.config.*, etc). Files over 500 KB are skipped.`
        );
        return;
      }
      // Settle individually so one bad blob doesn't lose every other file.
      const settled = await Promise.allSettled(
        filtered.map(async (f) => ({
          path: f.webkitRelativePath || f.name,
          content: await f.text(),
        }))
      );
      const out = [];
      let dropped = 0;
      settled.forEach((r, i) => {
        if (r.status === 'fulfilled') out.push(r.value);
        else {
          dropped++;
          log.warn('handleFiles: file read failed', {
            name: filtered[i]?.name,
            error: r.reason?.message,
          });
        }
      });
      if (out.length === 0) {
        setError(
          `Could not read any of the ${filtered.length} selected files (all reads failed). Try a different selection.`
        );
        return;
      }
      if (dropped > 0) {
        setError(
          `${dropped} of ${filtered.length} files could not be read and were skipped. The rest will be scanned.`
        );
      }
      setFiles(out);
    } catch (e) {
      log.error('handleFiles crashed', { error: e?.message, stack: e?.stack });
      setError(`File selection failed: ${e?.message || 'unknown error'}`);
    }
  }, []);

  const handleScan = async (urlOverride) => {
    // Top-level guard: ANY synchronous throw inside handleScan must surface as a visible error.
    // Without this, a thrown TypeError (e.g. a missing import) silently kills the click handler
    // and the user sees the button do nothing.
    let scanLog;
    let t0;
    let effectiveMode;
    let targetUrl;
    try {
      // Defensive: caller may have wired this directly to onClick. Strip event-shaped args.
      if (urlOverride && typeof urlOverride !== 'string') {
        log.warn('handleScan called with non-string urlOverride; ignoring', {
          typeofArg: typeof urlOverride,
        });
        urlOverride = undefined;
      }
      safeSetScanning(true);
      safeSetError(null);
      safeSetResults(null);
      setExpanded(new Set());
      safeSetProbeErrors([]);
      effectiveMode = urlOverride ? 'github' : mode;
      targetUrl = urlOverride || githubUrl;
      scanLog = log.child('scan');
      t0 = performance.now();
      try {
        track(`scan_started.${effectiveMode}`);
      } catch (te) {
        log.warn('analytics track failed', { error: te?.message });
      }
      scanLog.info('Scan started', {
        mode: effectiveMode,
        source: effectiveMode === 'github' ? targetUrl : `${files.length} files`,
      });
    } catch (preflight) {
      // Pre-try-block crashed (TypeError, ReferenceError, etc). Surface it.
      const msg = preflight?.message || String(preflight);
      log.error('handleScan preflight crash', { error: msg, stack: preflight?.stack });
      safeSetScanning(false);
      safeSetError(`Could not start scan: ${msg}. Open Diagnostics for the stack trace.`);
      return;
    }
    try {
      let scanFiles = files;
      if (effectiveMode === 'github') {
        scanFiles = await fetchGitHubRepo(targetUrl, setProgress);
      } else if (files.length === 0) {
        throw new Error('Select files or a folder first.');
      }
      scanLog.info('Files prepared', { fileCount: scanFiles.length });

      const allFindings = [];
      const probeFailures = [];
      for (let i = 0; i < PROBES.length; i++) {
        const probe = PROBES[i];
        safeSetProgress({ stage: probe.name, current: i + 1, total: PROBES.length });
        const tProbe = performance.now();
        try {
          const found = probe.fn(scanFiles);
          if (!Array.isArray(found)) {
            throw new Error(`Probe returned non-array: ${typeof found}`);
          }
          allFindings.push(...found);
          const ms = Math.round(performance.now() - tProbe);
          scanLog.debug('Probe ok', { probe: probe.name, findings: found.length, ms });
          track(`probe_run.${probe.name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`);
          timing(`probe.${probe.name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`, ms);
        } catch (probeErr) {
          probeFailures.push({ probe: probe.name, error: probeErr?.message || String(probeErr) });
          track(`probe_failed.${probe.name.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`);
          scanLog.error('Probe crashed', {
            probe: probe.name,
            error: probeErr?.message,
            stack: probeErr?.stack,
            ms: Math.round(performance.now() - tProbe),
          });
        }
        await new Promise((r) => setTimeout(r, 60));
      }
      safeSetProbeErrors(probeFailures);

      allFindings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
      // Attach a code snapshot (±5 lines) to each finding so reports + agent prompts have context.
      const fileMap = new Map(scanFiles.map((f) => [f.path, f.content]));
      allFindings.forEach((f) => {
        try {
          const content = fileMap.get(f.file);
          if (content && f.line) {
            f.snippet = buildSnippet(content, f.line, 5);
          }
        } catch (snipErr) {
          scanLog.warn('Snippet build failed', {
            file: f.file,
            line: f.line,
            error: snipErr?.message,
          });
        }
      });
      // Stable IDs: hash(probe + file + title + ±3-line context). Unlocks cross-scan diff
      // and suppression; the byte-offset-based `id` field stays as the React key.
      attachStableIds(allFindings, scanFiles);
      // Probe-level confidence + autofix metadata so the UI can render calibration tags.
      attachProbeMeta(allFindings);

      // .preflight.yml / .preflight.json — repo-local suppression file. If present, parse
      // and merge its suppression rules with the user's local-storage suppressions. Config-
      // sourced entries get `source: '.preflight config'` so the UI can label them.
      const configFile = findPreflightConfigFile(scanFiles);
      if (configFile) {
        const cfg = parsePreflightConfig(configFile.path, configFile.content);
        if (cfg.error) {
          scanLog.warn('Invalid .preflight config', { file: configFile.path, error: cfg.error });
        } else {
          const fromConfig = configToSuppressions(cfg, allFindings);
          const merged = { ...fromConfig, ...suppressions }; // user's local overrides config
          setSuppressions(merged);
          scanLog.info('Loaded .preflight config', {
            file: configFile.path,
            applied: Object.keys(fromConfig).length,
          });
        }
      }

      const score = computeScore(allFindings);
      const finalResults = {
        findings: allFindings,
        score,
        scannedAt: new Date(),
        filesScanned: scanFiles.length,
        source: effectiveMode === 'github' ? targetUrl : `${scanFiles.length} local files`,
      };
      safeSetResults(finalResults);
      safeSetHistory((prev) =>
        [makeHistoryEntry(finalResults, effectiveMode), ...prev].slice(0, HISTORY_MAX)
      );
      const totalMs = Math.round(performance.now() - t0);
      track('scan_completed');
      timing('scan.total', totalMs);
      // Record severity distribution as count buckets (no finding details).
      allFindings.forEach((f) => track(`finding_emitted.${f.severity}`));
      scanLog.info('Scan complete', {
        score,
        findings: allFindings.length,
        probeFailures: probeFailures.length,
        ms: totalMs,
      });
    } catch (e) {
      track('scan_failed');
      scanLog.error('Scan failed', { error: e?.message, stack: e?.stack });
      safeSetError(e?.message || 'Unknown scan error');
    } finally {
      safeSetScanning(false);
      safeSetProgress({ stage: '', current: 0, total: 0 });
    }
  };

  // Not memoized — handleScan is recreated each render so memoizing here would still recreate.
  // The function is cheap to allocate and only one button can call it at a time.
  const rerunFromHistory = (entry) => {
    if (entry.sourceType !== 'github') return; // upload entries can't be re-run (file contents not stored)
    setMode('github');
    setGithubUrl(entry.source);
    setUrlOpen(false);
    if (typeof window !== 'undefined') window.scrollTo({ top: 0, behavior: 'smooth' });
    handleScan(entry.source);
  };

  const reset = () => {
    setFiles([]);
    setGithubUrl('');
    setResults(null);
    setError(null);
    setExpanded(new Set());
  };

  // Partition findings by suppression status. The visible bucket drives the main list +
  // score recalculation; the suppressed bucket renders at the bottom with un-suppress buttons.
  const partitioned = useMemo(() => {
    if (!results) return { visible: [], suppressed: [] };
    return partitionFindings(results.findings, suppressions);
  }, [results, suppressions]);

  const handleSuppress = (finding, disposition, note = '') => {
    if (!finding?.stableId) return;
    setSuppressions((prev) => suppressFinding(prev, finding.stableId, disposition, note));
    track(`suppress.${disposition}`);
  };
  const handleUnsuppress = (finding) => {
    if (!finding?.stableId) return;
    setSuppressions((prev) => unsuppressFinding(prev, finding.stableId));
    track('unsuppress');
  };

  const filteredFindings = useMemo(() => {
    const source = partitioned.visible;
    if (filter === 'all') return source;
    return source.filter((f) => f.severity === filter || f.category === filter);
  }, [partitioned.visible, filter]);

  // Score is recomputed against the *visible* (non-suppressed) findings so dismissing a
  // false-positive raises the score honestly. Original results.score stays as the raw
  // historical baseline for the diff component.
  const liveScore = useMemo(() => {
    if (!results) return 100;
    return computeScore(partitioned.visible);
  }, [results, partitioned.visible]);

  // All severity / category counts use the VISIBLE (non-suppressed) findings so dismissing
  // a false-positive immediately updates everything the user sees.
  const sevCounts = useMemo(() => {
    if (!results) return {};
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    partitioned.visible.forEach((f) => {
      c[f.severity] = (c[f.severity] || 0) + 1;
    });
    return c;
  }, [results, partitioned.visible]);

  const catCounts = useMemo(() => {
    if (!results) return {};
    const c = {};
    Object.keys(T.cat).forEach((k) => {
      c[k] = 0;
    });
    partitioned.visible.forEach((f) => {
      c[f.category] = (c[f.category] || 0) + 1;
    });
    return c;
  }, [results, partitioned.visible]);

  const maxCat = Math.max(1, ...Object.values(catCounts));
  const tier = results
    ? riskTier(liveScore, {
        hasCritical: (sevCounts.critical || 0) > 0,
        hasHigh: (sevCounts.high || 0) > 0,
      })
    : null;
  const topFindings = partitioned.visible.slice(0, 3);
  // Compare current scan to prior scan of the same source (history is newest-first).
  // The current scan IS the head of history (just appended), so we look for a same-source entry below.
  const diff = useMemo(() => computeDiffAgainstPrior(results, history), [results, history]);

  return (
    <div className="ap-app">
      <GlobalStyle />
      <a href="#main" className="ap-skip-link">
        Skip to main content
      </a>
      <main
        id="main"
        className="ap-main"
        style={{ maxWidth: 1080, margin: '0 auto', padding: '40px 24px 80px' }}
      >
        {/* TOP NAV: appears on every route. Below 640 px the logo row and the Nav stack
            vertically (rule in GlobalStyle.jsx → .ap-app-header) so neither overflows. */}
        <div
          className="ap-app-header"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 28,
            gap: 16,
            flexWrap: 'wrap',
          }}
        >
          <Link
            to="/"
            aria-label="PreFlight home"
            style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none' }}
          >
            <img
              src="/maai-logo.svg"
              alt="Mid-Atlantic AI"
              style={{ height: 36, width: 'auto', display: 'block' }}
            />
            <div style={{ display: 'flex', flexDirection: 'column', lineHeight: 1 }}>
              <span
                className="ap-display"
                style={{
                  fontSize: 19,
                  fontWeight: 700,
                  fontStyle: 'italic',
                  color: T.accent,
                  letterSpacing: '-0.01em',
                }}
              >
                PreFlight
              </span>
              <span
                className="ap-eyebrow"
                style={{ fontSize: 10, color: T.textMuted, marginTop: 3 }}
              >
                BY MID-ATLANTIC AI
              </span>
            </div>
          </Link>
          <Nav />
        </div>

        <React.Suspense
          fallback={
            <div
              className="ap-card"
              style={{ padding: 28, color: T.textDim, fontSize: 14, textAlign: 'center' }}
            >
              Loading…
            </div>
          }
        >
          <Routes>
            <Route
              path="/"
              element={
                <AuditView
                  /* hero */
                  /* below: every piece of state + handler the existing audit JSX needs */
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
                  history={history}
                  showAllHistory={showAllHistory}
                  setShowAllHistory={setShowAllHistory}
                  clearHistory={clearHistory}
                  loadFromHistory={loadFromHistory}
                  rerunFromHistory={rerunFromHistory}
                  removeHistoryEntry={removeHistoryEntry}
                  scanning={scanning}
                  mode={mode}
                  setMode={setMode}
                  files={files}
                  setFiles={setFiles}
                  handleFiles={handleFiles}
                  githubUrl={githubUrl}
                  setGithubUrl={setGithubUrl}
                  handleScan={handleScan}
                  complianceScope={complianceScope}
                  setComplianceScope={setComplianceScope}
                  complianceFrameworks={SELECTABLE_FRAMEWORKS}
                  progress={progress}
                  error={error}
                  urlSuggestions={urlSuggestions}
                  urlOpen={urlOpen}
                  setUrlOpen={setUrlOpen}
                  urlIndex={urlIndex}
                  setUrlIndex={setUrlIndex}
                />
              }
            />
            <Route path="/learn" element={<LearnPage />}>
              <Route index element={<ManifestoView />} />
              <Route path="patterns" element={<IndexView type="pattern" />} />
              <Route path="patterns/:slug" element={<EntryView />} />
              <Route path="incidents" element={<IndexView type="incident" />} />
              <Route path="incidents/:slug" element={<EntryView />} />
              <Route path="shapes" element={<IndexView type="shape" />} />
              <Route path="shapes/:slug" element={<EntryView />} />
              <Route path="resources" element={<ResourcesView />} />
              <Route path="social" element={<SocialView />} />
              <Route path="owasp" element={<OwaspCoverageView />} />
              <Route path="how-it-works" element={<HowToView />} />
              <Route path="the-climb" element={<TheClimbView />} />
              <Route path="flight-school" element={<FlightSchoolView />} />
              <Route path="tools" element={<ToolsView />} />
              <Route path="glossary" element={<GlossaryView />} />
              <Route path="breakers" element={<BreakersInfoView />} />
            </Route>
            <Route path="/settings" element={<SettingsPage />}>
              <Route index element={<GeneralTab />} />
              <Route path="ai" element={<ExplainVerifyTab />} />
              <Route path="repos" element={<PrivateReposTab />} />
              <Route path="diagnostics" element={<DiagnosticsTab />} />
              <Route path="about" element={<AboutTab />} />
            </Route>
            <Route path="/privacy" element={<PrivacyView />} />
            <Route path="/terms" element={<TermsView />} />
            <Route path="*" element={<NotFoundView />} />
          </Routes>
        </React.Suspense>
      </main>

      {/*
        Floating AI · OFF and DIAGNOSTICS buttons removed in v0.4. AI settings live in
        Settings → Explain & Verify; diagnostics live in Settings → Diagnostics. The Bug
        icon stayed visible but mysterious for too long — moved to a labeled tab that has
        room to explain itself.
      */}
    </div>
  );
}
