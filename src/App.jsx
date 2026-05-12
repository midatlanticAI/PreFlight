import React, { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import {
  Upload,
  Github,
  Loader2,
  FileText,
  AlertCircle,
  Zap,
  Folder,
  MessageSquare,
  Bug,
} from 'lucide-react';
import { log, getLogs, subscribe as subscribeLogs } from './lib/logger.js';
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
import { AI_PROVIDERS, loadAIConfig, explainAndVerify } from './lib/ai.js';
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

import { DiagnosticsDrawer } from './components/DiagnosticsDrawer.jsx';
export { DiagnosticsDrawer };

import { FindingCard } from './components/FindingCard.jsx';
export { FindingCard };

// ==========================================================================
// AI SETTINGS MODAL
// =========================================================================
// BYOK panel. The user's key never leaves their browser — saved to
// localStorage, sent only to the provider endpoint they chose. The modal
// shows the privacy contract in plain language so it's clear what happens.

import { AISettingsModal } from './components/AISettingsModal.jsx';
import { HomeView } from './components/HomeView.jsx';
import { ResultsView } from './components/ResultsView.jsx';
export { AISettingsModal, HomeView, ResultsView };

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
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('all');
  const [expanded, setExpanded] = useState(new Set());
  const [copied, setCopied] = useState(null); // which export was just copied
  const [history, setHistory] = useState(() => loadHistory());
  const [showAllHistory, setShowAllHistory] = useState(false);
  const [urlOpen, setUrlOpen] = useState(false);
  const [urlIndex, setUrlIndex] = useState(-1);
  const [probeErrors, setProbeErrors] = useState([]);
  const [diagOpen, setDiagOpen] = useState(false);
  const [diagFilter, setDiagFilter] = useState('debug');
  const [suppressions, setSuppressions] = useState(() => loadSuppressions());
  // Default to *showing* suppressed findings — they're still useful context (".preflight.yml
  // says this is intentional, here's why") and hiding them by default obscures the workflow.
  const [showSuppressed, setShowSuppressed] = useState(true);
  // Persist suppressions whenever they change.
  useEffect(() => {
    saveSuppressions(suppressions);
  }, [suppressions]);

  // AI settings (BYOK). aiConfig is null until the user opens settings and pastes a key.
  const [aiSettingsOpen, setAiSettingsOpen] = useState(false);
  const [aiConfig, setAiConfig] = useState(() => loadAIConfig());
  // Per-finding AI responses, keyed by stableId. Session-only — not persisted, so users
  // re-running can choose to re-spend tokens or not. The shape is:
  //   { [stableId]: { status: 'streaming' | 'done' | 'error', text: string, error?: string, provider, model } }
  const [aiResponses, setAiResponses] = useState({});

  const handleAISaved = () => setAiConfig(loadAIConfig());

  const handleExplainVerify = async (finding) => {
    if (!finding?.stableId) return;
    if (!aiConfig) {
      setAiSettingsOpen(true);
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
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
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
  const tier = results ? riskTier(liveScore) : null;
  const topFindings = partitioned.visible.slice(0, 3);
  // Compare current scan to prior scan of the same source (history is newest-first).
  // The current scan IS the head of history (just appended), so we look for a same-source entry below.
  const diff = useMemo(() => computeDiffAgainstPrior(results, history), [results, history]);

  return (
    <div className="ap-app">
      <GlobalStyle />
      <main id="main" style={{ maxWidth: 1080, margin: '0 auto', padding: '40px 24px 80px' }}>
        {/* HEADER */}
        <header
          style={{
            marginBottom: 40,
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 24,
          }}
        >
          <div style={{ flex: '1 1 480px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14 }}>
              <img
                src="/maai-logo.svg"
                alt="Mid-Atlantic AI"
                style={{
                  height: 96,
                  width: 'auto',
                  display: 'block',
                }}
              />
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <span className="ap-eyebrow" style={{ color: T.accent, fontSize: 13 }}>
                  MID-ATLANTIC AI
                </span>
                <span className="ap-eyebrow" style={{ color: T.textMuted, fontSize: 11 }}>
                  PRE-FLIGHT AUDIT TOOL
                </span>
              </div>
            </div>
            <h1
              className="ap-display"
              style={{
                margin: 0,
                fontSize: 56,
                fontWeight: 400,
                letterSpacing: '-0.02em',
                lineHeight: 1,
                color: T.text,
              }}
            >
              Pre-Flight <span style={{ color: T.accent }}>audit</span>
              <br />
              for vibe-coded apps.
            </h1>
            <p
              style={{
                maxWidth: 580,
                marginTop: 16,
                fontSize: 13,
                color: T.textDim,
                lineHeight: 1.7,
              }}
            >
              A friendly second set of eyes for projects shipped through Lovable, Cursor, Bolt,
              Replit, Claude Code, or any AI tool. Catches the secrets, misconfigured RLS, exposed
              admin routes, and supply-chain hooks that the polish layer hides. All scanning runs
              locally in this tab.
            </p>
            <p
              style={{
                marginTop: 12,
                fontSize: 11,
                color: T.textMuted,
              }}
            >
              <time dateTime="2026-05-11">Updated 2026-05-11</time> · 26 probes · v0.3 · Free, no
              signup
            </p>
          </div>
        </header>

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
                  <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.6 }}>
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
                        fontSize: 12,
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
                            fontSize: 11,
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
                            style={{ fontSize: 11, padding: '2px 0', wordBreak: 'break-all' }}
                          >
                            {f.path}
                          </div>
                        ))}
                        {files.length > 10 && (
                          <div style={{ fontSize: 11, color: T.textMuted, marginTop: 4 }}>
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
                              fontSize: 12,
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
                  <div style={{ fontSize: 12, color: T.textMuted, lineHeight: 1.6, marginTop: 12 }}>
                    Public repos only. Reads up to 80 security-relevant files via the
                    unauthenticated GitHub API (60 requests per hour limit per IP). If the fetch
                    fails — sandboxed iframes sometimes block cross-origin requests — download the
                    repo as a zip from GitHub, expand it, and use the Files / Folder tab instead.
                    Start typing to autocomplete from prior scans.
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
                    style={{ fontSize: 11, color: T.textDim }}
                  >
                    [{progress.current}/{progress.total}] {progress.stage}
                  </span>
                )}
                {!scanning && mode === 'upload' && files.length === 0 && (
                  <span style={{ fontSize: 12, color: T.textMuted }} role="status">
                    ← Select files or a folder first.
                  </span>
                )}
                {!scanning && mode === 'github' && !githubUrl && (
                  <span style={{ fontSize: 12, color: T.textMuted }} role="status">
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
                    fontSize: 12,
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
            fontSize: 12,
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
            Static security review for vibe-coded apps. All scanning runs in your browser — no
            upload, no signup.
          </div>
          <nav aria-label="Footer links" style={{ display: 'flex', gap: 18 }}>
            <a
              href="mailto:John@midatlantic.ai"
              style={{ color: T.textDim, textDecoration: 'none' }}
            >
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
      </main>

      {/* AI SETTINGS: floating toggle (BYOK panel) */}
      <button
        onClick={() => setAiSettingsOpen(true)}
        aria-label="Open AI provider settings"
        title={
          aiConfig
            ? `AI configured: ${AI_PROVIDERS[aiConfig.provider]?.label || aiConfig.provider} · ${aiConfig.model}`
            : 'Configure AI provider (BYOK) to unlock Explain & Verify'
        }
        type="button"
        style={{
          position: 'fixed',
          right: 18,
          bottom: 68,
          background: T.panel,
          color: aiConfig ? T.accentAlt : T.textDim,
          border: `1px solid ${aiConfig ? T.accentAlt : T.borderAlt}`,
          padding: '10px 14px',
          fontFamily: fontMono,
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          cursor: 'pointer',
          zIndex: 40,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
        }}
      >
        <MessageSquare size={12} aria-hidden="true" />
        AI · {aiConfig ? 'configured' : 'off'}
      </button>

      <AISettingsModal
        open={aiSettingsOpen}
        onClose={() => setAiSettingsOpen(false)}
        onSaved={handleAISaved}
      />

      {/* DIAGNOSTICS: floating toggle + drawer */}
      <button
        onClick={() => setDiagOpen((o) => !o)}
        aria-label="Toggle diagnostics panel"
        title="Diagnostics & logs"
        style={{
          position: 'fixed',
          right: 18,
          bottom: 18,
          background: T.panel,
          color: T.accent,
          border: `1px solid ${T.borderAlt}`,
          padding: '10px 14px',
          fontFamily: fontMono,
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: '0.1em',
          textTransform: 'uppercase',
          cursor: 'pointer',
          zIndex: 40,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
        }}
      >
        <Bug size={12} />
        Diagnostics
        {(() => {
          const errs = getLogs().filter((e) => e.level === 'error').length;
          if (!errs) return null;
          return (
            <span
              style={{
                background: T.sev.critical.fg,
                color: T.bg,
                padding: '0 6px',
                fontSize: 10,
                fontWeight: 700,
              }}
            >
              {errs}
            </span>
          );
        })()}
      </button>
      <DiagnosticsDrawer
        open={diagOpen}
        onClose={() => setDiagOpen(false)}
        filter={diagFilter}
        setFilter={setDiagFilter}
      />
    </div>
  );
}
