import React, { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import {
  AlertTriangle,
  Eye,
  Upload,
  Github,
  Loader2,
  FileText,
  RefreshCw,
  AlertCircle,
  Zap,
  Folder,
  ShieldCheck,
  Copy,
  Download,
  FileJson,
  MessageSquare,
  Check,
  History,
  Trash2,
  Clock,
  Bug,
  ChevronLeft,
  TrendingUp,
  TrendingDown,
  Minus,
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
export { AISettingsModal };

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

        {/* RESULTS */}
        {results && tier && (
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
                style={{ padding: '8px 14px', fontSize: 11 }}
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
              <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
                Source:{' '}
                <span style={{ color: T.textDim, wordBreak: 'break-all' }}>{results.source}</span>
              </span>
            </div>

            {/* BASELINE DIFF — only when there is a prior scan of the same source */}
            {diff && (
              <div className="ap-card" style={{ padding: 16, marginBottom: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                  <span className="ap-eyebrow">
                    DELTA SINCE {timeAgo(diff.priorScannedAt).toUpperCase()}
                  </span>
                  <span className="ap-mono" style={{ fontSize: 12, color: T.textDim }}>
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
                    <span className="ap-mono" style={{ fontSize: 11, color: T.sev.critical.fg }}>
                      NEW:
                    </span>
                    <span
                      className="ap-mono"
                      style={{ fontSize: 12, color: T.text, marginLeft: 6 }}
                    >
                      {diff.introduced.count}
                    </span>
                    {SEV_ORDER.filter((s) => diff.introduced.bySeverity[s]).map((s) => (
                      <span
                        key={s}
                        className="ap-mono"
                        style={{
                          marginLeft: 6,
                          fontSize: 10,
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
                    <span className="ap-mono" style={{ fontSize: 11, color: T.good }}>
                      FIXED:
                    </span>
                    <span
                      className="ap-mono"
                      style={{ fontSize: 12, color: T.text, marginLeft: 6 }}
                    >
                      {diff.fixed.count}
                    </span>
                    {SEV_ORDER.filter((s) => diff.fixed.bySeverity[s]).map((s) => (
                      <span
                        key={s}
                        className="ap-mono"
                        style={{
                          marginLeft: 6,
                          fontSize: 10,
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
                    <span className="ap-mono" style={{ fontSize: 11, color: T.textMuted }}>
                      STILL OPEN:
                    </span>
                    <span
                      className="ap-mono"
                      style={{ fontSize: 12, color: T.text, marginLeft: 6 }}
                    >
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
                        fontSize: 36,
                        color: tier.color,
                      }}
                    >
                      {tier.label}
                    </span>
                    <span
                      className="ap-mono"
                      style={{
                        fontSize: 11,
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
                              fontSize: 14,
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
                                fontSize: 10,
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
                    <div style={{ fontSize: 14, color: T.good, marginTop: 8 }}>
                      <ShieldCheck
                        size={16}
                        aria-hidden="true"
                        style={{ display: 'inline-block', marginRight: 8, verticalAlign: '-3px' }}
                      />
                      No findings from this probe set across {results.filesScanned} file
                      {results.filesScanned === 1 ? '' : 's'}. This does not mean the app is fully
                      secure; manual IDOR testing and runtime probing remain out of scope.
                    </div>
                  )}
                  {results.filesScanned === 0 && (
                    <div
                      role="alert"
                      style={{
                        fontSize: 14,
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
                      <strong>0 files were scanned</strong> — the score of {results.score}/100 is
                      not real. The project may not contain any files matching our include patterns
                      (.env, package.json, .ts/.tsx/.js/.jsx, .html, .py, .sql, firestore.rules,
                      next.config.*, GitHub workflows, MCP configs). If this is an HTML-only or
                      static project, the new HTML Hygiene probe should still find things — check
                      that .html files were actually selected.
                    </div>
                  )}
                </div>
                <div
                  style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}
                >
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
                        fontSize: 10,
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
                        style={{ fontSize: 12, textTransform: 'uppercase', color: T.text }}
                      >
                        {s}
                      </span>
                    </div>
                    <span
                      className="ap-mono"
                      style={{ fontSize: 13, color: sevCounts[s] ? T.sev[s].fg : T.textMuted }}
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
                <div style={{ fontSize: 12, color: T.textDim, lineHeight: 2 }}>
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
                    {probeErrors.length} probe{probeErrors.length === 1 ? '' : 's'} hit a snag ·
                    results may be incomplete
                  </span>
                </div>
                <div style={{ fontSize: 12, color: T.textDim, lineHeight: 1.6 }}>
                  The remaining probes ran successfully. Open the Diagnostics panel for stack
                  traces.
                </div>
                <ul style={{ margin: '8px 0 0', padding: 0, listStyle: 'none' }}>
                  {probeErrors.map((p, i) => (
                    <li
                      key={i}
                      className="ap-mono"
                      style={{ fontSize: 11, color: T.textDim, padding: '2px 0' }}
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
                    <div style={{ fontSize: 12, color: T.textMuted }}>
                      Each export includes a ±5-line code snapshot per finding so an agent or dev
                      has enough context to fix.
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
                      fontSize: 32,
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
                          fontSize: 10,
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

                <div>
                  {filteredFindings.map((f) => (
                    <FindingCard
                      key={f.id}
                      finding={f}
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
                    <div
                      style={{ padding: 32, textAlign: 'center', color: T.textMuted, fontSize: 13 }}
                    >
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
                        fontSize: 20,
                        fontWeight: 700,
                        color: T.textDim,
                      }}
                    >
                      Suppressed ({partitioned.suppressed.length})
                    </h3>
                    <p style={{ fontSize: 12, color: T.textMuted, marginBottom: 12 }}>
                      These findings are excluded from the score and the filtered list above. Click
                      to expand and un-suppress.
                    </p>
                    {partitioned.suppressed.map((f) => (
                      <FindingCard
                        key={f.id}
                        finding={f}
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
        )}

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
                <Clock
                  size={20}
                  color={T.textMuted}
                  aria-hidden="true"
                  style={{ marginBottom: 8 }}
                />
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
                      <div
                        style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}
                      >
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
              is dropped automatically. GitHub URLs from history autocomplete in the URL input
              above.
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
              v0.2 prototype. Static analysis only. 24 probes covering OWASP Top 10 2025 + OWASP LLM
              Top 10 2025 + 2026 supply-chain incidents (Shai-Hulud, Axios/Sapphire Sleet, Mini
              Shai-Hulud) + MCP attack surface + AI-tooling rules-file injection. Does not perform
              live endpoint probing, IDOR testing, or runtime authentication checks. Findings are
              evidence-backed but should be verified manually before treating as confirmed
              vulnerabilities.
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
                  a: '27 probes covering hardcoded secrets (AWS, Stripe, OpenAI, Anthropic, GitHub, etc.), NEXT_PUBLIC_ leak of server secrets, Supabase Row-Level-Security misconfigurations, Firebase permissive rules, JWT alg-none unsigned tokens, package.json supply-chain hooks, 170+ known-compromised package versions including the May 11, 2026 Mini Shai-Hulud TanStack worm by TeamPCP (42 @tanstack/* packages plus @mistralai, @opensearch-project, @uipath, @squawk and others), post-infection IOCs the same worm drops on disk (the Claude Code / VS Code config-hijack files, the GitHub-token-monitor dead-man-switch service, the daemon-guard variable, and Session-messenger exfil endpoints), typosquatted and LLM-hallucinated package names, MCP server command-injection patterns, Cursor / Copilot rules-file backdoors, Trojan Source Unicode, prompt-injection sinks, system-prompt leakage to client bundles, missing security headers, CORS wildcards, SSRF and open-redirect patterns, and HTML hygiene.',
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
