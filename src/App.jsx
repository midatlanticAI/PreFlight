import React, { useState, useCallback, useMemo, useRef, useEffect } from 'react';
import {
  AlertTriangle,
  Eye,
  Upload,
  Github,
  Loader2,
  ChevronDown,
  ChevronRight,
  FileText,
  X,
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
  Activity,
  ChevronLeft,
  TrendingUp,
  TrendingDown,
  Minus,
} from 'lucide-react';
import { log, getLogs, clearLogs, subscribe as subscribeLogs, exportLogs } from './lib/logger.js';
import { track, timing } from './lib/analytics.js';

// ==========================================================================
// THEME — Mid-Atlantic AI brand: navy ground, orange CTA, mint accent
// Palette source: official brand kit (navy / white / mint cyan / orange / grays)
// ==========================================================================
const T = {
  bg: '#0a1226', // deep brand navy (darker than logo navy for AA contrast)
  bgGrid: 'rgba(159, 229, 221, 0.03)', // faint mint tint, echoes the eye color
  panel: '#11192e',
  panelAlt: '#172143',
  panelHover: '#1d294d',
  border: '#1f2a44',
  borderAlt: '#2c3a5e',
  text: '#f5f7fa', // contrast 17.7:1 on bg — WCAG AAA
  textDim: '#a8b1c5', // contrast 8.94:1 on bg — AAA
  textMuted: '#8a96b0', // contrast 6.5:1 on bg — AA (was #6b7693 = 4.15:1, failed AA)
  accent: '#f26b1f', // brand orange (antenna lights) — 6.18:1 on bg = AA Large
  accentDim: '#c2541a',
  accentAlt: '#9fe5dd', // brand mint (robot eyes) — for friendly highlights
  navy: '#1b2d52', // brand navy (logo body) — for chrome accents
  good: '#9fe5dd', // success uses the brand mint
  sev: {
    critical: {
      bg: '#1f0e1a',
      fg: '#fb7185',
      border: '#7f1d1d',
      glow: 'rgba(251, 113, 133, 0.15)',
    },
    high: { bg: '#1f140a', fg: '#f97316', border: '#9a3412', glow: 'rgba(249, 115, 22, 0.15)' },
    medium: { bg: '#1f1a0a', fg: '#fbbf24', border: '#854d0e', glow: 'rgba(251, 191, 36, 0.12)' },
    low: { bg: '#0e1a30', fg: '#60a5fa', border: '#1e3a8a', glow: 'rgba(96, 165, 250, 0.12)' },
    info: { bg: '#0d1d2c', fg: '#9fe5dd', border: '#3b6e69', glow: 'rgba(159, 229, 221, 0.12)' },
  },
  cat: {
    'Data Breach': '#f97316',
    'Code Injection': '#fbbf24',
    'Supply Chain': '#a78bfa',
    'Auth & Access': '#fb7185',
    'AI/LLM Security': '#9fe5dd',
    Misconfiguration: '#60a5fa',
  },
};

export const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_WEIGHT = { critical: 25, high: 10, medium: 5, low: 2, info: 1 };

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
import {
  AI_PROVIDERS,
  loadAIConfig,
  saveAIConfig,
  clearAIConfig,
  validateKeyShape,
  explainAndVerify,
} from './lib/ai.js';
import {
  findPreflightConfigFile,
  parsePreflightConfig,
  configToSuppressions,
} from './lib/preflight-config.js';

// ==========================================================================
// SCORING
// ==========================================================================
export function computeScore(findings) {
  let score = 100;
  findings.forEach((f) => {
    score -= SEV_WEIGHT[f.severity] || 0;
  });
  return Math.max(0, score);
}

export function riskTier(score) {
  if (score >= 80) return { label: 'LOW RISK', color: T.good, ring: T.good };
  if (score >= 60) return { label: 'MODERATE RISK', color: T.sev.medium.fg, ring: T.sev.medium.fg };
  if (score >= 40) return { label: 'HIGH RISK', color: T.sev.high.fg, ring: T.sev.high.fg };
  return { label: 'CRITICAL RISK', color: T.sev.critical.fg, ring: T.sev.critical.fg };
}

// ==========================================================================
// GITHUB FETCHER
// ==========================================================================
export async function fetchGitHubRepo(url, onProgress) {
  const ghLog = log.child('github');

  if (typeof url !== 'string') {
    ghLog.error('fetchGitHubRepo got non-string url', { typeofArg: typeof url });
    throw new Error(
      `We tried to read that GitHub URL but got something that wasn't a string (got ${typeof url}). Refresh the page and try again — if it keeps happening, open the Diagnostics panel and share the log.`
    );
  }
  const trimmed = url.trim();
  if (!trimmed) throw new Error('GitHub URL is empty.');

  const m = trimmed.match(/github\.com\/([^/]+)\/([^/?#]+)/i);
  if (!m) {
    ghLog.warn('URL did not match github.com/owner/repo pattern', { url: trimmed });
    throw new Error('Use the format https://github.com/owner/repo');
  }
  const owner = m[1];
  const repo = m[2].replace(/\.git$/i, '');
  ghLog.info('Resolved repo', { owner, repo });

  onProgress?.({ stage: 'Resolving repository', current: 0, total: 1 });

  let repoResp;
  try {
    repoResp = await fetch(`https://api.github.com/repos/${owner}/${repo}`);
  } catch (e) {
    ghLog.error('Repo metadata fetch threw', { error: e?.message });
    throw new Error(
      `Network call to api.github.com failed (${e.message || 'unknown'}). ` +
        `This artifact runs in a sandboxed iframe; some browsers / extensions ` +
        `block cross-origin fetches. Workaround: use the Files / Folder tab — ` +
        `download the repo as a zip from GitHub, expand it, and select the folder.`
    );
  }

  ghLog.debug('Repo response', { status: repoResp.status });

  if (repoResp.status === 404) {
    throw new Error(
      'Repository not found, or it is private. Public repos only via URL. Use Files / Folder for private repos.'
    );
  }
  if (repoResp.status === 403) {
    const remaining = repoResp.headers.get('x-ratelimit-remaining');
    const resetUnix = parseInt(repoResp.headers.get('x-ratelimit-reset') || '0', 10);
    const resetIn = resetUnix
      ? Math.max(0, Math.ceil((resetUnix * 1000 - Date.now()) / 60000))
      : null;
    ghLog.warn('Rate limit hit', { remaining, resetIn });
    throw new Error(
      `GitHub API rate limit hit (${remaining || 0} remaining)` +
        (resetIn !== null ? `, resets in ~${resetIn} min` : '') +
        `. Unauthenticated limit is 60/hour per IP. Use Files / Folder upload as fallback.`
    );
  }
  if (!repoResp.ok) {
    throw new Error(`GitHub API ${repoResp.status} ${repoResp.statusText}`);
  }

  let repoInfo;
  try {
    repoInfo = await repoResp.json();
  } catch (e) {
    ghLog.error('Repo metadata JSON parse failed', { error: e?.message });
    throw new Error('GitHub responded with non-JSON. Try again or use Files upload.');
  }

  const branch = repoInfo.default_branch;
  if (!branch) {
    throw new Error('GitHub did not report a default branch. Repository may be empty.');
  }

  onProgress?.({ stage: `Walking ${branch} tree`, current: 0, total: 1 });
  let treeResp;
  try {
    treeResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
    );
  } catch (e) {
    ghLog.error('Tree fetch threw', { error: e?.message });
    throw new Error(`Tree fetch failed: ${e.message || 'unknown'}. Try Files / Folder upload.`);
  }
  if (!treeResp.ok) {
    throw new Error(`Tree fetch returned ${treeResp.status}`);
  }
  const treeData = await treeResp.json();
  if (treeData.truncated) {
    ghLog.warn('Tree was truncated by GitHub (large repo)', { entryCount: treeData.tree?.length });
  }

  const targets = (treeData.tree || [])
    .filter(
      (node) => node.type === 'blob' && shouldScanFile(node.path) && (node.size || 0) < 200000
    )
    .slice(0, 80);
  ghLog.info('Targets selected', {
    totalEntries: treeData.tree?.length,
    targetCount: targets.length,
  });

  if (targets.length === 0) {
    throw new Error('No security-relevant files found in this repository tree.');
  }

  const out = [];
  let blobFailures = 0;
  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    onProgress?.({ stage: `Fetching ${t.path}`, current: i + 1, total: targets.length });
    try {
      const r = await fetch(
        `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${t.path}`
      );
      if (r.ok) {
        const content = await r.text();
        out.push({ path: t.path, content });
      } else {
        blobFailures++;
        ghLog.debug('Blob fetch non-OK', { path: t.path, status: r.status });
      }
    } catch (e) {
      blobFailures++;
      ghLog.debug('Blob fetch threw', { path: t.path, error: e?.message });
    }
  }
  if (blobFailures > 0) {
    ghLog.warn('Some blob fetches failed', { fetched: out.length, failed: blobFailures });
  }
  if (out.length === 0) {
    throw new Error(
      'Tree was readable but no file contents could be fetched. Likely a sandbox restriction. Use Files / Folder upload.'
    );
  }
  return out;
}

// ==========================================================================
// SNIPPETS, EXPORTS, CLIPBOARD
// ==========================================================================

// Capture ±ctx lines around the finding line. lineNum is 1-based.
export function buildSnippet(content, lineNum, ctx = 5) {
  if (!content || !lineNum) return null;
  const lines = content.split('\n');
  if (lines.length === 0) return null;
  // Clamp into file range — a probe that miscomputes lineNum past EOF still produces a useful snippet
  // anchored at the last real line, rather than an empty / inverted range.
  const clampedHit = Math.min(Math.max(1, lineNum), lines.length);
  const start = Math.max(1, clampedHit - ctx);
  const end = Math.min(lines.length, clampedHit + ctx);
  const out = [];
  for (let i = start; i <= end; i++) {
    out.push({ n: i, text: lines[i - 1] ?? '', isHit: i === clampedHit });
  }
  return { startLine: start, endLine: end, lines: out };
}

export function snippetToText(snippet) {
  if (!snippet) return '';
  return snippet.lines
    .map((l) => `${String(l.n).padStart(4)}${l.isHit ? '> ' : ': '}${l.text}`)
    .join('\n');
}

export function formatJSON(results) {
  return JSON.stringify(
    {
      schema: 'midatlantic-audit/v1',
      scannedAt: results.scannedAt.toISOString(),
      source: results.source,
      filesScanned: results.filesScanned,
      score: results.score,
      riskTier: riskTier(results.score).label,
      summary: {
        total: results.findings.length,
        bySeverity: results.findings.reduce((a, f) => {
          a[f.severity] = (a[f.severity] || 0) + 1;
          return a;
        }, {}),
      },
      findings: results.findings.map((f) => ({
        id: f.id,
        severity: f.severity,
        category: f.category,
        cwe: f.cwe,
        probe: f.probe,
        title: f.title,
        file: f.file,
        line: f.line,
        evidence: f.evidence,
        remediation: f.remediation,
        snippet: f.snippet
          ? {
              startLine: f.snippet.startLine,
              endLine: f.snippet.endLine,
              text: snippetToText(f.snippet),
            }
          : null,
      })),
    },
    null,
    2
  );
}

export function formatMarkdown(results) {
  const tier = riskTier(results.score);
  const sevCounts = results.findings.reduce((a, f) => {
    a[f.severity] = (a[f.severity] || 0) + 1;
    return a;
  }, {});
  const sevLine = SEV_ORDER.filter((s) => sevCounts[s])
    .map((s) => `${sevCounts[s]} ${s}`)
    .join(', ');

  let md = `# Pre-Flight Security Audit\n\n`;
  md += `- **Risk:** ${tier.label} — score ${results.score} / 100\n`;
  md += `- **Source:** ${results.source}\n`;
  md += `- **Files scanned:** ${results.filesScanned}\n`;
  md += `- **Scanned at:** ${results.scannedAt.toISOString()}\n`;
  md += `- **Findings:** ${results.findings.length}${sevLine ? ` (${sevLine})` : ''}\n\n`;
  md += `---\n\n`;

  results.findings.forEach((f, i) => {
    md += `## ${i + 1}. [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `- **File:** \`${f.file}${f.line ? ':' + f.line : ''}\`\n`;
    md += `- **Category:** ${f.category}\n`;
    md += `- **CWE:** ${f.cwe}\n`;
    md += `- **Probe:** ${f.probe}\n\n`;
    md += `**Evidence**\n\n\`${f.evidence}\`\n\n`;
    if (f.snippet) {
      md += `**Code snapshot** (line ${f.line} marked with \`>\`)\n\n`;
      md += '```\n' + snippetToText(f.snippet) + '\n```\n\n';
    }
    md += `**Remediation**\n\n${f.remediation}\n\n---\n\n`;
  });
  return md;
}

// PR-comment Markdown: fits in a collapsed <details> block, links findings by file path, summary tagline.
export function formatPRComment(results) {
  const tier = riskTier(results.score);
  const sevCounts = results.findings.reduce((a, f) => {
    a[f.severity] = (a[f.severity] || 0) + 1;
    return a;
  }, {});
  const top = SEV_ORDER.filter((s) => sevCounts[s]);
  const sevSummary = top.length
    ? top.map((s) => `${sevCounts[s]} ${s}`).join(' · ')
    : 'no findings';
  const titleEmoji = tier.label.startsWith('CRITICAL')
    ? '🟥'
    : tier.label.startsWith('HIGH')
      ? '🟧'
      : tier.label.startsWith('MODERATE')
        ? '🟨'
        : '🟩';

  let md = `## ${titleEmoji} Pre-Flight Audit — ${tier.label} (${results.score}/100)\n\n`;
  md += `**${results.findings.length} finding${results.findings.length === 1 ? '' : 's'}** · ${sevSummary} · ${results.filesScanned} file${results.filesScanned === 1 ? '' : 's'} scanned\n\n`;
  if (results.findings.length === 0) {
    md += '_No findings from this probe set. Manual IDOR / runtime checks remain out of scope._\n';
    return md;
  }
  md += `<details>\n<summary>Click to expand ${results.findings.length} finding${results.findings.length === 1 ? '' : 's'}</summary>\n\n`;
  // Group by file so the comment shows up next to the code review naturally.
  const byFile = new Map();
  results.findings.forEach((f) => {
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push(f);
  });
  for (const [filePath, fs] of byFile) {
    md += `### \`${filePath}\`\n\n`;
    for (const f of fs) {
      md +=
        `- **[${f.severity.toUpperCase()}]** ${f.title} — ${f.cwe}` +
        (f.line ? ` _(line ${f.line})_` : '') +
        `\n`;
      md += `  _${f.remediation.replace(/\n+/g, ' ').slice(0, 220)}${f.remediation.length > 220 ? '…' : ''}_\n`;
    }
    md += '\n';
  }
  md += `</details>\n\n`;
  md += `<sub>Generated by Mid-Atlantic AI Pre-Flight Audit Tool · ${results.scannedAt.toISOString()}</sub>\n`;
  return md;
}

export function formatAgentPrompt(results) {
  const tier = riskTier(results.score);
  const top = results.findings.slice(0, 30);
  let p = `You are a senior application-security engineer. The findings below come from a static audit of a web app (score ${results.score}/100, ${tier.label}). For each finding, propose the smallest correct fix:\n`;
  p += `- If you have enough context, output a unified diff against the file.\n`;
  p += `- Otherwise describe the change in one or two sentences with a precise file:line reference.\n`;
  p += `- Group fixes by file when there are multiple in the same file.\n`;
  p += `- Call out any finding that needs human judgement (auth model, business logic) instead of guessing.\n\n`;
  p += `Findings (highest severity first):\n\n`;

  top.forEach((f, i) => {
    p += `### ${i + 1}. [${f.severity}] ${f.title}\n`;
    p += `- File: ${f.file}${f.line ? ':' + f.line : ''}\n`;
    p += `- Category: ${f.category} | ${f.cwe} | probe: ${f.probe}\n`;
    p += `- Evidence: ${f.evidence}\n`;
    if (f.snippet) {
      p += `- Code (line ${f.line} marked with \`>\`):\n`;
      p += '```\n' + snippetToText(f.snippet) + '\n```\n';
    }
    p += `- Remediation hint: ${f.remediation}\n\n`;
  });

  if (results.findings.length > top.length) {
    p += `(${results.findings.length - top.length} additional findings omitted to keep the prompt small. Re-export to a JSON file for full data.)\n`;
  }
  return p;
}

export function downloadFile(content, filename, mime = 'text/plain') {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export async function copyToClipboard(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {}
  // fallback
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {}
  document.body.removeChild(ta);
  return ok;
}

export function timestampSlug(date) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}`;
}

export function timeAgo(iso) {
  const t = new Date(iso).getTime();
  if (!t) return '';
  const diff = Math.max(0, Date.now() - t);
  const sec = Math.floor(diff / 1000);
  if (sec < 45) return `${sec || 1}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 30) return `${day}d ago`;
  return new Date(iso).toLocaleDateString();
}

// ==========================================================================
// HISTORY (localStorage-backed)
// ==========================================================================

export const HISTORY_KEY = 'audit-app:history:v1';
export const HISTORY_MAX = 10;

export function loadHistory() {
  try {
    if (typeof localStorage === 'undefined') return [];
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function persistHistory(arr) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(arr));
    return true;
  } catch {
    // Quota exceeded — try shrinking by half and retry once.
    if (arr.length > 1) {
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(arr.slice(0, Math.floor(arr.length / 2))));
        return true;
      } catch {}
    }
    return false;
  }
}

export function makeHistoryEntry(results, sourceType) {
  const bySeverity = results.findings.reduce((a, f) => {
    a[f.severity] = (a[f.severity] || 0) + 1;
    return a;
  }, {});
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    scannedAt:
      results.scannedAt instanceof Date ? results.scannedAt.toISOString() : results.scannedAt,
    source: results.source,
    sourceType,
    filesScanned: results.filesScanned,
    score: results.score,
    bySeverity,
    findings: results.findings,
  };
}

// Compute "what's new / fixed / changed" between the current scan and the most recent prior scan of the same source.
// Pure function; testable in isolation.
export function computeDiffAgainstPrior(currentResults, history) {
  if (!currentResults || !Array.isArray(history)) return null;
  // Find the most recent prior entry for the same source (skip the entry that represents the current scan).
  // History is newest-first; skip entries that match BOTH source AND scannedAt of the current scan.
  const currentTs =
    currentResults.scannedAt instanceof Date
      ? currentResults.scannedAt.toISOString()
      : currentResults.scannedAt;
  const prior = history.find(
    (h) => h.source === currentResults.source && h.scannedAt !== currentTs
  );
  if (!prior) return null;

  // Use the deterministic stableId where available; fall back to the legacy composite key for
  // older history entries written before stable IDs existed. New scans always carry stableId
  // because handleScan calls attachStableIds(); old entries shipped without it.
  const keyOf = (f) => f.stableId || `legacy|${f.probe}|${f.file}|${f.line}|${f.title}`;
  const currentSet = new Set(currentResults.findings.map(keyOf));
  const priorSet = new Set((prior.findings || []).map(keyOf));

  const introduced = currentResults.findings.filter((f) => !priorSet.has(keyOf(f)));
  const fixed = (prior.findings || []).filter((f) => !currentSet.has(keyOf(f)));
  const persisted = currentResults.findings.filter((f) => priorSet.has(keyOf(f)));

  const bucket = (arr) =>
    arr.reduce((a, f) => {
      a[f.severity] = (a[f.severity] || 0) + 1;
      return a;
    }, {});
  return {
    priorScannedAt: prior.scannedAt,
    priorScore: prior.score,
    deltaScore: currentResults.score - prior.score,
    introduced: { count: introduced.length, bySeverity: bucket(introduced), items: introduced },
    fixed: { count: fixed.length, bySeverity: bucket(fixed), items: fixed },
    persisted: { count: persisted.length, bySeverity: bucket(persisted) },
  };
}

export function historyEntryToResults(entry) {
  return {
    findings: entry.findings || [],
    score: entry.score,
    scannedAt: new Date(entry.scannedAt),
    filesScanned: entry.filesScanned,
    source: entry.source,
  };
}

// ==========================================================================
// COMPONENTS
// ==========================================================================

// Brand fonts (Mid-Atlantic AI brand kit):
//  - Rubik          → display: titles + headings (Bold)
//  - Roboto         → body / captions / quotes (Regular + Italic)
//  - Roboto Condensed → subheadings
//  - Impact         → section-header / eyebrow labels (all-caps)
//  - Mono only used for code snapshots and line numbers
const fontDisplay = "'Rubik', 'Helvetica Neue', Helvetica, Arial, sans-serif";
const fontUI = "'Roboto', 'Helvetica Neue', Helvetica, Arial, sans-serif";
const fontCondensed = "'Roboto Condensed', 'Roboto', 'Helvetica Neue', Arial, sans-serif";
const fontEyebrow = "'Impact', 'Haettenschweiler', 'Arial Narrow Bold', sans-serif";
const fontMono = "ui-monospace, 'SF Mono', Menlo, Consolas, 'Roboto Mono', monospace";

export function GlobalStyle() {
  return (
    <style>{`
      /* Brand fonts loaded non-render-blocking via index.html's <link rel="preload" as="style"> +
         onload swap. Keeping @import here would re-fetch and re-block paint. */
      * { box-sizing: border-box; }
      body { margin: 0; }
      /* WCAG 2.4.7 — visible focus indicator for keyboard users */
      .ap-app *:focus-visible {
        outline: 2px solid ${T.accent};
        outline-offset: 2px;
      }
      /* WCAG 2.2 SC 2.5.8 Target Size (Minimum) — every interactive target ≥ 24×24 CSS px.
         Inline-styled buttons that need to be visually smaller use box-shadow / outline padding
         to retain the hit area while keeping the visible chrome compact. */
      .ap-app button, .ap-app [role="button"], .ap-app a {
        min-height: 24px;
        min-width: 24px;
      }
      /* Compact inline buttons (e.g. filter chips) still get a 24px hit-area via padding floor. */
      .ap-compact-btn {
        min-height: 24px !important;
        padding: 4px 10px !important;
        display: inline-flex; align-items: center; justify-content: center;
      }
      /* Honor reduced-motion preference (WCAG 2.3.3) */
      @media (prefers-reduced-motion: reduce) {
        .ap-app *, .ap-app *::before, .ap-app *::after {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }
      }
      /* Screen-reader-only utility */
      .ap-sr-only {
        position: absolute;
        width: 1px; height: 1px;
        padding: 0; margin: -1px;
        overflow: hidden; clip: rect(0,0,0,0);
        white-space: nowrap; border: 0;
      }
      /* Skip-to-content link — hidden until keyboard-focused (WCAG 2.4.1) */
      .ap-skip-link {
        position: absolute;
        top: -100px; left: 8px;
        background: ${T.accent};
        color: ${T.bg};
        padding: 10px 16px;
        font-family: ${fontUI};
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        z-index: 1000;
        transition: top 0.15s ease-out;
      }
      .ap-skip-link:focus {
        top: 8px;
        outline: 2px solid ${T.text};
        outline-offset: 2px;
      }
      /* High-contrast preference — flatten gradients and bump borders */
      @media (prefers-contrast: more) {
        .ap-app {
          background-image: none !important;
        }
        .ap-card, .ap-finding {
          border-color: ${T.text} !important;
        }
        .ap-eyebrow {
          color: ${T.text} !important;
        }
      }
      /* Forced-colors (Windows high contrast) — let the OS recolor */
      @media (forced-colors: active) {
        .ap-app {
          background: Canvas;
          color: CanvasText;
        }
        .ap-btn {
          border: 1px solid ButtonBorder;
          background: ButtonFace;
          color: ButtonText;
        }
      }
      .ap-app {
        background: ${T.bg};
        background-image:
          linear-gradient(${T.bgGrid} 1px, transparent 1px),
          linear-gradient(90deg, ${T.bgGrid} 1px, transparent 1px);
        background-size: 48px 48px;
        color: ${T.text};
        font-family: ${fontUI};
        font-size: 13px;
        line-height: 1.55;
        min-height: 100vh;
        letter-spacing: 0.01em;
      }
      .ap-app *::-webkit-scrollbar { width: 10px; height: 10px; }
      .ap-app *::-webkit-scrollbar-track { background: ${T.bg}; }
      .ap-app *::-webkit-scrollbar-thumb { background: ${T.border}; border-radius: 0; }
      .ap-app *::-webkit-scrollbar-thumb:hover { background: ${T.borderAlt}; }
      .ap-btn {
        font-family: ${fontMono};
        font-size: 12px;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        background: ${T.accent};
        color: ${T.bg};
        border: 1px solid ${T.accent};
        padding: 12px 20px;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      .ap-btn:hover:not(:disabled) { background: ${T.accentDim}; border-color: ${T.accentDim}; }
      /* Disabled: clearly distinct from enabled, still WCAG 3:1 UI contrast.
         textDim (#a8b1c5) on panel (#11192e) ≈ 7.5:1 so text is readable;
         strikethrough + dashed border + not-allowed cursor make "disabled" obvious. */
      .ap-btn:disabled, .ap-btn-ghost:disabled {
        background: ${T.panel};
        color: ${T.textDim};
        border: 1px dashed ${T.borderAlt};
        cursor: not-allowed;
        text-decoration: line-through;
        text-decoration-color: ${T.textMuted};
      }
      .ap-btn-ghost {
        background: transparent;
        color: ${T.textDim};
        border: 1px solid ${T.border};
      }
      .ap-btn-ghost:hover:not(:disabled) {
        background: ${T.panel};
        color: ${T.text};
        border-color: ${T.borderAlt};
      }
      .ap-input {
        font-family: ${fontMono};
        font-size: 13px;
        background: ${T.bg};
        color: ${T.text};
        border: 1px solid ${T.border};
        padding: 12px 14px;
        width: 100%;
        outline: none;
        transition: border-color 0.15s ease;
      }
      .ap-input:focus { border-color: ${T.accent}; }
      .ap-tab {
        font-family: ${fontMono};
        font-size: 11px;
        letter-spacing: 0.12em;
        text-transform: uppercase;
        padding: 14px 24px;
        background: transparent;
        color: ${T.textMuted};
        border: none;
        border-bottom: 2px solid transparent;
        cursor: pointer;
        transition: all 0.15s ease;
      }
      .ap-tab:hover { color: ${T.textDim}; }
      .ap-tab-active {
        color: ${T.accent};
        border-bottom-color: ${T.accent};
      }
      .ap-card {
        background: ${T.panel};
        border: 1px solid ${T.border};
      }
      .ap-finding {
        background: ${T.panel};
        border: 1px solid ${T.border};
        border-left-width: 3px;
        transition: background 0.15s ease;
      }
      .ap-finding:hover { background: ${T.panelHover}; }
      .ap-spin { animation: ap-spin 0.8s linear infinite; }
      @keyframes ap-spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
      .ap-pulse { animation: ap-pulse 2s ease-in-out infinite; }
      @keyframes ap-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
      .ap-fade-in { animation: ap-fade 0.4s ease-out; }
      @keyframes ap-fade { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
      .ap-eyebrow {
        font-family: ${fontEyebrow};
        font-size: 11px;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: ${T.textMuted};
        font-weight: 400;
      }
      .ap-display { font-family: ${fontDisplay}; font-weight: 700; font-style: normal; }
      .ap-condensed { font-family: ${fontCondensed}; }
      .ap-mono { font-family: ${fontMono}; }
    `}</style>
  );
}

export function ScoreGauge({ score }) {
  const tier = riskTier(score);
  const radius = 90;
  const circ = 2 * Math.PI * radius;
  const filled = (score / 100) * circ;
  return (
    <div
      role="img"
      aria-label={`Risk score ${score} out of 100, ${tier.label}`}
      style={{ position: 'relative', width: 220, height: 220 }}
    >
      <svg
        width="220"
        height="220"
        viewBox="0 0 220 220"
        style={{ transform: 'rotate(-90deg)' }}
        aria-hidden="true"
      >
        <circle cx="110" cy="110" r={radius} fill="none" stroke={T.borderAlt} strokeWidth="2" />
        <circle
          cx="110"
          cy="110"
          r={radius}
          fill="none"
          stroke={tier.ring}
          strokeWidth="3"
          strokeDasharray={`${filled} ${circ}`}
          strokeLinecap="butt"
          style={{ transition: 'stroke-dasharray 0.8s ease-out, stroke 0.4s ease' }}
        />
      </svg>
      <div
        style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <div className="ap-eyebrow" style={{ marginBottom: 4 }}>
          SCORE
        </div>
        <div className="ap-display" style={{ fontSize: 84, lineHeight: 1, color: tier.color }}>
          {score}
        </div>
        <div className="ap-mono" style={{ fontSize: 11, color: T.textMuted, marginTop: 2 }}>
          / 100
        </div>
      </div>
    </div>
  );
}

export function CategoryBar({ name, count, max, color }) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  return (
    <div style={{ marginBottom: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span className="ap-mono" style={{ fontSize: 12, color: T.text }}>
          {name}
        </span>
        <span className="ap-mono" style={{ fontSize: 12, color: T.textDim }}>
          {count}
        </span>
      </div>
      <div style={{ height: 4, background: T.border, position: 'relative' }}>
        <div
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            bottom: 0,
            width: `${pct}%`,
            background: color,
            transition: 'width 0.6s ease-out',
          }}
        />
      </div>
    </div>
  );
}

export function SeverityChip({ severity }) {
  const c = T.sev[severity];
  return (
    <span
      className="ap-mono"
      style={{
        fontSize: 10,
        letterSpacing: '0.12em',
        textTransform: 'uppercase',
        color: c.fg,
        background: c.bg,
        border: `1px solid ${c.border}`,
        padding: '3px 8px',
        fontWeight: 600,
      }}
    >
      {severity}
    </span>
  );
}

export function DiagnosticsDrawer({ open, onClose, filter, setFilter }) {
  const all = getLogs();
  const RANK = { debug: 0, info: 1, warn: 2, error: 3 };
  const visible = all.filter((e) => RANK[e.level] >= RANK[filter]);
  const counts = all.reduce((a, e) => {
    a[e.level] = (a[e.level] || 0) + 1;
    return a;
  }, {});
  const handleCopy = async () => {
    await copyToClipboard(exportLogs());
  };
  const handleDownload = () => {
    downloadFile(exportLogs(), `audit-logs-${timestampSlug(new Date())}.json`, 'application/json');
  };
  const drawerRef = useRef(null);
  const closeBtnRef = useRef(null);
  const lastFocusRef = useRef(null);

  // Focus management: trap Tab inside drawer, focus close button on open, restore focus on close.
  useEffect(() => {
    if (!open) return;
    lastFocusRef.current = document.activeElement;
    // Defer to next tick so the close button is in the DOM and focusable.
    const t = setTimeout(() => closeBtnRef.current?.focus(), 0);
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== 'Tab') return;
      const focusable = drawerRef.current?.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (!focusable || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => {
      clearTimeout(t);
      document.removeEventListener('keydown', onKey);
      // Restore focus to whatever element opened the drawer.
      if (lastFocusRef.current && lastFocusRef.current.focus) {
        try {
          lastFocusRef.current.focus();
        } catch {}
      }
    };
  }, [open, onClose]);

  return (
    <>
      {open && (
        <div
          onClick={onClose}
          aria-hidden="true"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            zIndex: 50,
          }}
        />
      )}
      <div
        ref={drawerRef}
        role="dialog"
        aria-label="Diagnostics log"
        aria-modal="true"
        aria-hidden={!open}
        style={{
          position: 'fixed',
          left: 0,
          right: 0,
          bottom: 0,
          maxHeight: '60vh',
          background: T.panel,
          borderTop: `2px solid ${T.accent}`,
          transform: open ? 'translateY(0)' : 'translateY(100%)',
          transition: 'transform 0.25s ease-out',
          zIndex: 60,
          display: 'flex',
          flexDirection: 'column',
        }}
      >
        <div
          style={{
            padding: '12px 18px',
            borderBottom: `1px solid ${T.border}`,
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            flexWrap: 'wrap',
          }}
        >
          <Activity size={14} color={T.accent} />
          <span className="ap-eyebrow" style={{ color: T.text }}>
            DIAGNOSTICS · {visible.length} / {all.length}
          </span>
          <div style={{ display: 'flex', gap: 4 }}>
            {['debug', 'info', 'warn', 'error'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilter(lvl)}
                className="ap-mono"
                style={{
                  fontSize: 10,
                  padding: '4px 8px',
                  letterSpacing: '0.1em',
                  textTransform: 'uppercase',
                  background: filter === lvl ? T.accent : 'transparent',
                  color: filter === lvl ? T.bg : T.textDim,
                  border: `1px solid ${filter === lvl ? T.accent : T.border}`,
                  cursor: 'pointer',
                }}
              >
                {lvl} {counts[lvl] ? `(${counts[lvl]})` : ''}
              </button>
            ))}
          </div>
          <div style={{ flex: 1 }} />
          <button
            onClick={handleCopy}
            className="ap-btn ap-btn-ghost"
            style={{ padding: '6px 12px', fontSize: 10 }}
            title="Copy all logs as JSON"
          >
            <Copy
              size={11}
              style={{ display: 'inline-block', marginRight: 5, verticalAlign: '-1px' }}
            />
            Copy
          </button>
          <button
            onClick={handleDownload}
            className="ap-btn ap-btn-ghost"
            style={{ padding: '6px 12px', fontSize: 10 }}
            title="Download log buffer as JSON"
          >
            <Download
              size={11}
              style={{ display: 'inline-block', marginRight: 5, verticalAlign: '-1px' }}
            />
            Save
          </button>
          <button
            onClick={() => clearLogs()}
            className="ap-btn ap-btn-ghost"
            style={{ padding: '6px 12px', fontSize: 10 }}
            title="Clear log buffer"
          >
            <Trash2
              size={11}
              style={{ display: 'inline-block', marginRight: 5, verticalAlign: '-1px' }}
            />
            Clear
          </button>
          <button
            onClick={onClose}
            ref={closeBtnRef}
            aria-label="Close diagnostics"
            type="button"
            style={{
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              cursor: 'pointer',
              padding: '6px 8px',
            }}
          >
            <X size={12} aria-hidden="true" />
          </button>
        </div>
        <div style={{ overflow: 'auto', flex: 1, padding: '8px 18px' }}>
          {visible.length === 0 ? (
            <div style={{ fontSize: 12, color: T.textMuted, padding: '16px 0' }}>
              No log entries at this filter level.
            </div>
          ) : (
            visible
              .slice()
              .reverse()
              .map((e) => {
                const colorMap = {
                  debug: T.textMuted,
                  info: T.text,
                  warn: T.sev.medium.fg,
                  error: T.sev.critical.fg,
                };
                return (
                  <div
                    key={e.id}
                    style={{
                      padding: '6px 0',
                      borderBottom: `1px solid ${T.border}`,
                      fontFamily: fontMono,
                      fontSize: 11,
                      display: 'grid',
                      gridTemplateColumns: '90px 60px 1fr',
                      gap: 12,
                      alignItems: 'baseline',
                    }}
                  >
                    <span style={{ color: T.textMuted }}>
                      {new Date(e.ts).toLocaleTimeString(undefined, { hour12: false })}
                    </span>
                    <span
                      style={{
                        color: colorMap[e.level],
                        fontWeight: 600,
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                      }}
                    >
                      {e.level}
                    </span>
                    <div style={{ color: colorMap[e.level], wordBreak: 'break-word' }}>
                      <span style={{ color: T.accent }}>[{e.scope}]</span> {e.message}
                      {e.context && (
                        <pre
                          style={{
                            margin: '4px 0 0',
                            padding: '6px 8px',
                            background: T.bg,
                            border: `1px solid ${T.border}`,
                            color: T.textDim,
                            fontSize: 10,
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-word',
                          }}
                        >
                          {typeof e.context === 'string'
                            ? e.context
                            : JSON.stringify(e.context, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>
                );
              })
          )}
        </div>
      </div>
    </>
  );
}

export function FindingCard({
  finding,
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
                fontSize: 10,
                color: T.cat[finding.category],
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              {finding.category}
            </span>
            <span className="ap-mono" style={{ fontSize: 10, color: T.textMuted }}>
              {finding.cwe}
            </span>
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
                  fontSize: 10,
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
                  fontSize: 10,
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
          </div>
          <div style={{ fontSize: 13, color: T.text, marginBottom: 4, fontWeight: 500 }}>
            {finding.title}
          </div>
          <div
            className="ap-mono"
            style={{ fontSize: 11, color: T.textMuted, wordBreak: 'break-all' }}
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
              fontSize: 12,
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
                    const ok = await copyToClipboard(snippetToText(finding.snippet));
                    if (ok) {
                      // brief visual confirmation via title on the button itself
                    }
                  }}
                  className="ap-mono"
                  style={{
                    background: 'transparent',
                    border: `1px solid ${T.border}`,
                    color: T.textMuted,
                    cursor: 'pointer',
                    fontSize: 10,
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
                  fontSize: 12,
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
          <div style={{ fontSize: 13, color: T.textDim, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>
            {finding.remediation}
          </div>
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
                style={{ fontSize: 11, padding: '6px 14px' }}
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
                      fontSize: 10,
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
                    <div style={{ fontSize: 12, color: T.sev.critical.fg }}>{aiResponse.error}</div>
                  ) : (
                    <div
                      style={{
                        fontSize: 13,
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
            <span className="ap-mono" style={{ fontSize: 10, color: T.textMuted }}>
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
                    fontSize: 10,
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
                <span className="ap-mono" style={{ fontSize: 10, color: T.textMuted }}>
                  set {timeAgo(finding.suppression.at)}
                </span>
                {finding.suppression.note && (
                  <span style={{ fontSize: 11, color: T.textDim, fontStyle: 'italic' }}>
                    “{finding.suppression.note}”
                  </span>
                )}
                {onUnsuppress && (
                  <button
                    onClick={() => onUnsuppress(finding)}
                    className="ap-btn ap-btn-ghost"
                    style={{ padding: '4px 10px', fontSize: 10 }}
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
                  style={{ padding: '4px 10px', fontSize: 10 }}
                  title="The scanner is wrong — this is not a real issue"
                >
                  False positive
                </button>
                <button
                  onClick={() => onSuppress(finding, 'wont-fix')}
                  className="ap-btn ap-btn-ghost"
                  style={{ padding: '4px 10px', fontSize: 10 }}
                  title="Real issue but intentionally not fixing"
                >
                  Won't fix
                </button>
                <button
                  onClick={() => onSuppress(finding, 'accepted-risk')}
                  className="ap-btn ap-btn-ghost"
                  style={{ padding: '4px 10px', fontSize: 10 }}
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

// ==========================================================================
// AI SETTINGS MODAL
// =========================================================================
// BYOK panel. The user's key never leaves their browser — saved to
// localStorage, sent only to the provider endpoint they chose. The modal
// shows the privacy contract in plain language so it's clear what happens.

export function AISettingsModal({ open, onClose, onSaved }) {
  // We pull `existing` lazily into a state slot so we can refresh it (without `useMemo` having
  // a deps-array lint complaint) and so the form resets to the stored values each time the
  // modal re-opens. Updates are deferred via queueMicrotask so they don't fire synchronously
  // inside the effect tick (react-hooks/set-state-in-effect).
  const [existing, setExisting] = useState(() => loadAIConfig());
  const [provider, setProvider] = useState(existing?.provider || 'openai');
  const [apiKey, setApiKey] = useState(existing?.apiKey || '');
  const [model, setModel] = useState(existing?.model || AI_PROVIDERS.openai.defaultModel);
  const [reveal, setReveal] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!open) return;
    queueMicrotask(() => {
      const cfg = loadAIConfig();
      setExisting(cfg);
      setProvider(cfg?.provider || 'openai');
      setApiKey(cfg?.apiKey || '');
      setModel(cfg?.model || AI_PROVIDERS[cfg?.provider || 'openai'].defaultModel);
      setError(null);
    });
  }, [open]);

  if (!open) return null;
  const meta = AI_PROVIDERS[provider];
  const keyOk = !apiKey || validateKeyShape(provider, apiKey);

  const handleSave = () => {
    if (!apiKey.trim()) {
      setError('Paste an API key, or click Clear to remove the current one.');
      return;
    }
    if (!validateKeyShape(provider, apiKey)) {
      setError(
        `That doesn't look like a ${meta.label} key (expected pattern: ${meta.keyPlaceholder}).`
      );
      return;
    }
    try {
      saveAIConfig({ provider, apiKey, model });
      track(`ai.config.save.${provider}`);
      onSaved?.();
      onClose();
    } catch (e) {
      setError(e?.message || 'Could not save.');
    }
  };

  const handleClear = () => {
    clearAIConfig();
    setApiKey('');
    track('ai.config.clear');
    onSaved?.();
  };

  return (
    <>
      <div
        onClick={onClose}
        aria-hidden="true"
        style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 70 }}
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="AI provider settings"
        style={{
          position: 'fixed',
          top: '50%',
          left: '50%',
          transform: 'translate(-50%, -50%)',
          maxWidth: 540,
          width: 'calc(100vw - 32px)',
          maxHeight: 'calc(100vh - 32px)',
          overflow: 'auto',
          background: T.panel,
          border: `1px solid ${T.borderAlt}`,
          padding: 24,
          zIndex: 80,
          boxShadow: '0 12px 40px rgba(0,0,0,0.6)',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 16,
          }}
        >
          <h2
            className="ap-display"
            style={{ margin: 0, fontSize: 22, fontWeight: 700, color: T.text }}
          >
            AI provider · BYOK
          </h2>
          <button
            onClick={onClose}
            aria-label="Close settings"
            type="button"
            style={{
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              cursor: 'pointer',
              padding: '6px 8px',
            }}
          >
            <X size={12} aria-hidden="true" />
          </button>
        </div>

        <p style={{ fontSize: 12, color: T.textDim, lineHeight: 1.7, marginBottom: 16 }}>
          The "Explain & Verify" button on each finding sends the finding metadata plus its ±5-line
          code snippet to the AI provider you choose, using <strong>your own key</strong>. Your key
          is stored in this browser's localStorage and is sent only to the provider's endpoint —
          never to our origin. There is no server proxy.
        </p>

        <div className="ap-eyebrow" style={{ marginBottom: 8 }}>
          PROVIDER
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          {Object.entries(AI_PROVIDERS).map(([key, p]) => (
            <button
              key={key}
              onClick={() => {
                setProvider(key);
                setModel(p.defaultModel);
                setError(null);
              }}
              className="ap-mono"
              style={{
                flex: 1,
                padding: '10px 12px',
                fontSize: 12,
                background: provider === key ? T.accent : 'transparent',
                color: provider === key ? T.bg : T.textDim,
                border: `1px solid ${provider === key ? T.accent : T.border}`,
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              {p.label}
            </button>
          ))}
        </div>

        <label
          htmlFor="ai-key-input"
          className="ap-eyebrow"
          style={{ display: 'block', marginBottom: 8 }}
        >
          API KEY
        </label>
        <div style={{ position: 'relative', marginBottom: 4 }}>
          <input
            id="ai-key-input"
            className="ap-input"
            type={reveal ? 'text' : 'password'}
            placeholder={meta.keyPlaceholder}
            value={apiKey}
            onChange={(e) => {
              setApiKey(e.target.value);
              setError(null);
            }}
            autoComplete="off"
            spellCheck={false}
            style={{ paddingRight: 70 }}
          />
          <button
            type="button"
            onClick={() => setReveal((v) => !v)}
            className="ap-mono"
            style={{
              position: 'absolute',
              right: 8,
              top: '50%',
              transform: 'translateY(-50%)',
              background: 'transparent',
              border: `1px solid ${T.border}`,
              color: T.textDim,
              cursor: 'pointer',
              fontSize: 10,
              padding: '4px 10px',
            }}
          >
            {reveal ? 'hide' : 'show'}
          </button>
        </div>
        <p style={{ fontSize: 11, color: T.textMuted, marginBottom: 16 }}>
          Get a key from{' '}
          <a
            href={meta.docsUrl}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: T.accent }}
          >
            {meta.docsUrl}
          </a>
          .{' '}
          {apiKey && !keyOk && (
            <span style={{ color: T.sev.medium.fg }}> Key shape doesn't match {meta.label}.</span>
          )}
        </p>

        <label
          htmlFor="ai-model-input"
          className="ap-eyebrow"
          style={{ display: 'block', marginBottom: 8 }}
        >
          MODEL
        </label>
        <select
          id="ai-model-input"
          value={model}
          onChange={(e) => setModel(e.target.value)}
          className="ap-input"
          style={{ marginBottom: 16 }}
        >
          {meta.models.map((m) => (
            <option key={m} value={m}>
              {m}
              {m === meta.defaultModel ? ' (default)' : ''}
            </option>
          ))}
        </select>

        {error && (
          <div
            role="alert"
            style={{
              padding: 10,
              marginBottom: 16,
              fontSize: 12,
              background: T.sev.critical.bg,
              border: `1px solid ${T.sev.critical.border}`,
              color: T.sev.critical.fg,
            }}
          >
            {error}
          </div>
        )}

        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          {existing && (
            <button onClick={handleClear} className="ap-btn ap-btn-ghost" type="button">
              <Trash2
                size={12}
                aria-hidden="true"
                style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
              />
              Clear stored key
            </button>
          )}
          <button onClick={onClose} className="ap-btn ap-btn-ghost" type="button">
            Cancel
          </button>
          <button onClick={handleSave} className="ap-btn" type="button">
            <Check
              size={12}
              aria-hidden="true"
              style={{ display: 'inline-block', marginRight: 6, verticalAlign: '-1px' }}
            />
            Save
          </button>
        </div>
      </div>
    </>
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
  const [showSuppressed, setShowSuppressed] = useState(false);
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
                    Prior score: {diff.priorScore} → {results.score}
                    {diff.deltaScore !== 0 && (
                      <span
                        style={{
                          marginLeft: 8,
                          color: diff.deltaScore > 0 ? T.good : T.sev.critical.fg,
                          fontWeight: 600,
                        }}
                      >
                        {diff.deltaScore > 0 ? (
                          <TrendingUp
                            size={11}
                            aria-hidden="true"
                            style={{
                              display: 'inline-block',
                              verticalAlign: '-1px',
                              marginRight: 2,
                            }}
                          />
                        ) : diff.deltaScore < 0 ? (
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
                        {diff.deltaScore > 0 ? '+' : ''}
                        {diff.deltaScore}
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
                      {diff.persisted.count}
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
                      {results.findings.length} OPEN
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
                  a: '26 probes covering hardcoded secrets (AWS, Stripe, OpenAI, Anthropic, GitHub, etc.), NEXT_PUBLIC_ leak of server secrets, Supabase Row-Level-Security misconfigurations, Firebase permissive rules, JWT algorithm: none, package.json supply-chain hooks, known-compromised package versions, typosquatted and LLM-hallucinated package names, MCP server command-injection patterns, Cursor / Copilot rules-file backdoors, Trojan Source Unicode, prompt-injection sinks, system-prompt leakage to client bundles, missing security headers, CORS wildcards, SSRF and open-redirect patterns, and HTML hygiene.',
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
