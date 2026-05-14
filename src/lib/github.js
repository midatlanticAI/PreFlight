// src/lib/github.js
// Fetch a public GitHub repository's tree and source contents from the browser using
// the public REST API + raw.githubusercontent.com. Filters the tree down to files that
// shouldScanFile() recognizes, caps at 80 files, and reports progress through onProgress.
//
// All errors are mapped to a friendly Error.message that explains the typical recovery
// (rate limit → wait, sandboxed iframe → use file upload, private repo → use file upload).

import { log } from './logger.js';
import { shouldScanFile } from './probes.js';

// BYOT — Bring Your Own Token. The Personal Access Token lives in localStorage under
// `preflight.github_pat`. When present, it's added as an `Authorization: token <pat>`
// header on every GitHub API + raw.githubusercontent.com request the scanner makes.
// Without a token: 60/hr unauthenticated, public repos only. With a token: 5000/hr,
// plus private repos the user has read access to.
const GITHUB_PAT_KEY = 'preflight.github_pat';

export function loadGitHubPAT() {
  try {
    if (typeof localStorage === 'undefined') return null;
    const raw = localStorage.getItem(GITHUB_PAT_KEY);
    return raw && raw.length > 0 ? raw : null;
  } catch {
    return null;
  }
}

export function saveGitHubPAT(pat) {
  try {
    if (typeof pat !== 'string' || pat.trim().length === 0) {
      localStorage.removeItem(GITHUB_PAT_KEY);
      return;
    }
    localStorage.setItem(GITHUB_PAT_KEY, pat.trim());
  } catch (e) {
    log.debug('github: PAT save failed', { error: e?.message });
  }
}

export function clearGitHubPAT() {
  try {
    localStorage.removeItem(GITHUB_PAT_KEY);
  } catch (e) {
    log.debug('github: PAT clear failed', { error: e?.message });
  }
}

// Verifies a token by calling api.github.com/user. Returns { ok, username, error }.
// Pure: doesn't read or write the PAT store; pass the candidate token in directly.
export async function testGitHubToken(pat) {
  if (!pat || typeof pat !== 'string') return { ok: false, error: 'No token provided.' };
  try {
    const resp = await fetch('https://api.github.com/user', {
      headers: { Authorization: `token ${pat.trim()}` },
    });
    if (resp.status === 401) {
      return { ok: false, error: 'Token rejected (401). Check the token and required scope.' };
    }
    if (resp.status === 403) {
      return {
        ok: false,
        error:
          'Forbidden (403). Most often this means the token lacks the `repo` scope, or the user is rate-limited.',
      };
    }
    if (!resp.ok) {
      return { ok: false, error: `GitHub API ${resp.status} ${resp.statusText}` };
    }
    const data = await resp.json();
    return { ok: true, username: data.login || '(unknown)' };
  } catch (e) {
    return { ok: false, error: e?.message || 'Network call failed.' };
  }
}

// Build the headers object once per scan. If the user has a PAT stored, attach it;
// otherwise return an empty object so fetch() goes out unauthenticated.
function buildAuthHeaders() {
  const pat = loadGitHubPAT();
  return pat ? { Authorization: `token ${pat}` } : {};
}

export async function fetchGitHubRepo(url, onProgress) {
  const ghLog = log.child('github');
  const authHeaders = buildAuthHeaders();
  const authenticated = Object.keys(authHeaders).length > 0;

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
    repoResp = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: authHeaders,
    });
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
      authenticated
        ? 'Repository not found, or the token does not have access to it. Verify the URL and the PAT scope (Settings → Private Repos).'
        : 'Repository not found, or it is private. Public repos need no auth; for a private repo, paste a GitHub Personal Access Token in Settings → Private Repos.'
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
  // raw.githubusercontent.com is the CDN-fast path but it does not reliably honor
  // Authorization headers for private-repo blobs (returns 404 even with a valid PAT).
  // For private repos we route blob fetches through api.github.com/repos/.../contents
  // with `Accept: application/vnd.github.raw` so the auth header is respected.
  const isPrivate = repoInfo.private === true;

  onProgress?.({ stage: `Walking ${branch} tree`, current: 0, total: 1 });
  let treeResp;
  try {
    treeResp = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
      { headers: authHeaders }
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
  // Path segments need to be individually URL-encoded so that spaces / unicode / hashes in
  // file names don't break the contents-endpoint URL. raw.githubusercontent.com is more
  // lenient but we encode either way for consistency.
  const encodePath = (p) => p.split('/').map(encodeURIComponent).join('/');
  // Build per-file blob fetcher. For private repos with a PAT we use the api.github.com
  // contents endpoint with `Accept: application/vnd.github.raw` because raw.gh ignores the
  // Authorization header for private blobs. For public repos we keep the CDN-fast path.
  const fetchBlob = isPrivate
    ? (path) =>
        fetch(
          `https://api.github.com/repos/${owner}/${repo}/contents/${encodePath(path)}?ref=${encodeURIComponent(branch)}`,
          { headers: { ...authHeaders, Accept: 'application/vnd.github.raw' } }
        )
    : (path) =>
        fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${encodePath(path)}`, {
          headers: authHeaders,
        });
  for (let i = 0; i < targets.length; i++) {
    const t = targets[i];
    onProgress?.({ stage: `Fetching ${t.path}`, current: i + 1, total: targets.length });
    try {
      const r = await fetchBlob(t.path);
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
    ghLog.warn('Some blob fetches failed', {
      fetched: out.length,
      failed: blobFailures,
      private: isPrivate,
    });
  }
  if (out.length === 0) {
    throw new Error(
      isPrivate
        ? `All ${targets.length} private-repo blob fetches failed. The PAT was accepted for repo metadata but rejected for file content. Verify the token has "Contents: read" repo access (fine-grained PAT) or the classic "repo" scope, then re-scan. Fallback: use Files / Folder upload.`
        : `All ${targets.length} blob fetches failed. Likely a sandboxed-iframe restriction or a transient GitHub outage. Use Files / Folder upload as a workaround.`
    );
  }
  return out;
}
