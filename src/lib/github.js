// src/lib/github.js
// Fetch a public GitHub repository's tree and source contents from the browser using
// the public REST API + raw.githubusercontent.com. Filters the tree down to files that
// shouldScanFile() recognizes, caps at 80 files, and reports progress through onProgress.
//
// All errors are mapped to a friendly Error.message that explains the typical recovery
// (rate limit → wait, sandboxed iframe → use file upload, private repo → use file upload).

import { log } from './logger.js';
import { shouldScanFile } from './probes.js';

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
