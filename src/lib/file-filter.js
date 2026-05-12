// src/lib/file-filter.js
// File inclusion / exclusion rules + the four helper predicates used by probes:
//   - shouldScanFile(path)        does any FILE_INCLUDE regex match, no FILE_EXCLUDE hit
//   - isTestFile(path)            is this a *.test.* / *.spec.* / under tests/ / __tests__/
//   - isScannerSelfSource(path)   is this src/lib/probes.{js,jsx,ts,tsx} or a bundled dist/*.js
//   - isMetaDocFile(path)         is this llms.txt / robots.txt / sitemap.xml / .preflight.*

// Pattern-matching probes use the exclusion helpers to avoid self-references and noisy
// test-file matches; file-size / structural probes still see those files (the LOC count
// is real either way).

// Structural probes (file size, missing .npmrc, architecture) should still see test files.
export function isTestFile(path) {
  if (!path) return false;
  if (/\.(test|spec)\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)(test|tests|__tests__)\//i.test(path)) return true;
  return false;
}

// --- Self-source exclusion: pattern-matching probes should skip scanner internals ---
// The scanner's own regex literals and remediation copy contain the exact patterns it looks
// for (eval, PythonREPL, dangerouslySetInnerHTML, algorithm: 'none'). Without an exclusion,
// every pattern-matching probe finds itself in src/lib/probes.js and in the production
// bundle (dist/) which inlines probes.js. These aren't real vulnerabilities; they're the
// scanner's definitions of what real vulnerabilities look like.
export function isScannerSelfSource(path) {
  if (!path) return false;
  // The scanner's own probe modules + the threat-intel manifests + the file/suppression
  // helpers ALL contain pattern literals and IOC strings that pattern-matching probes
  // would otherwise flag against themselves.
  if (/(^|\/)src\/lib\/probes\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)src\/lib\/probes\//i.test(path)) return true;
  if (/(^|\/)src\/lib\/threat-intel\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)src\/lib\/file-filter\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)src\/lib\/stable-id\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)src\/lib\/suppression\.[jt]sx?$/i.test(path)) return true;
  if (/(^|\/)src\/data\/compromised-packages\.[jt]s$/i.test(path)) return true;
  // v0.4: Learn content (markdown) + the components that render Settings / Learn pages
  // routinely contain pattern strings, sample IOC text, and reference URLs in their
  // teaching copy. They're not real code — exclude from pattern-matching probes.
  if (/(^|\/)src\/learn\//i.test(path)) return true;
  if (/(^|\/)src\/components\/learn\//i.test(path)) return true;
  if (/(^|\/)src\/components\/settings\//i.test(path)) return true;
  if (/(^|\/)src\/lib\/learn-content\.[jt]s$/i.test(path)) return true;
  // The Vite-bundled JS in dist/ contains the inlined probe source.
  if (/(^|\/)dist\/.*\.js$/i.test(path)) return true;
  return false;
}

// --- Meta-doc exclusion: discoverability files inherently contain URL references ---
// llms.txt, robots.txt, sitemap.xml, .preflight.yml/json are documentation/metadata files
// that legitimately list URLs as content (sitemap entries, llms.txt outbound links, suppress-
// rule reasons that quote probe titles). Pattern-matching probes scanning them produce noise:
// URL Reputation hits every documented help-link, and content probes can match suppress-rule
// title-patterns. We want these files visible to SEO/GEO probes (which target them by name)
// but invisible to generic content probes.
export function isMetaDocFile(path) {
  if (!path) return false;
  if (/(^|\/)llms\.txt$/i.test(path)) return true;
  if (/(^|\/)robots\.txt$/i.test(path)) return true;
  if (/(^|\/)sitemap\.xml$/i.test(path)) return true;
  if (/(^|\/)\.preflight\.(ya?ml|json)$/i.test(path)) return true;
  return false;
}

export const FILE_INCLUDE = [
  /(^|\/)\.env(\..+)?$/i,
  /package\.json$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /(^|\/)\.npmrc$/,
  /\.tsx?$/,
  /\.jsx?$/,
  /\.mjs$/,
  /\.cjs$/,
  /\.py$/,
  /\.go$/,
  /\.rb$/,
  /\.php$/,
  /\.java$/,
  /\.html?$/i,
  /\.vue$/,
  /\.svelte$/,
  /\.astro$/,
  /firestore\.rules$/,
  /storage\.rules$/,
  /firebase\.json$/,
  /(^|\/)supabase\/.*\.sql$/,
  /migrations\/.*\.sql$/,
  /next\.config\.(js|mjs|ts)$/,
  /vercel\.json$/,
  /netlify\.toml$/,
  /\.config\.[jt]s$/,
  /Dockerfile$/,
  /docker-compose\.ya?ml$/,
  // SEO / GEO / discoverability files
  /(^|\/)llms\.txt$/i,
  /(^|\/)robots\.txt$/i,
  /(^|\/)sitemap\.xml$/i,
  // Repo-local Pre-Flight config so the suppression workflow loads on GitHub URL scans
  /(^|\/)\.preflight\.(ya?ml|json)$/i,
  // 2026 additions: AI tooling configs, MCP servers, CI workflows
  /\.github\/workflows\/.+\.ya?ml$/,
  /(^|\/)\.cursorrules$/,
  /\.cursor\/rules\/.+\.(mdc?|md|txt)$/,
  /(^|\/)\.windsurfrules$/,
  /(^|\/)CLAUDE\.md$/,
  /claude_desktop_config\.json$/,
  /(^|\/)\.mcp\.json$/,
  /(^|\/)mcp\.json$/,
  // Mini Shai-Hulud post-infection artifacts (May 11, 2026 TanStack campaign):
  // the worm writes itself into .claude/* and .vscode/* to survive npm uninstall.
  /(^|\/)\.claude\/settings\.json$/,
  /(^|\/)\.claude\/setup\.mjs$/,
  /(^|\/)\.claude\/router_runtime\.js$/,
  /(^|\/)\.vscode\/tasks\.json$/,
  /(^|\/)\.vscode\/setup\.mjs$/,
  /(^|\/)tanstack_runner\.js$/,
  /(^|\/)router_init\.js$/,
];

export const FILE_EXCLUDE = [
  /node_modules/,
  /(^|\/)\.git\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)\.next\//,
  /(^|\/)coverage\//,
  /(^|\/)\.cache\//,
  /(^|\/)\.turbo\//,
];

export function shouldScanFile(path) {
  if (FILE_EXCLUDE.some((p) => p.test(path))) return false;
  return FILE_INCLUDE.some((p) => p.test(path));
}

// ==========================================================================
// PROBE MODULES
