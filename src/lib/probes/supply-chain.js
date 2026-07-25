// src/lib/probes/supply-chain.js
//
// Package supply-chain probes: package.json, compromised versions, typosquats, AI rules files, malicious artifacts, npmrc hygiene.
//
// Extracted from the prior builtin.js monolith when it crossed the
// file-size HIGH threshold. Probe bodies are byte-identical to the
// originals; only the location moved. Public import surface is
// preserved by builtin.js, which is now a back-compat shim re-exporting
// every probe function from its new family file.

import {
  COMPROMISED_PACKAGES,
  TYPOSQUATS,
  SLOPSQUAT_GENERIC_RE,
  BIDI_CONTROL_RE,
} from '../threat-intel.js';
import { isTestFile, isScannerSelfSource, isMetaDocFile } from '../file-filter.js';

export function probePackageJson(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/package\.json$/.test(file.path)) return;
    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return;
    }
    // Scan-coverage gap. The May 2026 emailassist field-tech PWA gap was
    // exactly this: package.json had "scripts.start": "node server.js" but
    // server.js was not in the scan set. The probe team-fixed the req.url
    // taint detector (commit 92b0c13), and this surfaces the OTHER half
    // of the gap: tell the user when their entry-point file is missing.
    const entryRefs = new Set();
    if (typeof pkg.main === 'string') entryRefs.add(pkg.main);
    const scriptCmds = pkg.scripts || {};
    for (const key of ['start', 'dev', 'serve', 'server']) {
      const cmd = scriptCmds[key];
      if (typeof cmd !== 'string') continue;
      // Extract a referenced file path from the command (e.g. "node server.js",
      // "ts-node src/server.ts", "nodemon --watch src api/index.js").
      const m =
        cmd.match(/\b(?:node|ts-node|nodemon|tsx|deno|bun)\s+[^&|;]*?(\S+\.[mc]?[jt]s)\b/) ||
        cmd.match(/(\S+\.[mc]?[jt]s)\b/);
      if (m && m[1] && !m[1].startsWith('-')) entryRefs.add(m[1]);
    }
    const baseDir = file.path.replace(/[^/]+$/, ''); // dir of this package.json
    const filePaths = new Set(files.map((x) => x.path));
    for (const ref of entryRefs) {
      const stripped = ref.replace(/^\.\//, '');
      const candidates = [
        stripped,
        baseDir + stripped,
        baseDir + stripped.replace(/^\.\//, ''),
        stripped.replace(/^\.?\.\//, ''),
      ];
      const found = candidates.some((c) => filePaths.has(c));
      if (!found && /\.[mc]?[jt]s$/.test(stripped)) {
        findings.push({
          id: `pkg-entry-not-scanned-${file.path}-${ref.replace(/\W/g, '_')}`,
          probe: 'Architecture',
          title: `Entry point referenced in package.json is not in the scan set: ${ref}`,
          severity: 'high',
          category: 'Misconfiguration',
          cwe: 'CWE-1059',
          file: file.path,
          line: 1,
          evidence: `package.json references "${ref}" via main / scripts.start / dev / serve / server, but this file was not loaded for scanning.`,
          remediation: `The backend entry point is the most security-sensitive file in a Node project (auth, routing, file serving, request parsing all live here). Re-run the scan with this file included: in GitHub mode the entry-point file is auto-prioritized; in Files / Folder mode, drag the file in or upload the parent directory. The May 2026 emailassist gap shipped because PreFlight scanned 5 frontend files and missed server.js, which had a public arbitrary-file-read. Do not ship without seeing the result for this file.`,
        });
      }
    }
    const scripts = pkg.scripts || {};
    if (scripts.postinstall || scripts.preinstall || scripts.install) {
      const script = scripts.postinstall || scripts.preinstall || scripts.install;
      if (/curl|wget|eval|http:\/\//.test(script)) {
        findings.push({
          id: `pkg-postinstall-${file.path}`,
          probe: 'Supply Chain',
          title: 'Suspicious install hook detected',
          severity: 'high',
          category: 'Supply Chain',
          cwe: 'CWE-506',
          file: file.path,
          line: 1,
          evidence: `"postinstall": ${JSON.stringify(script)}`,
          remediation: `Install hooks that download and execute remote code are a common supply-chain attack vector. Audit this script and any package that introduced it. Consider using --ignore-scripts during install in CI.`,
        });
      }
    }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    Object.entries(deps).forEach(([name, version]) => {
      if (typeof version === 'string' && /^(?:git\+|http:|https:|file:)/.test(version)) {
        findings.push({
          id: `pkg-nonregistry-${file.path}-${name}`,
          probe: 'Supply Chain',
          title: `Non-registry dependency "${name}"`,
          severity: 'medium',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${version}"`,
          remediation: `Dependencies installed from arbitrary git or HTTP sources bypass registry integrity checks. If this is intentional and trusted, pin to a specific commit hash rather than a branch. Otherwise migrate to a registry version.`,
        });
      }
      if (typeof version === 'string' && /^(\*|latest|>)/.test(version)) {
        findings.push({
          id: `pkg-floating-${file.path}-${name}`,
          probe: 'Supply Chain',
          title: `Unpinned dependency version "${name}": "${version}"`,
          severity: 'low',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${version}"`,
          remediation: `Floating versions like "*" or "latest" allow any future version, including malicious updates, to install. Pin to a caret range (^1.2.3) or exact version.`,
        });
      }
    });
  });
  return findings;
}

// --- 2026: Known compromised package versions ---
//
// Depth round 5 (latent bug fix per reviewer): the old probe had two latent
// bugs that silenced real npm worm threats:
//
//   1. LOCKFILE BLIND SPOT. The probe only read direct dependencies in
//      package.json. Modern npm worms (the May 2026 Mini Shai-Hulud
//      TanStack wave, the May 2025 Sapphire Sleet axios wave) ALWAYS ship
//      through the lockfile — a clean package.json pinning "axios": "^1.0.0"
//      resolves through package-lock.json to axios@1.14.1 (the compromised
//      version). The probe missed every transitive hit.
//   2. INVERTED SEMVER. The check was
//        versionStr.replace(/^[\^~>=<]+/, '').startsWith(v)
//      which asks "does the input start with the bad version" — backward.
//      "^1.14" became "1.14", which starts with "1.14.1"? Nope, false. So
//      ranges silently passed even when they contained the bad version.
//
// Both fixed below. Lockfile parsers for npm v7+, yarn, pnpm v9, and
// bun.lock (text). SemVer-aware comparison that handles ^/~/range/x.
//
// Helper: SemVer comparison. Minimal — handles the cases real lockfiles
// produce. Returns true if `spec` (a SemVer range string) intersects `bad`
// (a concrete version).
function semverRangeIncludes(spec, bad) {
  if (!spec || !bad) return false;
  spec = String(spec).trim();
  if (spec === '*' || spec === '') return true; // unbounded
  if (spec === 'latest' || spec === 'next') return true; // dist-tag, could resolve to bad
  // Exact match.
  if (spec === bad) return true;
  // Caret: ^1.14.0 means >=1.14.0 <2.0.0 (for x>=1) or >=0.14.0 <0.15.0 (for x=0).
  if (spec.startsWith('^')) {
    const base = spec.slice(1);
    return _withinCaret(base, bad);
  }
  // Tilde: ~1.14.0 means >=1.14.0 <1.15.0.
  if (spec.startsWith('~')) {
    const base = spec.slice(1);
    return _withinTilde(base, bad);
  }
  // x.x.x / 1.x / 1.14.x — wildcard at any position.
  if (/[xX*]/.test(spec)) {
    const re = new RegExp(
      '^' +
        spec
          .split('.')
          .map((p) => (/[xX*]/.test(p) ? '\\d+' : p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
          .join('\\.') +
        '($|[.\\-])'
    );
    return re.test(bad);
  }
  // Bounded range "a b" / "a || b" / ">=a <b".
  if (/\s/.test(spec) || spec.includes('||')) {
    // Split on || first.
    for (const clause of spec.split('||')) {
      const comparators = clause.trim().split(/\s+/);
      let inAll = true;
      for (const cmp of comparators) {
        if (!_satisfies(cmp, bad)) {
          inAll = false;
          break;
        }
      }
      if (inAll) return true;
    }
    return false;
  }
  // Single comparator (e.g. >=1.14.0).
  return _satisfies(spec, bad);
}

function _parseVer(v) {
  const clean = String(v).replace(/^v/, '').split('-')[0].split('+')[0];
  const [maj = 0, min = 0, pat = 0] = clean.split('.').map((n) => parseInt(n, 10) || 0);
  return [maj, min, pat];
}
function _cmp(a, b) {
  const [aM, am, ap] = _parseVer(a);
  const [bM, bm, bp] = _parseVer(b);
  if (aM !== bM) return aM - bM;
  if (am !== bm) return am - bm;
  return ap - bp;
}
function _withinCaret(base, bad) {
  const [bM, bm] = _parseVer(base);
  const [vM, vm] = _parseVer(bad);
  if (_cmp(bad, base) < 0) return false;
  if (bM === 0 && bm === 0) return vM === 0 && vm === 0;
  if (bM === 0) return vM === 0 && vm === bm;
  return vM === bM;
}
function _withinTilde(base, bad) {
  const [bM, bm] = _parseVer(base);
  const [vM, vm] = _parseVer(bad);
  if (_cmp(bad, base) < 0) return false;
  return vM === bM && vm === bm;
}
function _satisfies(comparator, bad) {
  const m = comparator.match(/^([<>]=?|=)\s*(\S+)$/);
  if (!m) return comparator === bad;
  const [, op, ver] = m;
  const c = _cmp(bad, ver);
  if (op === '=') return c === 0;
  if (op === '<') return c < 0;
  if (op === '<=') return c <= 0;
  if (op === '>') return c > 0;
  if (op === '>=') return c >= 0;
  return false;
}

// True if a known-compromised entry matches a concrete resolved version.
function _isCompromisedVersion(known, version) {
  if (!known) return false;
  if (known.versions.includes('*')) return true;
  return known.versions.some((v) => v === version || _cmp(v, version) === 0);
}

// Parse package-lock.json (npm v7+). Returns iterable of {name, version, chain}.
function* _walkNpmLock(content) {
  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return;
  }
  if (pkg.packages) {
    // npm v7+ format: keys like "node_modules/axios" or
    // "node_modules/foo/node_modules/axios".
    for (const [key, entry] of Object.entries(pkg.packages)) {
      if (!key.startsWith('node_modules/')) continue;
      const segments = key.split('node_modules/').filter(Boolean);
      const name = segments[segments.length - 1].replace(/\/$/, '');
      const chain =
        segments
          .slice(0, -1)
          .map((s) => s.replace(/\/$/, ''))
          .join(' > ') || 'root';
      yield { name, version: entry.version, chain };
    }
  } else if (pkg.dependencies) {
    // Legacy v1/v2 — recursive walker (named generator so `yield` is legal).
    function* walk(deps, parents) {
      for (const [name, entry] of Object.entries(deps)) {
        yield { name, version: entry.version, chain: parents.join(' > ') || 'root' };
        if (entry.dependencies) yield* walk(entry.dependencies, [...parents, name]);
      }
    }
    yield* walk(pkg.dependencies, []);
  }
}

// Parse yarn.lock (v1 + v2 berry). Returns iterable of {name, version}.
function* _walkYarnLock(content) {
  // yarn.lock entries look like:
  //   "@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":
  //     version "1.2.3"
  // The keys are comma-separated, the version line follows.
  const lines = content.split('\n');
  let currentKeys = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^[^\s#]/.test(line) && line.includes('@')) {
      // Header line.
      currentKeys = line
        .trim()
        .replace(/:$/, '')
        .split(/,\s*/)
        .map((k) => k.replace(/^["']|["']$/g, ''));
    } else if (currentKeys.length && /^\s+version\b/.test(line)) {
      const m = line.match(/version\s+["']?([^"']+)["']?/);
      if (m) {
        for (const key of currentKeys) {
          // Extract name from key like "@scope/pkg@^1.0.0" or "pkg@^1.0.0".
          const atIdx = key.lastIndexOf('@');
          if (atIdx <= 0) continue;
          const name = key.slice(0, atIdx);
          yield { name, version: m[1], chain: 'lockfile' };
        }
        currentKeys = [];
      }
    }
  }
}

// Parse pnpm-lock.yaml (v9+). Keys like "/@scope/pkg@1.2.3(react@18.2.0)" or
// "/pkg@1.2.3".
function* _walkPnpmLock(content) {
  const lines = content.split('\n');
  for (const line of lines) {
    // Look for keys at any indent that match a pnpm pkg path.
    const m = line.match(/^\s+(['"]?)(\/@?[\w\-./]+@[^()\s'"]+)\1\s*:/);
    if (!m) continue;
    const key = m[2];
    const slash = key.startsWith('/') ? key.slice(1) : key;
    const atIdx = slash.lastIndexOf('@');
    if (atIdx <= 0) continue;
    const name = slash.slice(0, atIdx);
    const version = slash.slice(atIdx + 1);
    yield { name, version, chain: 'lockfile' };
  }
}

// Parse bun.lock (text format, ~yarn-ish).
function* _walkBunLock(content) {
  // bun.lock looks similar to yarn.lock for parsing purposes.
  yield* _walkYarnLock(content);
}

export function probeCompromisedPackages(files) {
  const findings = [];
  const seenFindings = new Set();
  const emit = (name, version, chain, file, isTransitive, spec) => {
    const known = COMPROMISED_PACKAGES[name];
    if (!known) return;
    if (!_isCompromisedVersion(known, version)) return;
    const key = `${name}@${version}-${file.path}`;
    if (seenFindings.has(key)) return;
    seenFindings.add(key);
    findings.push({
      id: `compromised-${file.path}-${name}-${version}`,
      probe: 'Compromised Packages',
      title: isTransitive
        ? `Known-compromised package: ${name}@${version} (transitive via ${chain})`
        : `Known-compromised package: ${name}@${version}`,
      severity: 'critical',
      category: 'Supply Chain',
      cwe: 'CWE-506',
      file: file.path,
      line: 1,
      evidence: spec
        ? `${name}: ${spec} (resolved ${version}) — ${known.note}`
        : `${name}@${version} — ${known.note}`,
      remediation: `Confirmed malicious version per public threat intel. Remove or downgrade immediately, then rotate every secret accessible to your build environment (CI tokens, npm tokens, cloud creds). Audit the dependency chain in the lockfile. Review CISA / GHSA / vendor advisories for the specific incident.`,
    });
  };
  // Floating-spec warning: if a direct dep uses `latest`/`*`/`x`/empty range
  // AND the named package has a known-bad version, flag at HIGH (could
  // resolve to compromised).
  const emitFloating = (name, version, file) => {
    const known = COMPROMISED_PACKAGES[name];
    if (!known) return;
    findings.push({
      id: `compromised-floating-${file.path}-${name}`,
      probe: 'Compromised Packages',
      title: `Floating version spec on package with known-compromised release: ${name}: "${version}"`,
      severity: 'high',
      category: 'Supply Chain',
      cwe: 'CWE-1357',
      file: file.path,
      line: 1,
      evidence: `"${name}": "${version}" — package has a known-compromised version on the wire; floating specs could resolve to it on any install`,
      remediation: `Pin to a specific safe version of ${name} (avoid 'latest', '*', empty range, or x-wildcards). Also commit a lockfile to prevent silent resolution to the compromised version.`,
    });
  };

  files.forEach((file) => {
    // 1) Direct deps from package.json with SemVer-aware comparison.
    if (/package\.json$/.test(file.path)) {
      let pkg;
      try {
        pkg = JSON.parse(file.content);
      } catch {
        return;
      }
      const deps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
        ...(pkg.peerDependencies || {}),
        ...(pkg.optionalDependencies || {}),
        ...(pkg.bundleDependencies || {}),
        ...(pkg.bundledDependencies || {}),
        ...(pkg.overrides || {}),
        ...(pkg.resolutions || {}),
      };
      Object.entries(deps).forEach(([name, version]) => {
        const known = COMPROMISED_PACKAGES[name];
        if (!known) return;
        const versionStr = String(version);
        // Entries marked versions: ['*'] are compromised at every version;
        // any spec, pinned or floating, resolves to a bad release. Emit
        // critical directly (the floating downgrade below is for packages
        // where only SOME versions are bad).
        if (known.versions.includes('*')) {
          emit(name, versionStr || '*', 'root (direct)', file, false, null);
          return;
        }
        // Floating spec: warn even without a concrete bad version match.
        if (/^(?:latest|next|\*|)$/.test(versionStr.trim())) {
          emitFloating(name, versionStr, file);
          return;
        }
        // SemVer-aware: does the spec's range include any known bad version?
        const hit = known.versions.find((bad) => semverRangeIncludes(versionStr, bad));
        if (hit) emit(name, hit, 'root (direct)', file, false, versionStr);
      });
      return;
    }
    // 2) Lockfile walkers — resolve transitive hits.
    let walker = null;
    if (
      /(^|\/)package-lock\.json$/.test(file.path) ||
      /(^|\/)npm-shrinkwrap\.json$/.test(file.path)
    )
      walker = _walkNpmLock;
    else if (/(^|\/)yarn\.lock$/.test(file.path)) walker = _walkYarnLock;
    else if (/(^|\/)pnpm-lock\.yaml$/.test(file.path)) walker = _walkPnpmLock;
    else if (/(^|\/)bun\.lock$/.test(file.path)) walker = _walkBunLock;
    if (!walker) return;
    for (const entry of walker(file.content)) {
      if (!entry?.name || !entry?.version) continue;
      const isTransitive = entry.chain !== 'root';
      emit(entry.name, entry.version, entry.chain, file, isTransitive, null);
    }
  });
  return findings;
}

// --- 2026: Slopsquatting / Typosquat detection ---

export function probeSlopsquatting(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/package\.json$/.test(file.path)) return;
    let pkg;
    try {
      pkg = JSON.parse(file.content);
    } catch {
      return;
    }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    Object.keys(deps).forEach((name) => {
      if (TYPOSQUATS[name]) {
        findings.push({
          id: `typosquat-${file.path}-${name}`,
          probe: 'Slopsquat / Typosquat',
          title: `Likely typosquat: "${name}" (real package: "${TYPOSQUATS[name]}")`,
          severity: 'high',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${deps[name]}"`,
          remediation: `Typosquatted packages are a common malware delivery vector and a known artifact of LLM "package hallucination" (slopsquatting — ~20% of AI-generated code references nonexistent packages). Verify this name was intentional. If you meant ${TYPOSQUATS[name]}, fix it.`,
        });
      } else if (!name.startsWith('@') && SLOPSQUAT_GENERIC_RE.test(name)) {
        findings.push({
          id: `slopsquat-${file.path}-${name}`,
          probe: 'Slopsquat / Typosquat',
          title: `Generic-shaped package name (possible LLM hallucination): "${name}"`,
          severity: 'low',
          category: 'Supply Chain',
          cwe: 'CWE-1357',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${deps[name]}"`,
          remediation: `AI assistants frequently hallucinate plausible-sounding package names like ${name}. Attackers register the hallucinated names with malicious payloads. Verify this package exists, has reasonable download counts, and a credible maintainer before installing.`,
        });
      }
    });
  });
  return findings;
}

// --- 2026: MCP Server / AI Tooling Configuration ---

export function probeAIRulesFiles(files) {
  const findings = [];
  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (!/\.cursorrules$|\.cursor\/rules\/|\.windsurfrules$|CLAUDE\.md$/.test(file.path)) return;
    if (BIDI_CONTROL_RE.test(file.content)) {
      findings.push({
        id: `rules-bidi-${file.path}`,
        probe: 'AI Rules Files',
        title: `Hidden Unicode in AI rules file ${file.path}`,
        severity: 'critical',
        category: 'AI/LLM Security',
        cwe: 'CWE-1007',
        file: file.path,
        line: 1,
        evidence: 'Bidirectional Unicode detected',
        remediation:
          'Pillar Security demonstrated the "rules file backdoor": hidden instructions in rules files used by Cursor and Copilot get followed by the AI assistant invisibly. Inspect this file character-by-character. Strip non-printing Unicode.',
      });
    }
    if (
      /ignore\s+(?:previous|all|the)\s+(?:instructions|rules)|disregard\s+system|override\s+system/i.test(
        file.content
      )
    ) {
      findings.push({
        id: `rules-override-${file.path}`,
        probe: 'AI Rules Files',
        title: `Rules file contains instruction-override language`,
        severity: 'high',
        category: 'AI/LLM Security',
        cwe: 'CWE-1336',
        file: file.path,
        line: 1,
        evidence: 'Phrases like "ignore previous instructions" found',
        remediation:
          'Rules files that include override-style language are either jailbreak attempts or compromised. Verify every instruction was placed by your team. Treat these files as code that ships with the product.',
      });
    }
  });
  return findings;
}

// --- 2026: Malicious post-infection artifacts (Mini Shai-Hulud TanStack campaign) ---
//
// The May 11, 2026 npm worm by TeamPCP infects @tanstack/* / @mistralai/* / @uipath/* /
// @opensearch-project/* / @squawk/* etc. via the `prepare` lifecycle script of a
// poisoned `optionalDependencies` entry. After install it survives `npm uninstall` by
// writing itself into developer-tooling config files and dropping helper scripts at
// well-known paths. If a scanned project contains those files / strings, the host that
// installed the package is already compromised — credentials it could read have been
// exfiltrated, and the dead-man's-switch handler will `rm -rf ~/` if its stolen GitHub
// token gets revoked.
//
// Confirmed IOCs (verified against the TanStack postmortem, the GHSA advisory,
// and independent IOC tracking — see the Mini Shai-Hulud field report in Learn):
//   • Files dropped on disk:
//       .claude/router_runtime.js   .claude/setup.mjs   .vscode/setup.mjs
//       tanstack_runner.js          router_init.js  (committed at package root)
//   • Config-file payload paths the worm hijacks:
//       .claude/settings.json   .vscode/tasks.json
//   • Persistence script that polls api.github.com/user:
//       ~/.local/bin/gh-token-monitor.sh   (Linux systemd user service)
//       com.user.gh-token-monitor          (macOS LaunchAgent label)
//   • Distinctive in-payload strings:
//       __DAEMONIZED   tanstack_runner   filev2.getsession.org
//   • Spoofed commit author:
//       claude@users.noreply.github.com
//   • optionalDependencies pin:
//       "@tanstack/setup": "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c"

export function probeMaliciousArtifacts(files) {
  const findings = [];

  // Drop-file paths whose mere presence is a high-confidence indicator of infection.
  const ARTIFACT_PATHS = [
    {
      re: /(^|\/)\.claude\/router_runtime\.js$/,
      label: '.claude/router_runtime.js',
    },
    { re: /(^|\/)\.claude\/setup\.mjs$/, label: '.claude/setup.mjs' },
    { re: /(^|\/)\.vscode\/setup\.mjs$/, label: '.vscode/setup.mjs' },
    { re: /(^|\/)tanstack_runner\.js$/, label: 'tanstack_runner.js' },
    { re: /(^|\/)router_init\.js$/, label: 'router_init.js' },
  ];

  // Distinctive strings inside the payload. Any one is suggestive; multiple together
  // make false positives extremely unlikely in a static scan of normal source.
  const IOC_STRINGS = [
    { re: /\b__DAEMONIZED\b/, label: '__DAEMONIZED guard variable' },
    { re: /\btanstack_runner\b/i, label: 'tanstack_runner reference' },
    { re: /filev2\.getsession\.org/i, label: 'Session messenger exfil endpoint' },
    { re: /seed[123]\.getsession\.org/i, label: 'Session seed-node exfil endpoint' },
    { re: /gh-token-monitor/i, label: 'gh-token-monitor persistence handler' },
    { re: /com\.user\.gh-token-monitor/i, label: 'gh-token-monitor LaunchAgent label' },
    { re: /claude@users\.noreply\.github\.com/i, label: 'spoofed Claude commit author' },
    {
      re: /tanstack\/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c/i,
      label: 'malicious @tanstack/setup commit pin',
    },
  ];

  files.forEach((file) => {
    if (isTestFile(file.path) || isScannerSelfSource(file.path)) return;
    if (isMetaDocFile(file.path)) return;

    // 1. File-path indicators — presence alone is critical.
    for (const a of ARTIFACT_PATHS) {
      if (a.re.test(file.path)) {
        findings.push({
          id: `mal-artifact-path-${file.path}`,
          probe: 'Malicious Artifacts',
          title: `Post-infection artifact: ${a.label}`,
          severity: 'critical',
          category: 'Supply Chain',
          cwe: 'CWE-506',
          file: file.path,
          line: 1,
          evidence: `File path matches known Mini Shai-Hulud (TanStack, May 11, 2026) drop-file`,
          remediation: `This file is dropped by the Mini Shai-Hulud npm worm to survive \`npm uninstall\`. If it exists, the host that ran \`npm install\` is compromised — assume every credential the build process touched has been exfiltrated (npm tokens, GitHub tokens, OIDC tokens, cloud creds, crypto wallets, browser session cookies). Steps: 1) DO NOT revoke your GitHub token yet — the worm runs \`rm -rf ~/\` when its stolen token returns 40x. First disconnect the machine from the network. 2) Pull a known-good system. 3) Rotate every credential offline. 4) Audit CI for the malicious GitHub Actions workflows the worm tries to inject. See the Mini Shai-Hulud field report in Learn for the full IOC list and operational sequence.`,
        });
        return; // one path-based finding per file is enough; don't also string-scan it
      }
    }

    // 2. String indicators inside content — applicable to ANY scanned file, not just JS.
    const content = file.content || '';
    if (!content || content.length > 5_000_000) return; // skip very large blobs (memory)
    const hits = [];
    for (const ioc of IOC_STRINGS) {
      if (ioc.re.test(content)) hits.push(ioc.label);
    }
    if (hits.length > 0) {
      findings.push({
        id: `mal-ioc-${file.path}`,
        probe: 'Malicious Artifacts',
        title: `Mini Shai-Hulud IOC string in ${file.path}`,
        severity: 'critical',
        category: 'Supply Chain',
        cwe: 'CWE-506',
        file: file.path,
        line: 1,
        evidence: `Matched ${hits.length} IOC(s): ${hits.slice(0, 4).join(' · ')}`,
        remediation: `One or more strings from the Mini Shai-Hulud (TanStack, May 11, 2026) payload appear in this file. If you didn't put them there, your repo or your dev machine is compromised. See remediation in the per-file-path finding for incident response steps. Do NOT revoke the GitHub token before disconnecting the machine — the worm wipes \`~\` on 40x responses.`,
      });
    }
  });

  return findings;
}

// --- 2026: AI-generated code smells (insecure patterns common in LLM output) ---

export function probeNpmrcHygiene(files) {
  const findings = [];
  const npmrc = files.find((f) => /(^|\/)\.npmrc$/.test(f.path));
  const hasPackageJson = files.some((f) => /package\.json$/.test(f.path));
  if (!hasPackageJson) return findings;
  if (!npmrc) {
    findings.push({
      id: `npmrc-missing`,
      probe: 'Package Manager Hardening',
      title: '.npmrc with security defaults not found',
      severity: 'low',
      category: 'Supply Chain',
      cwe: 'CWE-1357',
      file: 'package.json (project root)',
      line: 1,
      evidence: 'No .npmrc in scanned files',
      remediation:
        'After the Shai-Hulud, Axios, and Mini Shai-Hulud incidents (2025-2026), recommended hardening: add .npmrc with min-release-age=10080 (7 days, blocks installing brand-new versions during the active worm window) and audit-level=high. Better yet, switch from npm CLI to pnpm v11+ which ships consumer-side defenses by default.',
    });
    return findings;
  }
  if (!/min-release-age/.test(npmrc.content)) {
    findings.push({
      id: `npmrc-cooldown-${npmrc.path}`,
      probe: 'Package Manager Hardening',
      title: '.npmrc missing min-release-age (release cooldown)',
      severity: 'low',
      category: 'Supply Chain',
      cwe: 'CWE-1357',
      file: npmrc.path,
      line: 1,
      evidence: 'No min-release-age directive',
      remediation:
        'Set min-release-age=10080 (7 days) so brand-new package versions are not installed during the typical worm propagation window. Most npm supply-chain incidents in 2025-2026 (Shai-Hulud, Axios, Mini Shai-Hulud) were detected and pulled within hours to days; a 7-day cooldown would have blocked them.',
    });
  }
  return findings;
}
