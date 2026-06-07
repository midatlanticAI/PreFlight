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

export function probeCompromisedPackages(files) {
  const findings = [];
  files.forEach((file) => {
    if (!/package\.json$/.test(file.path)) return;
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
    };
    Object.entries(deps).forEach(([name, version]) => {
      const known = COMPROMISED_PACKAGES[name];
      if (!known) return;
      const versionStr = String(version).replace(/^[\^~>=<]+/, '');
      const matches =
        known.versions.includes('*') ||
        known.versions.some((v) => versionStr === v || versionStr.startsWith(v));
      if (matches) {
        findings.push({
          id: `compromised-${file.path}-${name}`,
          probe: 'Compromised Packages',
          title: `Known-compromised package: ${name}@${versionStr}`,
          severity: 'critical',
          category: 'Supply Chain',
          cwe: 'CWE-506',
          file: file.path,
          line: 1,
          evidence: `"${name}": "${version}"  — ${known.note}`,
          remediation: `Confirmed malicious version per public threat intel (May 2026). Remove or downgrade immediately, then rotate every secret accessible to your build environment (CI tokens, npm tokens, cloud creds). Audit lockfile for the dependency chain. Review CISA / Socket / Wiz advisories for the specific incident.`,
        });
      }
    });
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
