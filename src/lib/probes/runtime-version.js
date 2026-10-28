// src/lib/probes/runtime-version.js
//
// Language runtime pinned below a known-exploited fix.
//
// The October 21, 2026 PHP security release (CVE-2026-109618, CVE-2026-109619,
// "php2shell") fixed unauthenticated remote code execution in the engine's
// request handling: every SAPI that serves web requests, mod_php worst. PHP's
// own advisory says there are no complete mitigations and updating is the
// only safe choice; CISA added both to the Known Exploited Vulnerabilities
// catalog on October 26. Fixed: 8.2.35, 8.3.36, 8.4.27, 8.5.12. PHP 8.1 and
// older no longer receive releases, so a pin there has no fix to move to.
//
// A static scanner cannot see what a host is running. It can see what the
// repo TELLS the host to run: a Dockerfile `FROM php:8.3.10-fpm`, a
// `.php-version` or `.tool-versions` pin, a composer `platform.php` pin.
// Those are exact statements of intent and they are what gets deployed.
// Floating tags (`php:8.3-fpm`) resolve to whatever was published when the
// image was pulled and are deliberately not reported: the scanner cannot
// know the pull date, and a guess either way teaches the wrong lesson.
// composer `require.php` is a constraint, not a runtime, and is skipped.

import { isTestFile, isScannerSelfSource } from '../file-filter.js';

// Branch -> first fixed patch. Checked against the PHP advisory of
// 2026-10-21 (https://www.php.net/archive/2026.php#2026-10-21-5).
export const PHP2SHELL_FIXED = { 8.2: 35, 8.3: 36, 8.4: 27, 8.5: 12 };
const PHP2SHELL_CVES = 'CVE-2026-109618 and CVE-2026-109619';

function phpPinVerdict(version) {
  const m = String(version).match(/^v?(\d+)\.(\d+)(?:\.(\d+))?/);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = m[3] === undefined ? null : Number(m[3]);
  if (major < 8 || (major === 8 && minor <= 1)) return 'unsupported';
  if (major > 8 || (major === 8 && minor >= 6)) return null; // 8.6.0 RC4+ carries the fix
  const fixed = PHP2SHELL_FIXED[`${major}.${minor}`];
  if (fixed === undefined || patch === null) return null; // floating minor: not reported
  return patch < fixed ? 'vulnerable' : null;
}

const finding = (file, line, evidence, verdict, pinned) => ({
  id: `runtime-php2shell-${file.path}-${line}`,
  probe: 'PHP Runtime Version',
  title:
    verdict === 'unsupported'
      ? `PHP ${pinned} is pinned and has no php2shell fix`
      : `PHP ${pinned} is pinned below the php2shell fix`,
  severity: 'critical',
  category: 'Supply Chain',
  cwe: 'CWE-1395',
  file: file.path,
  line,
  evidence: evidence.trim().slice(0, 200),
  remediation:
    verdict === 'unsupported'
      ? `${PHP2SHELL_CVES} allow unauthenticated remote code execution in every PHP SAPI that serves web requests, and CISA lists both as exploited in the wild. PHP 8.1 and older receive no releases, so this pin cannot be patched in place: move to 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or newer), or take the service offline until it is moved, which is CISA's own guidance for unsupported versions. If a distribution backport is what runs in production, say so in a comment next to this pin.`
      : `${PHP2SHELL_CVES} allow unauthenticated remote code execution in every PHP SAPI that serves web requests, mod_php worst, and CISA lists both as exploited in the wild. Move this pin to ${pinned.split('.').slice(0, 2).join('.')}.${PHP2SHELL_FIXED[pinned.split('.').slice(0, 2).join('.')]} or newer and redeploy. PHP's advisory is explicit that the ini mitigations only reduce exposure; updating is the fix.`,
});

export function probePhpRuntimeVersion(files) {
  const findings = [];
  (files || []).forEach((file) => {
    const path = file?.path || '';
    const content = typeof file?.content === 'string' ? file.content : '';
    if (!path || !content || isTestFile(path) || isScannerSelfSource(path)) return;
    const base = path.split('/').pop();
    const lines = content.split('\n');

    // Dockerfile: FROM php:8.3.10-fpm-alpine, FROM docker.io/library/php:8.2.1
    if (/^Dockerfile(?:\..+)?$|\.dockerfile$/i.test(base)) {
      lines.forEach((line, i) => {
        const m = line.match(
          /^\s*FROM\s+(?:[\w.-]+(?::\d+)?\/)*(?:library\/)?php:(\d+\.\d+\.\d+)/i
        );
        if (!m) return;
        const verdict = phpPinVerdict(m[1]);
        if (verdict) findings.push(finding(file, i + 1, line, verdict, m[1]));
      });
      return;
    }
    // .php-version: one version on the first line.
    if (base === '.php-version') {
      const v = lines[0].trim();
      const verdict = phpPinVerdict(v);
      if (verdict) findings.push(finding(file, 1, lines[0], verdict, v));
      return;
    }
    // .tool-versions (asdf / mise): `php 8.3.10`
    if (base === '.tool-versions') {
      lines.forEach((line, i) => {
        const m = line.match(/^\s*php\s+(\d+\.\d+\.\d+)/);
        if (!m) return;
        const verdict = phpPinVerdict(m[1]);
        if (verdict) findings.push(finding(file, i + 1, line, verdict, m[1]));
      });
      return;
    }
    // composer.json config.platform.php: the version Composer resolves FOR,
    // which is the version the team has decided production runs.
    if (base === 'composer.json') {
      let cfg;
      try {
        cfg = JSON.parse(content);
      } catch {
        return;
      }
      const pin = cfg?.config?.platform?.php;
      if (typeof pin !== 'string') return;
      const verdict = phpPinVerdict(pin);
      if (!verdict) return;
      const i = lines.findIndex((l) => /"php"\s*:/.test(l) && l.includes(pin));
      findings.push(
        finding(file, i === -1 ? 1 : i + 1, lines[i] ?? `"php": "${pin}"`, verdict, pin)
      );
    }
  });
  return findings;
}
