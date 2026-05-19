// src/lib/threat-intel.js
// Detection patterns + threat-intel constants. Pure data, no scanning logic.
// Updated as 2025-2026 incidents are published; sourced from CISA, Snyk, Socket, Wiz,
// Aikido, StepSecurity, Pillar Security, and OX Security advisories.

import compromisedPackagesManifest from '../data/compromised-packages.js';

export const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key ID',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'AWS Secret Access Key',
    regex: /aws[_\-]?secret[_\-]?(?:access[_\-]?)?key["'\s:=]+["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /\bsk_live_[A-Za-z0-9]{20,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Stripe Test Secret Key',
    regex: /\bsk_test_[A-Za-z0-9]{20,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'OpenAI API Key',
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Anthropic API Key',
    regex: /\bsk-ant-[A-Za-z0-9_\-]{40,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Google API Key',
    regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Slack Bot Token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Hugging Face Token',
    regex: /\bhf_[A-Za-z0-9]{30,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Replicate API Token',
    regex: /\br8_[A-Za-z0-9]{30,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Groq API Key',
    regex: /\bgsk_[A-Za-z0-9]{40,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Perplexity API Key',
    regex: /\bpplx-[A-Za-z0-9]{40,}\b/g,
    severity: 'high',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  // ReDoS-safe: each segment forbids ':' and '@' so the user / pass / host parts can't ambiguously overlap.
  {
    name: 'Database Connection URL with Credentials',
    regex:
      /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s"'<>:@/]+:[^\s"'<>:@/]+@[^\s"'<>/]+/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    severity: 'critical',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
  {
    name: 'Generic Hardcoded Secret',
    regex: /(?:secret|password|passwd|api[_-]?key)\s*[:=]\s*["'][A-Za-z0-9_\-!@#$%^&*]{16,}["']/gi,
    severity: 'medium',
    category: 'Data Breach',
    cwe: 'CWE-798',
  },
];

// ==========================================================================
// 2026 THREAT INTEL: known-compromised package versions
// Sources: CISA, GTIG/Mandiant, Socket, Wiz, Unit 42, OX Security, OWASP
// ==========================================================================

// NEXT_PUBLIC_* env-var name and value patterns used by probeNextPublic. Name match catches
// any variable whose identifier hints at secret material; value match catches secret-shaped
// values placed under a NEXT_PUBLIC_ prefix (always wrong — these get shipped to the browser).
export const NEXT_PUBLIC_DANGER_NAMES =
  /SECRET|PRIVATE|SERVICE_ROLE|TOKEN|PASSWORD|STRIPE_SECRET|OPENAI_API_KEY|ANTHROPIC_API_KEY/i;
export const NEXT_PUBLIC_DANGER_VALUES = /^sk_live_|^sk_test_|^sk-ant-|^sk-proj-|service_role/;

// Compromised npm/PyPI packages — sourced from src/data/compromised-packages.js.
// The data file is the single source of truth; this re-export strips meta-keys
// (_schema/_note/_lastReviewed) so probe code can iterate it as a flat map.
// Update the data file, not this object.
export const COMPROMISED_PACKAGES = Object.fromEntries(
  Object.entries(compromisedPackagesManifest).filter(([k]) => !k.startsWith('_'))
);

// Common typosquats targeting popular packages
export const TYPOSQUATS = {
  reactt: 'react',
  reactjs: 'react',
  lodahs: 'lodash',
  lodaash: 'lodash',
  lodashy: 'lodash',
  expreess: 'express',
  expres: 'express',
  crossenv: 'cross-env',
  'discord-js': 'discord.js',
  momnet: 'moment',
  momentjs: 'moment',
  noodejs: 'node',
  jsonwebtokenn: 'jsonwebtoken',
  colorss: 'colors',
};

// Generic-looking package name patterns common in LLM hallucinations (slopsquat)
export const SLOPSQUAT_GENERIC_RE =
  /^(auth|api|db|user|admin|util|helper|core|server|client|app|web|http|json|crypto|fast|smart|easy|simple|secure|pro|advanced)-(auth|api|util|utils|helper|helpers|core|client|server|tool|tools|kit|lib|js|ts|node|sdk|wrapper|manager)$/i;

// Bidirectional Unicode control characters (CVE-2021-42574 / Trojan Source).
// Built from \u escape codes (NOT literal characters) so this file itself doesn't trip our own
// Trojan Source probe when scanning the scanner. The codepoint ranges are:
//   U+202A-U+202E  LRE / RLE / PDF / LRO / RLO

export const BIDI_CONTROL_RE = new RegExp('[' + '\\u202A-\\u202E\\u2066-\\u2069' + ']');

// --- Test-file exclusion: pattern-matching probes should skip test files ---
// Test files legitimately demonstrate vulnerable patterns to verify detection. Running content-
// pattern probes against `*.test.{js,jsx,ts,tsx}`, `*.spec.*`, or anything under `test/`/`tests/`
// /`__tests__/` produces self-reference findings instead of real ones (the regression test for
// "we should detect eval()" is itself a string containing `eval(`).

// Includes the IANA-reserved example domains, common documentation strings, and RFC 5737
// reserved IP ranges (TEST-NET-1/2/3 — used in code samples and test fixtures).
export const URL_PLACEHOLDER_HOSTS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'example.io',
  'yourdomain.com',
  'yoursite.com',
  'mydomain.com',
  'somedomain.com',
  'foo.bar',
  'foo.baz',
  'host',
  '[::1]',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
]);
// RFC 5737 ranges: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — reserved for documentation.
export const URL_PLACEHOLDER_IP_RE = /^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/;

export const URL_SAFE_HOSTS = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'example.com',
  'example.org',
  'test.com',
  'github.com',
  'githubusercontent.com',
  'gitlab.com',
  'bitbucket.org',
  'npmjs.com',
  'pypi.org',
  'rubygems.org',
  'go.dev',
  'google.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'gstatic.com',
  'microsoft.com',
  'azure.com',
  'aws.amazon.com',
  'amazonaws.com',
  'cloudflare.com',
  'cloudflareinsights.com',
  'jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'mozilla.org',
  'developer.mozilla.org',
  'w3.org',
  'schema.org',
  'owasp.org',
  'genai.owasp.org',
  'cwe.mitre.org',
  'cisa.gov',
  'cheatsheetseries.owasp.org',
  'pnpm.io',
  'yarnpkg.com',
  // Established AI / LLM provider hosts. Documented endpoints, owned by
  // well-known companies, used by the PreFlight BYOK integration in src/lib/ai.js.
  // Criterion for inclusion: the host appears in the provider's official
  // developer documentation as the canonical API base, the company has a
  // verifiable corporate identity, and the host has been stable for 12+ months.
  'openai.com',
  'api.openai.com',
  'platform.openai.com',
  'developers.openai.com',
  'anthropic.com',
  'api.anthropic.com',
  'console.anthropic.com',
  'docs.anthropic.com',
  'x.ai',
  'api.x.ai',
  'docs.x.ai',
  'console.x.ai',
  'mistral.ai',
  'api.mistral.ai',
  'console.mistral.ai',
  'deepseek.com',
  'api.deepseek.com',
  'platform.deepseek.com',
  'groq.com',
  'api.groq.com',
  'console.groq.com',
  'openrouter.ai',
  'cohere.com',
  'cohere.ai',
  'api.cohere.ai',
  'dashboard.cohere.com',
  'google.dev',
  'ai.google.dev',
  'aistudio.google.com',
  'generativelanguage.googleapis.com',
  'huggingface.co',
  'replicate.com',
  'stripe.com',
  'twilio.com',
  'sendgrid.com',
  'vercel.com',
  'netlify.com',
  'render.com',
  'fly.io',
  'supabase.co',
  'supabase.com',
  'firebase.google.com',
  'firebaseio.com',
  'googleapis.com',
  'apple.com',
  'icloud.com',
  'tailwindcss.com',
  'reactjs.org',
  'react.dev',
  'nextjs.org',
  'vuejs.org',
]);
export const URL_SUSPICIOUS_TLD_RE =
  /\.(tk|ml|ga|cf|gq|top|xyz|click|loan|work|men|surf|cyou|rest|zip|mov|wang|country|kim|science|date|stream)$/i;
export const URL_RAW_IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
export const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  'goo.gl',
  't.co',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'shorte.st',
  'cutt.ly',
]);

// Returns true if host is in URL_SAFE_HOSTS or is a subdomain of any entry.
// Subdomain check protects against  and  while still
// catching deceptive look-alikes that just share a suffix.
export function isHostInSafeList(host) {
  if (URL_SAFE_HOSTS.has(host)) return true;
  for (const safe of URL_SAFE_HOSTS) {
    if (host.endsWith('.' + safe)) return true;
  }
  return false;
}

// --- GEO Hygiene: AI-search visibility ---
export const AI_CRAWLER_BOTS = [
  'GPTBot',
  'ChatGPT-User',
  'OAI-SearchBot',
  'anthropic-ai',
  'ClaudeBot',
  'Claude-Web',
  'PerplexityBot',
  'Google-Extended',
  'CCBot',
];

export const FILE_SIZE_WARN_LINES = 1500;
export const FILE_SIZE_FAIL_LINES = 5000;
