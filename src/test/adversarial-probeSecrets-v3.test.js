// Adversarial RECALL tests for probeSecrets.
//
// These tests come from the secret-scanner Pattern page spec, not from the
// implementation. The probe is a pure function over Array<{path, content}>
// that returns Array<Finding> shaped:
//   { id, probe='Secret Scanner', title, severity, category, cwe='CWE-798',
//     file, line, evidence, remediation }
//
// Provider shapes scanned (verbatim from spec):
//   AWS access key ID: AKIA[0-9A-Z]{16}
//   AWS secret key:    base64-shaped, 40 chars, often near "secret_access_key"
//   Stripe live:       sk_live_[A-Za-z0-9]{24,}
//   Stripe test:       sk_test_...
//   OpenAI:            sk-[A-Za-z0-9]{20,} or sk-proj-...
//   Anthropic:         sk-ant-[A-Za-z0-9_-]{20,}
//   Google:            AIza[A-Za-z0-9_-]{30,}
//   GitHub PAT:        ghp_[A-Za-z0-9]{36} classic, gho_ OAuth, github_pat_ fine-grained
//   Slack:             xox[bpas]-... bot/user/admin variants
//   Hugging Face:      hf_[A-Za-z0-9]{30,}
//   Replicate:         r8_[A-Za-z0-9]{30,}
//   Database URL:      postgres://user:pass@host, mysql://, mongodb://
//   Private key:       -----BEGIN ... PRIVATE KEY----- (RSA, EC, PGP, OpenSSH)
//
// Suppressed paths: *.test.*, *.spec.*, tests/, __tests__/, fixtures/, .md,
//                   .env.example, .env.template, .env.sample, .env.dist
//
// Placeholder markers the probe correctly suppresses:
//   EXAMPLE, REPLACE, DEMO, PLACEHOLDER, four-or-more consecutive x/X, <...>

import { describe, it, expect } from 'vitest';
import { probeSecrets } from '../lib/probes.js';

// ---------------------------------------------------------------------------
// Synthetic keys. None of these are real. All avoid the documented placeholder
// markers (EXAMPLE / REPLACE / DEMO / PLACEHOLDER / 4+ consecutive x|X / <...>).
// ---------------------------------------------------------------------------

const AWS_ACCESS = 'AKIA1234567890ABCDEF';
const AWS_SECRET = 'abcdefghijklmnopqrstuvwxyz0123456789ABCD'; // 40 chars
const STRIPE_LIVE = 'sk_live_4eC39HqLyjWDarjtT1zd';
const STRIPE_TEST = 'sk_test_4eC39HqLyjWDarjtT1zd';
const OPENAI_CLASSIC = 'sk-9aZbYcXdWeVfUgThSiRjQkPlOnMm';
const OPENAI_PROJ = 'sk-proj-9aZbYcXdWeVfUgThSiRjQkPlOnMm';
const ANTHROPIC_KEY = 'sk-ant-9aZbYcXdWeVfUgThSiRjQkPlOnMm01';
const GOOGLE_KEY = 'AIzaSyA0123456789abcdefghijklmnopqrstuvw';
const GITHUB_CLASSIC = 'ghp_abcdefghijklmnopqrstuvwz0123456789ABCD'; // 36 after prefix
const GITHUB_OAUTH = 'gho_abcdefghijklmnopqrstuvwz0123456789ABCD';
const GITHUB_FINE =
  'github_pat_11ABCDEFG0abcdefghijkl_0123456789abcdefghijklmnopqrstuvwz0123456789ABCDEF';
const SLACK_BOT = 'xoxb-aBcDeFgHiJkLmNoPqRsTuVwY';
const SLACK_USER = 'xoxp-aBcDeFgHiJkLmNoPqRsTuVwY';
const SLACK_ADMIN = 'xoxa-aBcDeFgHiJkLmNoPqRsTuVwY';
const SLACK_APP = 'xoxs-aBcDeFgHiJkLmNoPqRsTuVwY';
const HF_KEY = 'hf_abcdefghijklmnopqrstuvwz0123456789';
const REPLICATE_KEY = 'r8_abcdefghijklmnopqrstuvwz0123456789AB';
const PG_URL = 'postgres://dbuser:s3cr3tP4ss@db.internal.host:5432/appdb';
const MYSQL_URL = 'mysql://appuser:hunter2pass@10.0.0.5:3306/orders';
const MONGO_URL = 'mongodb://rootuser:Tr0ub4dor@mongo.cluster.local:27017/main';

const PRIVATE_KEY_RSA = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn2sNpYa8e5OvJqYP8j8gVeqdvR4xH9rXkc
abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab
-----END RSA PRIVATE KEY-----`;
const PRIVATE_KEY_EC = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBapTcZJYV6q5Sff7jH9Z0kPLWWY3vXnAvNqJgvN1xJroAoGCCqGSM49
-----END EC PRIVATE KEY-----`;
const PRIVATE_KEY_PGP = `-----BEGIN PGP PRIVATE KEY BLOCK-----
lQOYBFr1Z3UBCADQ0wjNUQTYS5cVj6lH9rXkcabcdefghijklmnopqrstuvwxyz
-----END PGP PRIVATE KEY BLOCK-----`;
const PRIVATE_KEY_OPENSSH = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
-----END OPENSSH PRIVATE KEY-----`;
const PRIVATE_KEY_GENERIC = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDQ0wjNUQTYS5cV
-----END PRIVATE KEY-----`;

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

function scan(files) {
  return probeSecrets(files);
}
function file(path, content) {
  return { path, content };
}
function hasFindingFor(findings, filePath) {
  return findings.some((f) => f.file === filePath);
}

// ===========================================================================
// PROVIDER POSITIVES
// ===========================================================================

describe('probeSecrets: provider positives (one finding per shape)', () => {
  it('detects AWS access key ID (AKIA...)', () => {
    const f = scan([file('src/config.js', `const KEY = "${AWS_ACCESS}";`)]);
    expect(f.length).toBeGreaterThan(0);
    expect(hasFindingFor(f, 'src/config.js')).toBe(true);
  });

  it('detects AWS secret access key (40-char near secret_access_key)', () => {
    const f = scan([file('src/aws.js', `const aws_secret_access_key = "${AWS_SECRET}";`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Stripe live key (sk_live_...)', () => {
    const f = scan([file('src/pay.js', `stripe("${STRIPE_LIVE}")`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Stripe test key (sk_test_...)', () => {
    const f = scan([file('src/pay-test.js', `const k = "${STRIPE_TEST}";`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects OpenAI classic key (sk-...)', () => {
    const f = scan([file('src/llm.js', `openai("${OPENAI_CLASSIC}")`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects OpenAI project key (sk-proj-...)', () => {
    const f = scan([file('src/llm2.js', `openai("${OPENAI_PROJ}")`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Anthropic key (sk-ant-...)', () => {
    const f = scan([file('src/claude.js', `key = "${ANTHROPIC_KEY}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Google API key (AIza...)', () => {
    const f = scan([file('src/maps.js', `apiKey:"${GOOGLE_KEY}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects GitHub classic PAT (ghp_...)', () => {
    const f = scan([file('src/gh.js', `token = "${GITHUB_CLASSIC}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects GitHub OAuth token (gho_...)', () => {
    const f = scan([file('src/gh2.js', `token = "${GITHUB_OAUTH}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects GitHub fine-grained PAT (github_pat_...)', () => {
    const f = scan([file('src/gh3.js', `token = "${GITHUB_FINE}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Slack bot token (xoxb-...)', () => {
    const f = scan([file('src/slack.js', `token = "${SLACK_BOT}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Slack user token (xoxp-...)', () => {
    const f = scan([file('src/slack2.js', `token = "${SLACK_USER}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Slack admin token (xoxa-...)', () => {
    const f = scan([file('src/slack3.js', `token = "${SLACK_ADMIN}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Slack legacy/app token (xoxs-...)', () => {
    const f = scan([file('src/slack4.js', `token = "${SLACK_APP}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Hugging Face token (hf_...)', () => {
    const f = scan([file('src/hf.js', `key = "${HF_KEY}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects Replicate token (r8_...)', () => {
    const f = scan([file('src/rep.js', `key = "${REPLICATE_KEY}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects postgres:// URL with creds', () => {
    const f = scan([file('src/db.js', `DATABASE_URL="${PG_URL}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects mysql:// URL with creds', () => {
    const f = scan([file('src/db-mysql.js', `URL = "${MYSQL_URL}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects mongodb:// URL with creds', () => {
    const f = scan([file('src/db-mongo.js', `URL = "${MONGO_URL}"`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects RSA private key block', () => {
    const f = scan([file('src/keys/rsa.js', `const PEM = \`${PRIVATE_KEY_RSA}\`;`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects EC private key block', () => {
    const f = scan([file('src/keys/ec.js', `const PEM = \`${PRIVATE_KEY_EC}\`;`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects PGP private key block', () => {
    const f = scan([file('src/keys/pgp.js', `const PEM = \`${PRIVATE_KEY_PGP}\`;`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects OpenSSH private key block', () => {
    const f = scan([file('src/keys/ssh.js', `const PEM = \`${PRIVATE_KEY_OPENSSH}\`;`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('detects generic PKCS8 PRIVATE KEY block', () => {
    const f = scan([file('src/keys/p8.js', `const PEM = \`${PRIVATE_KEY_GENERIC}\`;`)]);
    expect(f.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// FP SUPPRESSIONS (path-based and content-based)
// ===========================================================================

describe('probeSecrets: path suppressions', () => {
  it('skips *.test.* files', () => {
    const f = scan([file('src/secrets.test.js', `const K = "${STRIPE_LIVE}";`)]);
    expect(f.length).toBe(0);
  });

  it('skips *.spec.* files', () => {
    const f = scan([file('src/keys.spec.ts', `const K = "${OPENAI_CLASSIC}";`)]);
    expect(f.length).toBe(0);
  });

  it('skips tests/ directory', () => {
    const f = scan([file('tests/aws-keys.js', `const K = "${AWS_ACCESS}";`)]);
    expect(f.length).toBe(0);
  });

  it('skips __tests__/ directory', () => {
    const f = scan([file('src/__tests__/leaked.js', `const K = "${ANTHROPIC_KEY}";`)]);
    expect(f.length).toBe(0);
  });

  it('skips fixtures/ paths', () => {
    const f = scan([file('src/fixtures/sample.js', `const K = "${GITHUB_CLASSIC}";`)]);
    expect(f.length).toBe(0);
  });

  it('skips nested fixtures/ paths', () => {
    const f = scan([file('src/lib/probes/v05/fixtures/x.js', `const K = "${STRIPE_LIVE}";`)]);
    expect(f.length).toBe(0);
  });

  it('skips .md documentation files', () => {
    const f = scan([file('docs/setup.md', `Use a key like \`${STRIPE_LIVE}\` here.`)]);
    expect(f.length).toBe(0);
  });

  it('skips README.md', () => {
    const f = scan([file('README.md', `Example: ${OPENAI_CLASSIC}`)]);
    expect(f.length).toBe(0);
  });

  it('skips .env.example template file', () => {
    const f = scan([file('.env.example', `STRIPE_KEY=${STRIPE_LIVE}`)]);
    expect(f.length).toBe(0);
  });

  it('skips .env.template template file', () => {
    const f = scan([file('.env.template', `OPENAI_API_KEY=${OPENAI_CLASSIC}`)]);
    expect(f.length).toBe(0);
  });

  it('skips .env.sample template file', () => {
    const f = scan([file('.env.sample', `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}`)]);
    expect(f.length).toBe(0);
  });

  it('skips .env.dist template file', () => {
    const f = scan([file('.env.dist', `GOOGLE_API_KEY=${GOOGLE_KEY}`)]);
    expect(f.length).toBe(0);
  });
});

describe('probeSecrets: placeholder marker suppressions', () => {
  it('suppresses values containing EXAMPLE', () => {
    const f = scan([file('src/a.js', `const K = "AKIAEXAMPLE1234567890";`)]);
    expect(f.length).toBe(0);
  });

  it('suppresses values containing REPLACE', () => {
    const f = scan([file('src/b.js', `const K = "sk_live_REPLACEthisWithR";`)]);
    expect(f.length).toBe(0);
  });

  it('suppresses values containing DEMO', () => {
    const f = scan([file('src/c.js', `const K = "sk-DEMOabcdefghijklmnopqr";`)]);
    expect(f.length).toBe(0);
  });

  it('suppresses values containing PLACEHOLDER', () => {
    const f = scan([file('src/d.js', `const K = "ghp_PLACEHOLDERabcdefghijklmnop12345678";`)]);
    expect(f.length).toBe(0);
  });

  it('suppresses values with four or more consecutive x', () => {
    const f = scan([file('src/e.js', `const K = "sk_live_xxxxabcdefghijklmnopqr";`)]);
    expect(f.length).toBe(0);
  });

  it('suppresses values with four or more consecutive X', () => {
    const f = scan([file('src/f.js', `const K = "AKIAXXXX1234567890AB";`)]);
    expect(f.length).toBe(0);
  });

  it('suppresses angle-bracket placeholder values', () => {
    const f = scan([file('src/g.js', `const K = "<YOUR_STRIPE_KEY_HERE>";`)]);
    expect(f.length).toBe(0);
  });
});

// ===========================================================================
// STRUCTURAL ASSERTIONS
// ===========================================================================

describe('probeSecrets: finding structure (per spec)', () => {
  it('uses probe name "Secret Scanner"', () => {
    const f = scan([file('src/s.js', `const K = "${STRIPE_LIVE}";`)]);
    expect(f.length).toBeGreaterThan(0);
    for (const finding of f) {
      expect(finding.probe).toBe('Secret Scanner');
    }
  });

  it('tags CWE-798 (hard-coded credentials)', () => {
    const f = scan([file('src/s.js', `const K = "${OPENAI_CLASSIC}";`)]);
    expect(f.length).toBeGreaterThan(0);
    for (const finding of f) {
      expect(finding.cwe).toBe('CWE-798');
    }
  });

  it('reports a canonical severity string', () => {
    const f = scan([file('src/s.js', `const K = "${ANTHROPIC_KEY}";`)]);
    expect(f.length).toBeGreaterThan(0);
    const allowed = new Set(['critical', 'high', 'medium', 'low', 'info']);
    for (const finding of f) {
      expect(typeof finding.severity).toBe('string');
      expect(allowed.has(String(finding.severity).toLowerCase())).toBe(true);
    }
  });

  it('emits a non-empty string in evidence', () => {
    const f = scan([file('src/s.js', `const K = "${STRIPE_LIVE}";`)]);
    expect(f.length).toBeGreaterThan(0);
    for (const finding of f) {
      expect(typeof finding.evidence).toBe('string');
      expect(finding.evidence.length).toBeGreaterThan(0);
    }
  });

  it('emits the correct file path for the offending file', () => {
    const f = scan([file('src/specific/path.js', `const K = "${OPENAI_PROJ}";`)]);
    expect(f.length).toBeGreaterThan(0);
    expect(f[0].file).toBe('src/specific/path.js');
  });

  it('emits a line number (number type) when reporting a finding', () => {
    const f = scan([file('src/s.js', `// header\n// padding\nconst K = "${STRIPE_LIVE}";`)]);
    expect(f.length).toBeGreaterThan(0);
    for (const finding of f) {
      expect(typeof finding.line).toBe('number');
      expect(finding.line).toBeGreaterThan(0);
    }
  });

  it('emits a remediation string', () => {
    const f = scan([file('src/s.js', `const K = "${STRIPE_LIVE}";`)]);
    expect(f.length).toBeGreaterThan(0);
    for (const finding of f) {
      expect(typeof finding.remediation).toBe('string');
      expect(finding.remediation.length).toBeGreaterThan(0);
    }
  });

  it('returns an array even for empty input', () => {
    const f = scan([]);
    expect(Array.isArray(f)).toBe(true);
    expect(f.length).toBe(0);
  });

  it('returns an array even when input has only suppressed files', () => {
    const f = scan([
      file('README.md', `key ${STRIPE_LIVE}`),
      file('src/x.test.js', `const K = "${OPENAI_CLASSIC}";`),
    ]);
    expect(Array.isArray(f)).toBe(true);
    expect(f.length).toBe(0);
  });
});

// ===========================================================================
// MULTI-FILE SCENARIOS
// ===========================================================================

describe('probeSecrets: multi-file scenarios', () => {
  it('reports the real file in a mixed scan with a .test. suppressed sibling', () => {
    const f = scan([
      file('src/config.js', `const KEY = "${STRIPE_LIVE}";`),
      file('src/config.test.js', `const KEY = "${STRIPE_LIVE}";`),
    ]);
    expect(hasFindingFor(f, 'src/config.js')).toBe(true);
    expect(hasFindingFor(f, 'src/config.test.js')).toBe(false);
  });

  it('reports the real file but not the .env.example sibling', () => {
    const f = scan([
      file('.env', `STRIPE=${STRIPE_LIVE}`),
      file('.env.example', `STRIPE=${STRIPE_LIVE}`),
    ]);
    expect(hasFindingFor(f, '.env')).toBe(true);
    expect(hasFindingFor(f, '.env.example')).toBe(false);
  });

  it('reports the real source but not the docs/ markdown', () => {
    const f = scan([
      file('src/llm.js', `openai("${OPENAI_PROJ}")`),
      file('docs/onboarding.md', `Set OPENAI_API_KEY to ${OPENAI_PROJ}`),
    ]);
    expect(hasFindingFor(f, 'src/llm.js')).toBe(true);
    expect(hasFindingFor(f, 'docs/onboarding.md')).toBe(false);
  });

  it('reports multiple distinct provider shapes across multiple real files', () => {
    const f = scan([
      file('src/aws.js', `const K = "${AWS_ACCESS}";`),
      file('src/llm.js', `const K = "${ANTHROPIC_KEY}";`),
      file('src/pay.js', `const K = "${STRIPE_LIVE}";`),
      file('tests/leaked.js', `const K = "${GITHUB_CLASSIC}";`), // suppressed
    ]);
    expect(hasFindingFor(f, 'src/aws.js')).toBe(true);
    expect(hasFindingFor(f, 'src/llm.js')).toBe(true);
    expect(hasFindingFor(f, 'src/pay.js')).toBe(true);
    expect(hasFindingFor(f, 'tests/leaked.js')).toBe(false);
  });

  it('does not fire when every file is either a placeholder or in a suppressed path', () => {
    const f = scan([
      file('README.md', `KEY=${STRIPE_LIVE}`),
      file('.env.example', `KEY=${OPENAI_PROJ}`),
      file('src/cfg.js', `const K = "AKIAEXAMPLE1234567890";`),
      file('src/__tests__/x.js', `const K = "${ANTHROPIC_KEY}";`),
    ]);
    expect(f.length).toBe(0);
  });
});

// ===========================================================================
// EDGE CASES THE SPEC PINS DOWN
// ===========================================================================

describe('probeSecrets: spec-pinned edge cases', () => {
  it('fires on a real .env file with a non-placeholder key', () => {
    const f = scan([file('.env', `STRIPE_KEY=${STRIPE_LIVE}`)]);
    expect(f.length).toBeGreaterThan(0);
    expect(hasFindingFor(f, '.env')).toBe(true);
  });

  it('fires on .env.local (real, not a documented template suffix)', () => {
    const f = scan([file('.env.local', `OPENAI_API_KEY=${OPENAI_PROJ}`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('fires on a key embedded in JSON config', () => {
    const f = scan([file('config.json', `{ "stripe": "${STRIPE_LIVE}" }`)]);
    expect(f.length).toBeGreaterThan(0);
  });

  it('fires on a key in a YAML config', () => {
    const f = scan([file('app.yaml', `stripe_key: ${STRIPE_LIVE}\n`)]);
    expect(f.length).toBeGreaterThan(0);
  });
});

// ===========================================================================
// EDGE CASES THE SPEC DOES NOT PIN DOWN
// ===========================================================================

describe('edge cases the spec does not pin down', () => {
  // The spec lists suppression markers as case-sensitive tokens ("EXAMPLE",
  // "PLACEHOLDER", "DEMO", "REPLACE"). It does NOT say lowercase variants like
  // "example" are also suppressed. Flagging as ambiguous.
  it('AMBIGUOUS: lowercase "example" inside a value may or may not be suppressed', () => {
    const f = scan([file('src/amb1.js', `const K = "sk_live_exampleabcdefghijklmno";`)]);
    // Spec lists EXAMPLE (uppercase) as the marker. lowercase is undefined.
    // We assert only that the call returns an array. Either result is consistent.
    expect(Array.isArray(f)).toBe(true);
  });

  // Spec says "*.test.*" — unclear whether a `.tests.` (plural) sibling is suppressed.
  it('AMBIGUOUS: *.tests.* (plural) suppression is unspecified', () => {
    const f = scan([file('src/x.tests.js', `const K = "${STRIPE_LIVE}";`)]);
    expect(Array.isArray(f)).toBe(true);
  });

  // Spec lists Slack as "xox[bpas]-". The "s" branch covers app/legacy tokens,
  // but the spec phrasing "Bot/user/admin variants" is non-exhaustive.
  it('AMBIGUOUS: xoxe- refresh token shape is not in the spec list', () => {
    const f = scan([file('src/amb3.js', `const T = "xoxe-1234567890-abcdefghijklmnop";`)]);
    expect(Array.isArray(f)).toBe(true);
  });

  // Spec does not state whether DB URLs without credentials are suppressed.
  it('AMBIGUOUS: postgres:// without user:pass may or may not fire', () => {
    const f = scan([file('src/amb4.js', `URL = "postgres://db.host:5432/app"`)]);
    expect(Array.isArray(f)).toBe(true);
  });

  // Spec lists three xxx counts as "four or more consecutive x". Exactly three
  // is unspecified.
  it('AMBIGUOUS: exactly three consecutive x is below the documented threshold', () => {
    const f = scan([file('src/amb5.js', `const K = "sk_live_xxxabcdefghijklmnopqrst";`)]);
    expect(Array.isArray(f)).toBe(true);
  });
});
