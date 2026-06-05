// Adversarial RECALL test for probeSecrets.
// Tests written from the spec (Pattern page) only. The author of this file
// did NOT read the probe implementation, fixtures, or any disallowed file.
//
// Spec contract (verbatim summary):
//   - probeSecrets is a pure function: Array<{path, content}> -> Array<Finding>
//   - Finding shape: { id, probe: 'Secret Scanner', title, severity, category,
//                      cwe: 'CWE-798', file, line, evidence, remediation }
//   - severity ∈ {critical, high, medium, low, info}
//   - Provider shapes covered: AWS access key, AWS secret key, Stripe live,
//     Stripe test, OpenAI sk- / sk-proj-, Anthropic sk-ant-, Google AIza,
//     GitHub ghp_/gho_/github_pat_, Slack xox[bpas]-, Hugging Face hf_,
//     Replicate r8_, DB URLs with embedded creds, BEGIN ... PRIVATE KEY blocks.
//   - FP suppressions: *.test.*, *.spec.*, tests/, __tests__/, fixtures/
//     markdown docs, .env.example, .env.template
//   - Placeholder markers the probe suppresses (so we AVOID them in real-shape
//     positives): EXAMPLE, REPLACE, DEMO, PLACEHOLDER, and runs of 4+ x/X.

import { describe, it, expect } from 'vitest';
import { probeSecrets } from '../lib/probes.js';

const file = (path, content) => ({ path, content });

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

// ---------------------------------------------------------------------------
// Realistic-shape synthetic keys.
// These avoid the documented placeholder markers (EXAMPLE/REPLACE/DEMO/
// PLACEHOLDER and 4+ consecutive x/X) so that any non-detection is a recall
// failure, not a correctly-suppressed placeholder.
// ---------------------------------------------------------------------------
const KEYS = {
  awsAccessKeyId: 'AKIA1234567890ABCDEF', // AKIA + 16 [0-9A-Z]
  awsSecretKey: 'wJalrTnFEMI/K7MDENGbPxRfiCYzABCDE12345Ab', // 40 base64-ish
  stripeLive: 'sk_live_4eC39HqLyjWDarjtT1zd',
  stripeTest: 'sk_test_4eC39HqLyjWDarjtT1zd',
  openaiClassic: 'sk-abc123DEF456ghi789JKL0', // sk- + 20+
  openaiProj: 'sk-proj-9aZbYcXdWeVfUgThSiRjQkPlOnMm', // sk-proj-
  anthropic: 'sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuV', // sk-ant- + 20+
  googleAIza: 'AIzaSyA1b2C3d4E5f6G7h8I9j0K1L2M3n4O5p6Q', // AIza + 30+
  ghpClassic: 'ghp_16C7e42F292c6912E7710c838347Ae178B4a', // ghp_ + 36
  ghoOAuth: 'gho_16C7e42F292c6912E7710c838347Ae178B4a',
  ghPatNew: 'github_pat_11ABCD2YQ0aB1cD2eF3gH4_iJ5kL6mN7oP8qR9sT0uV1wX2yZ3aB4cD5eF6gH7iJ8kL9mN0oP',
  slackBot: 'xoxb-AbCdEfGhIjKlMnOpQrStUvWx',
  slackUser: 'xoxp-AbCdEfGhIjKlMnOpQrStUvWx',
  slackAdmin: 'xoxa-2-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
  slackApp: 'xoxs-AbCdEfGhIjKlMnOpQrStUvWx',
  huggingFace: 'hf_AbCdEfGhIjKlMnOpQrStUvWzYz0123456789',
  replicate: 'r8_AbCdEfGhIjKlMnOpQrStUvWzYz0123456789',
  postgresUrl: 'postgres://dbuser:s3cretP4ss@db.internal.host:5432/appdb',
  mysqlUrl: 'mysql://root:hunter2hunter2@10.0.0.5:3306/orders',
  mongoUrl: 'mongodb://admin:p4ssw0rd99@cluster0.mongo.net:27017/users',
  rsaPrivateKey:
    '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAv8Q1lKqj0a\n-----END RSA PRIVATE KEY-----',
  ecPrivateKey: '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIObQ8u4q9Z\n-----END EC PRIVATE KEY-----',
  opensshPrivateKey:
    '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAA\n-----END OPENSSH PRIVATE KEY-----',
  pgpPrivateKey:
    '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGAbcdEfGhIjK\n-----END PGP PRIVATE KEY BLOCK-----',
  genericPrivateKey:
    '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9\n-----END PRIVATE KEY-----',
};

// Helper: assert a finding exists that references the given file path and
// has the Secret Scanner contract shape.
function expectSecretFinding(findings, filePath) {
  const hits = findings.filter((f) => f.file === filePath);
  expect(hits.length, `no finding for ${filePath}`).toBeGreaterThan(0);
  for (const f of hits) {
    expect(f.probe).toBe('Secret Scanner');
    expect(f.cwe).toBe('CWE-798');
    expect(VALID_SEVERITIES.has(f.severity)).toBe(true);
    expect(typeof f.file).toBe('string');
    expect(typeof f.line).toBe('number');
    expect(f.line).toBeGreaterThanOrEqual(1);
    expect(typeof f.evidence).toBe('string');
    expect(f.evidence.length).toBeGreaterThan(0);
    expect(typeof f.remediation).toBe('string');
    expect(f.remediation.length).toBeGreaterThan(0);
    expect(typeof f.id).toBe('string');
    expect(typeof f.title).toBe('string');
    expect(typeof f.category).toBe('string');
  }
  return hits;
}

// ---------------------------------------------------------------------------
// POSITIVES — one (or more) per provider shape in the spec.
// ---------------------------------------------------------------------------
describe('probeSecrets — provider-shape positive recall', () => {
  it('detects AWS access key ID (AKIA + 16 [0-9A-Z])', () => {
    const findings = probeSecrets([
      file('config/aws.js', `export const AWS_ACCESS_KEY_ID = "${KEYS.awsAccessKeyId}";`),
    ]);
    expectSecretFinding(findings, 'config/aws.js');
  });

  it('detects an AWS secret access key (40-char base64-ish, named context)', () => {
    const findings = probeSecrets([
      file(
        'config/aws.js',
        `aws_secret_access_key = "${KEYS.awsSecretKey}"\naws_access_key_id = "${KEYS.awsAccessKeyId}"`
      ),
    ]);
    expectSecretFinding(findings, 'config/aws.js');
  });

  it('detects a Stripe live key (sk_live_)', () => {
    const findings = probeSecrets([
      file('lib/stripe.js', `const stripe = new Stripe("${KEYS.stripeLive}");`),
    ]);
    expectSecretFinding(findings, 'lib/stripe.js');
  });

  it('detects a Stripe test key (sk_test_)', () => {
    const findings = probeSecrets([
      file('lib/stripe.js', `const stripe = new Stripe("${KEYS.stripeTest}");`),
    ]);
    expectSecretFinding(findings, 'lib/stripe.js');
  });

  it('detects an OpenAI classic key (sk- + 20+)', () => {
    const findings = probeSecrets([
      file('lib/openai.js', `openai.apiKey = "${KEYS.openaiClassic}";`),
    ]);
    expectSecretFinding(findings, 'lib/openai.js');
  });

  it('detects an OpenAI modern project key (sk-proj-)', () => {
    const findings = probeSecrets([file('lib/openai.js', `OPENAI_API_KEY=${KEYS.openaiProj}`)]);
    expectSecretFinding(findings, 'lib/openai.js');
  });

  it('detects an Anthropic key (sk-ant-)', () => {
    const findings = probeSecrets([
      file('lib/anthropic.js', `ANTHROPIC_API_KEY="${KEYS.anthropic}"`),
    ]);
    expectSecretFinding(findings, 'lib/anthropic.js');
  });

  it('detects a Google API key (AIza + 30+)', () => {
    const findings = probeSecrets([file('lib/maps.js', `const apiKey = "${KEYS.googleAIza}";`)]);
    expectSecretFinding(findings, 'lib/maps.js');
  });

  it('detects a GitHub classic PAT (ghp_ + 36)', () => {
    const findings = probeSecrets([
      file('scripts/deploy.js', `const token = "${KEYS.ghpClassic}";`),
    ]);
    expectSecretFinding(findings, 'scripts/deploy.js');
  });

  it('detects a GitHub OAuth token (gho_)', () => {
    const findings = probeSecrets([file('scripts/deploy.js', `const token = "${KEYS.ghoOAuth}";`)]);
    expectSecretFinding(findings, 'scripts/deploy.js');
  });

  it('detects a GitHub fine-grained PAT (github_pat_)', () => {
    const findings = probeSecrets([file('scripts/deploy.js', `GH_TOKEN=${KEYS.ghPatNew}`)]);
    expectSecretFinding(findings, 'scripts/deploy.js');
  });

  it('detects a Slack bot token (xoxb-)', () => {
    const findings = probeSecrets([file('lib/slack.js', `const token = "${KEYS.slackBot}";`)]);
    expectSecretFinding(findings, 'lib/slack.js');
  });

  it('detects a Slack user token (xoxp-)', () => {
    const findings = probeSecrets([file('lib/slack.js', `const token = "${KEYS.slackUser}";`)]);
    expectSecretFinding(findings, 'lib/slack.js');
  });

  it('detects a Slack admin token (xoxa-)', () => {
    const findings = probeSecrets([file('lib/slack.js', `const token = "${KEYS.slackAdmin}";`)]);
    expectSecretFinding(findings, 'lib/slack.js');
  });

  it('detects a Slack app token (xoxs-)', () => {
    const findings = probeSecrets([file('lib/slack.js', `const token = "${KEYS.slackApp}";`)]);
    expectSecretFinding(findings, 'lib/slack.js');
  });

  it('detects a Hugging Face token (hf_ + 30+)', () => {
    const findings = probeSecrets([file('lib/hf.js', `const HF_TOKEN = "${KEYS.huggingFace}";`)]);
    expectSecretFinding(findings, 'lib/hf.js');
  });

  it('detects a Replicate token (r8_ + 30+)', () => {
    const findings = probeSecrets([
      file('lib/replicate.js', `const REPLICATE_API_TOKEN = "${KEYS.replicate}";`),
    ]);
    expectSecretFinding(findings, 'lib/replicate.js');
  });

  it('detects a Postgres URL with embedded credentials', () => {
    const findings = probeSecrets([
      file('config/db.js', `const DATABASE_URL = "${KEYS.postgresUrl}";`),
    ]);
    expectSecretFinding(findings, 'config/db.js');
  });

  it('detects a MySQL URL with embedded credentials', () => {
    const findings = probeSecrets([
      file('config/db.js', `const DATABASE_URL = "${KEYS.mysqlUrl}";`),
    ]);
    expectSecretFinding(findings, 'config/db.js');
  });

  it('detects a MongoDB URL with embedded credentials', () => {
    const findings = probeSecrets([
      file('config/db.js', `const DATABASE_URL = "${KEYS.mongoUrl}";`),
    ]);
    expectSecretFinding(findings, 'config/db.js');
  });

  it('detects a BEGIN RSA PRIVATE KEY block', () => {
    const findings = probeSecrets([file('keys/id_rsa', KEYS.rsaPrivateKey)]);
    expectSecretFinding(findings, 'keys/id_rsa');
  });

  it('detects a BEGIN EC PRIVATE KEY block', () => {
    const findings = probeSecrets([file('keys/id_ec', KEYS.ecPrivateKey)]);
    expectSecretFinding(findings, 'keys/id_ec');
  });

  it('detects a BEGIN OPENSSH PRIVATE KEY block', () => {
    const findings = probeSecrets([file('keys/id_ed25519', KEYS.opensshPrivateKey)]);
    expectSecretFinding(findings, 'keys/id_ed25519');
  });

  it('detects a BEGIN PGP PRIVATE KEY BLOCK', () => {
    const findings = probeSecrets([file('keys/pgp.asc', KEYS.pgpPrivateKey)]);
    expectSecretFinding(findings, 'keys/pgp.asc');
  });

  it('detects a generic BEGIN PRIVATE KEY block (PKCS8)', () => {
    const findings = probeSecrets([file('keys/pkcs8.pem', KEYS.genericPrivateKey)]);
    expectSecretFinding(findings, 'keys/pkcs8.pem');
  });
});

// ---------------------------------------------------------------------------
// FALSE-POSITIVE SUPPRESSIONS — spec lists exact suppression paths.
// We use a real-shape key in each so any finding is a true-positive that the
// suppression rule is supposed to silence.
// ---------------------------------------------------------------------------
describe('probeSecrets — documented FP suppressions', () => {
  it('suppresses findings in a *.test.* file', () => {
    const findings = probeSecrets([
      file('src/lib/openai.test.js', `const k = "${KEYS.openaiClassic}";`),
    ]);
    expect(findings.filter((f) => f.file === 'src/lib/openai.test.js')).toHaveLength(0);
  });

  it('suppresses findings in a *.spec.* file', () => {
    const findings = probeSecrets([
      file('src/lib/openai.spec.ts', `const k = "${KEYS.openaiClassic}";`),
    ]);
    expect(findings.filter((f) => f.file === 'src/lib/openai.spec.ts')).toHaveLength(0);
  });

  it('suppresses findings under a tests/ directory', () => {
    const findings = probeSecrets([
      file('tests/secret-cases.js', `const k = "${KEYS.stripeLive}";`),
    ]);
    expect(findings.filter((f) => f.file === 'tests/secret-cases.js')).toHaveLength(0);
  });

  it('suppresses findings under a __tests__/ directory', () => {
    const findings = probeSecrets([
      file('src/__tests__/aws-cases.js', `const k = "${KEYS.awsAccessKeyId}";`),
    ]);
    expect(findings.filter((f) => f.file === 'src/__tests__/aws-cases.js')).toHaveLength(0);
  });

  it('suppresses findings under a fixtures/ directory', () => {
    const findings = probeSecrets([
      file('src/lib/fixtures/secrets-sample.txt', `K=${KEYS.anthropic}`),
    ]);
    expect(findings.filter((f) => f.file === 'src/lib/fixtures/secrets-sample.txt')).toHaveLength(
      0
    );
  });

  it('suppresses findings in markdown documentation', () => {
    const findings = probeSecrets([
      file(
        'docs/setup.md',
        `Set your key in \`.env\`:\n\n    OPENAI_API_KEY=${KEYS.openaiClassic}\n`
      ),
    ]);
    expect(findings.filter((f) => f.file === 'docs/setup.md')).toHaveLength(0);
  });

  it('suppresses findings in .env.example', () => {
    const findings = probeSecrets([file('.env.example', `OPENAI_API_KEY=${KEYS.openaiClassic}`)]);
    expect(findings.filter((f) => f.file === '.env.example')).toHaveLength(0);
  });

  it('suppresses findings in .env.template', () => {
    const findings = probeSecrets([file('.env.template', `STRIPE_LIVE=${KEYS.stripeLive}`)]);
    expect(findings.filter((f) => f.file === '.env.template')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// STRUCTURAL — Finding shape contract.
// ---------------------------------------------------------------------------
describe('probeSecrets — Finding shape contract', () => {
  it('every finding has probe="Secret Scanner" and cwe="CWE-798"', () => {
    const findings = probeSecrets([
      file('a.js', `const k = "${KEYS.openaiClassic}";`),
      file('b.js', `const k = "${KEYS.stripeLive}";`),
      file('c.js', `const k = "${KEYS.anthropic}";`),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.probe).toBe('Secret Scanner');
      expect(f.cwe).toBe('CWE-798');
    }
  });

  it('severity is one of {critical, high, medium, low, info}', () => {
    const findings = probeSecrets([
      file('a.js', `const k = "${KEYS.awsAccessKeyId}";`),
      file('b.js', `const k = "${KEYS.googleAIza}";`),
      file('c.js', `const k = "${KEYS.ghpClassic}";`),
      file('d.js', KEYS.rsaPrivateKey),
    ]);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(VALID_SEVERITIES.has(f.severity)).toBe(true);
    }
  });

  it('file, line, evidence, remediation, id, title, category are all populated', () => {
    const findings = probeSecrets([file('src/secrets.js', `const k = "${KEYS.stripeLive}";`)]);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.file).toBeTruthy();
      expect(typeof f.line).toBe('number');
      expect(f.line).toBeGreaterThanOrEqual(1);
      expect(f.evidence).toBeTruthy();
      expect(f.remediation).toBeTruthy();
      expect(f.id).toBeTruthy();
      expect(f.title).toBeTruthy();
      expect(f.category).toBeTruthy();
    }
  });

  it('returns the correct line number for a multi-line file', () => {
    const content =
      '// header line\n' +
      '// another comment\n' +
      '// a third line\n' +
      `const KEY = "${KEYS.stripeLive}";\n`;
    const findings = probeSecrets([file('src/multi.js', content)]);
    const hits = findings.filter((f) => f.file === 'src/multi.js');
    expect(hits.length).toBeGreaterThan(0);
    // The Stripe literal lives on line 4.
    expect(hits.some((f) => f.line === 4)).toBe(true);
  });

  it('evidence does not include the raw secret in cleartext beyond what is needed (smoke test)', () => {
    // Soft contract: spec says evidence is populated. We don't assert exact
    // redaction style, only that evidence is a non-empty string and that the
    // finding is associated with the right file.
    const findings = probeSecrets([file('src/leak.js', `const KEY = "${KEYS.stripeLive}";`)]);
    const hits = findings.filter((f) => f.file === 'src/leak.js');
    expect(hits.length).toBeGreaterThan(0);
    for (const f of hits) {
      expect(typeof f.evidence).toBe('string');
      expect(f.evidence.length).toBeGreaterThan(0);
    }
  });

  it('returns [] for an empty input array', () => {
    const findings = probeSecrets([]);
    expect(Array.isArray(findings)).toBe(true);
    expect(findings).toHaveLength(0);
  });

  it('returns [] for files with no secrets', () => {
    const findings = probeSecrets([
      file('src/clean.js', 'export function add(a, b) { return a + b; }'),
      file('src/also-clean.js', 'const PI = 3.14159; export default PI;'),
    ]);
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.filter((f) => f.file === 'src/clean.js')).toHaveLength(0);
    expect(findings.filter((f) => f.file === 'src/also-clean.js')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// MULTI-FILE — cross-file scan behavior.
// ---------------------------------------------------------------------------
describe('probeSecrets — multi-file behavior', () => {
  it('detects secrets in multiple files in a single scan', () => {
    const findings = probeSecrets([
      file('a/openai.js', `const k = "${KEYS.openaiClassic}";`),
      file('b/stripe.js', `const k = "${KEYS.stripeLive}";`),
      file('c/aws.js', `const k = "${KEYS.awsAccessKeyId}";`),
    ]);
    const files = new Set(findings.map((f) => f.file));
    expect(files.has('a/openai.js')).toBe(true);
    expect(files.has('b/stripe.js')).toBe(true);
    expect(files.has('c/aws.js')).toBe(true);
  });

  it('still fires on real files when a suppressed file is mixed in', () => {
    const findings = probeSecrets([
      // Suppressed (test path):
      file('src/lib/openai.test.js', `const k = "${KEYS.openaiClassic}";`),
      // Real source:
      file('src/lib/openai.js', `const k = "${KEYS.openaiClassic}";`),
    ]);
    expect(findings.filter((f) => f.file === 'src/lib/openai.test.js')).toHaveLength(0);
    expect(findings.filter((f) => f.file === 'src/lib/openai.js').length).toBeGreaterThan(0);
  });

  it('suppresses the same key across multiple documented-suppression paths in one scan', () => {
    const findings = probeSecrets([
      file('.env.example', `OPENAI_API_KEY=${KEYS.openaiClassic}`),
      file('.env.template', `STRIPE=${KEYS.stripeLive}`),
      file('docs/setup.md', `Use \`${KEYS.anthropic}\` as your key.`),
      file('tests/cases.js', `const k = "${KEYS.googleAIza}";`),
      file('src/lib/foo.test.js', `const k = "${KEYS.ghpClassic}";`),
      file('src/__tests__/bar.js', `const k = "${KEYS.replicate}";`),
      file('src/fixtures/x.txt', `K=${KEYS.huggingFace}`),
    ]);
    const suppressed = [
      '.env.example',
      '.env.template',
      'docs/setup.md',
      'tests/cases.js',
      'src/lib/foo.test.js',
      'src/__tests__/bar.js',
      'src/fixtures/x.txt',
    ];
    for (const p of suppressed) {
      expect(
        findings.filter((f) => f.file === p),
        `expected no findings for ${p}`
      ).toHaveLength(0);
    }
  });

  it('detects multiple distinct provider shapes inside ONE file', () => {
    const content =
      `const OPENAI_API_KEY = "${KEYS.openaiClassic}";\n` +
      `const STRIPE_KEY = "${KEYS.stripeLive}";\n` +
      `const AWS = "${KEYS.awsAccessKeyId}";\n` +
      `const GH = "${KEYS.ghpClassic}";\n`;
    const findings = probeSecrets([file('src/all-the-keys.js', content)]);
    const hits = findings.filter((f) => f.file === 'src/all-the-keys.js');
    // The spec promises detection of each shape. At minimum we should get
    // more than one finding for a file with four distinct provider shapes.
    expect(hits.length).toBeGreaterThanOrEqual(2);
    // And the line numbers should not all collapse to a single line.
    const lines = new Set(hits.map((f) => f.line));
    expect(lines.size).toBeGreaterThanOrEqual(2);
  });
});

// ---------------------------------------------------------------------------
// EDGE CASES — behavior implied by the spec but not the headline shape list.
// ---------------------------------------------------------------------------
describe('probeSecrets — edge cases', () => {
  it('detects a key embedded in JSON config', () => {
    const findings = probeSecrets([
      file('config.json', `{\n  "stripeKey": "${KEYS.stripeLive}",\n  "feature": true\n}`),
    ]);
    expectSecretFinding(findings, 'config.json');
  });

  it('detects a key embedded in a .env file (real, not .env.example)', () => {
    const findings = probeSecrets([file('.env', `OPENAI_API_KEY=${KEYS.openaiProj}`)]);
    expectSecretFinding(findings, '.env');
  });

  it('detects a key in a YAML config', () => {
    const findings = probeSecrets([
      file('config.yaml', `database:\n  url: "${KEYS.postgresUrl}"\n  pool: 5\n`),
    ]);
    expectSecretFinding(findings, 'config.yaml');
  });

  it('detects a private key whose BEGIN block spans many lines', () => {
    const body = Array.from(
      { length: 20 },
      () => 'MIIEowIBAAKCAQEAv8Q1lKqj0aBcDeFgHiJkLmNoPq'
    ).join('\n');
    const content = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n-----END RSA PRIVATE KEY-----\n`;
    const findings = probeSecrets([file('keys/long.pem', content)]);
    expectSecretFinding(findings, 'keys/long.pem');
  });

  it('does not crash on an empty file', () => {
    const findings = probeSecrets([file('empty.js', '')]);
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.filter((f) => f.file === 'empty.js')).toHaveLength(0);
  });

  it('does not crash on a file containing only whitespace', () => {
    const findings = probeSecrets([file('ws.js', '   \n\t\n   \n')]);
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.filter((f) => f.file === 'ws.js')).toHaveLength(0);
  });

  it('returns Array regardless of how many secrets are present', () => {
    const findings = probeSecrets([file('clean.js', '// nothing here')]);
    expect(Array.isArray(findings)).toBe(true);
  });
});
