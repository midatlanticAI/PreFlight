// Adversarial PRECISION tests for probeSecrets.
//
// Every test in this file constructs benign code that LOOKS like a secret but
// isn't, and asserts that the probe produces ZERO critical-or-high findings.
// These are the "must NOT fire" cases. A naive scanner will over-fire here;
// PreFlight's secret-scanner must be precise enough to suppress these.

import { describe, expect, it } from 'vitest';
import { probeSecrets } from '../lib/probes.js';

const file = (path, content) => ({ path, content });
const real = (findings) =>
  findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
const expectClean = (files) => expect(real(probeSecrets(files))).toEqual([]);

describe('probeSecrets precision: placeholders', () => {
  it('Stripe live placeholder with angle brackets', () => {
    const src = `const key = 'sk_live_<your-key-here>';`;
    expectClean([file('config.js', src)]);
  });

  it('Stripe live placeholder REPLACE_ME', () => {
    const src = `const key = 'sk_live_REPLACE_ME';`;
    expectClean([file('config.js', src)]);
  });

  it('Stripe live placeholder YOUR_KEY_HERE', () => {
    const src = `const STRIPE = 'sk_live_YOUR_KEY_HERE';`;
    expectClean([file('config.js', src)]);
  });

  it('Stripe test placeholder', () => {
    const src = `const k = 'sk_test_<replace-with-real-test-key>';`;
    expectClean([file('config.js', src)]);
  });

  it('AWS key with X padding (obvious placeholder)', () => {
    const src = `const aws = 'AKIAXXXXXXXXXXXXXXXX';`;
    expectClean([file('aws.js', src)]);
  });

  it('AWS docs canonical EXAMPLE key', () => {
    // From AWS public docs; this is the literal example string AWS publishes.
    const src = `const example = 'AKIAIOSFODNN7EXAMPLE';`;
    expectClean([file('aws-example.js', src)]);
  });

  it('OpenAI placeholder', () => {
    const src = `const OPENAI_API_KEY = 'sk-<your-openai-key>';`;
    expectClean([file('ai.js', src)]);
  });

  it('OpenAI proj placeholder', () => {
    const src = `const k = 'sk-proj-REPLACE_WITH_KEY';`;
    expectClean([file('ai.js', src)]);
  });

  it('Anthropic placeholder', () => {
    const src = `const ANTHROPIC = 'sk-ant-<your-key>';`;
    expectClean([file('ai.js', src)]);
  });

  it('Google API placeholder', () => {
    const src = `const G = 'AIza<replace-with-your-api-key-here-please>';`;
    expectClean([file('google.js', src)]);
  });

  it('GitHub PAT placeholder', () => {
    const src = `const GH = 'ghp_<your-personal-access-token>';`;
    expectClean([file('gh.js', src)]);
  });

  it('Slack placeholder', () => {
    const src = `const SLACK = 'xoxb-<your-slack-token>';`;
    expectClean([file('slack.js', src)]);
  });

  it('Hugging Face placeholder', () => {
    const src = `const HF = 'hf_<replace-with-your-huggingface-token>';`;
    expectClean([file('hf.js', src)]);
  });

  it('Replicate placeholder', () => {
    const src = `const R = 'r8_<replace-with-your-replicate-token>';`;
    expectClean([file('rep.js', src)]);
  });
});

describe('probeSecrets precision: .env.example / template / sample', () => {
  it('.env.example with all placeholders', () => {
    const src = [
      'STRIPE_SECRET_KEY=sk_live_<your-stripe-secret-key>',
      'OPENAI_API_KEY=sk-<your-openai-api-key>',
      'ANTHROPIC_API_KEY=sk-ant-<your-anthropic-api-key>',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      'GITHUB_TOKEN=ghp_REPLACE_ME',
      'GOOGLE_API_KEY=AIza_REPLACE_WITH_YOUR_KEY_HERE_PLEASE',
    ].join('\n');
    expectClean([file('.env.example', src)]);
  });

  it('.env.template with placeholders', () => {
    const src = 'STRIPE_KEY=sk_live_REPLACE_ME\nDATABASE_URL=postgres://user:pass@host/db';
    expectClean([file('.env.template', src)]);
  });

  it('.env.sample with bracket placeholders', () => {
    const src = 'API=sk-<openai-key>\nSLACK=xoxb-<slack-bot-token>';
    expectClean([file('.env.sample', src)]);
  });

  it('.env.dist with placeholders', () => {
    const src = 'STRIPE=sk_live_<key>\nAWS_KEY=AKIAXXXXXXXXXXXXXXXX';
    expectClean([file('.env.dist', src)]);
  });

  it('env.example.yml with placeholders', () => {
    const src = 'stripe:\n  key: sk_live_<your-key>\nopenai:\n  key: sk-<your-key>';
    expectClean([file('env.example.yml', src)]);
  });
});

describe('probeSecrets precision: markdown documentation', () => {
  it('README docs Stripe key shape inside fenced code', () => {
    const src = [
      '# API Setup',
      '',
      'Set your Stripe secret:',
      '',
      '```bash',
      'export STRIPE_KEY=sk_live_<your-secret-key-here>',
      '```',
    ].join('\n');
    expectClean([file('README.md', src)]);
  });

  it('docs/api-keys.md showing AWS docs example', () => {
    const src = [
      '## AWS credentials',
      '',
      'The AWS docs use this example value:',
      '',
      '```',
      'AKIAIOSFODNN7EXAMPLE',
      'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      '```',
    ].join('\n');
    expectClean([file('docs/api-keys.md', src)]);
  });

  it('docs/openai.md showing format', () => {
    const src = [
      '## OpenAI key format',
      '',
      'Keys begin with `sk-` and are 51 chars long. Example placeholder:',
      '',
      '```',
      'sk-<your-openai-api-key-here-placeholder>',
      '```',
    ].join('\n');
    expectClean([file('docs/openai.md', src)]);
  });

  it('CONTRIBUTING.md showing example secret shapes', () => {
    const src = [
      '# Contributing',
      '',
      'When committing, never include real keys. Placeholders look like:',
      '',
      '- `sk_live_<key>`',
      '- `AKIAEXAMPLEPLACEHOLDR`',
      '- `ghp_<token>`',
    ].join('\n');
    expectClean([file('CONTRIBUTING.md', src)]);
  });

  it('SECURITY.md showing redacted shape', () => {
    const src = [
      '# Security policy',
      '',
      'If you find a leaked key like `sk_live_REDACTED_REDACTED_REDA`, report it via the form.',
    ].join('\n');
    expectClean([file('SECURITY.md', src)]);
  });
});

describe('probeSecrets precision: JSDoc / code comments naming the shape', () => {
  it('JSDoc explaining expected format', () => {
    const src = [
      '/**',
      ' * @param {string} key - Stripe secret, format: sk_live_<24+ chars>',
      ' * @example sk_live_<your-key>',
      ' */',
      'function stripe(key) { return key; }',
    ].join('\n');
    expectClean([file('stripe.js', src)]);
  });

  it('inline comment documenting AWS key shape', () => {
    const src = `// Expected format: AKIA followed by 16 uppercase alphanumeric chars\nconst label = 'AWS';`;
    expectClean([file('aws.js', src)]);
  });

  it('comment with sk-ant- format', () => {
    const src = `// Anthropic keys are sk-ant-<long random string>\nconst name = 'anthropic';`;
    expectClean([file('anthropic.js', src)]);
  });

  it('block comment describing GitHub token shape', () => {
    const src = '/* GitHub PATs are ghp_ + 36 chars. We never log them. */\nconst label = "gh";';
    expectClean([file('github.js', src)]);
  });

  it('TODO comment referencing placeholder', () => {
    const src = `// TODO: replace sk_test_REPLACE_ME with real test key in CI\nconst x = 1;`;
    expectClean([file('todo.js', src)]);
  });
});

describe('probeSecrets precision: AWS docs example value in comments', () => {
  it('inline comment with literal AWS example key', () => {
    const src = `// AKIAIOSFODNN7EXAMPLE is the AWS docs canonical example\nconst x = 1;`;
    expectClean([file('notes.js', src)]);
  });

  it('block comment with AWS example secret', () => {
    const src =
      '/* AWS docs example: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY */\nconst x = 1;';
    expectClean([file('notes.js', src)]);
  });

  it('markdown lists the AWS example pair', () => {
    const src =
      '# AWS\n\nDocs example:\n- access: AKIAIOSFODNN7EXAMPLE\n- secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n';
    expectClean([file('docs/aws.md', src)]);
  });
});

describe('probeSecrets precision: git SHA collisions', () => {
  it('40-char hex assigned to COMMIT_SHA', () => {
    const src = `const COMMIT_SHA = 'a1b2c3d4e5f6789012345678901234567890abcd';`;
    expectClean([file('build.js', src)]);
  });

  it('40-char hex assigned to GIT_COMMIT', () => {
    const src = `const GIT_COMMIT = 'deadbeefcafebabefeedfacefeedface00112233';`;
    expectClean([file('build.js', src)]);
  });

  it('git SHA in lockfile-style assignment', () => {
    const src = `"resolved-commit": "0123456789abcdef0123456789abcdef01234567"`;
    expectClean([file('lockfile.json', src)]);
  });

  it('git SHA inside fetch URL', () => {
    const src = `fetch('https://github.com/foo/bar/commit/0123456789abcdef0123456789abcdef01234567');`;
    expectClean([file('fetch.js', src)]);
  });

  it('SHA used as cache key constant', () => {
    const src = `const CACHE_KEY = '0123456789abcdef0123456789abcdef01234567';`;
    expectClean([file('cache.js', src)]);
  });
});

describe('probeSecrets precision: UUID v4 collisions', () => {
  it('UUID v4 assigned to RUN_ID', () => {
    const src = `const RUN_ID = '550e8400-e29b-41d4-a716-446655440000';`;
    expectClean([file('run.js', src)]);
  });

  it('UUID v4 in fixture', () => {
    const src = `const id = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';`;
    expectClean([file('id.js', src)]);
  });

  it('UUID v4 in JSON config', () => {
    const src = `{"trace_id": "16fd2706-8baf-433b-82eb-8c7fada847da"}`;
    expectClean([file('trace.json', src)]);
  });

  it('UUID v4 in array literal', () => {
    const src = `const ids = ['9c5b94b1-35ad-49bb-b118-8e8fc24abf80'];`;
    expectClean([file('ids.js', src)]);
  });
});

describe('probeSecrets precision: base64 data URLs', () => {
  it('1x1 png data URL', () => {
    const src = `const px = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkAAIAAAoAAv/lxKUAAAAASUVORK5CYII=';`;
    expectClean([file('img.js', src)]);
  });

  it('svg data URL', () => {
    const src = `const svg = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=';`;
    expectClean([file('svg.js', src)]);
  });

  it('audio data URL', () => {
    const src = `const a = 'data:audio/mpeg;base64,SUQzBAAAAAAAI1RTU0UAAAAPAAADTGF2ZjU4LjQ1LjEwMAAAAAAAAAAAAAAA';`;
    expectClean([file('audio.js', src)]);
  });

  it('font data URL', () => {
    const src = `const f = 'data:font/woff2;base64,d09GMgABAAAAAAcsAA0AAAAAEKwAAAbWAAEAAAAA';`;
    expectClean([file('font.js', src)]);
  });
});

describe('probeSecrets precision: hex hashes of non-secret values', () => {
  it('SHA-256 of non-secret content', () => {
    const src = `const SRI = 'sha256-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';`;
    expectClean([file('sri.js', src)]);
  });

  it('SHA-1 of non-secret content', () => {
    const src = `const SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';`;
    expectClean([file('sha.js', src)]);
  });

  it('MD5 of non-secret content', () => {
    const src = `const ETAG = 'd41d8cd98f00b204e9800998ecf8427e';`;
    expectClean([file('etag.js', src)]);
  });

  it('integrity attribute in HTML', () => {
    const src = `<script integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo"></script>`;
    expectClean([file('index.html', src)]);
  });
});

describe('probeSecrets precision: JWTs of public payloads', () => {
  it('JWT with public claims', () => {
    // header: {"alg":"HS256","typ":"JWT"}
    // payload: {"role":"public","note":"demo only"}
    // signature: fake (not a real secret)
    const src = `const demo = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoicHVibGljIiwibm90ZSI6ImRlbW8gb25seSJ9.ZmFrZS1zaWdu';`;
    expectClean([file('jwt.js', src)]);
  });

  it('JWT used as a documentation example', () => {
    const src = [
      '/**',
      ' * Example JWT (not a credential):',
      ' * eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIn0.demo',
      ' */',
      'function decode(t) { return t; }',
    ].join('\n');
    expectClean([file('jwt-docs.js', src)]);
  });

  it('JWT in markdown', () => {
    const src = '# JWT format\n\n```\neyJhbGciOiJub25lIn0.eyJzdWIiOiJleGFtcGxlIn0.\n```\n';
    expectClean([file('docs/jwt.md', src)]);
  });
});

describe('probeSecrets precision: self-references (regex/pattern data)', () => {
  it('SECRET_PATTERNS array of regex literals', () => {
    const src = [
      'export const SECRET_PATTERNS = [',
      '  /AKIA[A-Z0-9]{16}/,',
      '  /sk_live_[A-Za-z0-9]{24,}/,',
      '  /sk-ant-[A-Za-z0-9-_]{20,}/,',
      '  /ghp_[A-Za-z0-9]{36}/,',
      '  /AIza[A-Za-z0-9_-]{35}/,',
      '];',
    ].join('\n');
    expectClean([file('src/lib/patterns.js', src)]);
  });

  it('SECRET_PATTERNS as string array', () => {
    const src = [
      'const SECRET_PATTERNS = [',
      '  "AKIA[A-Z0-9]{16}",',
      '  "sk_live_[A-Za-z0-9]{24,}",',
      '  "sk-ant-[A-Za-z0-9-_]{20,}",',
      '];',
    ].join('\n');
    expectClean([file('src/lib/patterns.js', src)]);
  });

  it('detection rule object literal', () => {
    const src = [
      'const RULES = {',
      '  aws: { prefix: "AKIA", len: 20 },',
      '  stripe: { prefix: "sk_live_", min: 24 },',
      '  openai: { prefix: "sk-", min: 20 },',
      '};',
    ].join('\n');
    expectClean([file('rules.js', src)]);
  });

  it('learn pattern markdown describing detection', () => {
    const src = [
      '# Secret scanner spec',
      '',
      'Match `AKIA` followed by 16 uppercase alphanumeric characters.',
      'Match `sk_live_` followed by 24+ base62 characters.',
    ].join('\n');
    expectClean([file('src/learn/patterns/secret-scanner-spec.md', src)]);
  });
});

describe('probeSecrets precision: bare process.env references', () => {
  it('process.env.STRIPE_SECRET_KEY', () => {
    const src = `const k = process.env.STRIPE_SECRET_KEY;`;
    expectClean([file('config.js', src)]);
  });

  it('import.meta.env reference', () => {
    const src = `const k = import.meta.env.VITE_OPENAI_KEY;`;
    expectClean([file('config.js', src)]);
  });

  it('os.environ in python-like file', () => {
    const src = `key = os.environ.get('AWS_SECRET_ACCESS_KEY')`;
    expectClean([file('config.py', src)]);
  });

  it('destructured env vars', () => {
    const src = `const { STRIPE_SECRET_KEY, OPENAI_API_KEY } = process.env;`;
    expectClean([file('env.js', src)]);
  });
});

describe('probeSecrets precision: DB URLs without credentials', () => {
  it('postgres localhost no creds', () => {
    const src = `const URL = 'postgres://localhost:5432/myapp';`;
    expectClean([file('db.js', src)]);
  });

  it('mongodb localhost no creds', () => {
    const src = `const URL = 'mongodb://localhost:27017/mydb';`;
    expectClean([file('db.js', src)]);
  });

  it('redis localhost no creds', () => {
    const src = `const URL = 'redis://localhost:6379';`;
    expectClean([file('cache.js', src)]);
  });

  it('postgres with placeholder creds in env example', () => {
    const src = `DATABASE_URL=postgres://user:<password>@host:5432/db`;
    expectClean([file('.env.example', src)]);
  });
});

describe('probeSecrets precision: AWS ARNs and resource paths', () => {
  it('Secrets Manager ARN', () => {
    const src = `const arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/stripe/key-abcdef';`;
    expectClean([file('arn.js', src)]);
  });

  it('SSM Parameter Store path', () => {
    const src = `const path = '/prod/api/stripe-secret-key';`;
    expectClean([file('ssm.js', src)]);
  });

  it('KMS key ARN', () => {
    const src = `const k = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';`;
    expectClean([file('kms.js', src)]);
  });

  it('IAM role ARN', () => {
    const src = `const r = 'arn:aws:iam::123456789012:role/MyServiceRole';`;
    expectClean([file('iam.js', src)]);
  });
});

describe('probeSecrets precision: shape-like substrings in URLs / versions / filenames', () => {
  it('npm version contains "sk-"', () => {
    const src = `const v = "musk-models@1.0.0";`;
    expectClean([file('pkg.js', src)]);
  });

  it('URL path contains AKIA-like substring', () => {
    const src = `const u = 'https://example.com/akiagama-store';`;
    expectClean([file('u.js', src)]);
  });

  it('filename contains ghp_', () => {
    const src = `const f = 'graph_renderer.js';`;
    expectClean([file('f.js', src)]);
  });

  it('css class contains hf_', () => {
    const src = `const c = 'half-width-button';`;
    expectClean([file('css.js', src)]);
  });

  it('variable name contains sk_live (not a value)', () => {
    const src = `let sk_live_count = 0;`;
    expectClean([file('counter.js', src)]);
  });
});

describe('probeSecrets precision: production-shaped non-secret strings', () => {
  it('variable named OPENAI_API_KEY with empty string', () => {
    const src = `const OPENAI_API_KEY = '';`;
    expectClean([file('init.js', src)]);
  });

  it('label string mentioning key shape', () => {
    const src = `const label = 'Enter your sk-... key';`;
    expectClean([file('ui.js', src)]);
  });

  it('placeholder attribute in JSX', () => {
    const src = `<input placeholder="sk-... or sk-proj-..." />`;
    expectClean([file('input.jsx', src)]);
  });

  it('error message describing key format', () => {
    const src = `throw new Error('Expected an OpenAI key beginning with sk- or sk-proj-');`;
    expectClean([file('err.js', src)]);
  });
});

describe('probeSecrets precision: long base64 of legitimate binary content', () => {
  it('large inlined PNG payload', () => {
    const long =
      'iVBORw0KGgoAAAANSUhEUgAAAGQAAABkCAYAAABw4pVUAAAACXBIWXMAAAsTAAALEwEAmpwYAAAB' +
      'cmlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczpt' +
      'ZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNi4wLjAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRw' +
      'Oi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0';
    const src = `const png = "data:image/png;base64,${long}";`;
    expectClean([file('asset.js', src)]);
  });

  it('large inlined SVG payload', () => {
    const long =
      'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAy' +
      'NCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJjdXJyZW50Q29sb3IiIHN0cm9rZS13aWR0aD0iMiI+PHBh' +
      'dGggZD0iTTEyIDJMMiAyMmwxMC0xMHoiLz48L3N2Zz4=';
    const src = `const svg = "data:image/svg+xml;base64,${long}";`;
    expectClean([file('icon.js', src)]);
  });

  it('woff2 font base64', () => {
    const long =
      'd09GMgABAAAAAAcsAA0AAAAAEKwAAAbWAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABGRlRNG' +
      'h4bjB4cm5tZXRhAAABaAAAACwAAAA0AhUCFEdQT1MAAAGYAAAA';
    const src = `const font = "data:font/woff2;base64,${long}";`;
    expectClean([file('font.js', src)]);
  });
});

describe('probeSecrets precision: test fixture paths', () => {
  it('__tests__ directory with placeholder values', () => {
    const src = `const fakeKey = 'sk_live_REPLACE_ME_IN_TEST_ONLY';`;
    expectClean([file('src/__tests__/billing.test.js', src)]);
  });

  it('tests/ directory with shape-like value', () => {
    const src = `const fake = 'AKIAIOSFODNN7EXAMPLE';`;
    expectClean([file('tests/aws.spec.js', src)]);
  });

  it('*.test.* file', () => {
    const src = `const k = 'sk-<test-key-placeholder>';`;
    expectClean([file('src/lib/openai.test.js', src)]);
  });

  it('*.spec.* file', () => {
    const src = `const k = 'ghp_REPLACE_ME';`;
    expectClean([file('src/lib/gh.spec.ts', src)]);
  });

  it('cypress/ directory', () => {
    const src = `const k = 'sk_test_<key>';`;
    expectClean([file('cypress/integration/checkout.js', src)]);
  });
});

describe('probeSecrets precision: fixtures/ directories', () => {
  it('fixtures/ with shape strings', () => {
    const src = `export const fixture = { key: 'sk_live_<placeholder>' };`;
    expectClean([file('src/fixtures/stripe.js', src)]);
  });

  it('__fixtures__/ with AWS shape', () => {
    const src = `export const F = { aws: 'AKIAIOSFODNN7EXAMPLE' };`;
    expectClean([file('src/__fixtures__/aws.js', src)]);
  });

  it('fixtures.json', () => {
    const src = `{"openai": "sk-<placeholder-value>"}`;
    expectClean([file('test/fixtures.json', src)]);
  });

  it('snapshot file', () => {
    const src = `exports['render 1'] = '<input value="sk_live_<placeholder>" />';`;
    expectClean([file('src/__snapshots__/Comp.snap', src)]);
  });
});

describe('probeSecrets precision: PEM placeholder bodies', () => {
  it('placeholder private key block', () => {
    const src = [
      '-----BEGIN PRIVATE KEY-----',
      'REPLACE_WITH_YOUR_PRIVATE_KEY',
      '-----END PRIVATE KEY-----',
    ].join('\n');
    expectClean([file('docs/keys.md', src)]);
  });

  it('placeholder RSA private key', () => {
    const src = [
      '-----BEGIN RSA PRIVATE KEY-----',
      '<your private key here>',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');
    expectClean([file('.env.example', src)]);
  });

  it('placeholder EC private key', () => {
    const src = [
      '-----BEGIN EC PRIVATE KEY-----',
      'YOUR_KEY_GOES_HERE',
      '-----END EC PRIVATE KEY-----',
    ].join('\n');
    expectClean([file('config.example.txt', src)]);
  });

  it('PEM in docs with template marker', () => {
    const src = [
      '# Setting up TLS',
      '',
      '```',
      '-----BEGIN PRIVATE KEY-----',
      '{{ replace with your PEM-encoded key }}',
      '-----END PRIVATE KEY-----',
      '```',
    ].join('\n');
    expectClean([file('docs/tls.md', src)]);
  });
});

describe('edge cases where benign-vs-secret is genuinely ambiguous', () => {
  // Ambiguous: a 24+ char string after sk_live_ that is all hyphens / underscores.
  // It satisfies the shape regex but contains no entropy. Treating as benign.
  it('sk_live_ followed by hyphens and underscores only', () => {
    const src = `const k = 'sk_live_____________________';`;
    expectClean([file('config.js', src)]);
  });

  // Ambiguous: real-looking AWS shape inside a docs example file but the
  // value is a fabricated EXAMPLE-style key. PreFlight relies on the
  // EXAMPLE suffix being treated as a known placeholder.
  it('AWS key shape with EXAMPLE suffix in production code path', () => {
    const src = `const aws = 'AKIAEXAMPLEPLACEHOLDR';`;
    expectClean([file('src/lib/aws.js', src)]);
  });

  // Ambiguous: AKIA prefix + correct length + plausible entropy, but the
  // surrounding variable name is `EXAMPLE_KEY` and the file is a tutorial.
  it('AKIA-shape value in a tutorial code block, var named EXAMPLE_KEY', () => {
    const src = [
      '# Tutorial: never commit keys',
      '',
      '```js',
      "const EXAMPLE_KEY = 'AKIAZ7Q9KLMNPQRSTUVW';",
      '```',
    ].join('\n');
    expectClean([file('docs/tutorial.md', src)]);
  });

  // Ambiguous: shape-correct GitHub PAT inside a markdown fenced block in a
  // contributor guide. We expect file-type plus fence context to suppress.
  it('ghp_ token in fenced block of CONTRIBUTING.md', () => {
    const src = [
      '# Contributing',
      '',
      '```bash',
      'export GH_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      '```',
    ].join('\n');
    expectClean([file('CONTRIBUTING.md', src)]);
  });

  // Ambiguous: 40-char hex inside a non-COMMIT_SHA variable in production
  // code. Most scanners treat 40-hex as low-entropy SHA-shape; PreFlight
  // should not light up critical/high.
  it('40-char hex assigned to a non-credential variable', () => {
    const src = `const FINGERPRINT = '0123456789abcdef0123456789abcdef01234567';`;
    expectClean([file('src/lib/hash.js', src)]);
  });

  // Ambiguous: base64-shaped 40-char string assigned to a variable named
  // something unrelated to credentials.
  it('40-char base64-shape assigned to ETAG_VALUE', () => {
    const src = `const ETAG_VALUE = 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCd';`;
    expectClean([file('etag.js', src)]);
  });
});
