// Adversarial precision tests for probeSecrets.
//
// Every test asserts the probe returns ZERO critical-or-high findings on
// inputs that LOOK like secrets but are not. These are "must NOT fire" cases.
//
// The failure mode this suite targets: line-scoped scanners that miss the
// surrounding context, especially MULTI-LINE block comments and MULTI-LINE
// template literals containing example/placeholder material.

import { describe, it, expect } from 'vitest';
import { probeSecrets } from '../lib/probes.js';

const file = (path, content) => ({ path, content });
const real = (findings) =>
  findings.filter((f) => f.severity === 'critical' || f.severity === 'high');

// -----------------------------------------------------------------------------
// 1. Placeholder values across all provider shapes
// -----------------------------------------------------------------------------
describe('placeholders across provider shapes', () => {
  it('AWS docs canonical example AKIAIOSFODNN7EXAMPLE', () => {
    const src = `
      // From AWS Identity and Access Management docs:
      const accessKeyId = 'AKIAIOSFODNN7EXAMPLE';
      const secretAccessKey = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    `;
    expect(real(probeSecrets([file('aws.js', src)]))).toEqual([]);
  });

  it('REPLACE_ME / YOUR_KEY markers across providers', () => {
    const src = `
      const config = {
        openai: 'sk-REPLACE_WITH_YOUR_OPENAI_KEY_HERE',
        anthropic: 'sk-ant-REPLACE_WITH_YOUR_ANTHROPIC_KEY',
        google: 'AIzaREPLACE_WITH_YOUR_GOOGLE_API_KEY',
        github: 'ghp_REPLACE_WITH_YOUR_GITHUB_TOKEN_HERE',
        stripe: 'sk_live_REPLACE_WITH_YOUR_STRIPE_SECRET',
        hf: 'hf_REPLACE_WITH_YOUR_HUGGINGFACE_TOKEN_HERE',
      };
    `;
    expect(real(probeSecrets([file('config.js', src)]))).toEqual([]);
  });

  it('XXXXXXXX placeholders with 4+ X characters', () => {
    const src = `
      const stripe = 'sk_live_xxxxxxxxxxxxxxxxxxxx';
      const openai = 'sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
      const aws = 'AKIAXXXXXXXXXXXXXXXX';
      const ghp = 'ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    `;
    expect(real(probeSecrets([file('xxx.js', src)]))).toEqual([]);
  });

  it('DEMO / EXAMPLE / TEST placeholder markers', () => {
    const src = `
      const demoStripe = 'sk_test_DEMO_KEY_NEVER_USE_IN_PRODUCTION';
      const demoOpenAI = 'sk-EXAMPLE_KEY_FOR_DOCS_ONLY_DO_NOT_USE';
      const demoHF = 'hf_DEMO_TOKEN_FOR_DOCUMENTATION_PURPOSES_ONLY';
    `;
    expect(real(probeSecrets([file('demo.js', src)]))).toEqual([]);
  });

  it('Slack placeholders xoxb/xoxp with REPLACE markers', () => {
    const src = `
      const slackBot = 'xoxb-REPLACE-WITH-YOUR-SLACK-BOT-TOKEN';
      const slackUser = 'xoxp-YOUR-SLACK-USER-TOKEN-HERE';
    `;
    expect(real(probeSecrets([file('slack.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 2. .env.example / .env.template / .env.sample / .env.dist files
// -----------------------------------------------------------------------------
describe('.env.example variants', () => {
  it('.env.example with realistic-looking placeholders', () => {
    const src = `
STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zd
OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123
ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx
GOOGLE_API_KEY=AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
`;
    expect(real(probeSecrets([file('.env.example', src)]))).toEqual([]);
  });

  it('.env.template with realistic shapes', () => {
    const src = `
DATABASE_URL=postgres://user:password@localhost:5432/mydb
STRIPE_SECRET_KEY=sk_test_thisIsAFakeKeyFor123
HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyzABCD
`;
    expect(real(probeSecrets([file('.env.template', src)]))).toEqual([]);
  });

  it('.env.sample', () => {
    const src = `
GITHUB_PAT=github_pat_11ABCDEFG0abcdefghijkl_abcdefghijklmnopqrstuvwxyz0123456789
R8_TOKEN=r8_abcdefghijklmnopqrstuvwxyzABCDEFGH
`;
    expect(real(probeSecrets([file('.env.sample', src)]))).toEqual([]);
  });

  it('.env.dist file', () => {
    const src = `
OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz
ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz
`;
    expect(real(probeSecrets([file('.env.dist', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 3. Markdown documentation files containing keys in fenced code blocks
// -----------------------------------------------------------------------------
describe('markdown documentation with keys in fences', () => {
  it('README.md showing OpenAI key shape in fenced block', () => {
    const src = [
      '# Configuration',
      '',
      'Set your API key in `.env`:',
      '',
      '```bash',
      'export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123',
      '```',
      '',
      'Or in code:',
      '',
      '```js',
      "const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123';",
      '```',
      '',
    ].join('\n');
    expect(real(probeSecrets([file('README.md', src)]))).toEqual([]);
  });

  it('docs/setup.md with AWS key example in fence', () => {
    const src = [
      '# AWS Setup',
      '',
      '```',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      '```',
      '',
    ].join('\n');
    expect(real(probeSecrets([file('docs/setup.md', src)]))).toEqual([]);
  });

  it('CHANGELOG.md mentioning key shapes in fences', () => {
    const src = [
      '## v1.2.0',
      '',
      '- Support for `ghp_` GitHub PAT tokens',
      '',
      'Example:',
      '',
      '```',
      'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
      '```',
      '',
    ].join('\n');
    expect(real(probeSecrets([file('CHANGELOG.md', src)]))).toEqual([]);
  });

  it('docs page with multiple provider shapes in fences', () => {
    const src = [
      '# BYOK Configuration',
      '',
      '## OpenAI',
      '```',
      'sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGH',
      '```',
      '',
      '## Anthropic',
      '```',
      'sk-ant-api03-abcdefghijklmnopqrstuvwxyz',
      '```',
      '',
      '## Google',
      '```',
      'AIzaSyBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      '```',
      '',
    ].join('\n');
    expect(real(probeSecrets([file('docs/byok.md', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 4. JSDoc / // line comments naming the shape inline
// -----------------------------------------------------------------------------
describe('line comments naming the shape', () => {
  it('// comment mentioning a stripe-shaped value', () => {
    const src = `
      // Example Stripe live key shape: sk_live_4eC39HqLyjWDarjtT1zd
      function getKey() { return process.env.STRIPE_SECRET_KEY; }
    `;
    expect(real(probeSecrets([file('s.js', src)]))).toEqual([]);
  });

  it('JSDoc @example with openai-shaped value', () => {
    const src = `
      /**
       * Validate an OpenAI key.
       * @example
       * isValidOpenAIKey('sk-proj-abcdefghijklmnopqrstuvwxyz')
       */
      export function isValidOpenAIKey(k) { return /^sk-/.test(k); }
    `;
    expect(real(probeSecrets([file('v.js', src)]))).toEqual([]);
  });

  it('JSDoc @param showing GitHub token format', () => {
    const src = `
      /**
       * @param {string} token - e.g. ghp_abcdefghijklmnopqrstuvwxyz0123456
       */
      export function setToken(token) {}
    `;
    expect(real(probeSecrets([file('g.js', src)]))).toEqual([]);
  });

  it('// inline AWS shape comment', () => {
    const src = `
      // AWS access keys look like AKIAIOSFODNN7EXAMPLE (always 20 chars, AKIA prefix).
      const id = process.env.AWS_ACCESS_KEY_ID;
    `;
    expect(real(probeSecrets([file('a.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 5. /* ... */ block comments — single-line and MULTI-LINE
// -----------------------------------------------------------------------------
describe('block comments — single and multi-line', () => {
  it('single-line block comment with stripe shape', () => {
    const src = `/* example sk_live_4eC39HqLyjWDarjtT1zd */`;
    expect(real(probeSecrets([file('b1.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE block comment with openai shape across lines', () => {
    const src = `
      /*
       * Valid keys look like:
       *   sk-proj-abcdefghijklmnopqrstuvwxyz0123456789
       *   sk-ant-api03-abcdefghijklmnopqrstuvwx
       * Do not commit real keys to this repo.
       */
      export function load() {}
    `;
    expect(real(probeSecrets([file('m1.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE block comment listing many provider shapes', () => {
    const src = `
      /*
       * Provider key shape reference:
       *   OpenAI:    sk-proj-abcdefghijklmnopqrstuvwxyz0123456789
       *   Anthropic: sk-ant-api03-abcdefghijklmnopqrstuvwxyz
       *   Google:    AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
       *   GitHub:    ghp_abcdefghijklmnopqrstuvwxyz0123456789
       *   AWS:       AKIAIOSFODNN7EXAMPLE
       *   Stripe:    sk_live_4eC39HqLyjWDarjtT1zd
       *   HF:        hf_abcdefghijklmnopqrstuvwxyzABCD
       *   Replicate: r8_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL
       */
      export const PROVIDERS = [];
    `;
    expect(real(probeSecrets([file('m2.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE block comment with stripe key body spanning lines', () => {
    const src = `
      /*
       Quick reference:

         sk_live_4eC39HqLyjWDarjtT1zd

       The above is an example value used in Stripe documentation.
      */
      export const KEY_PREFIX = 'sk_';
    `;
    expect(real(probeSecrets([file('m3.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE block comment with PEM private key shape inside', () => {
    const src = `
      /*
       Example PEM-encoded private key (placeholder body):

         -----BEGIN RSA PRIVATE KEY-----
         REPLACE_WITH_YOUR_PRIVATE_KEY_CONTENTS_HERE
         -----END RSA PRIVATE KEY-----

       Replace the body before deploying.
      */
      export const PEM_HEADER = 'BEGIN';
    `;
    expect(real(probeSecrets([file('m4.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE block comment with postgres URL shape', () => {
    const src = `
      /*
       Connection examples:

         postgres://user:password@localhost:5432/mydb
         postgres://admin:hunter2@db.example.com/app

       Use environment variables in production.
      */
      export const SCHEME = 'postgres';
    `;
    expect(real(probeSecrets([file('m5.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE block comment with multiple xoxb tokens', () => {
    const src = `
      /*
       Slack token shapes:

         xoxb-AbCdEfGhIjKlMnOpQrStUvWx
         xoxp-abcdefghijklmnopqr

       These are example shapes only; real tokens are user-specific.
      */
      export const SLACK_PREFIX = 'xox';
    `;
    expect(real(probeSecrets([file('m6.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 6. Template literals — single-line and MULTI-LINE used as code samples
// -----------------------------------------------------------------------------
describe('template literals containing shape — single and multi-line', () => {
  it('single-line template literal as code sample', () => {
    const src = "export const sample = `const k = 'sk-proj-abcdefghijklmnopqrstuvwxyz';`;";
    expect(real(probeSecrets([file('t1.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE template literal containing openai key shape', () => {
    const src = `
      export const sample = \`
        // Setup
        const openai = new OpenAI({
          apiKey: 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789',
        });
      \`;
    `;
    expect(real(probeSecrets([file('t2.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE template literal containing AWS shape', () => {
    const src = `
      export const awsSample = \`
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      \`;
    `;
    expect(real(probeSecrets([file('t3.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE template literal listing multiple provider shapes', () => {
    const src = `
      export const allSamples = \`
        STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zd
        OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123
        ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx
        GOOGLE_API_KEY=AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789
        HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyzABCD
      \`;
    `;
    expect(real(probeSecrets([file('t4.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE template literal with PEM block', () => {
    const src = `
      export const pemSample = \`
        -----BEGIN RSA PRIVATE KEY-----
        REPLACE_WITH_YOUR_PRIVATE_KEY_HERE
        -----END RSA PRIVATE KEY-----
      \`;
    `;
    expect(real(probeSecrets([file('t5.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE template literal rendering a markdown fenced example', () => {
    const src = `
      export const markdownDoc = \`
        # Config

        \\\`\\\`\\\`
        sk-ant-api03-abcdefghijklmnopqrstuvwxyz
        ghp_abcdefghijklmnopqrstuvwxyz0123456789
        \\\`\\\`\\\`
      \`;
    `;
    expect(real(probeSecrets([file('t6.js', src)]))).toEqual([]);
  });

  it('MULTI-LINE template literal with stripe sample across many lines', () => {
    const src = `
      export const stripeSample = \`
        // Initialize Stripe with the secret key (test mode).
        import Stripe from 'stripe';

        const stripe = new Stripe(
          'sk_test_4eC39HqLyjWDarjtT1zd'
        );

        export default stripe;
      \`;
    `;
    expect(real(probeSecrets([file('t7.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 7. Git SHA collisions: 40-char hex
// -----------------------------------------------------------------------------
describe('git SHA collisions (40-char hex)', () => {
  it('commit SHA as a variable value', () => {
    const src = `
      export const BUILD_COMMIT = '3e3f463abcdef0123456789abcdef0123456789a';
    `;
    expect(real(probeSecrets([file('build.js', src)]))).toEqual([]);
  });

  it('commit SHA list', () => {
    const src = `
      export const COMMITS = [
        '67c8cdaabcdef0123456789abcdef0123456789a',
        '3e3f463abcdef0123456789abcdef0123456789b',
        'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
      ];
    `;
    expect(real(probeSecrets([file('commits.js', src)]))).toEqual([]);
  });

  it('git SHA in URL', () => {
    const src = `
      export const PERMALINK = 'https://github.com/midatlanticAI/PreFlight/commit/3e3f463abcdef0123456789abcdef0123456789a';
    `;
    expect(real(probeSecrets([file('link.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 8. UUID v4 collisions
// -----------------------------------------------------------------------------
describe('UUID v4 collisions', () => {
  it('UUID as a session ID', () => {
    const src = `
      export const SESSION_ID = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';
    `;
    expect(real(probeSecrets([file('s.js', src)]))).toEqual([]);
  });

  it('list of UUIDs', () => {
    const src = `
      export const FEATURE_IDS = [
        '550e8400-e29b-41d4-a716-446655440000',
        '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
        '6ba7b811-9dad-11d1-80b4-00c04fd430c8',
      ];
    `;
    expect(real(probeSecrets([file('flags.js', src)]))).toEqual([]);
  });

  it('UUID as URL path segment', () => {
    const src = `
      export const TENANT_URL = 'https://api.example.com/tenants/f47ac10b-58cc-4372-a567-0e02b2c3d479';
    `;
    expect(real(probeSecrets([file('u.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 9. Base64 data URLs
// -----------------------------------------------------------------------------
describe('base64 data URLs', () => {
  it('image/png data URL', () => {
    const src = `
      export const ICON = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==';
    `;
    expect(real(probeSecrets([file('icon.js', src)]))).toEqual([]);
  });

  it('image/svg+xml data URL', () => {
    const src = `
      export const SVG = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PC9zdmc+';
    `;
    expect(real(probeSecrets([file('svg.js', src)]))).toEqual([]);
  });

  it('font/woff2 data URL', () => {
    const src = `
      export const FONT = 'data:font/woff2;base64,d09GMgABAAAAAAUEAA0AAAAACoAAAATuAAEAAAAAAAA';
    `;
    expect(real(probeSecrets([file('font.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 10. Hex hashes: SHA-256, SHA-1, MD5
// -----------------------------------------------------------------------------
describe('hex hashes', () => {
  it('SHA-256 of a file', () => {
    const src = `
      export const INTEGRITY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    `;
    expect(real(probeSecrets([file('h256.js', src)]))).toEqual([]);
  });

  it('SHA-1 collision shape', () => {
    const src = `
      export const SRI = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
    `;
    expect(real(probeSecrets([file('h1.js', src)]))).toEqual([]);
  });

  it('MD5 cache key', () => {
    const src = `
      export const CACHE_KEY = 'd41d8cd98f00b204e9800998ecf8427e';
    `;
    expect(real(probeSecrets([file('md5.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 11. JWT of public payloads
// -----------------------------------------------------------------------------
describe('JWT of public payloads', () => {
  it('typical example JWT (no secret content)', () => {
    const src = `
      // Public example JWT from jwt.io
      export const SAMPLE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    `;
    expect(real(probeSecrets([file('jwt.js', src)]))).toEqual([]);
  });

  it('JWT in a JSDoc example', () => {
    const src = `
      /**
       * @example
       * decode('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.bSig')
       */
      export function decode(jwt) { return jwt.split('.')[1]; }
    `;
    expect(real(probeSecrets([file('jwt2.js', src)]))).toEqual([]);
  });

  it('JWT inside markdown fence', () => {
    const src = [
      '# Decoding',
      '',
      '```',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dummysig',
      '```',
      '',
    ].join('\n');
    expect(real(probeSecrets([file('jwt.md', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 12. Self-references: regex patterns matching secret shapes as data
// -----------------------------------------------------------------------------
describe('regex patterns describing secret shapes', () => {
  it('AKIA regex literal', () => {
    const src = `
      export const AWS_KEY_PATTERN = /AKIA[0-9A-Z]{16}/;
    `;
    expect(real(probeSecrets([file('r1.js', src)]))).toEqual([]);
  });

  it('stripe regex literal', () => {
    const src = `
      export const STRIPE_KEY_PATTERN = /sk_(?:live|test)_[A-Za-z0-9]{24,}/;
    `;
    expect(real(probeSecrets([file('r2.js', src)]))).toEqual([]);
  });

  it('multi-provider regex map', () => {
    const src = `
      export const PATTERNS = {
        openai: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/,
        anthropic: /sk-ant-[A-Za-z0-9_-]{20,}/,
        google: /AIza[0-9A-Za-z_-]{30,}/,
        github: /(?:ghp|gho|github_pat)_[A-Za-z0-9_]{20,}/,
        hf: /hf_[A-Za-z0-9]{30,}/,
        replicate: /r8_[A-Za-z0-9]{30,}/,
      };
    `;
    expect(real(probeSecrets([file('r3.js', src)]))).toEqual([]);
  });

  it('regex source as a string', () => {
    const src = `
      export const SOURCE = 'AKIA[0-9A-Z]{16}';
    `;
    expect(real(probeSecrets([file('r4.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 13. Bare env-var references
// -----------------------------------------------------------------------------
describe('bare env-var references', () => {
  it('process.env.STRIPE_SECRET_KEY', () => {
    const src = `
      export function getStripe() {
        return process.env.STRIPE_SECRET_KEY;
      }
    `;
    expect(real(probeSecrets([file('env1.js', src)]))).toEqual([]);
  });

  it('destructured env vars', () => {
    const src = `
      const { OPENAI_API_KEY, ANTHROPIC_API_KEY, AWS_SECRET_ACCESS_KEY } = process.env;
      export { OPENAI_API_KEY, ANTHROPIC_API_KEY, AWS_SECRET_ACCESS_KEY };
    `;
    expect(real(probeSecrets([file('env2.js', src)]))).toEqual([]);
  });

  it('import.meta.env for vite', () => {
    const src = `
      export const KEY = import.meta.env.VITE_STRIPE_PUBLIC_KEY;
    `;
    expect(real(probeSecrets([file('env3.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 14. DB URLs without credentials
// -----------------------------------------------------------------------------
describe('DB URLs without credentials', () => {
  it('postgres URL without user:pass', () => {
    const src = `
      export const DB = 'postgres://localhost/myapp';
    `;
    expect(real(probeSecrets([file('db1.js', src)]))).toEqual([]);
  });

  it('postgres URL with empty creds', () => {
    const src = `
      export const DB = 'postgres://@localhost:5432/myapp';
    `;
    expect(real(probeSecrets([file('db2.js', src)]))).toEqual([]);
  });

  it('mongodb URL without creds', () => {
    const src = `
      export const DB = 'mongodb://localhost:27017/myapp';
    `;
    expect(real(probeSecrets([file('db3.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 15. AWS Secrets Manager ARNs / resource paths
// -----------------------------------------------------------------------------
describe('AWS resource paths', () => {
  it('Secrets Manager ARN', () => {
    const src = `
      export const SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/stripe/secret_key-AbCdEf';
    `;
    expect(real(probeSecrets([file('arn1.js', src)]))).toEqual([]);
  });

  it('IAM role ARN', () => {
    const src = `
      export const ROLE_ARN = 'arn:aws:iam::123456789012:role/MyAppRole';
    `;
    expect(real(probeSecrets([file('arn2.js', src)]))).toEqual([]);
  });

  it('SSM parameter path', () => {
    const src = `
      export const PARAM = '/prod/app/STRIPE_SECRET_KEY';
    `;
    expect(real(probeSecrets([file('ssm.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 16. Shape-like substrings in URLs / version strings / filenames
// -----------------------------------------------------------------------------
describe('shape-like substrings in URLs, versions, filenames', () => {
  it('URL path that begins with sk-', () => {
    const src = `
      export const SKI_RESORT_API = 'https://api.example.com/sk-resorts/list';
    `;
    expect(real(probeSecrets([file('u1.js', src)]))).toEqual([]);
  });

  it('asset filename containing AIza prefix', () => {
    const src = `
      export const ASSET = '/static/AIzaSyB-image-thumbnail-cdn-cache.png';
    `;
    expect(real(probeSecrets([file('a.js', src)]))).toEqual([]);
  });

  it('version string', () => {
    const src = `
      export const VERSION = 'v0.5.0-sk-rc.1';
    `;
    expect(real(probeSecrets([file('v.js', src)]))).toEqual([]);
  });

  it('CDN URL containing ghp_ as a path segment', () => {
    const src = `
      export const CDN = 'https://cdn.example.com/assets/ghp_default_avatar.svg';
    `;
    expect(real(probeSecrets([file('cdn.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 17. Test fixture paths
// -----------------------------------------------------------------------------
describe('test fixture paths', () => {
  it('*.test.js with shape-like literal', () => {
    const src = `
      import { describe, it, expect } from 'vitest';
      describe('keys', () => {
        it('rejects malformed keys', () => {
          expect(isValid('AKIAIOSFODNN7EXAMPLE')).toBe(false);
        });
      });
    `;
    expect(real(probeSecrets([file('foo.test.js', src)]))).toEqual([]);
  });

  it('*.spec.js with shape-like literal', () => {
    const src = `
      it('parses stripe key', () => {
        const k = 'sk_live_4eC39HqLyjWDarjtT1zd';
        expect(parse(k).livemode).toBe(true);
      });
    `;
    expect(real(probeSecrets([file('stripe.spec.js', src)]))).toEqual([]);
  });

  it('tests/ directory file', () => {
    const src = `
      export const SAMPLE = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789';
    `;
    expect(real(probeSecrets([file('tests/fixtures/github.js', src)]))).toEqual([]);
  });

  it('__tests__/ directory file', () => {
    const src = `
      export const SAMPLE_OPENAI = 'sk-proj-abcdefghijklmnopqrstuvwxyz';
    `;
    expect(real(probeSecrets([file('src/__tests__/openai.fixture.js', src)]))).toEqual([]);
  });

  it('fixtures/ directory', () => {
    const src = `
      module.exports = { key: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz' };
    `;
    expect(real(probeSecrets([file('fixtures/anthropic.cjs', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 18. PEM blocks with PLACEHOLDER body content
// -----------------------------------------------------------------------------
describe('PEM blocks with placeholder bodies', () => {
  it('RSA private key with REPLACE_WITH_YOUR_KEY placeholder', () => {
    const src = `
      export const PEM_TEMPLATE = \`
-----BEGIN RSA PRIVATE KEY-----
REPLACE_WITH_YOUR_PRIVATE_KEY_CONTENTS
-----END RSA PRIVATE KEY-----
      \`;
    `;
    expect(real(probeSecrets([file('pem1.js', src)]))).toEqual([]);
  });

  it('EC private key placeholder in markdown fence', () => {
    const src = [
      '```',
      '-----BEGIN EC PRIVATE KEY-----',
      'YOUR_KEY_HERE',
      '-----END EC PRIVATE KEY-----',
      '```',
      '',
    ].join('\n');
    expect(real(probeSecrets([file('pem.md', src)]))).toEqual([]);
  });

  it('OpenSSH private key placeholder', () => {
    const src = `
      // Example layout (do not commit real keys):
      // -----BEGIN OPENSSH PRIVATE KEY-----
      // REPLACE_THIS_LINE_WITH_YOUR_KEY
      // -----END OPENSSH PRIVATE KEY-----
      export const HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----';
    `;
    expect(real(probeSecrets([file('ssh.js', src)]))).toEqual([]);
  });

  it('PEM headers as string constants only (no body)', () => {
    const src = `
      export const BEGIN = '-----BEGIN PRIVATE KEY-----';
      export const END = '-----END PRIVATE KEY-----';
    `;
    expect(real(probeSecrets([file('pem-headers.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 19. Variable names containing prefix substrings but no value
// -----------------------------------------------------------------------------
describe('variable names containing prefix substrings', () => {
  it('variable named like a token prefix, with non-secret value', () => {
    const src = `
      export const ghp_token_label = 'GitHub personal access token';
      export const sk_live_description = 'A live Stripe secret key.';
      export const AKIA_PREFIX_LABEL = 'AWS Access Key ID prefix';
    `;
    expect(real(probeSecrets([file('labels.js', src)]))).toEqual([]);
  });

  it('functions named after providers', () => {
    const src = `
      export function getSk_live_label() { return 'Stripe live'; }
      export function buildGhpUrl(repo) { return 'https://github.com/' + repo; }
    `;
    expect(real(probeSecrets([file('fns.js', src)]))).toEqual([]);
  });

  it('object keys that are prefix-shaped, with descriptive values', () => {
    const src = `
      export const PROVIDER_LABELS = {
        sk_live: 'Stripe live secret key',
        sk_test: 'Stripe test secret key',
        ghp: 'GitHub personal access token (classic)',
        AKIA: 'AWS access key identifier',
      };
    `;
    expect(real(probeSecrets([file('plabels.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// 20. Long base64 of legitimate binary content
// -----------------------------------------------------------------------------
describe('long base64 of legitimate binary content', () => {
  it('inlined PNG icon as base64', () => {
    const b64 =
      'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAACXBIWXMAAAsTAAALEwEAmpwYAAAA' +
      'GXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyJpVFh0WE1MOmNvbS5hZG9iZS54' +
      'bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlk' +
      'Ij8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhN' +
      'UCBDb3JlIDUuNi1jMTQwIDc5LjE2MDQ1MSwgMjAxNy8wNS8wNi0wMTowODoyMSAgICAgICAgIj4g';
    const src = `export const PNG = '${b64}';`;
    expect(real(probeSecrets([file('png.js', src)]))).toEqual([]);
  });

  it('inlined SVG icon as base64', () => {
    const b64 =
      'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+' +
      'PHBhdGggZmlsbD0iIzAwMCIgZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAg' +
      'MTAtNC40OCAxMC0xMFMxNy41MiAyIDEyIDJ6Ii8+PC9zdmc+';
    const src = `export const SVG = '${b64}';`;
    expect(real(probeSecrets([file('svg.js', src)]))).toEqual([]);
  });

  it('font binary base64', () => {
    const b64 =
      'd09GMgABAAAAAAUEAA0AAAAACoAAAATuAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' +
      'AABaAQAANgAAAFwBQ0FMVCMSF4kAAAFwAAAAVgAAAFoIIQjPY21hcAAAAcgAAABMAAABYg6N' +
      'kE9jdnQgAAACFAAAABMAAAAUBwn/lGZwZ20AAAIoAAAFkAAAC3CKkZBZZ2FzcAAAB7gAAAA';
    const src = `export const FONT = '${b64}';`;
    expect(real(probeSecrets([file('font.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Extra block-comment multi-line coverage (the line-scoped fix's failure mode)
// -----------------------------------------------------------------------------
describe('extra multi-line block-comment cases', () => {
  it('block comment with stripe key wrapped over 3+ lines', () => {
    const src = `
      /*
       The stripe key shape:

           sk_live_4eC39HqLyjWDarjtT1zd

       is the canonical Stripe documentation example.
       Do not use real keys in source.
      */
      export const X = 1;
    `;
    expect(real(probeSecrets([file('xm1.js', src)]))).toEqual([]);
  });

  it('block comment containing TWO multi-line shapes', () => {
    const src = `
      /*
       Examples (do not commit real values):

           ghp_abcdefghijklmnopqrstuvwxyz0123456789

       and:

           sk-ant-api03-abcdefghijklmnopqrstuvwxyz

       are both placeholders for documentation.
      */
      export const Y = 2;
    `;
    expect(real(probeSecrets([file('xm2.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Extra template-literal multi-line coverage
// -----------------------------------------------------------------------------
describe('extra multi-line template-literal cases', () => {
  it('multi-line template literal as React JSX child', () => {
    const src = `
      export const CodeSample = () => (
        <pre>
{\`OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz
ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx
GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789
\`}
        </pre>
      );
    `;
    expect(real(probeSecrets([file('Sample.jsx', src)]))).toEqual([]);
  });

  it('multi-line template literal in a learn pattern fixture', () => {
    const src = `
      export const PATTERN_BODY = \`
        Detection example shape:

            sk_live_4eC39HqLyjWDarjtT1zd
            AKIAIOSFODNN7EXAMPLE

        These are documentation values.
      \`;
    `;
    expect(real(probeSecrets([file('pattern-body.js', src)]))).toEqual([]);
  });
});

// -----------------------------------------------------------------------------
// Edge cases where benign-vs-secret is genuinely ambiguous
// -----------------------------------------------------------------------------
describe('edge cases where benign-vs-secret is genuinely ambiguous', () => {
  // Ambiguous: a 40-char hex literal in a source file with no obvious
  // "commit"/"sha"/"hash" context could be either a git SHA or an AWS secret.
  // Treating it as a SHA when stored in BUILD_COMMIT seems correct, but a
  // naive scanner may still over-fire.
  it('40-char hex stored under a name that could be either', () => {
    const src = `
      export const RELEASE = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
    `;
    expect(real(probeSecrets([file('release.js', src)]))).toEqual([]);
  });

  // Ambiguous: a JWT with a real-looking signature segment cannot be
  // distinguished from a published example without out-of-band context.
  it('JWT-shaped value in production code with example comment', () => {
    const src = `
      // Example JWT (from RFC 7519 appendix, public test vector):
      export const RFC_EXAMPLE = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    `;
    expect(real(probeSecrets([file('rfc.js', src)]))).toEqual([]);
  });

  // Ambiguous: a value with the prefix `sk-` and 20+ chars without any
  // surrounding placeholder marker, in a file outside .env.example, is
  // exactly the high-confidence shape; this one only reads as benign
  // because the variable name and comment both flag it as a sample.
  it('sk- value in source code with only a comment to disambiguate', () => {
    const src = `
      // sample value used in unit tests; never a real key
      export const SAMPLE_OPENAI_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz';
    `;
    expect(real(probeSecrets([file('sample.js', src)]))).toEqual([]);
  });
});
