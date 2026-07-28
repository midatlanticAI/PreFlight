/**
 * Weak cryptography probe.
 *
 * The registry had exactly one crypto-primitive rule before this probe, and it
 * turned on the variable NAME rather than the construct: Auth Weakness fires
 * only when `password|passwd|pwd|pw` appears inside the `.update(...)`
 * argument. Rename the parameter and the finding disappears. Cipher mode,
 * cipher algorithm and IV reuse had no coverage at all, so a module that
 * encrypted every record with `aes-256-ecb` and a zero IV came back clean.
 *
 * The precision half matters as much. md5 for a cache key, sha1 for a
 * checksum, sha256 for an integrity digest, AES-GCM with `randomBytes` and a
 * decrypt path that reads the IV back off the payload are all correct, and
 * three of them are the exact fix this probe's remediation recommends.
 * Flagging your own remediation is how a tool loses a user for good.
 */

import { describe, it, expect } from 'vitest';
import { probeWeakCryptography } from '../lib/probes/crypto.js';

const f = (path, content) => ({ path, content });
const scan = (content, path = 'server/crypto.js') =>
  probeWeakCryptography([f(path, content)]) || [];

// One module holding both the bugs and the fixes. Seven lines must fire and
// five must not, which is the property a file-level heuristic cannot have.
const MIXED_MODULE = `const crypto = require('crypto');

function cacheKey(url) {
  return crypto.createHash('md5').update(url).digest('hex');
}
function etagFor(body) {
  return crypto.createHash('sha1').update(body).digest('hex');
}
function integrity(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('base64');
}

function hashPassword(p) {
  return crypto.createHash('md5').update(p).digest('hex');
}
function storeSecret(plaintext) {
  return crypto.createHash('sha1').update(plaintext).digest('hex');
}
function register(email, value) {
  const digest = crypto.createHash('sha256').update(value).digest('hex');
  return { email, digest };
}

function sealGood(key, data) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  return { iv, out: Buffer.concat([c.update(data), c.final()]), tag: c.getAuthTag() };
}
function openGood(key, ivHex, tagHex, body) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  d.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([d.update(body, 'hex'), d.final()]);
}

const FIXED_IV = Buffer.from('0000000000000000', 'hex');
function sealEcb(key, d) {
  return crypto.createCipheriv('aes-256-ecb', key, null).update(d);
}
function sealDes(key, iv, d) {
  return crypto.createCipheriv('des-ede3', key, iv).update(d);
}
function sealFixed(key, d) {
  return crypto.createCipheriv('aes-256-cbc', key, FIXED_IV).update(d);
}
function sealLegacy(passphrase, d) {
  return crypto.createCipher('aes-256-cbc', passphrase).update(d);
}
`;

describe('probeWeakCryptography — recall', () => {
  it('reports every wrong line of the mixed module and none of the right ones', () => {
    const found = scan(MIXED_MODULE);
    const lines = [...new Set(found.map((x) => x.line))].sort((a, b) => a - b);
    // 14 md5(p) in hashPassword, 17 sha1(plaintext), 20 sha256 in register(),
    // 37 ECB, 40 3DES, 43 fixed IV, 46 createCipher. The five correct lines
    // (5 cacheKey, 8 etagFor, 11 integrity, 26 GCM seal, 30 GCM open) are absent.
    expect(lines).toEqual([14, 17, 20, 37, 40, 43, 46]);
    for (const cwe of ['CWE-916', 'CWE-327', 'CWE-329']) {
      expect(
        found.some((x) => x.cwe === cwe),
        `expected a ${cwe} finding`
      ).toBe(true);
    }
  });

  const shapes = [
    [
      'md5 password hash whose argument is NOT named password',
      'CWE-916',
      "const crypto = require('crypto');\nfunction hashPassword(p) {\n  return crypto.createHash('md5').update(p).digest('hex');\n}\n",
    ],
    [
      'md5 over a value named plaintext',
      'CWE-916',
      "import crypto from 'crypto';\nexport function store(plaintext) {\n  return crypto.createHash('md5').update(plaintext).digest('hex');\n}\n",
    ],
    [
      'sha1 with a single-letter argument inside an auth function',
      'CWE-916',
      "import crypto from 'crypto';\nexport async function login(u, p) {\n  const h = crypto.createHash('sha1').update(p).digest('hex');\n  return db.user.find({ u, h });\n}\n",
    ],
    [
      'the chained call split across lines',
      'CWE-916',
      "import crypto from 'crypto';\nexport function setPassword(user, value) {\n  user.hash = crypto\n    .createHash('md5')\n    .update(value)\n    .digest('hex');\n}\n",
    ],
    [
      'sha256 password hashing with no KDF anywhere in the file',
      'CWE-916',
      "import { createHash } from 'crypto';\nexport function register(email, passwordValue) {\n  return db.insert({ email, h: createHash('sha256').update(passwordValue).digest('hex') });\n}\n",
    ],
    [
      'ECB mode',
      'CWE-327',
      "const crypto = require('crypto');\nexport const seal = (key, d) => crypto.createCipheriv('aes-256-ecb', key, null).update(d);\n",
    ],
    [
      'ECB reached through an algorithm constant',
      'CWE-327',
      "const crypto = require('crypto');\nconst ALGO = 'AES-128-ECB';\nexport const seal = (key, d) => crypto.createCipheriv(ALGO, key, null).update(d);\n",
    ],
    [
      'ECB on the decrypt side, which Node spells createDecipheriv',
      'CWE-327',
      "const crypto = require('crypto');\nexport const open = (key, b) => crypto.createDecipheriv('aes-256-ecb', key, null).update(b);\n",
    ],
    [
      'ECB selected in CryptoJS',
      'CWE-327',
      "import CryptoJS from 'crypto-js';\nexport const seal = (d, k) => CryptoJS.AES.encrypt(d, k, { mode: CryptoJS.mode.ECB }).toString();\n",
    ],
    [
      '3DES',
      'CWE-327',
      "const crypto = require('crypto');\nexport const seal = (k, iv, d) => crypto.createCipheriv('des-ede3', k, iv).update(d);\n",
    ],
    [
      'RC4',
      'CWE-327',
      "const crypto = require('crypto');\nexport const seal = (k, iv, d) => crypto.createCipheriv('rc4', k, iv).update(d);\n",
    ],
    [
      'Blowfish',
      'CWE-327',
      "const crypto = require('crypto');\nexport const seal = (k, iv, d) => crypto.createCipheriv('bf-cbc', k, iv).update(d);\n",
    ],
    [
      'crypto.createCipher, which derives the key with MD5 and a zero IV',
      'CWE-327',
      "const crypto = require('crypto');\nexport const seal = (pass, d) => crypto.createCipher('aes-256-cbc', pass).update(d);\n",
    ],
    [
      'a fixed IV bound one hop away',
      'CWE-329',
      "const crypto = require('crypto');\nconst IV = Buffer.from('0000000000000000', 'hex');\nexport const seal = (k, d) => crypto.createCipheriv('aes-256-cbc', k, IV).update(d);\n",
    ],
    [
      'a fixed IV written inline',
      'CWE-329',
      "const crypto = require('crypto');\nexport const seal = (k, d) =>\n  crypto.createCipheriv('aes-256-gcm', k, Buffer.from('abcdef0123456789', 'hex')).update(d);\n",
    ],
    [
      'an all-zero Buffer.alloc IV',
      'CWE-329',
      "const crypto = require('crypto');\nexport function seal(k, d) {\n  const iv = Buffer.alloc(16);\n  return crypto.createCipheriv('aes-256-cbc', k, iv).update(d);\n}\n",
    ],
    [
      'a fixed IV in a call wrapped across lines',
      'CWE-329',
      "const crypto = require('crypto');\nconst NONCE = Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);\nexport function seal(k, d) {\n  const c = crypto.createCipheriv(\n    'aes-256-gcm',\n    k,\n    NONCE\n  );\n  return c.update(d);\n}\n",
    ],
    [
      'a fixed IV passed to WebCrypto',
      'CWE-329',
      "const IV = new Uint8Array(12);\nexport const seal = (key, data) =>\n  crypto.subtle.encrypt({ name: 'AES-GCM', iv: IV }, key, data);\n",
    ],
  ];
  for (const [name, cwe, src] of shapes) {
    it(`${name} fires ${cwe}`, () => {
      expect(scan(src).some((x) => x.cwe === cwe)).toBe(true);
    });
  }

  it('fires on TypeScript as well as JavaScript', () => {
    const src =
      "import { createHash } from 'node:crypto';\nexport function hashCredential(credential: string): string {\n  return createHash('md5').update(credential).digest('hex');\n}\n";
    expect(scan(src, 'src/auth/hash.ts').some((x) => x.cwe === 'CWE-916')).toBe(true);
  });

  it('emits every field a finding card needs', () => {
    const [finding] = scan(
      "const crypto = require('crypto');\nexport const seal = (k, d) => crypto.createCipheriv('aes-256-ecb', k, null).update(d);\n"
    );
    for (const key of [
      'id',
      'probe',
      'title',
      'severity',
      'category',
      'cwe',
      'file',
      'line',
      'evidence',
      'remediation',
    ]) {
      expect(finding, `missing ${key}`).toHaveProperty(key);
    }
    expect(finding.probe).toBe('Weak Cryptography');
    expect(finding.category).toBe('Cryptographic Failure');
  });

  it('writes remediation in the house voice: no em-dashes', () => {
    const all = shapes.flatMap(([, , src]) => scan(src));
    expect(all.length).toBeGreaterThan(0);
    const offenders = all
      .filter((x) => /[—–]/.test(`${x.title} ${x.remediation}`))
      .map((x) => x.title);
    expect(offenders).toEqual([]);
  });
});

describe('probeWeakCryptography — precision', () => {
  const safe = [
    [
      'AES-256-GCM with a per-message random IV, which is the recommended fix',
      "const crypto = require('crypto');\nexport function seal(key, data) {\n  const iv = crypto.randomBytes(12);\n  const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n  return { iv, tag: c.getAuthTag(), out: c.update(data) };\n}\n",
    ],
    [
      'AES-256-CBC with crypto.randomBytes(16) written inline',
      "const crypto = require('crypto');\nexport const seal = (k, d) =>\n  crypto.createCipheriv('aes-256-cbc', k, crypto.randomBytes(16)).update(d);\n",
    ],
    [
      'a decrypt path reading the IV back off the payload',
      "const crypto = require('crypto');\nexport function open(key, payload) {\n  const iv = Buffer.from(payload.iv, 'hex');\n  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);\n  d.setAuthTag(Buffer.from(payload.tag, 'hex'));\n  return d.update(payload.body, 'hex');\n}\n",
    ],
    [
      'md5 as a cache key',
      "const crypto = require('crypto');\nexport const cacheKey = (url) => crypto.createHash('md5').update(url).digest('hex');\n",
    ],
    [
      'md5 as an ETag',
      "import { createHash } from 'crypto';\nexport const etagFor = (body) => '\"' + createHash('md5').update(body).digest('hex') + '\"';\n",
    ],
    [
      'sha1 as a file checksum',
      "import { createHash } from 'crypto';\nexport const checksum = (buf) => createHash('sha1').update(buf).digest('hex');\n",
    ],
    [
      'sha256 as a content integrity digest',
      "import { createHash } from 'node:crypto';\nexport const integrity = (b) => 'sha256-' + createHash('sha256').update(b).digest('base64');\n",
    ],
    [
      'sha256 inside PBKDF2, where a real KDF does the work',
      "import crypto from 'crypto';\nexport const hashPassword = (password, salt) =>\n  crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256').toString('hex');\n",
    ],
    [
      'bcrypt',
      "import bcrypt from 'bcrypt';\nexport const setPassword = (p) => bcrypt.hash(p, 12);\nexport const checkPassword = (p, h) => bcrypt.compare(p, h);\n",
    ],
    [
      'argon2id',
      "import argon2 from 'argon2';\nexport const setPassword = (password) => argon2.hash(password, { type: argon2.argon2id });\n",
    ],
    [
      'crypto.scrypt',
      "import { scrypt, randomBytes } from 'node:crypto';\nexport function storePassword(password) {\n  const salt = randomBytes(16);\n  return new Promise((res) => scrypt(password, salt, 64, (_, k) => res({ salt, k })));\n}\n",
    ],
    [
      'WebCrypto AES-GCM with getRandomValues',
      "export async function seal(key, data) {\n  const iv = crypto.getRandomValues(new Uint8Array(12));\n  return { iv, out: await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data) };\n}\n",
    ],
    [
      'HMAC-SHA256, which is signing rather than password storage',
      "import { createHmac } from 'crypto';\nexport const sign = (payload, secret) =>\n  createHmac('sha256', secret).update(payload).digest('hex');\n",
    ],
    [
      'a cache key in a file that also handles passwords',
      "import { createHash } from 'crypto';\nimport bcrypt from 'bcrypt';\nexport const verifyPassword = (p, h) => bcrypt.compare(p, h);\nexport const cacheKey = (url) => createHash('md5').update(url).digest('hex');\n",
    ],
    [
      'sha256 deriving a subkey from a master key rather than a password',
      "import { createHash } from 'crypto';\nexport const subkey = (masterKey, label) =>\n  createHash('sha256').update(masterKey + label).digest();\n",
    ],
    [
      'an allow-list naming only safe algorithms',
      "const crypto = require('crypto');\nconst ALLOWED = ['aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'];\nexport const seal = (algo, key, d) => {\n  if (!ALLOWED.includes(algo)) throw new Error('bad algo');\n  return crypto.createCipheriv(algo, key, crypto.randomBytes(12)).update(d);\n};\n",
    ],
    [
      'an IV supplied by the caller, whose provenance this probe cannot see',
      "const crypto = require('crypto');\nexport const seal = (key, iv, d) => crypto.createCipheriv('aes-256-cbc', key, iv).update(d);\n",
    ],
    [
      'an algorithm-shaped word in a file that never builds a cipher',
      "export const LOCALES = { fr: 'liste des articles', es: 'des' };\nexport const RC4 = 'rc4';\n",
    ],
    [
      'the narrow shape Auth Weakness already reports, so nobody is billed twice',
      "const crypto = require('crypto');\nexport const hash = (password) => crypto.createHash('md5').update(password).digest('hex');\n",
    ],
    [
      'timingSafeEqual over an HMAC',
      "import { timingSafeEqual, createHmac } from 'crypto';\nexport const valid = (sig, body, secret) =>\n  timingSafeEqual(Buffer.from(sig), createHmac('sha256', secret).update(body).digest());\n",
    ],
  ];
  for (const [name, src] of safe) {
    it(`${name} is silent`, () => {
      expect(scan(src)).toHaveLength(0);
    });
  }

  it('a comment describing the vulnerable call is not the call', () => {
    const src = `const crypto = require('crypto');
// Never do this: crypto.createCipheriv('aes-256-ecb', key, null)
// and never crypto.createHash('md5').update(password).digest('hex')
/* const IV = Buffer.from('0000000000000000', 'hex'); */
export const seal = (k, d) => crypto.createCipheriv('aes-256-gcm', k, crypto.randomBytes(12)).update(d);
`;
    expect(scan(src)).toHaveLength(0);
  });

  it('a documentation snippet held in a template literal is not code', () => {
    const src = [
      "const crypto = require('crypto');",
      'export const BAD_EXAMPLE = `',
      "  crypto.createCipheriv('aes-256-ecb', key, null);",
      "  crypto.createCipheriv('des-ede3', key, iv);",
      "  crypto.createHash('md5').update(password).digest('hex');",
      '`;',
      'export const seal = (k, d) =>',
      "  crypto.createCipheriv('aes-256-gcm', k, crypto.randomBytes(12)).update(d);",
      '',
    ].join('\n');
    expect(scan(src)).toHaveLength(0);
  });

  it('non-JS/TS files are out of scope', () => {
    const py =
      'import hashlib\ndef f(password):\n    return hashlib.md5(password.encode()).hexdigest()\n';
    expect(scan(py, 'app/main.py')).toHaveLength(0);
  });

  it('test files are skipped', () => {
    const src =
      "const crypto = require('crypto');\nit('encrypts', () => {\n  crypto.createCipheriv('aes-256-ecb', key, null);\n  crypto.createHash('md5').update(plaintextPassword).digest('hex');\n});\n";
    expect(scan(src, 'src/test/crypto.test.js')).toHaveLength(0);
  });

  it('reports one finding per line, never two names for one bug', () => {
    // `des-ecb` is a broken algorithm AND an exposing mode. The user gets the
    // algorithm finding, which is the deeper fix, and only that one.
    const src =
      "const crypto = require('crypto');\nexport const seal = (k, iv, d) => crypto.createCipheriv('des-ecb', k, iv).update(d);\n";
    const found = scan(src);
    expect(found).toHaveLength(1);
    expect(found[0].title).toContain('Broken cipher algorithm');
  });
});

describe('the electerm shape: static IV spelling and KDF parameters', () => {
  // Reported as three gaps by one adversarial pass and re-checked by a second,
  // contextless one before anything was built. Two were real. The third,
  // `aes-192-cbc`, is correct silence: AES-192 is NIST-approved and CBC with a
  // random IV is fine, so a key-size list would have shipped a false-positive
  // generator against perfectly good crypto. The defects in that module are the
  // IV and the salt; the algorithm is a red herring.
  const scan = (content) =>
    probeWeakCryptography([{ path: 'src/server/encryption.js', content }]) || [];

  it('the whole module reports the IV and the salt', () => {
    const src = `import crypto from 'crypto'
const algorithmDefault = 'aes-192-cbc'
const iv = Buffer.alloc(16, 0)
export function encrypt(text, password, algorithm = algorithmDefault) {
  const key = crypto.scryptSync(password, 'salt', 24)
  const cipher = crypto.createCipheriv(algorithm, key, iv)
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex')
}
`;
    const found = scan(src);
    expect(found.some((x) => x.cwe === 'CWE-329')).toBe(true);
    expect(found.some((x) => x.cwe === 'CWE-760')).toBe(true);
  });

  // The explicit zero-fill was silent while the implicit one fired, which is
  // backwards: `, 0` states intent, and `Buffer.alloc(16)` may not even be
  // known by its author to zero-fill.
  const ivSpellings = [
    ['Buffer.alloc(16, 0)', 'Buffer.alloc(16, 0)'],
    ['Buffer.alloc(16,0)', 'Buffer.alloc(16,0)'],
    ['Buffer.alloc(16, 0x00)', 'Buffer.alloc(16, 0x00)'],
    ["Buffer.alloc(16, 'a')", "Buffer.alloc(16, 'a')"],
    ['Buffer.alloc(16)', 'Buffer.alloc(16)'],
  ];
  for (const [name, expr] of ivSpellings) {
    it(`${name} is a fixed IV`, () => {
      const src = `import crypto from 'crypto'\nconst iv = ${expr}\nexport function e(k, t) {\n  return crypto.createCipheriv('aes-256-cbc', k, iv).update(t)\n}\n`;
      expect(scan(src).some((x) => x.cwe === 'CWE-329')).toBe(true);
    });
  }

  it('a variable fill is not assumed to be zero', () => {
    const src = `import crypto from 'crypto'\nexport function e(k, t, fillByte) {\n  const iv = Buffer.alloc(16, fillByte)\n  return crypto.createCipheriv('aes-256-cbc', k, iv).update(t)\n}\n`;
    expect(scan(src).filter((x) => x.cwe === 'CWE-329')).toHaveLength(0);
  });

  // `{ iv }` is the idiomatic modern spelling and was the one that escaped.
  it('WebCrypto shorthand { iv } is a fixed IV', () => {
    const src = `export async function e(key, data) {\n  const iv = new Uint8Array(12)\n  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)\n}\n`;
    expect(scan(src).some((x) => x.cwe === 'CWE-329')).toBe(true);
  });

  it('WebCrypto shorthand with a random IV stays silent', () => {
    const src = `export async function e(key, data) {\n  const iv = crypto.getRandomValues(new Uint8Array(12))\n  return crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data)\n}\n`;
    expect(scan(src).filter((x) => x.cwe === 'CWE-329')).toHaveLength(0);
  });

  // A module that only derives a key matches none of the cipher or hash tokens,
  // so the file-level fast gate returned before any check ran.
  it('a key-derivation-only module is still scanned', () => {
    const src = `import crypto from 'crypto'\nexport function k(password) {\n  return crypto.scryptSync(password, 'salt', 24)\n}\n`;
    expect(scan(src).some((x) => x.cwe === 'CWE-760')).toBe(true);
  });

  it('a hoisted literal salt resolves one hop back', () => {
    const src = `import crypto from 'crypto'\nconst SALT = 'pepper'\nexport function k(password) {\n  return crypto.scryptSync(password, SALT, 32)\n}\n`;
    expect(scan(src).some((x) => x.cwe === 'CWE-760')).toBe(true);
  });

  it('too few PBKDF2 iterations reports', () => {
    const src = `import crypto from 'crypto'\nexport function k(password, salt) {\n  return crypto.pbkdf2Sync(password, salt, 100, 32, 'sha1')\n}\n`;
    expect(scan(src).some((x) => x.cwe === 'CWE-916')).toBe(true);
  });

  const safe = [
    [
      'a random salt',
      "import crypto from 'crypto'\nexport function k(password) {\n  const salt = crypto.randomBytes(16)\n  return { key: crypto.scryptSync(password, salt, 32), salt }\n}\n",
    ],
    [
      'a salt supplied by the caller',
      "import crypto from 'crypto'\nexport function k(password, salt) {\n  return crypto.scryptSync(password, salt, 32)\n}\n",
    ],
    [
      'a salt read back from storage',
      "import crypto from 'crypto'\nexport function v(password, row) {\n  const salt = Buffer.from(row.salt, 'hex')\n  return crypto.scryptSync(password, salt, 32)\n}\n",
    ],
    [
      'PBKDF2 at the OWASP iteration count',
      "import crypto from 'crypto'\nexport function k(password, salt) {\n  return crypto.pbkdf2Sync(password, salt, 600000, 32, 'sha256')\n}\n",
    ],
    [
      'aes-192-cbc with a random IV',
      "import crypto from 'crypto'\nexport function e(k, t) {\n  const iv = crypto.randomBytes(16)\n  return crypto.createCipheriv('aes-192-cbc', k, iv).update(t)\n}\n",
    ],
  ];
  for (const [name, src] of safe) {
    it(`${name} stays silent`, () => {
      expect(scan(src)).toHaveLength(0);
    });
  }
});
